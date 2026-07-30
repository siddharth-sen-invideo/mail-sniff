"""
Mail Sniff: free, no-API email discovery + confidence scoring.

Discovery sources (all free, no keys), tried cheapest-first with fallbacks:
  on-page  ·  contact/about/legal/team/careers/press pages  ·  JSON-LD structured
  data  ·  security.txt  ·  RSS feeds  ·  Cloudflare-decode  ·  linked PDFs (media
  kits)  ·  sitemap team/author pages  ·  GitHub profile+commits  ·  Wayback Machine
  ·  certificate-transparency subdomains (crt.sh)  ·  social bios (Linktree/Mastodon/
  Facebook)  ·  DuckDuckGo search  ·  WHOIS

Verification (Tier A, safe, instant):
  syntax + MX/A record + disposable-domain + role-address  ->  High / Medium / Low

Priority: a NAMED PERSON's address ranks first, then role (support@), then catch-all (info@).
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import re
import subprocess
import time
from urllib.parse import urljoin, urlparse

import httpx

import people as P

try:
    import dns.resolver
    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}")
CFEMAIL_RE = re.compile(r'data-cfemail="([0-9a-fA-F]{4,})"')
CF_LINK_RE = re.compile(r'/cdn-cgi/l/email-protection#([0-9a-fA-F]{4,})')
GH_USER_RE = re.compile(r'github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})', re.I)
GH_SKIP = {"features", "about", "pricing", "topics", "sponsors", "orgs", "marketplace",
           "explore", "login", "join", "settings", "apps", "site", "security", "enterprise",
           "customer-stories", "readme", "contact", "blog", "dashboard", "new", "search",
           "collections", "github", "home", "pulls", "issues", "notifications"}
AUTHOR_RE = re.compile(r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']{2,60})["\']', re.I)
SITENAME_RE = re.compile(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']{2,60})["\']', re.I)
HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
WHOIS_NAME_RE = re.compile(r'Registrant Name:\s*(.+)', re.I)
JSONLD_RE = re.compile(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.I | re.S)
LINKEDIN_IN_RE = re.compile(r'linkedin\.com/in/([A-Za-z0-9\-_%.]+)', re.I)
LINKEDIN_COMPANY_RE = re.compile(r'linkedin\.com/company/([A-Za-z0-9\-_%.]+)', re.I)
LINKTREE_RE = re.compile(r'https?://linktr\.ee/[A-Za-z0-9_.\-]+', re.I)
MASTODON_RE = re.compile(r'https?://[a-z0-9.\-]+/@[A-Za-z0-9_.\-]+', re.I)
FACEBOOK_RE = re.compile(r'https?://(?:www\.)?facebook\.com/[A-Za-z0-9_.\-/]+', re.I)

CANDIDATE_PATHS = [
    "contact", "contact-us", "contactus", "about", "about-us", "about-me",
    "privacy", "privacy-policy", "terms", "terms-of-service", "terms-and-conditions",
    "legal", "imprint", "impressum", "cookie-policy", "disclaimer",
    "team", "our-team", "about/team", "staff", "people", "authors", "author",
    "contributors", "masthead", "editorial", "meet-the-team",
    "careers", "jobs", "press", "media", "media-kit", "advertise", "write-for-us",
    "blog", "news", "articles", "insights", "resources",
    ".well-known/security.txt", "humans.txt",
]
FEED_PATHS = ["feed", "rss", "rss.xml", "atom.xml", "feed.xml", "index.xml", "blog/feed"]
LINK_KEYWORDS = ("contact", "about", "privacy", "terms", "legal", "impressum", "imprint",
                 "cookie", "team", "staff", "people", "author", "masthead", "write-for-us",
                 "advertise", "press", "media", "career", "job", "blog", "editorial")

CATCHALL_LOCALS = {"info", "contact", "hello", "hi", "hey", "support", "team", "office",
                   "enquiries", "inquiries", "mail", "general", "help", "press", "admin"}
ROLE_LOCALS = {
    "info", "support", "contact", "hello", "hi", "admin", "sales", "team", "help",
    "office", "mail", "marketing", "press", "media", "dmca", "privacy", "legal",
    "abuse", "webmaster", "noreply", "no-reply", "hey", "enquiries", "inquiries",
    "general", "editor", "editorial", "service", "services", "billing", "careers", "hr",
}
ROLE_DESIGNATION = {
    "support": "Support", "help": "Support", "info": "General enquiries",
    "contact": "General enquiries", "hello": "General enquiries", "hi": "General enquiries",
    "hey": "General enquiries", "enquiries": "General enquiries", "inquiries": "General enquiries",
    "sales": "Sales", "press": "Press / Media", "media": "Press / Media",
    "editor": "Editorial", "editorial": "Editorial", "careers": "Careers / HR",
    "jobs": "Careers / HR", "hr": "Careers / HR", "marketing": "Marketing",
    "partnerships": "Partnerships", "legal": "Legal", "privacy": "Privacy / Legal",
    "dpo": "Data Protection", "billing": "Billing", "admin": "Admin", "dmca": "Legal / DMCA",
}
TITLE_TOKENS = [
    "editor-in-chief", "managing editor", "co-founder", "cofounder", "vice president",
    "chief executive", "chief marketing", "chief technology", "head of", "ceo", "cto",
    "coo", "cmo", "cfo", "founder", "owner", "president", "director", "editor", "journalist",
    "writer", "author", "reporter", "publisher", "marketing", "content lead", "seo",
    "growth", "public relations", "communications", "partnerships", "outreach", "manager",
    "principal", "chief", "creator", "producer", "designer", "developer", "engineer",
    "consultant", "strategist", "specialist", "coordinator", "photographer", "blogger",
]

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "yahoo.co.uk", "icloud.com", "proton.me", "protonmail.com", "aol.com",
    "gmx.com", "yandex.com", "mail.com", "zoho.com",
}
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "trashmail.com",
    "getnada.com", "sharklasers.com", "dispostable.com", "maildrop.cc",
}
BAD_DOMAINS = {
    "example.com", "example.org", "example.net", "domain.com", "yourdomain.com",
    "email.com", "yourcompany.com", "company.com", "sentry.io", "wixpress.com",
    "test.com", "email.example.com", "mydomain.com", "site.com", "website.com",
    "substackinc.com", "twobirds.com", "automattic.com", "sentry.wixpress.com",
}
BAD_LOCALS = {"you", "your-email", "youremail", "name", "username", "firstname",
              "lastname", "user", "example", "email", "yourname", "someone"}
BOILERPLATE_EMAILS = {
    "support@substack.com", "help@substack.com", "privacy@substack.com",
    "abuse@substack.com", "dmca@substack.com", "tos@substack.com",
    "no-reply@substack.com", "noreply@substack.com", "hello@substack.com",
    "press@substack.com", "legal@substack.com",
}
IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".css",
           ".js", ".woff", ".woff2", ".ttf", ".mp4", ".pdf")
REGISTRAR_HINTS = ("godaddy", "namecheap", "publicdomainregistry", "tucows", "enom",
                   "gandi", "ovh", "ionos", "cloudflare", "registrar", "markmonitor",
                   "csc", "nic.", "verisign", "afilias", "identitydigital")
PRIVACY_HINTS = ("privacy", "proxy", "withheld", "redacted", "whoisguard", "gdpr",
                 "domainsbyproxy", "perfectprivacy", "contactprivacy", "privatewho",
                 "dataprotected", "data-protected", "not-disclosed", "anonymize",
                 "privacyprotect", "whoisprivacy")
GENERIC_NAMES = {"home", "blog", "wordpress", "squarespace", "wix", "website",
                 "untitled", "shopify", "webflow", "ghost", "medium", "substack"}
INTERESTING_SUBS = ("blog", "help", "support", "careers", "press", "team", "about",
                    "media", "news", "docs", "kb", "go", "info", "hello")
# who has the authority to edit site content, ranked best-first for outreach
AUTHORITY_RANK = [
    ("founder", 0), ("co-founder", 0), ("cofounder", 0), ("owner", 0), ("ceo", 0),
    ("president", 0), ("chief executive", 0), ("proprietor", 0),
    ("editor-in-chief", 1), ("managing editor", 1), ("editor", 1), ("editorial", 1),
    ("publisher", 1), ("head of content", 1), ("content", 1),
    ("seo", 2), ("marketing", 2), ("growth", 2), ("brand", 2),
    ("partnership", 3), ("public relations", 3), ("communications", 3), ("outreach", 3), ("pr", 3),
    ("head of", 4), ("director", 4), ("manager", 4), ("lead", 4),
]
LI_SKIP_SLUGS = {"company", "school", "jobs", "feed", "pub", "shareArticle", "sharing",
                 "login", "signup", "cws", "learning", "posts"}
MAX_EMAILS_PER_DOMAIN = 25   # was 6, which silently hid real addresses
PER_DOMAIN_BUDGET = 50  # seconds; bot-walled domains can't stall the whole batch
MAX_PEOPLE_PER_DOMAIN = 8
MAX_PAGE_FETCHES = 48

_mx_cache: dict[str, bool] = {}


def normalize_domain(raw: str) -> str:
    raw = (raw or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).netloc or raw.split("://", 1)[1]
    raw = raw.split("/")[0].split("?")[0].strip().strip(".")
    return raw


def decode_cfemail(hexstr: str) -> str | None:
    try:
        data = bytes.fromhex(hexstr)
        key = data[0]
        return "".join(chr(b ^ key) for b in data[1:])
    except Exception:
        return None


def _valid_email(e: str) -> str | None:
    e = e.strip().strip(".,;:<>()[]'\"").lower().replace("mailto:", "")
    # strip leading JSON/unicode-escape fragments like ">" -> "u003e..."
    e = re.sub(r"^(?:u00[0-9a-f]{2})+", "", e)
    if e.endswith(IMG_EXT):
        return None
    local, _, dom = e.partition("@")
    if not local or not dom or "." not in dom:
        return None
    if dom.endswith(IMG_EXT):
        return None
    if dom in BAD_DOMAINS or local in BAD_LOCALS:
        return None
    if e in BOILERPLATE_EMAILS:
        return None
    if any(h in dom for h in ("sentry", "wixpress", "example", "yourdomain")):
        return None
    if len(e) > 100:
        return None
    return e


def find_emails(text: str) -> set[str]:
    out: set[str] = set()
    for m in EMAIL_RE.findall(text):
        v = _valid_email(m)
        if v:
            out.add(v)
    return out


_OB_LOCAL = r"[A-Za-z0-9._%+\-]{2,64}"
_OB_DOM = r"[A-Za-z0-9\-]{2,63}"
_OB_TLD = r"[A-Za-z]{2,12}"
_OB_AT_MARKED = (r"(?:\[\s*(?:at|@)\s*\]|\(\s*(?:at|@)\s*\)|\{\s*(?:at|@)\s*\}"
                 r"|&#0?64;|%40|\s+@\s+)")
_OB_DOT_ANY = (r"(?:\[\s*(?:dot|\.)\s*\]|\(\s*(?:dot|\.)\s*\)"
               r"|\{\s*(?:dot|\.)\s*\}|\s+dot\s+|\.)")
_OB_DOT_MARKED = (r"(?:\[\s*(?:dot|\.)\s*\]|\(\s*(?:dot|\.)\s*\)"
                  r"|\{\s*(?:dot|\.)\s*\}|\s+dot\s+)")
# marked "at" allows any dot form; a plainly spelled " at " demands a spelled dot,
# otherwise prose like "available at example.com" would become an address.
OBFUS_RES = [
    re.compile(rf"({_OB_LOCAL})\s*{_OB_AT_MARKED}\s*({_OB_DOM})\s*{_OB_DOT_ANY}\s*({_OB_TLD})", re.I),
    re.compile(rf"({_OB_LOCAL})\s+at\s+({_OB_DOM})\s*{_OB_DOT_MARKED}\s*({_OB_TLD})", re.I),
]


def find_obfuscated_emails(text: str) -> set[str]:
    """Catch 'hello [at] site [dot] com' and &#64; forms that plain regex misses."""
    out: set[str] = set()
    for rx in OBFUS_RES:
        for loc, dom, tld in rx.findall(text or ""):
            v = _valid_email(f"{loc}@{dom}.{tld}")
            if v:
                out.add(v)
    return out


def find_cfemails(html: str) -> set[str]:
    out: set[str] = set()
    for hx in CFEMAIL_RE.findall(html) + CF_LINK_RE.findall(html):
        dec = decode_cfemail(hx)
        if not dec:
            continue
        for m in EMAIL_RE.findall(dec):
            v = _valid_email(m)
            if v:
                out.add(v)
    return out


def _walk_jsonld(data):
    if isinstance(data, dict):
        yield data
        for v in data.values():
            yield from _walk_jsonld(v)
    elif isinstance(data, list):
        for it in data:
            yield from _walk_jsonld(it)


def find_jsonld(html: str):
    """Return (emails{email:designation}, name_title{name:jobTitle}) from schema.org."""
    emails: dict[str, str] = {}
    name_title: dict[str, str] = {}
    for block in JSONLD_RE.findall(html):
        try:
            data = json.loads(block.strip())
        except Exception:
            continue
        for node in _walk_jsonld(data):
            if not isinstance(node, dict):
                continue
            t = node.get("@type")
            types = t if isinstance(t, list) else [t]
            em = node.get("email")
            if isinstance(em, str):
                v = _valid_email(em)
                if v:
                    desig = node.get("jobTitle", "") if "Person" in types else ""
                    emails.setdefault(v, desig if isinstance(desig, str) else "")
            if "Person" in types:
                nm, jt = node.get("name"), node.get("jobTitle")
                if isinstance(nm, str) and isinstance(jt, str) and jt.strip():
                    name_title[nm.strip()] = jt.strip()
            cp = node.get("contactPoint")
            for c in (cp if isinstance(cp, list) else [cp] if cp else []):
                if isinstance(c, dict) and isinstance(c.get("email"), str):
                    v = _valid_email(c["email"])
                    if v:
                        emails.setdefault(v, str(c.get("contactType", "") or ""))
    return emails, name_title


def _clean_name(n: str) -> str | None:
    n = re.sub(r"\s+", " ", n).strip(" -|·,")
    if not n or len(n) > 60 or n.lower() in GENERIC_NAMES:
        return None
    if any(g in n.lower() for g in ("wordpress", "squarespace", " wix", "webflow", "shopify")):
        return None
    return n


def names_from(html: str) -> set[str]:
    out: set[str] = set()
    for rx in (AUTHOR_RE, SITENAME_RE):
        m = rx.search(html)
        if m:
            c = _clean_name(m.group(1))
            if c:
                out.add(c)
    return out


def derive_name(email: str) -> str | None:
    local = email.split("@")[0]
    if local in ROLE_LOCALS or local.isdigit():
        return None
    parts = re.split(r"[._\-]+", local)
    parts = [p for p in parts if p.isalpha() and len(p) > 1]
    if not parts or len(parts) > 3:
        return None
    if len(parts) == 1 and len(parts[0]) < 4:
        return None
    return " ".join(p.capitalize() for p in parts)


def _visible_text(html: str) -> str:
    return TAG_RE.sub(" ", SCRIPT_STYLE_RE.sub(" ", html))


def _title_from_text(text: str, name: str) -> str:
    if not name:
        return ""
    idx = text.lower().find(name.lower())
    if idx < 0:
        return ""
    window = text[max(0, idx - 15): idx + len(name) + 90]
    wl = window.lower()
    for kw in TITLE_TOKENS:
        j = wl.find(kw)
        if j >= 0:
            phrase = window[j:j + 42].strip(" ,.—-|\n\t")
            # reject anything that looks like leaked code/markup rather than a title
            if any(ch in phrase for ch in '{}"<>@:\\/=[]') or sum(c.isdigit() for c in phrase) > 3:
                return ""
            return phrase[:42].strip().title() if phrase.islower() else phrase[:42].strip()
    return ""


def designation_for(email: str, jsonld: dict, name_title: dict, text: str) -> str:
    local = email.split("@")[0]
    if jsonld.get(email):
        return str(jsonld[email]).strip()
    if local in ROLE_DESIGNATION:
        return ROLE_DESIGNATION[local]
    name = derive_name(email)
    if name:
        if name in name_title:
            return name_title[name]
        for n, t in name_title.items():
            if name.lower() in n.lower() or n.lower() in name.lower():
                return t
        th = _title_from_text(text, name)
        if th:
            return th
    return ""


def _has_mailserver(domain: str) -> bool:
    if domain in _mx_cache:
        return _mx_cache[domain]
    ok = False
    if _HAS_DNS:
        for rtype in ("MX", "A"):
            try:
                if dns.resolver.resolve(domain, rtype, lifetime=5):
                    ok = True
                    break
            except Exception:
                continue
    else:
        ok = True
    _mx_cache[domain] = ok
    return ok


def classify(email: str) -> tuple[str, str]:
    local, _, dom = email.partition("@")
    if dom in DISPOSABLE:
        return ("low", "Disposable domain")
    if not _has_mailserver(dom):
        return ("low", "No mail server (MX)")
    if local in ROLE_LOCALS:
        return ("medium", "Role address")
    if dom in FREE_PROVIDERS:
        return ("medium", "Personal (free provider)")
    return ("high", "Valid domain mailbox")


def _whois_lookup(domain: str) -> tuple[list[str], str | None]:
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return [], None
    if not out:
        return [], None
    low = out.lower()
    emails = []
    for e in EMAIL_RE.findall(out):
        v = _valid_email(e)
        if not v:
            continue
        loc, _, edom = v.partition("@")
        on_domain = edom == domain or edom.endswith("." + domain) or domain.endswith("." + edom)
        if not (on_domain or edom in FREE_PROVIDERS):
            continue
        if loc in ("abuse", "noc", "hostmaster", "postmaster") or loc.startswith("tld"):
            continue
        emails.append(v)
    emails = [e for e in emails if not any(h in e for h in PRIVACY_HINTS)]
    name = None
    m = WHOIS_NAME_RE.search(out)
    if m:
        cand = m.group(1).strip()
        if cand and not any(h in cand.lower() for h in PRIVACY_HINTS):
            name = _clean_name(cand)
    seen, uniq = set(), []
    for e in emails:
        if e not in seen:
            seen.add(e)
            uniq.append(e)
    return uniq[:3], name


CF_CHALLENGE = ("just a moment", "cf-chl-", "challenge-platform", "cf-browser-verification",
                "enable javascript and cookies", "attention required | cloudflare",
                "jschallenge", "checking your browser", "verifying you are human")


def _is_challenge(body: str) -> bool:
    """A bot-challenge interstitial pretending to be the site."""
    if not body:
        return False
    low = body[:6000].lower()
    return any(m in low for m in CF_CHALLENGE)


async def _curl(url: str):
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "--compressed", "--max-time", "8", "-A", UA, url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=9)
        txt = out.decode("utf-8", "ignore")
        return txt[:700000] if txt.strip() else None
    except Exception:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        return None


async def _fetch(client: httpx.AsyncClient, url: str, timeout=None):
    status = None
    try:
        r = await client.get(url, timeout=timeout) if timeout else await client.get(url)
        ct = r.headers.get("content-type", "").lower()
        if r.status_code == 200 and (
            "html" in ct or "xml" in ct or "text" in ct or "json" in ct
            or url.endswith(("security.txt", "humans.txt"))
        ):
            if any(m in r.text[:4000].lower() for m in CF_CHALLENGE):
                status = 403
            else:
                return str(r.url), r.text[:700000]
        else:
            status = r.status_code
    except Exception:
        status = None
    if status in (None, 401, 403, 429, 500, 503):
        txt = await _curl(url)
        if txt and ("<" in txt or "@" in txt):
            return url, txt
    return None, None


def _discover_links(html: str, base: str) -> list[str]:
    out, seen = [], set()
    for href in HREF_RE.findall(html):
        h = href.lower()
        if h.startswith(("mailto:", "tel:", "#", "javascript:")):
            continue
        if any(k in h for k in LINK_KEYWORDS):
            try:
                u = urljoin(base, href)
            except Exception:
                continue
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out[:18]


def _collect_socials(html: str) -> list[str]:
    out = []
    for rx in (LINKTREE_RE, MASTODON_RE, FACEBOOK_RE):
        for u in rx.findall(html):
            if u not in out:
                out.append(u)
    return out[:6]


def _collect_pdfs(html: str, base: str) -> list[str]:
    out = []
    for href in HREF_RE.findall(html):
        if href.lower().split("?")[0].endswith(".pdf"):
            try:
                out.append(urljoin(base, href))
            except Exception:
                continue
    return out[:4]


def _github_users(html: str) -> list[str]:
    out = []
    for u in GH_USER_RE.findall(html):
        if u.lower() in GH_SKIP or u.lower().endswith(".git"):
            continue
        if u not in out:
            out.append(u)
    return out[:3]


async def _github_emails(client, users):
    found = {}
    headers = {"Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    calls = 0
    for u in users:
        if calls >= 8:
            break
        try:
            r = await client.get(f"https://api.github.com/users/{u}", headers=headers)
            calls += 1
            if r.status_code == 403:
                break
            if r.status_code == 200:
                em = (r.json() or {}).get("email")
                if em:
                    v = _valid_email(em)
                    if v:
                        found.setdefault(v, "GitHub profile")
            repos = await client.get(
                f"https://api.github.com/users/{u}/repos?sort=pushed&per_page=3", headers=headers)
            calls += 1
            if repos.status_code != 200:
                continue
            for repo in (repos.json() or [])[:2]:
                if calls >= 8:
                    break
                name = repo.get("name")
                if not name:
                    continue
                rc = await client.get(
                    f"https://api.github.com/repos/{u}/{name}/commits?per_page=5", headers=headers)
                calls += 1
                if rc.status_code != 200:
                    continue
                for c in (rc.json() or []):
                    login = ((c.get("author") or {}).get("login") or "").lower()
                    if login != u.lower():
                        continue
                    em = ((c.get("commit") or {}).get("author") or {}).get("email")
                    if em and "noreply" not in em and "users.noreply.github" not in em:
                        v = _valid_email(em)
                        if v:
                            found.setdefault(v, "GitHub commits")
        except Exception:
            continue
    return found


SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)


async def _js_bundle_emails(client, pages, domain, left):
    """A JS app serves the same shell for every route and keeps the contact
    address in a script chunk. Without this, those sites look email-free."""
    found: dict[str, str] = {}
    srcs, seen = [], set()
    bare = domain.replace("www.", "")
    for url, html in pages:
        for m in SCRIPT_SRC_RE.findall(html):
            try:
                u = urljoin(url, m)
            except Exception:
                continue
            host = urlparse(u).netloc.replace("www.", "")
            if host and host != bare and not host.endswith("." + bare):
                continue                      # same-site bundles only
            if u not in seen:
                seen.add(u)
                srcs.append(u)
    for u in srcs[:8]:
        if left() < 8:
            break
        try:
            r = await client.get(u, timeout=httpx.Timeout(10.0))
            if r.status_code != 200:
                continue
            body = r.text[:900000]
        except Exception:
            continue
        for e in find_emails(body):
            found.setdefault(e, "JS bundle")
        for e in find_cfemails(body):
            found.setdefault(e, "obfuscated (decoded)")
    return found


async def _sitemap_person_pages(client, base):
    kws = ("team", "author", "staff", "people", "contributor", "masthead", "about",
           "contact", "press", "career", "job", "editor", "meet")
    for sm in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/sitemap.txt"):
        _, txt = await _fetch(client, urljoin(base, sm))
        if not txt:
            continue
        locs = re.findall(r"<loc>\s*([^<]+?)\s*</loc>", txt) or [
            l.strip() for l in txt.splitlines() if l.strip().startswith("http")]
        children = [u for u in locs if u.endswith(".xml")][:3]
        for c in children:
            _, ct = await _fetch(client, c)
            if ct:
                locs += re.findall(r"<loc>\s*([^<]+?)\s*</loc>", ct)
        hits, seen = [], set()
        for u in locs:
            if any(k in u.lower() for k in kws) and u not in seen:
                seen.add(u)
                hits.append(u)
        if hits:
            return hits[:12]
    return []


async def _pdf_emails(client, pdf_urls):
    try:
        import pypdf
    except Exception:
        return {}
    out = {}
    for u in pdf_urls[:3]:
        try:
            r = await client.get(u)
            if r.status_code != 200:
                continue
            reader = pypdf.PdfReader(io.BytesIO(r.content))
            text = "".join((p.extract_text() or "") for p in reader.pages[:12])
            for e in find_emails(text):
                out.setdefault(e, "PDF / media kit")
        except Exception:
            continue
    return out


async def _wayback(client, domain):
    out = {}
    for path in ("contact", "about", "contact-us", "about-us"):
        try:
            r = await client.get(f"http://archive.org/wayback/available?url={domain}/{path}")
            if r.status_code != 200:
                continue
            snap = ((r.json() or {}).get("archived_snapshots") or {}).get("closest") or {}
            u = snap.get("url")
            if not u:
                continue
            _, html = await _fetch(client, u)
            if html:
                for e in find_emails(html) | find_cfemails(html):
                    if not e.endswith(("@web.archive.org", "@archive.org")):
                        out.setdefault(e, "Wayback archive")
        except Exception:
            continue
        if out:
            break
    return out


async def _crtsh_scan(client, domain):
    subs = set()
    try:
        r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                             timeout=httpx.Timeout(8.0))
        if r.status_code == 200:
            for row in (r.json() or []):
                for nv in str(row.get("name_value", "")).split("\n"):
                    nv = nv.strip().lower().lstrip("*.")
                    if nv.endswith(domain) and nv != domain:
                        subs.add(nv)
    except Exception:
        return {}
    interesting = [s for s in subs if any(s.startswith(p + ".") for p in INTERESTING_SUBS)]
    out = {}
    for s in interesting[:5]:
        for u in (f"https://{s}", f"https://{s}/contact", f"https://{s}/about"):
            _, html = await _fetch(client, u)
            if html:
                for e in find_emails(html) | find_cfemails(html):
                    out.setdefault(e, f"subdomain ({s})")
        if out:
            break
    return out


async def _social_bios(client, social_urls):
    out = {}
    for u in social_urls[:5]:
        target = u.rstrip("/") + "/about" if "facebook.com" in u.lower() else u
        _, html = await _fetch(client, target)
        if html:
            for e in find_emails(html) | find_cfemails(html):
                out.setdefault(e, "social profile")
        if out:
            break
    return out


async def _ddg(client, domain):
    out = {}
    for q in (f'"@{domain}"', f'{domain} contact email'):
        try:
            r = await client.get("https://html.duckduckgo.com/html/", params={"q": q})
            if r.status_code != 200:
                continue
            for e in find_emails(r.text):
                if e.endswith("@" + domain):
                    out.setdefault(e, "web search (DuckDuckGo)")
        except Exception:
            continue
        if out:
            break
    return out


def _name_from_slug(slug: str) -> str:
    slug = re.sub(r"%[0-9a-f]{2}", "-", slug, flags=re.I)
    parts = [p for p in re.split(r"[-_.]+", slug) if p.isalpha() and len(p) > 1][:3]
    return " ".join(p.capitalize() for p in parts) if parts else ""


def _role_rank(text: str):
    tl = (text or "").lower()
    best, label = 9, ""
    for kw, rk in AUTHORITY_RANK:
        if kw in tl and rk < best:
            best, label = rk, kw
    return best, label


def _pick_linkedin(pages, name_title):
    """Best decision-maker LinkedIn from links the SITE publishes (no LinkedIn fetch)."""
    cands, seen = [], set()
    for _url, html in pages:
        for m in LINKEDIN_IN_RE.finditer(html):
            slug = m.group(1).split("?")[0].rstrip("/")
            if not slug or slug.lower() in LI_SKIP_SLUGS:
                continue
            purl = "https://www.linkedin.com/in/" + slug
            if purl in seen:
                continue
            seen.add(purl)
            ctx = _visible_text(html[max(0, m.start() - 400): m.end() + 400])
            name = _name_from_slug(slug)
            rank, label = _role_rank(ctx)
            role = label
            if name and name in name_title:
                r2, _ = _role_rank(name_title[name])
                if r2 < rank:
                    rank = r2
                role = name_title[name]
            cands.append((rank, purl, name, role))
    if cands:
        cands.sort(key=lambda c: (c[0], c[1]))
        rank, purl, name, role = cands[0]
        return {"url": purl, "name": name, "role": role, "kind": "person"}
    for _url, html in pages:               # fall back to the company page
        m = LINKEDIN_COMPANY_RE.search(html)
        if m:
            slug = m.group(1).split("?")[0].rstrip("/")
            return {"url": "https://www.linkedin.com/company/" + slug,
                    "name": "", "role": "company page", "kind": "company"}
    return None


async def _linkedin_via_ddg(client, brand, domain):
    from urllib.parse import unquote
    q = f'{brand} (founder OR editor OR marketing OR SEO) site:linkedin.com/in'
    try:
        r = await client.get("https://html.duckduckgo.com/html/", params={"q": q})
        if r.status_code == 200:
            txt = unquote(r.text)
            for m in LINKEDIN_IN_RE.finditer(txt):
                slug = m.group(1).split("?")[0].split("&")[0].rstrip("/")
                if slug and slug.lower() not in LI_SKIP_SLUGS:
                    return {"url": "https://www.linkedin.com/in/" + slug,
                            "name": _name_from_slug(slug), "role": "",
                            "kind": "person", "guess": True}
    except Exception:
        pass
    return None


def _source_label(url: str) -> str:
    p = urlparse(url).path.lower()
    if p in ("", "/"):
        return "homepage"
    for key, lbl in (("privacy", "privacy page"), ("term", "terms page"), ("contact", "contact page"),
                     ("team", "team page"), ("staff", "team page"), ("people", "team page"),
                     ("author", "author page"), ("masthead", "masthead"), ("career", "careers page"),
                     ("job", "careers page"), ("press", "press page"), ("about", "about page"),
                     ("impressum", "imprint page"), ("imprint", "imprint page"),
                     ("security.txt", "security.txt"), ("legal", "legal page"),
                     ("cookie", "legal page"), ("disclaimer", "legal page")):
        if key in p:
            return lbl
    return "site page"


def _has_personal(emails) -> bool:
    for e in emails:
        loc = e.split("@")[0]
        if loc not in ROLE_LOCALS and loc not in CATCHALL_LOCALS:
            return True
    return False


async def process_domain(client: httpx.AsyncClient, raw_domain: str) -> dict:
    domain = normalize_domain(raw_domain)
    result = {"domain": raw_domain.strip(), "normalized": domain,
              "emails": [], "names": [], "found": False}
    if not domain:
        return result

    deadline = time.monotonic() + PER_DOMAIN_BUDGET
    left = lambda: deadline - time.monotonic()

    base, home = None, None
    for candidate in (f"https://{domain}", f"https://www.{domain}"):
        b, h = await _fetch(client, candidate)
        if h:
            base, home = b, h
            break

    emails: dict[str, str] = {}          # email -> source label
    jsonld_desig: dict[str, str] = {}    # email -> designation
    name_title: dict[str, str] = {}      # person name -> job title
    names: set[str] = set()
    person_names: set[str] = set()       # validated humans (people engine)
    author_links: list[str] = []
    gh_users: list[str] = []
    socials: list[str] = []
    pdfs: list[str] = []
    text_blobs: list[str] = []
    pages: list[tuple[str, str]] = []

    if home:
        pages.append((base, home))
        # REAL links found in the page come first (they are known to exist), then the
        # guessed paths. Nothing is truncated: a [:26] cap here was silently dropping
        # security.txt, humans.txt, /blog, /careers AND every discovered link.
        urls, seen_u = [], set()
        for u in _discover_links(home, base):
            if u not in seen_u:
                seen_u.add(u)
                urls.append(u)
        for pth in CANDIDATE_PATHS:
            u = urljoin(base, "/" + pth)
            if u not in seen_u:
                seen_u.add(u)
                urls.append(u)
        # in waves, so a single host is not hit with 50 sockets at once
        for i in range(0, min(len(urls), MAX_PAGE_FETCHES), 16):
            if left() < 14:
                break
            wave = urls[i:i + 16]
            for (fu, fh) in await asyncio.gather(*[_fetch(client, u) for u in wave]):
                if fh:
                    pages.append((fu, fh))

    for url, html in pages:
        src = _source_label(url)
        for e in find_emails(html):
            emails.setdefault(e, src)
        for e in find_cfemails(html):
            emails.setdefault(e, "obfuscated (decoded)")
        vis = _visible_text(html)
        for e in find_obfuscated_emails(vis):
            emails.setdefault(e, "obfuscated text")
        je, jt = find_jsonld(html)
        for e, d in je.items():
            emails.setdefault(e, "structured data")
            if d:
                jsonld_desig.setdefault(e, d)
        name_title.update(jt)
        names |= names_from(html)
        # bylines on terms/privacy pages are legal prose, not authors
        person_names |= P.harvest_person_names(
            html, bylines=src not in ('terms page', 'privacy page',
                                      'legal page', 'imprint page'))
        for al in P.author_page_links(html, url):
            if al not in author_links:
                author_links.append(al)
        for gu in _github_users(html):
            if gu not in gh_users:
                gh_users.append(gu)
        for s in _collect_socials(html):
            if s not in socials:
                socials.append(s)
        for pf in _collect_pdfs(html, url):
            if pf not in pdfs:
                pdfs.append(pf)
        text_blobs.append(_visible_text(html))

    # If we have no PERSON email yet, dig person-oriented sources even if a role
    # address was found (the user wants a named person first).
    if not _has_personal(emails) and left() > 12:
        for e, src in (await _pdf_emails(client, pdfs)).items():
            emails.setdefault(e, src)
        if not _has_personal(emails) and left() > 10:
            sp = await _sitemap_person_pages(client, base) if base else []
            for (fu, fh) in await asyncio.gather(*[_fetch(client, u) for u in sp]):
                if fh:
                    for e in find_emails(fh):
                        emails.setdefault(e, _source_label(fu))
                    for e in find_cfemails(fh):
                        emails.setdefault(e, "obfuscated (decoded)")
                    je, jt = find_jsonld(fh)
                    for e, d in je.items():
                        emails.setdefault(e, "structured data")
                        if d:
                            jsonld_desig.setdefault(e, d)
                    name_title.update(jt)
                    text_blobs.append(_visible_text(fh))

    # Full fallback chain: only when nothing at all has turned up yet.
    if not _has_personal(emails) and base:
        for fp in FEED_PATHS:
            _, fh = await _fetch(client, urljoin(base, "/" + fp))
            if fh:
                for e in find_emails(fh):
                    emails.setdefault(e, "RSS feed")
            if emails:
                break
    # JS-app fallback: the address lives in a script chunk, not the markup
    if not _has_personal(emails) and left() > 12:
        for e, src in (await _js_bundle_emails(client, pages, domain, left)).items():
            emails.setdefault(e, src)

    if not _has_personal(emails) and gh_users and left() > 8:
        for e, src in (await _github_emails(client, gh_users)).items():
            emails.setdefault(e, src)
    if not emails and left() > 8:
        for e, src in (await _wayback(client, domain)).items():
            emails.setdefault(e, src)
    if not emails and left() > 10:
        for e, src in (await _crtsh_scan(client, domain)).items():
            emails.setdefault(e, src)
    if not _has_personal(emails) and socials and left() > 5:
        for e, src in (await _social_bios(client, socials)).items():
            emails.setdefault(e, src)
    if not _has_personal(emails) and left() > 5:
        for e, src in (await _ddg(client, domain)).items():
            emails.setdefault(e, src)
    if not emails and left() > 6:
        wemails, wname = await asyncio.to_thread(_whois_lookup, domain)
        for e in wemails:
            emails.setdefault(e, "WHOIS")
        if wname:
            names.add(wname)

    # resolve MX in threads (blocking DNS must not freeze the event loop)
    mx_targets = {e.partition("@")[2] for e in emails}
    if mx_targets:
        await asyncio.gather(*[asyncio.to_thread(_has_mailserver, d) for d in mx_targets])

    # order: PERSON first, then role, then catch-all; same-domain then confidence
    def sort_key(item):
        email, _src = item
        local, _, edom = email.partition("@")
        same = 0 if (edom == domain or edom == f"www.{domain}" or domain.endswith("." + edom)) else 1
        if local in CATCHALL_LOCALS:
            tier = 2
        elif local in ROLE_LOCALS:
            tier = 1
        else:
            tier = 0
        level, _ = classify(email)
        rank = {"high": 0, "medium": 1, "low": 2}[level]
        return (tier, same, rank, email)

    full_text = " ".join(text_blobs)[:400000]
    ordered = sorted(emails.items(), key=sort_key)[:MAX_EMAILS_PER_DOMAIN]
    out_emails, designations = [], []
    for email, src in ordered:
        level, label = classify(email)
        title = designation_for(email, jsonld_desig, name_title, full_text)
        out_emails.append({"email": email, "level": level, "label": label,
                           "source": src, "title": title})
        if title and title not in designations:
            designations.append(title)
        dn = derive_name(email)
        if dn:
            names.add(dn)

    # ================= PEOPLE PASS: real humans, not info@ =================
    # names+titles from free sources -> infer the domain's pattern -> generate
    # -> verify for free. Every row labelled confirmed / likely / guess.
    people: list[dict] = []
    try:
        brand = domain.split(".")[0]
        cand: dict[str, str] = {}        # name -> title
        for n in person_names:
            cand.setdefault(n, name_title.get(n, ""))
        for n, t in name_title.items():
            if P.looks_like_person_name(n):
                cand.setdefault(n, t)

        cand = P.drop_brandy_names(cand, brand, domain)

        # author archive pages: the byline author IS the outreach target
        if author_links and left() > 14:
            for (fu, fh) in await asyncio.gather(
                    *[_fetch(client, u) for u in author_links[:4]]):
                if not fh:
                    continue
                for e in find_emails(fh) | find_cfemails(fh):
                    emails.setdefault(e, "author page")
                for n in P.harvest_person_names(fh):
                    cand.setdefault(n, "")
                slug = urlparse(fu).path.rstrip("/").split("/")[-1].replace("-", " ")
                sn = P.looks_like_person_name(slug.title())
                if sn:
                    cand.setdefault(sn, "")

        # blog posts: follow a few articles and read their bylines. This is the
        # sturdiest free name source and lands exactly on editors/writers.
        if len(cand) < 6 and left() > 16 and base:
            posts = []
            for url, html in pages:
                if not re.search(r"/(blog|news|articles|insights|resources)", url, re.I):
                    continue
                for href in HREF_RE.findall(html):
                    if href.startswith(("mailto:", "tel:", "#", "javascript:")):
                        continue
                    try:
                        u = urljoin(url, href.split("#")[0])
                    except Exception:
                        continue
                    if urlparse(u).netloc.replace("www.", "") != domain.replace("www.", ""):
                        continue
                    path = urlparse(u).path.rstrip("/")
                    if (re.search(r"/(blog|news|articles|insights)/[a-z0-9-]{8,}$", path, re.I)
                            and u not in posts):
                        posts.append(u)
                if len(posts) >= 4:
                    break
            for (fu, fh) in await asyncio.gather(*[_fetch(client, u) for u in posts[:4]]):
                if not fh:
                    continue
                for n in P.harvest_person_names(fh):
                    cand.setdefault(n, "")
                for al in P.author_page_links(fh, fu):
                    if al not in author_links:
                        author_links.append(al)
            cand = P.drop_brandy_names(cand, brand, domain)

        # RSS post authors (one fetch, many names)
        if base and len(cand) < 6 and left() > 12:
            for n in await P.feed_creators(_fetch, client, base):
                cand.setdefault(n, "")

        cand = P.drop_brandy_names(cand, brand, domain)

        # public search-result snippets: name + job title, LinkedIn never fetched
        if len(cand) < 8 and left() > 12:
            for n, t in (await P.serp_people(client, brand, left)).items():
                if n in cand and t and not cand[n]:
                    cand[n] = t
                else:
                    cand.setdefault(n, t)

        # confirmed personal addresses already found on the site
        confirmed_local: dict[str, str] = {}
        for email, src in emails.items():
            local, _, edom = email.partition("@")
            if edom != domain or local in ROLE_LOCALS or local in CATCHALL_LOCALS:
                continue
            confirmed_local[email] = src

        # infer the domain's email pattern from a real address
        pattern = None
        for email in confirmed_local:
            pattern = P.detect_pattern(email.split("@")[0], cand.keys())
            if pattern:
                break

        # a published address only counts as a PERSON if we can name the human
        # behind it; ethics@ / safety@ stay in the generic email column instead.
        seen_emails = set()
        for email, src in confirmed_local.items():
            local = email.split("@")[0]
            if local in P.CONCEPT_LOCALS:
                continue
            nm = P.match_local_to_name(local, cand.keys())
            if not nm:
                dn = derive_name(email)
                nm = dn if (dn and len(dn.split()) >= 2) else None
            if not nm:
                continue
            people.append({"name": nm, "title": cand.get(nm, ""), "email": email,
                           "status": "scraped", "source": f"found on the {src}",
                           "rank": P.role_rank(cand.get(nm, ""))})
            seen_emails.add(email)

        # generate + verify for people we have a name but no address for
        todo = [(n, t) for n, t in cand.items()
                if not any(p["name"] == n for p in people)]
        todo.sort(key=lambda nt: P.role_rank(nt[1]))
        todo = todo[:MAX_PEOPLE_PER_DOMAIN]

        generated: list[tuple[str, str, str, str]] = []   # email, pattern, name, title
        for n, t in todo:
            for e, pn in P.gen_candidates(n, domain, pattern, limit=2):
                if e not in seen_emails:
                    seen_emails.add(e)
                    generated.append((e, pn, n, t))

        if generated and left() > 10:
            hits = await P.search_confirm(client, [g[0] for g in generated], left)
            grav = set()
            unconfirmed = [g[0] for g in generated if g[0] not in hits][:6]
            if unconfirmed and left() > 8:
                res = await asyncio.gather(
                    *[P.gravatar_exists(client, e) for e in unconfirmed])
                grav = {e for e, ok in zip(unconfirmed, res) if ok}
            mx_ok = _has_mailserver(domain)
            for e, pn, n, t in generated:
                if e in hits:
                    status, why = "verified", "generated, then found in public search results"
                elif e in grav:
                    status, why = "verified", "generated, confirmed by a Gravatar account"
                elif pattern and pn == pattern and mx_ok:
                    status, why = "likely", f"guessed from this domain's {pn} pattern"
                else:
                    status, why = "guess", f"guessed, {pn} pattern, unverified"
                people.append({"name": n, "title": t, "email": e, "status": status,
                               "source": why, "rank": P.role_rank(t)})

        # authentic first: scraped off the site, then verified, then guesses.
        # role seniority only orders people INSIDE the same tier.
        _ORDER = {"scraped": 0, "verified": 1, "likely": 2, "guess": 3}
        people.sort(key=lambda p: (_ORDER.get(p["status"], 4), p["rank"],
                                   len(p["email"]), p["email"]))
        # one row per human: keep their best-verified address
        deduped, seen_names = [], set()
        for p in people:
            key = (p["name"] or p["email"]).lower()
            if key in seen_names:
                continue
            seen_names.add(key)
            p.pop("rank", None)
            deduped.append(p)
        people = deduped[:MAX_PEOPLE_PER_DOMAIN]
    except Exception as exc:      # people pass must never break the email result
        print(f"[people] {domain}: {type(exc).__name__}: {exc}")
        people = []

    # decision-maker LinkedIn (from links the site publishes; falls back to search)
    linkedin = _pick_linkedin(pages, name_title)
    if (not linkedin or linkedin.get("kind") == "company") and left() > 4:
        brand = domain.split(".")[0]
        guess = await _linkedin_via_ddg(client, brand, domain)
        if guess:
            linkedin = guess

    if not out_emails and not people:
        if not home:
            result["note"] = "site unreachable"
        elif pages and all(_is_challenge(h) for _, h in pages):
            result["note"] = "blocked by a bot challenge (needs a real browser)"
        else:
            result["note"] = "no email published on the site"

    result["emails"] = out_emails
    result["names"] = sorted(names)[:4]
    result["designations"] = designations
    result["linkedin"] = linkedin
    result["people"] = people
    result["found"] = bool(out_emails) or bool(people)
    return result


def domain_confidence(emails: list[dict]) -> str:
    if not emails:
        return "none"
    if any(e["level"] == "high" for e in emails):
        return "high"
    if any(e["level"] == "medium" for e in emails):
        return "medium"
    return "low"
