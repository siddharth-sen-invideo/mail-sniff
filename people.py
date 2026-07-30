"""
Mail Sniff people engine: find REAL HUMANS at a domain, not just info@ / support@.

The formula every paid tool uses, rebuilt with free sources only:

    NAME + PATTERN + VERIFICATION

  names   : bylines, rel=author, author archive pages, RSS dc:creator, JSON-LD
            Person nodes, and public SEARCH-RESULT snippets (never LinkedIn itself)
  pattern : inferred from any already-confirmed address on the domain
            (ankit@ -> "first", siddharth.sen@ -> "first.last")
  verify  : search-confirm (address appears verbatim in public results) + Gravatar
            existence + MX. No SMTP probing (blocked on hosts, risks blacklisting).

Every candidate is labelled honestly: confirmed / likely / guess.
This module is dependency-free: callers inject fetch helpers.
"""
from __future__ import annotations

import hashlib
import html as _html
import re
from urllib.parse import urljoin

import httpx

TAG_RE = re.compile(r"<[^>]+>")
META_AUTHOR_RE = re.compile(
    r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']{2,60})["\']', re.I)
RELAUTHOR_RE = re.compile(r'rel=["\']author["\'][^>]*>\s*([^<]{3,48})\s*<', re.I)
BYLINE_RE = re.compile(
    r'(?:^|[>\s])(?:by|written by|posted by)[:\s]+'
    r'([A-Z][\w.\'’-]+(?:\s+[A-Z][\w.\'’-]+){1,2})', re.I)
AUTHOR_LINK_RE = re.compile(
    r'href=["\']([^"\']*/(?:author|authors|contributor|contributors|profile)/[^"\']+)["\']',
    re.I)
DC_CREATOR_RE = re.compile(
    r'<(?:dc:creator|itunes:author)[^>]*>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?'
    r'</(?:dc:creator|itunes:author)>', re.I | re.S)
A_TEXT_RE = re.compile(r'<a\b[^>]*>(.*?)</a>', re.I | re.S)

# words that disqualify a "name" (page furniture, roles, boilerplate)
_NAME_STOP = {
    "admin", "editor", "team", "staff", "support", "guest", "author", "contributor",
    "blog", "news", "the", "and", "by", "posted", "written", "company", "press",
    "media", "marketing", "sales", "info", "contact", "hello", "help", "careers",
    "jobs", "home", "linkedin", "facebook", "twitter", "instagram", "youtube",
    "profile", "view", "see", "more", "all", "posts", "articles", "read", "about",
    "us", "our", "privacy", "policy", "terms", "cookie", "menu", "search", "share",
    "copyright", "reserved", "rights", "inc", "ltd", "llc", "group", "solutions",
    "sign", "log", "get", "started", "free", "trial", "pricing", "product", "learn",
    # legal / boilerplate prose words (terms pages are full of "by X" phrases)
    "you", "your", "yours", "we", "our", "ours", "they", "them", "this", "that",
    "these", "those", "jury", "federal", "express", "posting", "third", "party",
    "parties", "services", "service", "entering", "into", "agreement", "dispute",
    "resolution", "registration", "arbitration", "class", "action", "waiver",
    "limitation", "liability", "warranty", "warranties", "indemnity", "governing",
    "law", "notice", "changes", "use", "uses", "license", "prohibited", "intellectual",
    "property", "user", "account", "payment", "refund", "cancellation", "termination",
    "disclaimer", "force", "majeure", "severability", "assignment", "entire",
    "effective", "date", "updated", "last", "please", "note", "shall", "may", "will",
    "must", "agree", "agrees", "acknowledge", "including", "without", "with", "such",
    "any", "each", "either", "neither", "if", "or", "to", "and", "not", "no", "hereby",
    "herein", "thereof", "pursuant", "applicable", "reasonable", "material",
}

# free HTML search endpoints, rotated (each rate-limits independently).
# DuckDuckGo wants POST for its html endpoints; a GET returns a 202 challenge page.
SERP_ENGINES = [
    ("https://html.duckduckgo.com/html/", "post"),
    ("https://lite.duckduckgo.com/lite/", "post"),
    ("https://www.mojeek.com/search", "get"),
    ("https://www.bing.com/search", "get"),
    ("https://search.marcia.cc/search", "get"),
]
SERP_URLS = [u for u, _ in SERP_ENGINES]   # back-compat

_SERP_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://duckduckgo.com/",
}
# pages that are a bot wall / empty rather than real results
_CHALLENGE = ("anomaly", "unusual traffic", "captcha", "are you a robot",
              "verify you are human", "access denied", "blocked")


async def _curl_serp(url, q, method):
    """System curl has a different TLS fingerprint and often clears these walls."""
    import asyncio as _a
    args = ["curl", "-sL", "--compressed", "--max-time", "10",
            "-A", _SERP_HEADERS["User-Agent"], "-H", "Accept-Language: en-US,en;q=0.9"]
    if method == "post":
        args += ["--data-urlencode", f"q={q}", url]
    else:
        args += ["-G", "--data-urlencode", f"q={q}", url]
    proc = None
    try:
        proc = await _a.create_subprocess_exec(
            *args, stdout=_a.subprocess.PIPE, stderr=_a.subprocess.DEVNULL)
        out, _ = await _a.wait_for(proc.communicate(), timeout=12)
        return out.decode("utf-8", "ignore") or None
    except Exception:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        return None


def _looks_like_results(body):
    if not body or len(body) < 900:
        return False
    low = body[:6000].lower()
    return not any(m in low for m in _CHALLENGE)


async def serp_fetch(client, url, q, method="get"):
    """One search query against one engine, with a curl fallback. None on failure."""
    try:
        if method == "post":
            r = await client.post(url, data={"q": q}, headers=_SERP_HEADERS,
                                  timeout=httpx.Timeout(10.0))
        else:
            r = await client.get(url, params={"q": q}, headers=_SERP_HEADERS,
                                 timeout=httpx.Timeout(10.0))
        if r.status_code == 200 and _looks_like_results(r.text):
            return r.text
    except Exception:
        pass
    body = await _curl_serp(url, q, method)
    return body if _looks_like_results(body) else None
_ROLE_QUERY = ('(founder OR CEO OR editor OR content OR SEO OR marketing '
               'OR communications OR PR OR partnerships)')

_PATTERNS = {
    "first.last": lambda f, l: f"{f}.{l}",
    "first": lambda f, l: f,
    "firstlast": lambda f, l: f"{f}{l}",
    "flast": lambda f, l: f"{f[0]}{l}",
    "first_last": lambda f, l: f"{f}_{l}",
    "f.last": lambda f, l: f"{f[0]}.{l}",
    "firstl": lambda f, l: f"{f}{l[0]}",
    "last.first": lambda f, l: f"{l}.{f}",
}
_PATTERN_FALLBACK = ["first.last", "first", "flast", "firstlast"]

# who can actually get a link placed, best first
_AUTHORITY = [
    (0, ("founder", "co-founder", "cofounder", "owner", "ceo", "president",
         "chief executive", "proprietor")),
    (1, ("editor-in-chief", "managing editor", "editor", "editorial", "publisher",
         "head of content", "content lead", "content manager", "content")),
    (2, ("seo", "growth", "marketing", "brand", "demand gen")),
    (3, ("partnership", "public relations", "communications", "outreach", "pr")),
    (4, ("writer", "journalist", "author", "blogger", "head of", "director",
         "manager", "lead", "specialist")),
]


def visible_text(html_text: str) -> str:
    return TAG_RE.sub(" ", re.sub(r"<(script|style)[^>]*>.*?</\1>", " ",
                                  html_text or "", flags=re.I | re.S))


def looks_like_person_name(s):
    """Strict human-name check: two or three capitalised alphabetic words."""
    s = re.sub(r"\s+", " ", _html.unescape(s or "")).strip()
    s = re.sub(r"^(?:by|written by|posted by|author:?)\s+", "", s, flags=re.I)
    s = s.strip(" ,.:-|·")
    if not s or len(s) > 48:
        return None
    parts = s.split(" ")
    if not (2 <= len(parts) <= 3):
        return None
    clean = []
    for p in parts:
        q = p.strip(".,'’")
        bare = q.replace("'", "").replace("’", "").replace("-", "")
        if len(q) < 2 or not bare.isalpha():
            return None
        if q.lower() in _NAME_STOP or not q[0].isupper():
            return None
        if len(q) > 2 and q.isupper():   # ALL-CAPS legal headings are not names
            return None
        clean.append(q)
    return " ".join(clean)


# single-word mailbox names that are CONCEPTS, not humans (ethics@, safety@ ...)
CONCEPT_LOCALS = {
    "ethics", "safety", "security", "trust", "compliance", "feedback", "business",
    "bizdev", "invest", "investors", "ir", "brand", "community", "events", "api",
    "dev", "developers", "docs", "status", "bounce", "mailer", "notifications",
    "alerts", "updates", "newsletter", "recruiting", "talent", "finance", "accounts",
    "invoices", "orders", "refunds", "returns", "shipping", "wholesale", "affiliate",
    "affiliates", "partner", "partners", "vendors", "suppliers", "procurement",
    "reception", "enquiry", "inquiry", "booking", "bookings", "reservations",
    "newsroom", "advertising", "ads", "submissions", "pitch", "guest", "content",
    "social", "digital", "studio", "agency", "shop", "store", "sales", "service",
}


def match_local_to_name(local, names):
    """Tie a mailbox local part to a harvested human name (sanket -> Sanket Shah).
    Returns None when nothing matches, which keeps ethics@ out of the people list."""
    toks = {t for t in re.split(r"[._\-+]+", (local or "").lower()) if t}
    if not toks:
        return None
    for c in names:
        sp = split_name(c)
        if not sp:
            continue
        f, l = sp
        if toks & {f, l} or toks <= {f, l, f[0] + l, f + l, f[0] + "." + l}:
            return c
    return None


def split_name(name):
    parts = [re.sub(r"[^a-z]", "", p.lower()) for p in (name or "").split()]
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return None
    return parts[0], parts[-1]


def role_rank(title):
    tl = (title or "").lower()
    for rank, words in _AUTHORITY:
        if any(w in tl for w in words):
            return rank
    return 8


def harvest_person_names(html_text, bylines=True):
    """Validated human names from bylines, rel=author and meta author.
    Set bylines=False on legal pages: 'delivered by Federal Express' is not a byline."""
    out = set()
    sources = [(RELAUTHOR_RE, html_text), (META_AUTHOR_RE, html_text)]
    if bylines:
        sources.append((BYLINE_RE, visible_text(html_text)))
    for rx, src in sources:
        for m in rx.findall(src):
            n = looks_like_person_name(m)
            if n:
                out.add(n)
    return out


def drop_brandy_names(names, brand, domain):
    """A 'name' containing the company's own token is page furniture, not a human."""
    bad = {(brand or "").lower()} | {t for t in re.split(r"[.\-]", domain or "") if len(t) > 2}
    return {n: t for n, t in names.items()
            if not ({w.lower() for w in n.split()} & bad)}


def author_page_links(html_text, base, cap=5):
    out, seen = [], set()
    for href in AUTHOR_LINK_RE.findall(html_text or ""):
        try:
            u = urljoin(base, href)
        except Exception:
            continue
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:cap]


async def feed_creators(fetch, client, base):
    """Author names from RSS dc:creator. One fetch yields many post authors."""
    names = set()
    for fp in ("feed", "rss", "rss.xml", "feed.xml", "atom.xml", "blog/feed"):
        _, txt = await fetch(client, urljoin(base, "/" + fp))
        if not txt:
            continue
        for raw in DC_CREATOR_RE.findall(txt):
            n = looks_like_person_name(TAG_RE.sub(" ", raw))
            if n:
                names.add(n)
        if names:
            break
    return names


def parse_serp_people(page, brand):
    """Pull 'Name - Title - Company | LinkedIn' from search-result titles.
    We read the SEARCH ENGINE's public results; LinkedIn is never fetched."""
    out = []
    bl = (brand or "").lower()
    if not bl:
        return out
    for raw in A_TEXT_RE.findall(page or ""):
        t = re.sub(r"\s+", " ", _html.unescape(TAG_RE.sub(" ", raw))).strip()
        low = t.lower()
        if "linkedin" not in low or bl not in low:
            continue
        t = re.sub(r"\s*[|\-–]\s*LinkedIn.*$", "", t, flags=re.I)
        parts = [p.strip() for p in re.split(r"\s+[-–|]\s+", t) if p.strip()]
        if not parts:
            continue
        nm = looks_like_person_name(parts[0])
        if not nm:
            continue
        title = ""
        if len(parts) > 1:
            title = re.sub(r"\s+at\s+.*$", "", parts[1], flags=re.I).strip()[:50]
            if title.lower() == bl:
                title = ""
        out.append((nm, title))
    return out


async def serp_people(client, brand, left):
    """Names + job titles of people at a company, from public search results."""
    found = {}
    queries = [f'site:linkedin.com/in "{brand}" {_ROLE_QUERY}',
               f'site:linkedin.com/in "{brand}"']
    for url, method in SERP_ENGINES:
        for q in queries:
            if left() < 8:
                return found
            body = await serp_fetch(client, url, q, method)
            if not body:
                continue
            for nm, ti in parse_serp_people(body, brand):
                if nm not in found or (ti and not found[nm]):
                    found[nm] = ti
        if found:
            break
    return found


def detect_pattern(local, known_names=()):
    """Infer the domain's email pattern from a known-real local part."""
    local = (local or "").lower()
    for nm in known_names:
        sp = split_name(nm)
        if not sp:
            continue
        f, l = sp
        for pname, fn in _PATTERNS.items():
            try:
                if fn(f, l) == local:
                    return pname
            except Exception:
                continue
    if "." in local:
        a, b = local.split(".", 1)
        if a.isalpha() and b.isalpha():
            return "f.last" if len(a) == 1 else "first.last"
    if "_" in local and local.replace("_", "").isalpha():
        return "first_last"
    if local.isalpha() and 2 < len(local) <= 12:
        return "first"
    return None


def gen_candidates(name, domain, pattern, limit=3):
    """Ranked likely addresses for a person. Detected pattern first."""
    sp = split_name(name)
    if not sp:
        return []
    f, l = sp
    order = ([pattern] if pattern else []) + [p for p in _PATTERN_FALLBACK if p != pattern]
    out, seen = [], set()
    for pn in order:
        fn = _PATTERNS.get(pn)
        if not fn:
            continue
        try:
            local = fn(f, l)
        except Exception:
            continue
        if not local or len(local) < 3:
            continue
        e = f"{local}@{domain}"
        if e not in seen:
            seen.add(e)
            out.append((e, pn))
        if len(out) >= limit:
            break
    return out


async def gravatar_exists(client, email):
    """A registered Gravatar proves a real person owns that address. Free, no risk."""
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    try:
        r = await client.get(f"https://www.gravatar.com/avatar/{h}?d=404&s=1",
                             timeout=httpx.Timeout(6.0))
        return r.status_code == 200
    except Exception:
        return False


_NO_RESULTS = ("did not match any", "no results found", "nothing found",
               "no documents were found")


def _strip_query_echo(text, q, chunk):
    """Search pages repeat the query in <title>, the search box, and 'results for'
    banners. Without removing that, every queried address looks confirmed."""
    t = re.sub(r"<title>.*?</title>", " ", text or "", flags=re.S | re.I)
    t = re.sub(r"<input\b[^>]*>", " ", t, flags=re.I)
    t = re.sub(r"<textarea\b.*?</textarea>", " ", t, flags=re.S | re.I)
    t = t.lower().replace(q.lower(), " ")
    for e in chunk:
        el = e.lower()
        for form in (f'"{el}"', f"&quot;{el}&quot;", f"%22{el}%22"):
            t = t.replace(form, " ")
    return t


async def search_confirm(client, emails, left):
    """Addresses appearing verbatim in public results are CONFIRMED, not guessed.
    Batched with OR so one query checks several at once."""
    hits = set()
    emails = list(emails)
    for i in range(0, len(emails), 4):
        if left() < 7:
            break
        chunk = emails[i:i + 4]
        q = " OR ".join(f'"{e}"' for e in chunk)
        for url, method in SERP_ENGINES[:3]:
            body = await serp_fetch(client, url, q, method)
            if not body:
                continue
            low = _strip_query_echo(body, q, chunk)
            if any(m in low for m in _NO_RESULTS):
                continue
            got = [e for e in chunk if e.lower() in low]
            if got:
                hits.update(got)
                break
    return hits
