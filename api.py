"""
Mail Sniff REST API (v1).

Synchronous endpoints for embedding in another tool. Interactive docs are served
at /docs, the machine-readable schema at /openapi.json.

Auth, in the order it is checked:

  1. MAILSNIFF_API_KEY  - machine clients send it as either header:
         X-API-Key: <key>
         Authorization: Bearer <key>
  2. Proxy identity     - when MAILSNIFF_TRUST_PROXY_IDENTITY=1, a request that
     arrives with Pomerium's identity headers is already SSO-authenticated and
     is allowed through. ONLY enable this where the app cannot be reached except
     through the proxy, because the header is otherwise trivially forged.
  3. Open mode          - no key configured, which is fine on localhost and not
     fine on a shared host. Set MAILSNIFF_REQUIRE_KEY=1 to fail closed instead.
"""
from __future__ import annotations

import os
import secrets
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

import runner

router = APIRouter(prefix="/api/v1", tags=["Mail Sniff v1"])

# A domain takes 40-155s on a fraction-of-a-CPU host, so a large synchronous
# call just hangs the caller. Keep the blocking path small there and steer
# batches to the async job endpoints.
SYNC_MAX_DOMAINS = 3 if runner.SMALL_HOST else 10


def _flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


# Pomerium injects these once pass_identity_headers is on. Presence alone is not
# proof of anything unless the app is unreachable except through the proxy, which
# is why trusting them is opt-in.
_POMERIUM_HEADERS = ("x-pomerium-jwt-assertion", "x-pomerium-claim-email")


def _proxy_identity(request: Optional[Request]) -> Optional[str]:
    """The SSO email the proxy vouched for, or None."""
    if request is None or not _flag("MAILSNIFF_TRUST_PROXY_IDENTITY"):
        return None
    h = request.headers
    if not any(h.get(name) for name in _POMERIUM_HEADERS):
        return None
    return (h.get("x-pomerium-claim-email") or "sso-user").strip()


def _authorize(x_api_key: Optional[str], authorization: Optional[str],
               request: Optional[Request] = None) -> str:
    """Return how the caller was authorized, or raise 401/503."""
    key = (os.environ.get("MAILSNIFF_API_KEY") or "").strip()

    if key:
        supplied = (x_api_key or "").strip()
        if not supplied and authorization:
            parts = authorization.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                supplied = parts[1].strip()
        if supplied and secrets.compare_digest(supplied, key):
            return "api_key"
        # a key is configured, so an SSO-authenticated browser still gets in
        who = _proxy_identity(request)
        if who:
            return "sso:" + who
        raise HTTPException(status_code=401, detail="invalid or missing API key")

    who = _proxy_identity(request)
    if who:
        return "sso:" + who

    # Turning on proxy identity is a statement that callers ARE authenticated,
    # so never fall through to open mode here: a request with no key and no
    # forwarded identity is unauthenticated, and if the proxy route is ever
    # bypassed that request must be refused rather than served.
    if _flag("MAILSNIFF_TRUST_PROXY_IDENTITY"):
        raise HTTPException(
            status_code=401,
            detail="unauthenticated: no API key and no proxy identity headers")

    if _flag("MAILSNIFF_REQUIRE_KEY"):
        raise HTTPException(
            status_code=503,
            detail="server misconfigured: MAILSNIFF_REQUIRE_KEY is set but "
                   "MAILSNIFF_API_KEY is empty, so every request is refused")
    return "open"


# kept so any older import path still works
def _require_key(x_api_key: Optional[str], authorization: Optional[str]) -> None:
    _authorize(x_api_key, authorization, None)


class FindBody(BaseModel):
    domains: List[str] = Field(..., description="Domains or URLs to scan",
                               min_items=1)
    include_people: bool = Field(True, description="Include named humans and their addresses")


class VerifyBody(BaseModel):
    email: str = Field(..., description="Address to check")


def _clean(domains) -> List[str]:
    out = [str(d).strip() for d in domains if str(d).strip()]
    if not out:
        raise HTTPException(400, "no domains supplied")
    if len(out) > SYNC_MAX_DOMAINS:
        raise HTTPException(
            413, f"at most {SYNC_MAX_DOMAINS} domains per synchronous call; "
                 f"use POST /api/find plus GET /api/job/{{id}} for larger batches")
    return out


def _strip_people(results, include_people: bool):
    if include_people:
        return results
    for r in results:
        emails = {e["email"] for e in r["emails"]}
        r["people"] = []
        r["all_emails"] = [e for e in r["all_emails"] if e in emails]
    return results


@router.get("/find", summary="Find contacts for one domain")
async def find_one(
    domain: str = Query(..., description="A single domain, e.g. invideo.io"),
    include_people: bool = Query(True),
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Blocking scan of one domain. Typically 15 to 60 seconds, so allow a
    generous client timeout."""
    _authorize(x_api_key, authorization, request)
    results = _strip_people(await runner.run_domains(_clean([domain])), include_people)
    return {"count": 1, "results": results, "result": results[0]}


@router.post("/find", summary="Find contacts for up to 10 domains")
async def find_many(
    body: FindBody,
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Blocking scan, results in the exact order supplied. For bigger batches use
    the async job endpoints (POST /api/find, GET /api/job/{id})."""
    _authorize(x_api_key, authorization, request)
    results = _strip_people(await runner.run_domains(_clean(body.domains)),
                            body.include_people)
    return {"count": len(results),
            "with_contacts": sum(1 for r in results if r["all_emails"]),
            "results": results}


@router.get("/verify", summary="Check one address")
async def verify_get(
    email: str = Query(..., description="Address to check"),
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    _authorize(x_api_key, authorization, request)
    return await runner.verify_email(email)


@router.post("/verify", summary="Check one address")
async def verify_post(
    body: VerifyBody,
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    _authorize(x_api_key, authorization, request)
    return await runner.verify_email(body.email)


@router.get("/health", summary="Liveness and capability check")
async def health():
    import finder
    import runner
    has_key = bool((os.environ.get("MAILSNIFF_API_KEY") or "").strip())
    trust_proxy = _flag("MAILSNIFF_TRUST_PROXY_IDENTITY")
    return {"ok": True, "dns": finder._HAS_DNS,
            "auth_required": has_key,
            "sync_max_domains": SYNC_MAX_DOMAINS,
            "auth": {"api_key": has_key,
                     "proxy_identity": trust_proxy,
                     "fail_closed": _flag("MAILSNIFF_REQUIRE_KEY"),
                     # the state worth catching before anyone finds the URL
                     "open_to_anyone": not has_key and not trust_proxy},
            "config": {"small_host": runner.SMALL_HOST,
                       "concurrency": runner.CONCURRENCY,
                       "max_pages": finder.MAX_PAGE_FETCHES,
                       "budget_s": finder.PER_DOMAIN_BUDGET}}


@router.get("/whoami", summary="How this request was authorized")
async def whoami(
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Diagnostic for wiring a client up: says whether the call arrived as an
    API key, an SSO identity forwarded by the proxy, or open mode."""
    how = _authorize(x_api_key, authorization, request)
    seen = []
    if request is not None:
        seen = [h for h in _POMERIUM_HEADERS if request.headers.get(h)]
    return {"authorized_as": how, "proxy_headers_seen": seen}
