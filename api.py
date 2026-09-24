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

import auth
import jobs
import runner
import store

router = APIRouter(prefix="/api/v1", tags=["Mail Sniff v1"])

# A domain takes 40-155s on a fraction-of-a-CPU host, so a large synchronous
# call just hangs the caller. Keep the blocking path small there and steer
# batches to the async job endpoints.
SYNC_MAX_DOMAINS = 3 if runner.SMALL_HOST else 10


def _flag(name: str) -> bool:
    return auth.flag(name)


_POMERIUM_HEADERS = auth._POMERIUM_HEADERS


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
    """Return the principal that made this call, or raise 401/429/503."""
    principal = None

    if auth.keys_configured():
        supplied = (x_api_key or "").strip()
        if not supplied and authorization:
            parts = authorization.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                supplied = parts[1].strip()
        if supplied:
            name = auth.match_key(supplied)
            if name:
                principal = "key:" + name
        if principal is None:
            who = _proxy_identity(request)
            if who:
                principal = "sso:" + who
        if principal is None:
            raise HTTPException(status_code=401, detail="invalid or missing API key")
    else:
        who = _proxy_identity(request)
        if who:
            principal = "sso:" + who
        elif _flag("MAILSNIFF_TRUST_PROXY_IDENTITY"):
            # Enabling proxy identity asserts that callers ARE authenticated, so
            # never fall through to open mode: if the proxy route is ever
            # bypassed the request must be refused rather than served.
            raise HTTPException(
                status_code=401,
                detail="unauthenticated: no API key and no proxy identity headers")
        elif _flag("MAILSNIFF_REQUIRE_KEY"):
            raise HTTPException(
                status_code=503,
                detail="server misconfigured: MAILSNIFF_REQUIRE_KEY is set but "
                       "MAILSNIFF_API_KEY is empty, so every request is refused")
        else:
            principal = "open"

    allowed, retry = auth.rate_check(principal)
    if not allowed:
        raise HTTPException(status_code=429,
                            detail="rate limit exceeded, retry in %ds" % retry,
                            headers={"Retry-After": str(retry)})
    return principal


# kept so any older import path still works
def _require_key(x_api_key: Optional[str], authorization: Optional[str]) -> None:
    _authorize(x_api_key, authorization, None)


class JobBody(BaseModel):
    domains: List[str] = Field(..., description="Domains or URLs to scan",
                               min_items=1, max_items=500)
    include_people: bool = Field(True, description="Include named humans")
    webhook_url: Optional[str] = Field(
        None, description="POSTed the finished job instead of you polling for it")


class FindBody(BaseModel):
    domains: List[str] = Field(..., description="Domains or URLs to scan",
                               min_items=1)
    include_people: bool = Field(True, description="Include named humans and their addresses")
    fresh: bool = Field(False, description="Ignore the cache and re-scan")


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


async def _scan_cached(domains: List[str], fresh: bool = False):
    """Serve each domain from cache when a fresh entry exists, scan the rest.
    Results come back in the order supplied."""
    out: List[Optional[dict]] = [None] * len(domains)
    todo = []
    for i, d in enumerate(domains):
        hit = None if fresh else store.cache_get(d)
        if hit:
            out[i] = hit
        else:
            todo.append((i, d))
    if todo:
        scanned = await runner.run_domains([d for _, d in todo])
        for (i, _), res in zip(todo, scanned):
            res["cached"] = False
            store.cache_put(res.get("domain") or domains[i], res)
            out[i] = res
    return [r for r in out if r is not None]


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
    fresh: bool = Query(False, description="Ignore the cache and re-scan"),
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Blocking scan of one domain. Typically 15 to 60 seconds on a fresh
    domain, or instant when the cache has it, so allow a generous client
    timeout. Pass `fresh=true` to bypass the cache."""
    _authorize(x_api_key, authorization, request)
    results = _strip_people(await _scan_cached(_clean([domain]), fresh), include_people)
    return {"count": 1, "results": results, "result": results[0]}


@router.post("/find", summary="Find contacts for up to 10 domains")
async def find_many(
    body: FindBody,
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Blocking scan, results in the exact order supplied. For bigger batches use
    the async job endpoints (POST /api/v1/jobs)."""
    _authorize(x_api_key, authorization, request)
    results = _strip_people(await _scan_cached(_clean(body.domains), body.fresh),
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
    has_key = auth.keys_configured()
    trust_proxy = _flag("MAILSNIFF_TRUST_PROXY_IDENTITY")
    return {"ok": True, "dns": finder._HAS_DNS,
            "auth_required": has_key,
            "sync_max_domains": SYNC_MAX_DOMAINS,
            "cache": store.cache_stats(),
            "rate_limit": {"per_min": auth.RATE_LIMIT},
            "auth": {"api_key": has_key,
                     "key_names": auth.key_names(),
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


# --------------------------------------------------------------- jobs
@router.post("/jobs", status_code=202, summary="Submit a batch scan")
async def job_submit(
    body: JobBody,
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Queue up to 500 domains and return immediately. Poll
    `GET /api/v1/jobs/{id}`, or give a `webhook_url` and be told when it is done.

    Jobs are persisted, so a restart resumes them rather than losing the id.
    """
    who = _authorize(x_api_key, authorization, request)
    domains = [str(d).strip() for d in body.domains if str(d).strip()]
    if not domains:
        raise HTTPException(400, "no domains supplied")
    if body.webhook_url:
        ok, why = jobs.webhook_url_ok(body.webhook_url)
        if not ok:
            raise HTTPException(400, why)
    jid = store.job_create(domains, include_people=body.include_people,
                           webhook=body.webhook_url, owner=who)
    jobs.start()
    return {"job_id": jid, "status": "queued", "total": len(domains),
            "poll": "/api/v1/jobs/%s" % jid}


@router.get("/jobs", summary="List recent jobs")
async def job_index(
    limit: int = Query(25, ge=1, le=200),
    mine: bool = Query(True, description="Only jobs submitted with your credential"),
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    who = _authorize(x_api_key, authorization, request)
    return {"jobs": store.job_list(limit=limit, owner=who if mine else None)}


@router.get("/jobs/{job_id}", summary="Job status and results")
async def job_status(
    job_id: str,
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    _authorize(x_api_key, authorization, request)
    job = store.job_get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    results = [r for r in job["results"] if r is not None]
    return {
        "job_id": job["id"], "status": job["status"],
        "done": job["done"], "total": job["total"],
        "found": sum(1 for r in results if r.get("all_emails")),
        "webhook_status": job["webhook_status"],
        "error": job["error"],
        # partial results stream out as they land, in input order
        "results": job["results"],
    }


@router.delete("/jobs/{job_id}", summary="Delete a job")
async def job_remove(
    job_id: str,
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    _authorize(x_api_key, authorization, request)
    if not store.job_delete(job_id):
        raise HTTPException(404, "job not found")
    return {"deleted": job_id}


# --------------------------------------------------------------- cache
@router.get("/cache", summary="Cache statistics")
async def cache_info(
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    _authorize(x_api_key, authorization, request)
    return store.cache_stats()


@router.delete("/cache", summary="Drop cached results")
async def cache_drop(
    domain: Optional[str] = Query(None, description="One domain, or all if omitted"),
    request: Request = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    _authorize(x_api_key, authorization, request)
    return {"removed": store.cache_clear(domain)}
