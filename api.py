"""
Mail Sniff REST API (v1).

Synchronous endpoints for embedding in another tool. Interactive docs are served
at /docs, the machine-readable schema at /openapi.json.

Auth: set MAILSNIFF_API_KEY to require a key. When unset the API is open, which
is what you want on localhost and NOT what you want on a public host.
Send it as either header:
    X-API-Key: <key>
    Authorization: Bearer <key>
"""
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

import runner

router = APIRouter(prefix="/api/v1", tags=["Mail Sniff v1"])

# A domain takes 40-155s on a fraction-of-a-CPU host, so a large synchronous
# call just hangs the caller. Keep the blocking path small there and steer
# batches to the async job endpoints.
SYNC_MAX_DOMAINS = 3 if runner.SMALL_HOST else 10


def _require_key(x_api_key: Optional[str], authorization: Optional[str]) -> None:
    key = (os.environ.get("MAILSNIFF_API_KEY") or "").strip()
    if not key:
        return                                    # open mode
    supplied = (x_api_key or "").strip()
    if not supplied and authorization:
        parts = authorization.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            supplied = parts[1].strip()
    if supplied != key:
        raise HTTPException(status_code=401, detail="invalid or missing API key")


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
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Blocking scan of one domain. Typically 15 to 60 seconds, so allow a
    generous client timeout."""
    _require_key(x_api_key, authorization)
    results = _strip_people(await runner.run_domains(_clean([domain])), include_people)
    return {"count": 1, "results": results, "result": results[0]}


@router.post("/find", summary="Find contacts for up to 10 domains")
async def find_many(
    body: FindBody,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Blocking scan, results in the exact order supplied. For bigger batches use
    the async job endpoints (POST /api/find, GET /api/job/{id})."""
    _require_key(x_api_key, authorization)
    results = _strip_people(await runner.run_domains(_clean(body.domains)),
                            body.include_people)
    return {"count": len(results),
            "with_contacts": sum(1 for r in results if r["all_emails"]),
            "results": results}


@router.get("/verify", summary="Check one address")
async def verify_get(
    email: str = Query(..., description="Address to check"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    _require_key(x_api_key, authorization)
    return await runner.verify_email(email)


@router.post("/verify", summary="Check one address")
async def verify_post(
    body: VerifyBody,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    _require_key(x_api_key, authorization)
    return await runner.verify_email(body.email)


@router.get("/health", summary="Liveness and capability check")
async def health():
    import finder
    import runner
    return {"ok": True, "dns": finder._HAS_DNS,
            "auth_required": bool((os.environ.get("MAILSNIFF_API_KEY") or "").strip()),
            "sync_max_domains": SYNC_MAX_DOMAINS,
            "config": {"small_host": runner.SMALL_HOST,
                       "concurrency": runner.CONCURRENCY,
                       "max_pages": finder.MAX_PAGE_FETCHES,
                       "budget_s": finder.PER_DOMAIN_BUDGET}}
