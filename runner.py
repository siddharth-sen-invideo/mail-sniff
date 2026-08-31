"""
Shared domain-scan runner.

Single place where concurrency and timeouts live, used by the REST API, the MCP
server and the web UI, so the three cannot drift apart.
"""
from __future__ import annotations

import asyncio
import os

import httpx

import finder

# Render's free/starter instances get a fraction of a CPU, so settings tuned for
# a laptop starve there: pages parse slowly, the budget blows, and every domain
# times out. Detect the constrained host and back off. Override with env vars.
SMALL_HOST = bool(os.environ.get("RENDER") or os.environ.get("MAILSNIFF_SMALL_HOST"))


def _envint(name, default):
    try:
        return max(1, int(os.environ.get(name, "")))
    except (TypeError, ValueError):
        return default


CONCURRENCY = _envint("MAILSNIFF_CONCURRENCY", 2 if SMALL_HOST else 5)
PER_DOMAIN_TIMEOUT = _envint("MAILSNIFF_HARD_TIMEOUT", 150 if SMALL_HOST else 110)
READ_TIMEOUT = float(_envint("MAILSNIFF_READ_TIMEOUT", 18))
CONNECT_TIMEOUT = 8.0


def shape(r: dict) -> dict:
    """Stable public view of one domain result."""
    emails = [
        {"email": e["email"], "source": e.get("source"),
         "confidence": e.get("level"), "role": e.get("title") or None}
        for e in (r.get("emails") or [])
    ]
    people = [
        {"name": p.get("name") or None, "title": p.get("title") or None,
         "email": p.get("email"), "sourcing": p.get("status"),
         "evidence": p.get("source")}
        for p in (r.get("people") or [])
    ]
    seen, all_emails = set(), []
    for e in [x["email"] for x in emails] + [x["email"] for x in people]:
        if e and e not in seen:
            seen.add(e)
            all_emails.append(e)
    return {
        "domain": r.get("domain"),
        "emails": emails,
        "people": people,
        "all_emails": all_emails,          # convenience for callers
        "linkedin": (r.get("linkedin") or {}).get("url"),
        "confidence": r.get("confidence"),
        "note": r.get("note"),
    }


def new_client() -> httpx.AsyncClient:
    limits = httpx.Limits(max_connections=CONCURRENCY * 20,
                          max_keepalive_connections=CONCURRENCY * 6)
    return httpx.AsyncClient(
        headers={"User-Agent": finder.UA}, follow_redirects=True, verify=False,
        timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT), limits=limits)


async def run_domains(domains, concurrency: int = CONCURRENCY):
    """Scan domains, preserving input order. Never raises for a single domain."""
    sem = asyncio.Semaphore(max(1, concurrency))
    out = [None] * len(domains)
    async with new_client() as client:
        async def one(i, dom):
            async with sem:
                try:
                    r = await asyncio.wait_for(finder.process_domain(client, dom),
                                               timeout=PER_DOMAIN_TIMEOUT)
                except asyncio.TimeoutError:
                    r = {"domain": dom, "emails": [], "people": [], "note": "timed out"}
                except Exception as exc:
                    r = {"domain": dom, "emails": [], "people": [],
                         "note": f"error: {type(exc).__name__}: {exc}"[:200]}
                r["confidence"] = finder.domain_confidence(r.get("emails", []))
                out[i] = shape(r)
        await asyncio.gather(*[one(i, d) for i, d in enumerate(domains)])
    return out


async def verify_email(email: str) -> dict:
    email = (email or "").strip().lower()
    valid = finder._valid_email(email)
    if not valid:
        return {"email": email, "valid": False, "confidence": "low",
                "reason": "not a valid address", "role_address": False}
    await asyncio.to_thread(finder._has_mailserver, valid.split("@")[1])
    level, label = finder.classify(valid)
    return {"email": valid, "valid": True, "confidence": level, "reason": label,
            "role_address": valid.split("@")[0] in finder.ROLE_LOCALS}
