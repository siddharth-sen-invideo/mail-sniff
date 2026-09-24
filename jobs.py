"""
Background job worker.

Jobs are rows in SQLite, not entries in a dict, so a redeploy no longer 404s a
job id a caller is polling: anything left 'running' is requeued at boot and the
per-domain results already written are kept.

Each domain is served from the cache when a fresh entry exists, which is what
makes a repeat lookup instant instead of a fresh crawl.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import traceback
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

import finder
import runner
import store

POLL_SECONDS = 2.0
WEBHOOK_TIMEOUT = 15.0
# The server makes this request, so an unrestricted callback URL is an SSRF
# hole. Internal targets are refused unless explicitly allowed, which an
# in-cluster consumer will need.
ALLOW_PRIVATE_WEBHOOKS = (os.environ.get("MAILSNIFF_WEBHOOK_ALLOW_PRIVATE")
                          or "").strip().lower() in ("1", "true", "yes", "on")

_task: Optional[asyncio.Task] = None


def webhook_url_ok(url: str) -> tuple:
    """(ok, reason). Rejects non-http and, by default, private/loopback hosts."""
    try:
        u = urlparse(url)
    except Exception:
        return False, "unparseable url"
    if u.scheme not in ("http", "https"):
        return False, "webhook must be http or https"
    if not u.hostname:
        return False, "webhook has no host"
    if ALLOW_PRIVATE_WEBHOOKS:
        return True, ""
    try:
        infos = socket.getaddrinfo(u.hostname, None)
    except Exception:
        return False, "webhook host does not resolve"
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            return False, ("webhook points at an internal address (%s); set "
                           "MAILSNIFF_WEBHOOK_ALLOW_PRIVATE=1 to permit it" % ip)
    return True, ""


async def _scan_one(client, domain: str, use_cache: bool) -> Dict[str, Any]:
    if use_cache:
        hit = store.cache_get(domain)
        if hit:
            return hit
    try:
        raw = await asyncio.wait_for(finder.process_domain(client, domain),
                                     timeout=runner.PER_DOMAIN_TIMEOUT)
        res = runner.shape(raw)
    except asyncio.TimeoutError:
        return {"domain": domain, "emails": [], "people": [], "all_emails": [],
                "linkedin": None, "confidence": "none", "note": "timed out"}
    except Exception as e:
        return {"domain": domain, "emails": [], "people": [], "all_emails": [],
                "linkedin": None, "confidence": "none",
                "note": "error: %s" % str(e)[:160]}
    res["cached"] = False
    store.cache_put(domain, res)
    return res


async def run_job(jid: str) -> None:
    job = store.job_get(jid)
    if not job:
        return
    store.job_set_status(jid, "running")
    try:
        sem = asyncio.Semaphore(runner.CONCURRENCY)
        async with runner.new_client() as client:
            async def one(i: int, dom: str):
                async with sem:
                    res = await _scan_one(client, dom, use_cache=True)
                    if not job["include_people"]:
                        keep = {e["email"] for e in res.get("emails", [])}
                        res = dict(res, people=[],
                                   all_emails=[e for e in res.get("all_emails", [])
                                               if e in keep])
                    store.job_set_result(jid, i, res)   # persisted per domain
            await asyncio.gather(*[one(i, d) for i, d in enumerate(job["domains"])])
        store.job_set_status(jid, "done")
    except Exception as e:
        traceback.print_exc()
        store.job_set_status(jid, "failed", str(e)[:300])
    await _fire_webhook(jid)


async def _fire_webhook(jid: str) -> None:
    job = store.job_get(jid)
    if not job or not job.get("webhook"):
        return
    ok, why = webhook_url_ok(job["webhook"])
    if not ok:
        store.job_set_webhook_status(jid, "refused: " + why)
        return
    payload = {"job_id": jid, "status": job["status"], "total": job["total"],
               "done": job["done"], "results": job["results"]}
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT,
                                         follow_redirects=False) as c:
                r = await c.post(job["webhook"], json=payload)
            if 200 <= r.status_code < 300:
                store.job_set_webhook_status(jid, "delivered %d" % r.status_code)
                return
            store.job_set_webhook_status(jid, "http %d" % r.status_code)
        except Exception as e:
            store.job_set_webhook_status(jid, "error: %s" % str(e)[:120])
        await asyncio.sleep(2 ** attempt)


async def worker_loop() -> None:
    """One worker per process; jobs run one at a time so a batch cannot starve
    the synchronous endpoints of the whole connection pool."""
    recovered = store.jobs_recover()
    if recovered:
        print("[jobs] requeued %d job(s) interrupted by a restart" % recovered)
    while True:
        try:
            pending = store.jobs_pending()
            if not pending:
                await asyncio.sleep(POLL_SECONDS)
                continue
            for jid in pending:
                await run_job(jid)
            store.prune()
        except asyncio.CancelledError:
            raise
        except Exception:
            traceback.print_exc()
            await asyncio.sleep(POLL_SECONDS)


def start(loop=None) -> None:
    global _task
    if _task is None or _task.done():
        _task = asyncio.ensure_future(worker_loop())


def stop() -> None:
    if _task and not _task.done():
        _task.cancel()
