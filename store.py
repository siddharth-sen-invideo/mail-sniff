"""
SQLite store for the API: a result cache and a durable job queue.

Both live in one file so a restart does not lose work. Jobs used to be a dict in
process memory, which meant a redeploy silently 404'd every job id a caller was
polling; and every repeat lookup of a domain re-scraped the whole site.

WAL mode plus a busy timeout because the API and the background worker write
concurrently.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

DB_PATH = os.environ.get("MAILSNIFF_DB", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "mailsniff.db"))

# A site's contact page does not change hourly. Re-scraping on every call is the
# single biggest waste for a tool that looks up the same domains repeatedly.
CACHE_TTL = int(os.environ.get("MAILSNIFF_CACHE_TTL_DAYS", "7")) * 86400
JOB_RETENTION = int(os.environ.get("MAILSNIFF_JOB_RETENTION_DAYS", "14")) * 86400

_local = threading.local()


def _conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        c = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=15000")
        c.execute("PRAGMA synchronous=NORMAL")
        _local.conn = c
    return c


def init() -> None:
    c = _conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS cache (
        domain      TEXT PRIMARY KEY,
        result      TEXT NOT NULL,
        found_at    REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS jobs (
        id          TEXT PRIMARY KEY,
        status      TEXT NOT NULL,          -- queued | running | done | failed
        created_at  REAL NOT NULL,
        updated_at  REAL NOT NULL,
        domains     TEXT NOT NULL,
        results     TEXT NOT NULL,
        done        INTEGER NOT NULL DEFAULT 0,
        total       INTEGER NOT NULL,
        webhook     TEXT,
        webhook_status TEXT,
        include_people INTEGER NOT NULL DEFAULT 1,
        owner       TEXT,
        error       TEXT
    );
    CREATE INDEX IF NOT EXISTS jobs_created ON jobs(created_at);
    CREATE INDEX IF NOT EXISTS jobs_status  ON jobs(status);
    """)
    c.commit()


# ---------------------------------------------------------------- cache
def cache_get(domain: str, max_age: Optional[int] = None) -> Optional[Dict[str, Any]]:
    ttl = CACHE_TTL if max_age is None else max_age
    if ttl <= 0:
        return None
    row = _conn().execute(
        "SELECT result, found_at FROM cache WHERE domain=?", (domain.lower(),)).fetchone()
    if not row or (time.time() - row["found_at"]) > ttl:
        return None
    out = json.loads(row["result"])
    out["cached"] = True
    out["cached_age_s"] = int(time.time() - row["found_at"])
    return out


def cache_put(domain: str, result: Dict[str, Any]) -> None:
    c = _conn()
    c.execute("INSERT OR REPLACE INTO cache(domain, result, found_at) VALUES (?,?,?)",
              (domain.lower(), json.dumps(result), time.time()))
    c.commit()


def cache_stats() -> Dict[str, Any]:
    c = _conn()
    n = c.execute("SELECT COUNT(*) n FROM cache").fetchone()["n"]
    fresh = c.execute("SELECT COUNT(*) n FROM cache WHERE found_at > ?",
                      (time.time() - CACHE_TTL,)).fetchone()["n"]
    return {"entries": n, "fresh": fresh, "ttl_days": CACHE_TTL // 86400}


def cache_clear(domain: Optional[str] = None) -> int:
    c = _conn()
    if domain:
        cur = c.execute("DELETE FROM cache WHERE domain=?", (domain.lower(),))
    else:
        cur = c.execute("DELETE FROM cache")
    c.commit()
    return cur.rowcount


# ---------------------------------------------------------------- jobs
def job_create(domains: List[str], include_people: bool = True,
               webhook: Optional[str] = None, owner: Optional[str] = None) -> str:
    jid = uuid.uuid4().hex[:16]
    now = time.time()
    c = _conn()
    c.execute("""INSERT INTO jobs(id,status,created_at,updated_at,domains,results,
                                  done,total,webhook,include_people,owner)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
              (jid, "queued", now, now, json.dumps(domains), json.dumps([None] * len(domains)),
               0, len(domains), webhook, 1 if include_people else 0, owner))
    c.commit()
    return jid


def job_get(jid: str) -> Optional[Dict[str, Any]]:
    row = _conn().execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["domains"] = json.loads(d["domains"])
    d["results"] = json.loads(d["results"])
    d["include_people"] = bool(d["include_people"])
    return d


def job_set_status(jid: str, status: str, error: Optional[str] = None) -> None:
    c = _conn()
    c.execute("UPDATE jobs SET status=?, updated_at=?, error=? WHERE id=?",
              (status, time.time(), error, jid))
    c.commit()


def job_set_result(jid: str, index: int, result: Dict[str, Any]) -> None:
    """Persist one finished domain. Written per domain so a crash keeps the rest."""
    c = _conn()
    row = c.execute("SELECT results, done FROM jobs WHERE id=?", (jid,)).fetchone()
    if not row:
        return
    results = json.loads(row["results"])
    if 0 <= index < len(results):
        was_empty = results[index] is None
        results[index] = result
        done = row["done"] + (1 if was_empty else 0)
        c.execute("UPDATE jobs SET results=?, done=?, updated_at=? WHERE id=?",
                  (json.dumps(results), done, time.time(), jid))
        c.commit()


def job_set_webhook_status(jid: str, status: str) -> None:
    c = _conn()
    c.execute("UPDATE jobs SET webhook_status=? WHERE id=?", (status, jid))
    c.commit()


def job_list(limit: int = 25, owner: Optional[str] = None) -> List[Dict[str, Any]]:
    q = "SELECT id,status,created_at,updated_at,done,total,owner FROM jobs"
    args: List[Any] = []
    if owner:
        q += " WHERE owner=?"
        args.append(owner)
    q += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in _conn().execute(q, args).fetchall()]


def job_delete(jid: str) -> bool:
    c = _conn()
    cur = c.execute("DELETE FROM jobs WHERE id=?", (jid,))
    c.commit()
    return cur.rowcount > 0


def jobs_recover() -> int:
    """Anything left 'running' when the process died is requeued on boot."""
    c = _conn()
    cur = c.execute("UPDATE jobs SET status='queued' WHERE status='running'")
    c.commit()
    return cur.rowcount


def jobs_pending() -> List[str]:
    return [r["id"] for r in _conn().execute(
        "SELECT id FROM jobs WHERE status='queued' ORDER BY created_at").fetchall()]


def prune() -> int:
    c = _conn()
    cur = c.execute("DELETE FROM jobs WHERE created_at < ?", (time.time() - JOB_RETENTION,))
    c.execute("DELETE FROM cache WHERE found_at < ?", (time.time() - CACHE_TTL * 4,))
    c.commit()
    return cur.rowcount
