"""
API authentication and rate limiting.

Keys come from MAILSNIFF_API_KEY as a comma-separated list. Each entry is either
a bare key or `name:key`, so every tool that calls this API gets its own named
credential and shows up separately in the logs and rate limiter:

    MAILSNIFF_API_KEY="rankfuel:s3cr3t...,citations:0th3r..."

One bare key still works for a single consumer.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from typing import Dict, List, Optional, Tuple

# requests per minute per principal; 0 disables
RATE_LIMIT = int(os.environ.get("MAILSNIFF_RATE_LIMIT", "120"))

_POMERIUM_HEADERS = ("x-pomerium-jwt-assertion", "x-pomerium-claim-email")


def flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def _parse_keys() -> List[Tuple[str, str]]:
    raw = (os.environ.get("MAILSNIFF_API_KEY") or "").strip()
    out: List[Tuple[str, str]] = []
    for i, part in enumerate(raw.split(",")):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            name, key = part.split(":", 1)
            name, key = name.strip(), key.strip()
        else:
            name, key = ("key%d" % (i + 1) if i else "default"), part
        if key:
            out.append((name, key))
    return out


def keys_configured() -> bool:
    return bool(_parse_keys())


def key_names() -> List[str]:
    return [n for n, _ in _parse_keys()]


def match_key(supplied: str) -> Optional[str]:
    """Constant-time compare against every configured key; returns its name."""
    found = None
    for name, key in _parse_keys():
        if secrets.compare_digest(supplied, key):
            found = name           # no early return: keep the timing flat
    return found


# ----------------------------------------------------------- rate limiting
class _Bucket:
    __slots__ = ("tokens", "last")

    def __init__(self, tokens: float, last: float):
        self.tokens, self.last = tokens, last


_buckets: Dict[str, _Bucket] = {}
_lock = threading.Lock()


def rate_check(principal: str) -> Tuple[bool, int]:
    """Token bucket. Returns (allowed, retry_after_seconds)."""
    if RATE_LIMIT <= 0:
        return True, 0
    now = time.time()
    per_sec = RATE_LIMIT / 60.0
    with _lock:
        b = _buckets.get(principal)
        if b is None:
            _buckets[principal] = _Bucket(RATE_LIMIT - 1, now)
            return True, 0
        b.tokens = min(float(RATE_LIMIT), b.tokens + (now - b.last) * per_sec)
        b.last = now
        if b.tokens >= 1:
            b.tokens -= 1
            return True, 0
        return False, max(1, int((1 - b.tokens) / per_sec) + 1)


def rate_state(principal: str) -> Dict[str, object]:
    with _lock:
        b = _buckets.get(principal)
        left = RATE_LIMIT if b is None else int(b.tokens)
    return {"limit_per_min": RATE_LIMIT, "remaining": left}
