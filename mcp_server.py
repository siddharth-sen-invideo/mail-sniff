#!/usr/bin/env python3
"""
Mail Sniff MCP server (stdio transport).

Speaks MCP over JSON-RPC 2.0 on stdin/stdout with no SDK, so it runs on the
Python 3.9 this project already uses (the official SDK needs 3.10+).

Tools exposed:
  find_contacts  bulk domains -> scraped emails + named people + LinkedIn
  find_people    one domain   -> humans only (name, title, email, sourcing tier)
  verify_email   one address  -> syntax + MX + role/disposable confidence

Every address carries its provenance:
  scraped   found verbatim on the site
  verified  generated, then proven by public search or a Gravatar account
  likely    generated from the domain's own pattern, MX valid
  guess     generated, unverified
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import sys

import httpx

import finder

PROTOCOL_DEFAULT = "2024-11-05"
SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
SERVER_INFO = {"name": "mail-sniff", "version": "1.0.0"}

MAX_DOMAINS = 50
CONCURRENCY = 5
PER_DOMAIN_TIMEOUT = 110

TOOLS = [
    {
        "name": "find_contacts",
        "description": (
            "Find contact emails for one or more domains, free and with no API keys. "
            "Scrapes the site first (contact/about/team/legal pages, JSON-LD, RSS, "
            "security.txt, Cloudflare-obfuscated addresses, JS bundles), then finds "
            "named humans and only guesses an address from the domain's own email "
            "pattern as a last resort. Results keep the exact input order. Each "
            "address states where it came from, so scraped addresses are "
            "distinguishable from generated ones."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Domains or URLs, e.g. ['invideo.io', 'ahrefs.com'].",
                    "minItems": 1,
                    "maxItems": MAX_DOMAINS,
                }
            },
            "required": ["domains"],
        },
    },
    {
        "name": "find_people",
        "description": (
            "Find the real humans at a company domain: name, job title, email and "
            "how the address was sourced. Names come from bylines, author pages, RSS "
            "authors, JSON-LD and public search-result snippets. Ordered by "
            "authenticity first, then by who can actually approve a link "
            "(founder, editor, SEO/marketing, PR)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "A single domain, e.g. 'invideo.io'."}
            },
            "required": ["domain"],
        },
    },
    {
        "name": "verify_email",
        "description": (
            "Check a single address without sending mail: syntax, whether the domain "
            "has a working mail server (MX), and whether it is a role address "
            "(info@, support@) or a disposable domain. Returns high, medium or low. "
            "This is domain-level verification; it deliberately does not probe the "
            "individual mailbox over SMTP."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "description": "Address to check."}
            },
            "required": ["email"],
        },
    },
]


def _shape(r: dict) -> dict:
    """Compact, model-friendly view of one domain result."""
    return {
        "domain": r.get("domain"),
        "emails": [
            {"email": e["email"], "source": e.get("source"),
             "confidence": e.get("level"), "role": e.get("title") or None}
            for e in (r.get("emails") or [])
        ],
        "people": [
            {"name": p.get("name") or None, "title": p.get("title") or None,
             "email": p.get("email"), "sourcing": p.get("status"),
             "evidence": p.get("source")}
            for p in (r.get("people") or [])
        ],
        "linkedin": (r.get("linkedin") or {}).get("url"),
        "confidence": r.get("confidence"),
        "note": r.get("note"),
    }


async def _run_domains(domains):
    sem = asyncio.Semaphore(CONCURRENCY)
    limits = httpx.Limits(max_connections=CONCURRENCY * 20,
                          max_keepalive_connections=CONCURRENCY * 6)
    timeout = httpx.Timeout(18.0, connect=8.0)
    out = [None] * len(domains)
    async with httpx.AsyncClient(headers={"User-Agent": finder.UA}, follow_redirects=True,
                                 timeout=timeout, verify=False, limits=limits) as client:
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
                out[i] = _shape(r)
        await asyncio.gather(*[one(i, d) for i, d in enumerate(domains)])
    return out


async def _verify(email: str) -> dict:
    email = (email or "").strip().lower()
    valid = finder._valid_email(email)
    if not valid:
        return {"email": email, "confidence": "low", "reason": "not a valid address"}
    await asyncio.to_thread(finder._has_mailserver, valid.split("@")[1])
    level, label = finder.classify(valid)
    return {"email": valid, "confidence": level, "reason": label,
            "role_address": valid.split("@")[0] in finder.ROLE_LOCALS}


def _call_tool(name: str, args: dict):
    if name == "find_contacts":
        domains = [str(d).strip() for d in (args.get("domains") or []) if str(d).strip()]
        if not domains:
            raise ValueError("domains must be a non-empty list")
        if len(domains) > MAX_DOMAINS:
            raise ValueError(f"at most {MAX_DOMAINS} domains per call")
        results = asyncio.run(_run_domains(domains))
        found = sum(1 for r in results if r["emails"] or r["people"])
        return {"searched": len(results), "with_contacts": found, "results": results}

    if name == "find_people":
        dom = str(args.get("domain") or "").strip()
        if not dom:
            raise ValueError("domain is required")
        r = asyncio.run(_run_domains([dom]))[0]
        return {"domain": r["domain"], "people": r["people"],
                "linkedin": r["linkedin"], "note": r["note"]}

    if name == "verify_email":
        addr = str(args.get("email") or "").strip()
        if not addr:
            raise ValueError("email is required")
        return asyncio.run(_verify(addr))

    raise ValueError(f"unknown tool: {name}")


def _handle(msg: dict):
    """Return a JSON-RPC response, or None for notifications."""
    mid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}

    def ok(result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code, message):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

    if method == "initialize":
        want = params.get("protocolVersion")
        return ok({
            "protocolVersion": want if want in SUPPORTED_PROTOCOLS else PROTOCOL_DEFAULT,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        })

    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return None                      # notifications get no reply

    if method == "ping":
        return ok({})

    if method == "tools/list":
        return ok({"tools": TOOLS})

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            # finder prints diagnostics; keep stdout clean for the protocol
            with contextlib.redirect_stdout(sys.stderr):
                payload = _call_tool(name, args)
            text = json.dumps(payload, indent=2, ensure_ascii=False)
            return ok({"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as exc:
            return ok({"content": [{"type": "text",
                                    "text": f"{type(exc).__name__}: {exc}"}],
                       "isError": True})

    if mid is None:
        return None                      # unknown notification
    return err(-32601, f"method not found: {method}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            resp = _handle(msg)
        except Exception as exc:         # never die on one bad message
            resp = {"jsonrpc": "2.0", "id": msg.get("id"),
                    "error": {"code": -32603, "message": str(exc)}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
