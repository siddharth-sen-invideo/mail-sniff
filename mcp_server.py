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

import finder
import runner

PROTOCOL_DEFAULT = "2024-11-05"
SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
SERVER_INFO = {"name": "mail-sniff", "version": "1.0.0"}

MAX_DOMAINS = 50

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


def _call_tool(name: str, args: dict):
    if name == "find_contacts":
        domains = [str(d).strip() for d in (args.get("domains") or []) if str(d).strip()]
        if not domains:
            raise ValueError("domains must be a non-empty list")
        if len(domains) > MAX_DOMAINS:
            raise ValueError(f"at most {MAX_DOMAINS} domains per call")
        results = asyncio.run(runner.run_domains(domains))
        found = sum(1 for r in results if r["emails"] or r["people"])
        return {"searched": len(results), "with_contacts": found, "results": results}

    if name == "find_people":
        dom = str(args.get("domain") or "").strip()
        if not dom:
            raise ValueError("domain is required")
        r = asyncio.run(runner.run_domains([dom]))[0]
        return {"domain": r["domain"], "people": r["people"],
                "linkedin": r["linkedin"], "note": r["note"]}

    if name == "verify_email":
        addr = str(args.get("email") or "").strip()
        if not addr:
            raise ValueError("email is required")
        return asyncio.run(runner.verify_email(addr))

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
