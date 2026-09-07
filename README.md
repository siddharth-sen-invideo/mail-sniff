# Mail Sniff

A tiny, self-contained tool: paste domains → get contact emails back **in your exact order**,
each with any names found and a confidence score. **Completely free - no API keys, nothing paid.**

An internal tool built for invideo link-building outreach: it finds who to contact
at a site when you only have the domain.

## Live

**https://mail-sniff.apps.iv1.in** - on the company server, SSO login with your
invideo account. UI at the root, REST API under `/api/v1`, docs at `/docs`.

API clients need one more step: the host is behind Pomerium, which 302s anything
without an SSO session, so a machine caller receives a login page rather than
JSON. Either use a Pomerium service-account token (no infra change) or let
`/api/` through the proxy. See **[deploy/README.md](deploy/README.md)**, and run
`./deploy/selfcheck.sh` to see where it stands.

## Run it locally

```bash
./run.sh
```

Then open **http://localhost:8100**. (First run creates a virtualenv and installs deps; ~30s.)
Use a different port with `PORT=8200 ./run.sh`.

## Deploy

Single container from this repo's `Dockerfile`, listening on `$PORT` (default 8100).
No database, no state beyond in-memory jobs. Environment variables:

| Variable | Purpose |
|---|---|
| `MAILSNIFF_API_KEY` | Required in production, or the API is world-callable. Send as `X-API-Key`. |
| `MAILSNIFF_REQUIRE_KEY` | `1` makes the app return 503 rather than ever serving open. |
| `MAILSNIFF_TRUST_PROXY_IDENTITY` | `1` accepts Pomerium's SSO identity headers. Only where the app is unreachable except through the proxy. |
| `ALLOWED_ORIGINS` | Comma-separated origins for browser clients. Defaults to `*`. |
| `MAILSNIFF_CONCURRENCY` / `MAILSNIFF_MAX_PAGES` / `MAILSNIFF_BUDGET` | Override the host-aware scraper limits. |

The service detects a small host (Render's `RENDER` env) and automatically drops to
2 domains in flight over 26 pages each. On a fraction-of-a-CPU instance a domain
takes 40 to 155 seconds, so **use the async job endpoints for batches** and keep
synchronous calls to a few domains. `GET /api/v1/health` reports the live config.

## Honest limits

- Sites behind a JS bot challenge (Cloudflare interstitials) need a real browser; those are reported as blocked rather than silently empty.
- LinkedIn, Instagram and X are login-walled, so only public search snippets are read. No LinkedIn scraping.
- Verification is domain-level (syntax, MX, role, disposable). It deliberately does not probe individual mailboxes over SMTP.
- Generated addresses are always labelled (`likely` / `guess`) and never mixed in with scraped ones.

## What it does

1. Paste domains (or upload a `.txt`/`.csv`), hit **Find emails**.
2. It scans each domain and returns a live table: **Domain · Emails found · Names · Confidence**.
3. Rows stay in the exact order you entered them. No email? The row says **“email not found.”**
4. Export the whole thing as **CSV** or **Excel** (both keep your order; all emails for a domain sit in one cell).

## How it finds emails (all free, no keys)

- Homepage + auto-discovered contact / about / legal links
- Known pages: contact, about, privacy, terms, legal, imprint/impressum, cookie
- `/.well-known/security.txt` and `/humans.txt`
- Cloudflare `data-cfemail` de-obfuscation (decodes scrambled addresses)
- RSS/Atom feed editor fields (`webMaster`, `managingEditor`, `itunes:email`)
- WHOIS registrant email (fallback; privacy-proxied records are skipped)

## Confidence score (free Tier-A verification)

Per email: syntax + **MX record** (can the domain receive mail?) + disposable-domain + role-address checks.

- 🟢 **High** - valid mailbox on a domain with working mail servers
- 🟡 **Medium** - role address (`info@`, `support@`…) or a free-provider personal address
- 🔴 **Low** - no mail server, or a disposable domain

> Note: this is safe, instant, on-domain verification. It deliberately does **not** do per-mailbox
> SMTP probing (blocked on most hosts, useless for Gmail, and risks IP blacklisting). The real
> final check is simply sending and watching for bounces.

## Use it from your own tool (REST API)

Synchronous JSON endpoints, interactive docs at `/docs`:

```bash
curl -H "X-API-Key: $MAILSNIFF_API_KEY" \
  "https://mail-sniff.apps.iv1.in/api/v1/find?domain=invideo.io"
```

Full reference in **[API.md](API.md)**, including auth, batching and the
`sourcing` field that tells you which addresses were scraped and which were
generated.

## Use it from another tool (MCP)

Mail Sniff ships an MCP server so other tools can call it directly.
See **[MCP.md](MCP.md)**, or add it to Claude Code with:

```bash
claude mcp add mail-sniff -- "$(pwd)/mcp_run.sh"
```

## Files

| File | Purpose |
|---|---|
| `finder.py` | discovery + verification engine |
| `server.py` | FastAPI backend (jobs, live status, CSV/XLSX export) |
| `index.html` | the whole UI (single file, no build step) |
| `runner.py` | shared concurrency, timeouts and result shaping (one source of truth) |
| `api.py` | REST API v1 |
| `mcp_server.py` | MCP stdio server |
| `people.py` | name extraction + email-pattern inference |
| `clients/` | ready-made Python + TypeScript API clients |
| `deploy/` | Pomerium route config for the internal host |
| `run.sh` | setup + launch |
