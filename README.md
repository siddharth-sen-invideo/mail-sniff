# Mail Sniff

A tiny, self-contained tool: paste domains → get contact emails back **in your exact order**,
each with any names found and a confidence score. **Completely free - no API keys, nothing paid.**

## Run

```bash
./run.sh
```

Then open **http://localhost:8100**. (First run creates a virtualenv and installs deps; ~30s.)

To use a different port: `PORT=8200 ./run.sh`

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
| `run.sh` | setup + launch |
