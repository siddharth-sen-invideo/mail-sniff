# Mail Sniff as an MCP server

Exposes Mail Sniff's contact discovery as MCP tools, so any MCP client
(Claude Code, Claude Desktop, Cursor, or your own tool) can call it.

Runs over **stdio** and speaks JSON-RPC 2.0 directly, so it needs **no MCP SDK**
and works on Python 3.9.

## Tools

| Tool | Input | Returns |
|---|---|---|
| `find_contacts` | `domains: string[]` (max 50) | Per domain: scraped emails, named people, LinkedIn. Input order preserved. |
| `find_people` | `domain: string` | Humans only: name, title, email, sourcing tier |
| `verify_email` | `email: string` | high / medium / low, with the reason |

### Sourcing tiers

Every person's address says where it came from, authentic first:

- `scraped` found verbatim on the site (the evidence names the page)
- `verified` generated, then proven by public search or a Gravatar account
- `likely` generated from the domain's own pattern, MX valid
- `guess` generated, unverified

## Add it to a client

Claude Code, one command:

```bash
claude mcp add mail-sniff -- "/Users/user/Claude Code/contact-finder/mcp_run.sh"
```

Claude Desktop, in `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mail-sniff": {
      "command": "/Users/user/Claude Code/contact-finder/mcp_run.sh"
    }
  }
}
```

Any other MCP client: run the command `mcp_run.sh` with stdio transport. To
invoke Python directly instead of the wrapper:

```json
{
  "mcpServers": {
    "mail-sniff": {
      "command": "/Users/user/Claude Code/contact-finder/.venv/bin/python",
      "args": ["/Users/user/Claude Code/contact-finder/mcp_server.py"]
    }
  }
}
```

## Check it works

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | ./mcp_run.sh
```

You should see the three tools listed.

## Notes

- Costs nothing to run: no API keys, same free sources as the web UI.
- A domain takes roughly 15 to 60 seconds, so set a generous client timeout on
  large batches. Six domains are scanned in parallel.
- Diagnostics go to stderr, keeping stdout clean for the protocol.
