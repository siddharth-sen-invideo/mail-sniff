#!/bin/bash
# Mail Sniff MCP server (stdio). Point your MCP client at this script.
cd "$(dirname "$0")"
[ -d .venv ] || { python3 -m venv .venv; ./.venv/bin/pip install -q -r requirements.txt; }
exec ./.venv/bin/python mcp_server.py
