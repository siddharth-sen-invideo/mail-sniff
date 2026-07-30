#!/bin/bash
# Mail Sniff - one command to set up and run.
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  echo "· creating virtualenv…"
  python3 -m venv .venv
fi
echo "· installing dependencies…"
./.venv/bin/pip install -q --upgrade pip >/dev/null 2>&1 || true
./.venv/bin/pip install -q -r requirements.txt
PORT="${PORT:-8100}"
echo ""
echo "  Mail Sniff running →  http://localhost:${PORT}"
echo ""
exec ./.venv/bin/python -m uvicorn server:app --host 127.0.0.1 --port "${PORT}"
