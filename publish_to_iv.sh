#!/bin/bash
# Publish Mail Sniff to the iv-business repo.
#   ./publish_to_iv.sh git@github.com:ORG/iv-business.git
# Adds it as a second remote named "iv-business" and pushes main there.
# origin (the personal repo) is left alone because Render autodeploys from it.
set -e
cd "$(dirname "$0")"
URL="$1"
[ -z "$URL" ] && { echo "usage: ./publish_to_iv.sh <git@github.com:ORG/iv-business.git>"; exit 1; }
git remote remove iv-business 2>/dev/null || true
git remote add iv-business "$URL"
echo "· fetching to see what is already there…"
git fetch iv-business 2>&1 | tail -2 || true
echo "· pushing main…"
git push -u iv-business HEAD:main
echo ""
echo "  published → $URL"
echo "  NOTE: Render still deploys from 'origin'. Push both:"
echo "    git push origin main && git push iv-business main"
