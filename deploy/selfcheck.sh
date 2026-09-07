#!/bin/bash
# Check a Mail Sniff deployment: reachability, SSO interception, auth posture.
#   ./deploy/selfcheck.sh https://mail-sniff.apps.iv1.in
# Optional: MAILSNIFF_API_KEY and/or MAILSNIFF_POMERIUM_TOKEN in the environment.
BASE="${1:-https://mail-sniff.apps.iv1.in}"
BASE="${BASE%/}"
H=()
[ -n "$MAILSNIFF_API_KEY" ]       && H+=(-H "X-API-Key: $MAILSNIFF_API_KEY")
[ -n "$MAILSNIFF_POMERIUM_TOKEN" ] && H+=(-H "Authorization: Pomerium $MAILSNIFF_POMERIUM_TOKEN")

echo "checking $BASE"
[ ${#H[@]} -eq 0 ] && echo "  (no credentials in env: set MAILSNIFF_API_KEY and/or MAILSNIFF_POMERIUM_TOKEN)"
echo

sso=0
for p in /healthz /api/v1/health /api/v1/whoami /docs; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 40 "${H[@]}" "$BASE$p")
  loc=$(curl -s -o /dev/null -w "%{redirect_url}" --max-time 40 "${H[@]}" "$BASE$p")
  note=""
  case "$code" in
    30*) note="-> SSO login"; sso=1;;
    200) note="ok";;
    401|403) note="refused (auth reached the app)";;
    404) note="route not found";;
  esac
  printf "  %-18s %s  %s\n" "$p" "$code" "$note"
done

echo
body=$(curl -s --max-time 60 "${H[@]}" "$BASE/api/v1/health")
if echo "$body" | grep -q '"ok"'; then
  echo "$body" | python3 -c '
import sys, json
d = json.load(sys.stdin)
a = d.get("auth", {})
c = d.get("config", {})
print("  API IS REACHABLE")
print("    key required   :", a.get("api_key"))
print("    proxy identity :", a.get("proxy_identity"))
print("    OPEN TO ANYONE :", a.get("open_to_anyone"))
print("    concurrency    :", c.get("concurrency"), "| max pages:", c.get("max_pages"),
      "| budget:", str(c.get("budget_s")) + "s")
print("    small host     :", c.get("small_host"), "(false = full-speed settings)")
if a.get("open_to_anyone"):
    print("    WARNING: no key and no proxy identity, so anyone with the URL can run scans")
'
  who=$(curl -s --max-time 40 "${H[@]}" "$BASE/api/v1/whoami")
  echo "    whoami         : $who"
elif [ "$sso" = "1" ]; then
  echo "  API NOT REACHABLE: the proxy is intercepting with an SSO redirect."
  echo "  Fix: a Pomerium service-account token (no route change), or let /api/"
  echo "  through the proxy. Both are in deploy/README.md."
else
  echo "  API NOT REACHABLE. Response was:"
  echo "$body" | head -c 200
fi
