# Mail Sniff REST API

Interactive docs: **`/docs`** · schema: **`/openapi.json`**

## Base URL

There are two deployments, and they behave differently:

| Host | Use it for | Machine-callable today |
|---|---|---|
| `https://mail-sniff.apps.iv1.in` | the internal UI, SSO login with your invideo account | **No, see below** |
| `https://mail-sniff.onrender.com` | API calls right now | Yes |

### The internal host is behind SSO

`mail-sniff.apps.iv1.in` sits behind Pomerium. Every request that is not already
carrying an SSO session gets a `302` to `pomerium.iv1.in`, so an API client
receives an HTML login page instead of JSON. Measured 2026-09-07: only `/healthz`
(answered by Envoy, not by Mail Sniff) returns 200; `/api/v1/health`, `/api/v1/find`,
`/docs` and `/openapi.json` all return 302. Sending `X-API-Key` makes no
difference, because the proxy rejects the request before the app ever sees it.

**To make the internal host callable**, someone with access to the Pomerium config
applies `deploy/pomerium-route.yaml`: it lets `/api/` through unauthenticated at
the proxy and has the app require `MAILSNIFF_API_KEY` instead, while the UI stays
behind SSO. The alternative in that file is a Pomerium service-account JWT, which
needs no proxy change but has to be provisioned and rotated.

Until that lands, point clients at the Render host.

```bash
curl -H "X-API-Key: $MAILSNIFF_API_KEY" \
  "https://mail-sniff.onrender.com/api/v1/health"
```

Expect `{"ok":true,...,"auth":{"open_to_anyone":false}}`. If `open_to_anyone` is
`true`, no key is set and anyone with the URL can run scans.

## Auth

Checked in this order:

1. **API key** - `X-API-Key: <key>` or `Authorization: Bearer <key>`, compared in
   constant time. Set `MAILSNIFF_API_KEY` to turn it on.
2. **Proxy identity** - with `MAILSNIFF_TRUST_PROXY_IDENTITY=1`, a request
   carrying Pomerium's `X-Pomerium-Jwt-Assertion` / `X-Pomerium-Claim-Email` is
   already SSO-authenticated and is allowed through. Enabling this also means an
   unauthenticated request is **refused** rather than served, so the app never
   falls open if the proxy route is bypassed. Only enable it where the app cannot
   be reached except through the proxy: the header is not signature-verified, so
   a directly reachable pod could be fed a forged one.
3. **Open mode** - no key configured. Fine on localhost, not on a shared host.
   `MAILSNIFF_REQUIRE_KEY=1` makes the app return `503` instead of serving open.

`GET /api/v1/whoami` reports which of the three let your call in, which is the
quickest way to debug a client:

```bash
curl -H "X-API-Key: $MAILSNIFF_API_KEY" https://mail-sniff.onrender.com/api/v1/whoami
# {"authorized_as":"api_key","proxy_headers_seen":[]}
```

## Clients

Ready-made, in `clients/`:

- **`clients/mailsniff.py`** - `MailSniff().find("invideo.io")`, `.find_many([...])`
  (async job, polled), `.verify(...)`. Reads `MAILSNIFF_URL` and `MAILSNIFF_API_KEY`.
- **`clients/mailsniff.ts`** - same surface, no dependencies, typed results.

Both refuse to follow a redirect and raise `NotAuthenticated` with the login URL
if they hit an SSO wall, instead of handing you back HTML.

```python
from mailsniff import MailSniff
ms = MailSniff(base_url="https://mail-sniff.onrender.com", api_key=KEY)
print(ms.find("invideo.io")["all_emails"])
print(ms.find_many(["a.com", "b.com"]))     # batch, keeps input order
```

Do not put the key in browser code: it would ship to every visitor. Call it from
your backend.

## Running it live on Render

Set these under the service's **Environment** tab, then redeploy:

| Variable | Why |
|---|---|
| `MAILSNIFF_API_KEY` | Required. Without it your endpoint is world-callable and strangers burn your instance. |
| `ALLOWED_ORIGINS` | `https://yourapp.com` so only your tool's browser code can call it. Defaults to `*`. |

Three things about the **free** tier that affect an API consumer:

1. **It sleeps after about 15 minutes idle.** The next request waits 30 to 60
   seconds while it wakes. Your tool must use a generous timeout, or keep the
   service warm by pinging `/api/v1/health` every 10 minutes from a free cron
   (cron-job.org). Render's Starter plan removes the sleeping.
2. **Jobs live in memory.** A sleep or redeploy discards job IDs, so a
   `/api/job/{id}` poll can 404 mid-batch. For long lists, either chunk into
   synchronous calls of 10 or expect to retry.
3. **Scraping runs from a datacenter IP,** which more sites block than a home
   connection. If the live hit rate is noticeably worse than local, that is why,
   and the fix is a proxy rather than a code change.

## Examples

curl:

```bash
curl "https://mail-sniff.onrender.com/api/v1/find?domain=invideo.io"
```

```bash
curl -X POST https://mail-sniff.onrender.com/api/v1/find \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-key' \
  -d '{"domains":["invideo.io","ahrefs.com"],"include_people":true}'
```

Python:

```python
import requests

r = requests.post(
    "https://mail-sniff.onrender.com/api/v1/find",
    json={"domains": ["invideo.io", "ahrefs.com"]},
    headers={"X-API-Key": "your-key"},
    timeout=300,
)
for row in r.json()["results"]:
    print(row["domain"], row["all_emails"])
    for p in row["people"]:
        if p["sourcing"] in ("scraped", "verified"):
            print("  ", p["name"], p["email"])
```

JavaScript:

```js
const res = await fetch("https://mail-sniff.onrender.com/api/v1/find", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-API-Key": "your-key" },
  body: JSON.stringify({ domains: ["invideo.io"] }),
});
const { results } = await res.json();
console.log(results[0].all_emails);
```

Large batches (over 10 domains) use the async pair:

```bash
JOB=$(curl -s -X POST https://mail-sniff.onrender.com/api/find \
  -H 'Content-Type: application/json' \
  -d '{"domains":["a.com","b.com","c.com"]}' | jq -r .job_id)
curl -s "https://mail-sniff.onrender.com/api/job/$JOB" | jq '{done,total,running}'
```

Poll until `running` is false. CSV and XLSX exports are at
`/api/job/{id}/export.csv` and `/api/job/{id}/export.xlsx`.

## Errors

| Code | Meaning |
|---|---|
| 400 | No domains supplied |
| 401 | Missing or wrong API key |
| 413 | More than 10 domains on a synchronous call |
| 422 | Body failed validation |

A domain that fails never fails the request: it comes back with an empty
`all_emails` and a `note` explaining why.
