# Mail Sniff REST API

Interactive docs: **`/docs`** · schema: **`/openapi.json`**

## Base URL

```
https://mail-sniff.apps.iv1.in
```

Hosted on the company server. Web UI at the root, this API under `/api/v1`,
interactive docs at `/docs`.

### One thing to sort out first: the API is behind SSO

The host sits behind Pomerium, which redirects any request without an SSO
session to `pomerium.iv1.in`. A browser is fine. An API client gets an HTML
login page instead of JSON. Verified against the live host: `/api/v1/health`,
`/api/v1/find`, `/api/v1/whoami`, `/docs` and `/openapi.json` all return `302`.
Only `/healthz` returns 200, and that is Envoy answering rather than Mail Sniff.
Sending `X-API-Key` changes nothing, because the proxy rejects the request
before the app ever sees it.

Two fixes, and **the first needs no infrastructure change**:

1. **A Pomerium service-account token.** Whoever runs `pomerium.iv1.in` issues
   one for this route; clients send `Authorization: Pomerium <jwt>` and the proxy
   lets them through. Both clients in `clients/` support it.
2. **Let `/api/` through the proxy** and have the app's `MAILSNIFF_API_KEY` guard
   it instead, with the UI still behind SSO. Config in `deploy/pomerium-route.yaml`.

Trade-offs and env vars: **[deploy/README.md](deploy/README.md)**. Check where it
stands at any time:

```bash
./deploy/selfcheck.sh https://mail-sniff.apps.iv1.in
```

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
curl -H "X-API-Key: $MAILSNIFF_API_KEY" https://mail-sniff.apps.iv1.in/api/v1/whoami
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
ms = MailSniff(base_url="https://mail-sniff.apps.iv1.in", api_key=KEY)
print(ms.find("invideo.io")["all_emails"])
print(ms.find_many(["a.com", "b.com"]))     # batch, keeps input order
```

Do not put the key in browser code: it would ship to every visitor. Call it from
your backend.

## Running it on the company server

Environment, set on the deployment:

| Variable | Why |
|---|---|
| `MAILSNIFF_TRUST_PROXY_IDENTITY=1` | The app is behind Pomerium. Accepts the forwarded SSO identity, and makes the app refuse anything with neither identity nor key. |
| `MAILSNIFF_API_KEY` | Needed for machine clients, and required if `/api/` is opened at the proxy. |
| `ALLOWED_ORIGINS` | Your tool's origin, so any site's browser code cannot call it. Defaults to `*`. |

Two behaviours worth knowing as an API consumer:

1. **Speed.** 15 to 60 seconds per domain, 5 in parallel, up to 10 domains per
   synchronous call. Set a client timeout of at least 120s. `GET /api/v1/health`
   reports the live figures under `config`; `small_host: false` confirms it is
   not throttling itself.
2. **Jobs live in memory.** A restart or redeploy discards job IDs, so a
   `/api/job/{id}` poll can 404 mid-batch. For long lists either chunk into
   synchronous calls of 10, or be ready to retry.

## Examples

curl:

```bash
curl "https://mail-sniff.apps.iv1.in/api/v1/find?domain=invideo.io"
```

```bash
curl -X POST https://mail-sniff.apps.iv1.in/api/v1/find \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-key' \
  -d '{"domains":["invideo.io","ahrefs.com"],"include_people":true}'
```

Python:

```python
import requests

r = requests.post(
    "https://mail-sniff.apps.iv1.in/api/v1/find",
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
const res = await fetch("https://mail-sniff.apps.iv1.in/api/v1/find", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-API-Key": "your-key" },
  body: JSON.stringify({ domains: ["invideo.io"] }),
});
const { results } = await res.json();
console.log(results[0].all_emails);
```

Large batches (over 10 domains) use the async pair:

```bash
JOB=$(curl -s -X POST https://mail-sniff.apps.iv1.in/api/find \
  -H 'Content-Type: application/json' \
  -d '{"domains":["a.com","b.com","c.com"]}' | jq -r .job_id)
curl -s "https://mail-sniff.apps.iv1.in/api/job/$JOB" | jq '{done,total,running}'
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
