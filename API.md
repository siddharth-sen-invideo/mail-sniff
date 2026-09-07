# Mail Sniff REST API

Interactive docs: **`/docs`** · schema: **`/openapi.json`**

## Base URL

Use your deployed service, which runs whether or not your laptop is on:

```
https://mail-sniff.onrender.com
```

Find it in the Render dashboard: click the service, the URL sits at the top.
`http://localhost:8100` is only for local development. Every example below works
against either; swap the host.

Confirm the live one is up and serving this API:

```bash
curl https://mail-sniff.onrender.com/api/v1/health
```

Expect `{"ok":true,"dns":true,"auth_required":false,"sync_max_domains":10}`. A
404 means the deploy has not picked up the API yet, and `auth_required:false` on
a public host means anyone can call it, so set a key (below).

## Endpoints

| Method | Path | Use |
|---|---|---|
| `GET` | `/api/v1/find?domain=invideo.io` | One domain, blocking |
| `POST` | `/api/v1/find` | Up to 10 domains, blocking, input order kept |
| `GET` | `/api/v1/verify?email=a@b.com` | Check one address |
| `POST` | `/api/v1/verify` | Same, JSON body |
| `GET` | `/api/v1/health` | Liveness, and whether a key is required |
| `POST` | `/api/find` + `GET` `/api/job/{id}` | Async, for large batches |

### How long a call takes

Measured on the live free-tier instance: **40 to 155 seconds per domain**, two in
parallel. On a laptop it is 15 to 60 seconds with five in parallel.

That has a practical consequence: **use the synchronous endpoint for 1 to 3
domains, and the async job endpoints for anything larger.** A synchronous call
with five domains on the free tier runs past ten minutes and most HTTP clients
give up. `GET /api/v1/health` reports the live `sync_max_domains`.

## Response

```json
{
  "count": 1,
  "results": [{
    "domain": "growthlens.co",
    "emails": [
      {"email": "pat@growthlens.co", "source": "contact page",
       "confidence": "high", "role": null}
    ],
    "people": [
      {"name": "Andrey Zhuravlev", "title": "Co-Founder",
       "email": "andrey@growthlens.co", "sourcing": "likely",
       "evidence": "guessed from this domain's first pattern"}
    ],
    "all_emails": ["pat@growthlens.co", "andrey@growthlens.co"],
    "linkedin": "https://www.linkedin.com/in/and-9037a129",
    "confidence": "high",
    "note": null
  }],
  "result": { "...same as results[0], for single-domain calls..." }
}
```

`all_emails` is a flat, de-duplicated list if you just want addresses.

### Trust the `sourcing` field

`emails[]` is always **scraped from the site**. `people[]` may contain generated
addresses, so check `sourcing` before you send anything:

| `sourcing` | Meaning | Safe to send? |
|---|---|---|
| `scraped` | Found verbatim on the site | Yes |
| `verified` | Generated, then proven by public search or a Gravatar account | Yes |
| `likely` | Generated from the domain's own pattern, MX valid | Probably |
| `guess` | Generated, unverified | Verify first |

When nothing is found, `note` says why: `no email published on the site`,
`blocked by a bot challenge (needs a real browser)`, `site unreachable`, or
`timed out`.

## Auth

Open by default, which is fine on localhost and **not** fine on a public host.
Set `MAILSNIFF_API_KEY` to require a key, then send either header:

```
X-API-Key: your-key
Authorization: Bearer your-key
```

On Render: Environment, add `MAILSNIFF_API_KEY`. Restrict browser callers with
`ALLOWED_ORIGINS=https://yourapp.com` (defaults to `*`).

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
