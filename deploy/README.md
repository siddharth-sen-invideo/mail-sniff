# Deploying Mail Sniff at mail-sniff.apps.iv1.in

The app is a single container (`Dockerfile`, listens on `$PORT`, default 8100).
It holds no database and no state beyond in-memory jobs, so it scales by
restarting. The company deployment builds from this repo's Dockerfile.

## Environment

| Variable | Set it to | Why |
|---|---|---|
| `MAILSNIFF_TRUST_PROXY_IDENTITY` | `1` | The app is behind Pomerium. This accepts the SSO identity the proxy forwards, and makes the app **refuse** any request that arrives with neither an identity nor a key. |
| `MAILSNIFF_API_KEY` | a long random string | Needed for machine clients. Required if `/api/` is ever made public at the proxy. |
| `ALLOWED_ORIGINS` | `https://mail-sniff.apps.iv1.in` | CORS. Leaving it `*` lets any site's browser code call the API. |
| `MAILSNIFF_CONCURRENCY` etc. | leave unset | The defaults suit a real CPU. See below. |

`MAILSNIFF_TRUST_PROXY_IDENTITY` treats Pomerium's `X-Pomerium-Jwt-Assertion` /
`X-Pomerium-Claim-Email` as proof of identity **without verifying the
signature**. That is safe only while the pod cannot be reached except through
Pomerium. Keep the service cluster-internal, with no second ingress and no
NodePort. If it ever becomes directly reachable, set `MAILSNIFF_API_KEY` too so a
key is still required.

## Sizing

The scraper auto-detects a constrained host and backs off. On Render's shared
CPU that meant 2 domains in flight and 26 pages each, and a domain took 40 to
155 seconds. On a real company box none of that applies: it uses 5 domains in
flight over 70 pages, and a domain takes 15 to 60 seconds. `GET
/api/v1/health` reports the live numbers under `config`, so check there rather
than guessing. Override with `MAILSNIFF_CONCURRENCY`, `MAILSNIFF_MAX_PAGES`,
`MAILSNIFF_BUDGET` if you want it to work harder.

It is CPU-bound on HTML parsing and network-bound on fetches, so give it 1 CPU
and 512Mi and it will comfortably beat the free-tier numbers above.

## The API is not reachable yet, and why

Verified 2026-09-07 against the live host: **every** app path returns `302` to
`pomerium.iv1.in`. Only `/healthz` returns 200, and that is Envoy answering, not
Mail Sniff. Sending `X-API-Key` changes nothing, because the proxy rejects the
request before the app sees it. So a browser works and an API client receives an
HTML login page instead of JSON.

Two ways to fix it. **Option 1 needs no proxy change.**

### Option 1: a Pomerium service-account token (fastest, no route change)

Whoever runs `pomerium.iv1.in` issues a service account for this route. Clients
then send it as `Authorization: Pomerium <jwt>`; Pomerium validates it and
forwards the identity to the app. Both clients in `clients/` support this:

```python
MailSniff(pomerium_token=os.environ["MAILSNIFF_POMERIUM_TOKEN"])
```

Trade-off: the token expires and has to be rotated, and it is a credential to
store wherever your tool runs.

### Option 2: let `/api/` through the proxy, key-guard it in the app

Split the route so the UI stays behind SSO and the API does not, then the app's
own `MAILSNIFF_API_KEY` is what guards it. Config in `pomerium-route.yaml`.
Trade-off: one more public surface, so the key becomes load-bearing and
`MAILSNIFF_REQUIRE_KEY=1` should be set so the app can never serve open.

## Checking it

```bash
./deploy/selfcheck.sh https://mail-sniff.apps.iv1.in
```

It says which paths are reachable, whether SSO is intercepting, and how the API
authorized the call. Run it after any proxy or env change.
