"""
Mail Sniff API client.

    from mailsniff import MailSniff
    ms = MailSniff()                      # https://mail-sniff.apps.iv1.in
                                          # env: MAILSNIFF_URL, MAILSNIFF_API_KEY,
                                          #      MAILSNIFF_POMERIUM_TOKEN
    print(ms.find("invideo.io"))
    print(ms.find_many(["a.com", "b.com"]))       # async job, polls to completion
    print(ms.verify("hello@invideo.io"))

Only dependency is requests. Timeouts default high on purpose: a domain takes
15-60s on the company server, and a cold container adds to the first call.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import requests

DEFAULT_URL = os.environ.get("MAILSNIFF_URL", "https://mail-sniff.apps.iv1.in").rstrip("/")

# The host sits behind Pomerium. A service-account JWT is what gets a machine
# client through the proxy without changing any route: Pomerium validates it,
# then forwards the identity to the app. Ask whoever runs pomerium.iv1.in to
# issue one, and put it in MAILSNIFF_POMERIUM_TOKEN.
DEFAULT_POMERIUM_TOKEN = os.environ.get("MAILSNIFF_POMERIUM_TOKEN")


class MailSniffError(RuntimeError):
    pass


class NotAuthenticated(MailSniffError):
    """The API refused the call, or an SSO proxy intercepted it."""


class MailSniff:
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None,
                 pomerium_token: Optional[str] = None, timeout: int = 300):
        self.base = (base_url or DEFAULT_URL).rstrip("/")
        self.key = api_key if api_key is not None else os.environ.get("MAILSNIFF_API_KEY")
        self.pomerium = (pomerium_token if pomerium_token is not None
                         else DEFAULT_POMERIUM_TOKEN)
        self.timeout = timeout
        self.s = requests.Session()
        if self.key:
            # the app's own check; kept out of Authorization, which the proxy uses
            self.s.headers["X-API-Key"] = self.key
        if self.pomerium:
            self.s.headers["Authorization"] = "Pomerium " + self.pomerium

    # ---- plumbing -------------------------------------------------------
    def _call(self, method: str, path: str, **kw) -> Any:
        url = self.base + path
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", False)   # never follow an SSO redirect
        r = self.s.request(method, url, **kw)

        if r.status_code in (301, 302, 303, 307, 308):
            hint = ("Supply a Pomerium service-account token (pomerium_token= or "
                    "MAILSNIFF_POMERIUM_TOKEN) which needs no route change, or "
                    "have /api/ allowed through the proxy. See deploy/README.md."
                    if not self.pomerium else
                    "A Pomerium token was sent but the proxy still rejected it: "
                    "it may be expired, or lack access to this route.")
            raise NotAuthenticated(
                "%s redirected to %r. This host is behind Pomerium SSO. %s"
                % (url, (r.headers.get("location") or "")[:80], hint))
        if r.status_code in (401, 403):
            raise NotAuthenticated("%s returned %s: %s"
                                   % (url, r.status_code, r.text[:200]))
        if not r.ok:
            raise MailSniffError("%s returned %s: %s" % (url, r.status_code, r.text[:300]))
        ctype = r.headers.get("content-type", "")
        if "json" not in ctype:
            raise NotAuthenticated(
                "%s returned %r instead of JSON, which usually means a login "
                "page was served in place of the API." % (url, ctype[:40]))
        return r.json()

    # ---- endpoints ------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        return self._call("GET", "/api/v1/health")

    def whoami(self) -> Dict[str, Any]:
        """Says whether the call was authorized by key, SSO or open mode."""
        return self._call("GET", "/api/v1/whoami")

    def find(self, domain: str, include_people: bool = True) -> Dict[str, Any]:
        return self._call("GET", "/api/v1/find",
                          params={"domain": domain, "include_people": include_people})["result"]

    def verify(self, email: str) -> Dict[str, Any]:
        return self._call("GET", "/api/v1/verify", params={"email": email})

    def find_many(self, domains: List[str], poll: float = 5.0,
                  max_wait: float = 3600.0) -> List[Dict[str, Any]]:
        """Batch scan via the async job endpoints, which is the right path for
        more than a couple of domains: results keep the input order."""
        if not domains:
            return []
        job = self._call("POST", "/api/find", json={"domains": list(domains)})
        job_id = job["job_id"]
        waited = 0.0
        while waited < max_wait:
            st = self._call("GET", "/api/job/%s" % job_id)
            if not st.get("running"):
                return st["results"]
            time.sleep(poll)
            waited += poll
        raise MailSniffError("job %s still running after %ss" % (job_id, max_wait))


if __name__ == "__main__":
    import json
    import sys
    ms = MailSniff()
    print("base:", ms.base, "| key:", "set" if ms.key else "none")
    try:
        print("whoami:", ms.whoami())
    except MailSniffError as e:
        print("whoami failed:", e)
    for d in sys.argv[1:]:
        print(json.dumps(ms.find(d), indent=2))
