/**
 * Mail Sniff API client (TypeScript / JavaScript, no dependencies).
 *
 *   const ms = new MailSniff({ baseUrl: "https://mail-sniff.apps.iv1.in", apiKey: process.env.MAILSNIFF_API_KEY });
 *   await ms.find("invideo.io");
 *   await ms.findMany(["a.com", "b.com"]);   // async job, polled
 *   await ms.verify("hello@invideo.io");
 *
 * Never call this from browser code with a real key in it: the key would ship
 * to every visitor. Put it in your own backend and proxy the call.
 */

export type Sourcing = "scraped" | "verified" | "likely" | "guess";

export interface Person {
  name: string | null;
  title: string | null;
  email: string | null;
  status: Sourcing | null;
}

export interface FindResult {
  domain: string;
  emails: { email: string; label: string }[];
  people: Person[];
  all_emails: string[];
  linkedin: { url?: string; name?: string; role?: string; guess?: boolean } | null;
  confidence: "high" | "medium" | "low" | "none" | null;
  note: string | null;
}

export class NotAuthenticated extends Error {}
export class MailSniffError extends Error {}

export class MailSniff {
  private base: string;
  private apiKey?: string;
  private timeoutMs: number;

  constructor(opts: { baseUrl?: string; apiKey?: string; timeoutMs?: number } = {}) {
    this.base = (opts.baseUrl ?? "https://mail-sniff.apps.iv1.in").replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    // a domain takes 40-155s on a small instance; a cold start adds more
    this.timeoutMs = opts.timeoutMs ?? 300_000;
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = this.base + path;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers: {
          ...(this.apiKey ? { "X-API-Key": this.apiKey } : {}),
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        redirect: "manual", // never follow an SSO redirect
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
      throw new NotAuthenticated(
        `${url} redirected to a login page. This host is behind an SSO proxy, so ` +
          `it cannot be called with an API key until the /api/v1 route is allowed ` +
          `through. See deploy/pomerium-route.yaml.`,
      );
    }
    if (res.status === 401 || res.status === 403) {
      throw new NotAuthenticated(`${url} returned ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
    if (!res.ok) {
      throw new MailSniffError(`${url} returned ${res.status}: ${(await res.text()).slice(0, 300)}`);
    }
    if (!(res.headers.get("content-type") ?? "").includes("json")) {
      throw new NotAuthenticated(
        `${url} returned HTML instead of JSON, which usually means a login page was served.`,
      );
    }
    return (await res.json()) as T;
  }

  health() {
    return this.call<Record<string, unknown>>("GET", "/api/v1/health");
  }

  /** Says whether the call was authorized by key, SSO or open mode. */
  whoami() {
    return this.call<{ authorized_as: string; proxy_headers_seen: string[] }>("GET", "/api/v1/whoami");
  }

  async find(domain: string, includePeople = true): Promise<FindResult> {
    const q = new URLSearchParams({ domain, include_people: String(includePeople) });
    const r = await this.call<{ result: FindResult }>("GET", `/api/v1/find?${q}`);
    return r.result;
  }

  verify(email: string) {
    const q = new URLSearchParams({ email });
    return this.call<Record<string, unknown>>("GET", `/api/v1/verify?${q}`);
  }

  /** Batch scan through the async job endpoints. Results keep the input order. */
  async findMany(domains: string[], pollMs = 5000, maxWaitMs = 3_600_000): Promise<FindResult[]> {
    if (domains.length === 0) return [];
    const job = await this.call<{ job_id: string }>("POST", "/api/find", { domains });
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      const st = await this.call<{ running: boolean; results: FindResult[] }>(
        "GET",
        `/api/job/${job.job_id}`,
      );
      if (!st.running) return st.results;
      await new Promise((r) => setTimeout(r, pollMs));
    }
    throw new MailSniffError(`job ${job.job_id} still running after ${maxWaitMs}ms`);
  }
}
