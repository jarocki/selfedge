/**
 * index.ts — SelfEdge edge Worker. Faces the hostile internet directly.
 *
 * Per request:
 *   1. load current tripwires (KV, cached, fail-safe empty)
 *   2. route the contact form; else serve the static asset
 *   3. classify the request (tier + reason) from the tripwires
 *   4. record telemetry OUT OF BAND (waitUntil) — never delays the response:
 *        Stream A -> Analytics Engine (low-sensitivity operational metrics)
 *        Stream B -> envelope-encrypted full record to R2 (forensics)
 *   5. tier-3 -> content-free doorbell alert
 *   6. decoy hits get a believable 404 (never reveal it was a tripwire)
 *   7. apply the (shuffled) security headers to every response
 *
 * The Worker seals but cannot read forensics, holds no long-lived secret it
 * doesn't need, and degrades safely if KV/R2/Analytics are all unavailable.
 */
import { getTripwire } from "./tripwire";
import { classify, securityHeaders, type Tripwire, type Verdict } from "./classify";
import { seal } from "./crypto";
import { handleContact } from "./contact";
import { alert } from "./alert";

export interface Env {
  ASSETS: Fetcher;
  TRIPWIRE_KV?: KVNamespace;
  FORENSIC_BUCKET?: R2Bucket;
  ANALYTICS?: AnalyticsEngineDataset;
  PUBLIC_JWK?: string;          // public key JWK as JSON (a var — not secret)
  ALERT_WEBHOOK_URL?: string;   // secret
  TURNSTILE_SECRET?: string;    // secret
  CONTACT_PATH?: string;        // default "/contact"
}

function withHeaders(res: Response, tw: Tripwire): Response {
  const out = new Response(res.body, res);
  for (const [name, value] of securityHeaders(tw)) out.headers.set(name, value);
  return out;
}

function uaFamily(ua: string): string {
  ua = ua.toLowerCase();
  if (!ua) return "none";
  if (/bot|crawl|spider|scan|curl|wget|python|go-http|libwww|http/.test(ua)) return "bot";
  if (/edg\//.test(ua)) return "edge";
  if (/chrome\//.test(ua)) return "chrome";
  if (/firefox\//.test(ua)) return "firefox";
  if (/safari\//.test(ua)) return "safari";
  return "other";
}

async function record(env: Env, request: Request, url: URL, v: Verdict): Promise<void> {
  const cf = (request as any).cf || {};
  const ua = request.headers.get("user-agent") || "";

  // Stream A — operational telemetry, no IP / no raw UA. Positional schema.
  try {
    env.ANALYTICS?.writeDataPoint({
      blobs: [url.pathname, cf.country || "", String(cf.asn || ""), uaFamily(ua), v.reason, request.method],
      doubles: [v.tier],
      indexes: [url.pathname.slice(0, 96)],
    });
  } catch { /* analytics best-effort */ }

  // Stream B — full record, envelope-encrypted, forensic. Metadata only (never
  // request bodies; contact messages are sealed separately in contact.ts).
  if (v.tier >= 2 && env.PUBLIC_JWK && env.FORENSIC_BUCKET) {
    try {
      const rec = {
        ts: new Date().toISOString(),
        tier: v.tier, reason: v.reason, method: request.method,
        path: url.pathname, query: url.search, status: 0,
        ip: request.headers.get("cf-connecting-ip"),
        asn: cf.asn, asOrganization: cf.asOrganization, country: cf.country, colo: cf.colo,
        tlsVersion: cf.tlsVersion, userAgent: ua, referer: request.headers.get("referer"),
      };
      const sealed = await seal(JSON.parse(env.PUBLIC_JWK), JSON.stringify(rec));
      const d = rec.ts.slice(0, 10).replace(/-/g, "/");
      await env.FORENSIC_BUCKET.put(`raw/${d}/${rec.ts}-${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}.json`, JSON.stringify(sealed));
    } catch { /* forensic storage best-effort; never impacts the visitor */ }
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const tw = await getTripwire(env);

    // ---- contact form ----
    if (request.method === "POST" && url.pathname === (env.CONTACT_PATH || "/contact")) {
      const res = await handleContact(request, env, tw);
      ctx.waitUntil(record(env, request, url, { tier: 2, reason: "contact" }));
      return withHeaders(res, tw);
    }

    // ---- serve static asset ----
    let asset: Response;
    try { asset = await env.ASSETS.fetch(request); }
    catch { asset = new Response("Service Unavailable", { status: 503 }); }
    const assetExists = asset.status !== 404;

    const verdict = classify(url.pathname, assetExists, tw);
    ctx.waitUntil(record(env, request, url, verdict));
    if (verdict.tier >= 3 && env.ALERT_WEBHOOK_URL) {
      const cf = (request as any).cf || {};
      ctx.waitUntil(alert(env, `tripwire: ${verdict.reason} ${url.pathname} from ${cf.country || "??"} AS${cf.asn || "?"}`));
    }

    // Decoy/canary hits get a believable 404 — never reveal it was a tripwire.
    let res = asset;
    if (verdict.reason === "decoy_path" || verdict.reason === "tokened_asset") {
      res = new Response("Not Found\n", { status: 404, headers: { "Content-Type": "text/plain" } });
    }
    return withHeaders(res, tw);
  },
};
