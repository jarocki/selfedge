/**
 * tripwire.ts — load the per-deployment moving-target config from KV.
 *
 * `selfedge spin` writes tripwire.json; a deploy pushes it to KV under key
 * "tripwire". The Worker reads it here, cached 60s per isolate so a reshuffle
 * propagates within a minute without a redeploy. On miss/error we return an
 * EMPTY config — which is safe, because securityHeaders()/classify() always
 * apply the fixed strong headers and only lose the (optional) decoy layer.
 */
import type { Tripwire } from "./classify";

let cache: { at: number; data: Tripwire } | null = null;
const TTL_MS = 60_000;

export async function getTripwire(env: { TRIPWIRE_KV?: KVNamespace }): Promise<Tripwire> {
  const now = Date.now();
  if (cache && now - cache.at < TTL_MS) return cache.data;
  try {
    if (env.TRIPWIRE_KV) {
      const t = await env.TRIPWIRE_KV.get<Tripwire>("tripwire", "json");
      if (t && typeof t === "object") { cache = { at: now, data: t }; return t; }
    }
  } catch {
    // KV unavailable — fall through to the empty (fail-safe) config.
  }
  cache = { at: now, data: {} };
  return cache.data;
}
