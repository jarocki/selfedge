/**
 * classify.ts — tiering + header emission. Pure functions, no I/O, easy to test.
 *
 * classify(): decides a request's tier and reason from the current tripwires.
 *   tier 3 = canary hit (decoy path / tokened asset / honeypot) — highest signal
 *   tier 2 = suspicious (probing a path that 404s, sensitive-looking request)
 *   tier 1 = normal
 *
 * securityHeaders(): the four FIXED strong headers are ALWAYS emitted (even with
 * no tripwire config), and the shuffled optional headers are layered on top.
 * Security posture never depends on the moving-target layer being present.
 */
export interface Tripwire {
  decoy_paths?: string[];
  honeypot_field?: string;
  canary_asset_paths?: string[];
  cookie_names?: { session?: string; csrf?: string };
  csrf?: { pattern?: string; field?: string; header?: string };
  headers?: { fixed?: Record<string, string>; optional?: Record<string, string>; order?: string[] };
}

export interface Verdict { tier: 1 | 2 | 3; reason: string; }

// FIXED strong headers — identical to what `spin` records; kept here so the
// Worker applies them even before any tripwire config exists (fail-safe).
export const FIXED_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const norm = (p: string) => (p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p).toLowerCase();

export function classify(pathname: string, assetExists: boolean, tw: Tripwire): Verdict {
  const p = norm(pathname);
  const decoys = (tw.decoy_paths || []).map(norm);
  const canaries = (tw.canary_asset_paths || []).map(norm);

  if (canaries.includes(p)) return { tier: 3, reason: "tokened_asset" };
  if (decoys.includes(p)) return { tier: 3, reason: "decoy_path" };

  // A request for something that doesn't exist and looks like probing.
  if (!assetExists) {
    const pp = p.slice(0, 512); // bound input before regex work
    if (/\.(php|asp|aspx|jsp|env|git|sql|bak|zip|ini|yml|yaml)$/i.test(pp) ||
        /\b(admin|login|wp-|phpmyadmin|actuator|console|shell)\b/i.test(pp) ||
        /\.well-known\/.*\.php$/i.test(pp)) {
      return { tier: 2, reason: "probe" };
    }
    return { tier: 1, reason: "not_found" };
  }
  return { tier: 1, reason: "normal" };
}

/** Detect an incoming honeypot hit given the current field name. */
export function honeypotTripped(form: { get(k: string): unknown }, tw: Tripwire): boolean {
  const field = tw.honeypot_field;
  if (!field) return false;
  const v = form.get(field);
  return typeof v === "string" && v.trim() !== "";
}

/** Build the response security headers: fixed (always) + optional (shuffled). */
export function securityHeaders(tw: Tripwire): [string, string][] {
  const fixed = tw.headers?.fixed && Object.keys(tw.headers.fixed).length ? tw.headers.fixed : FIXED_HEADERS;
  const optional = tw.headers?.optional || {};
  const all: Record<string, string> = { ...fixed, ...optional };
  const order = tw.headers?.order && tw.headers.order.length ? tw.headers.order : Object.keys(all);
  const out: [string, string][] = [];
  const seen = new Set<string>();
  for (const name of order) {
    if (all[name] !== undefined && !seen.has(name)) { out.push([name, all[name]]); seen.add(name); }
  }
  // any header not named in `order` still gets emitted (never drop a fixed one)
  for (const [name, value] of Object.entries(all)) {
    if (!seen.has(name)) { out.push([name, value]); seen.add(name); }
  }
  return out;
}
