#!/usr/bin/env node
/**
 * selfedge spin — the moving-target defense engine.
 *
 * Regenerates this deployment's tripwires — decoy paths, honeypot field, cookie
 * and CSRF token names, CSRF pattern, and response-header set/order — choosing
 * from pools where EVERY option is functionally equivalent and equally strong.
 * The result is tripwire.json, unique to your site, deployed to your edge store
 * and read by both the Worker and the log tools. Re-run anytime to reshuffle.
 *
 * Why this exists: the framework is public. Without per-deployment randomization,
 * every site would ship identical default tripwires and reading the source would
 * reveal everyone's canaries. `spin` breaks that monoculture.
 *
 * TWO HARD RULES, enforced in code below:
 *   1. EQUIVALENCE — we only ever pick among options of equal strength. Changing
 *      a cookie's NAME costs an attacker recon and costs you nothing; that's fair
 *      game. Weakening a security header is NOT, so:
 *   2. FIXED SECURITY HEADERS — CSP, HSTS, X-Content-Type-Options, X-Frame-Options
 *      have one strong value each and are ALWAYS present unchanged. Only their
 *      POSITION among headers shuffles (order is semantically free).
 *
 *   selfedge spin                 # fresh reshuffle, write tripwire.json
 *   selfedge spin --dry-run       # preview, write nothing
 *   selfedge spin --seed <hex>    # reproducible (testing); default is random
 *   selfedge spin --profile paranoid
 */
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createHmac, createHash, randomBytes } from "node:crypto";
import { parse as parseToml } from "smol-toml";

const TTY = process.stdout.isTTY;
const c = TTY ? { g: "\x1b[32m", y: "\x1b[33m", b: "\x1b[36m", d: "\x1b[2m", B: "\x1b[1m", x: "\x1b[0m" }
             : { g: "", y: "", b: "", d: "", B: "", x: "" };

// ===========================================================================
// EQUIVALENCE POOLS — every entry in a pool is interchangeable with the others
// at equal security strength. This is the security crux; edit with that in mind.
// ===========================================================================

// Fake "sensitive" paths attackers probe but legitimate visitors never request.
// All equivalent: each is pure bait, none collides with real site content.
const DECOY_PATHS = [
  "/.env", "/.env.local", "/.env.backup", "/.git/config", "/.git/HEAD",
  "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/administrator/", "/admin/",
  "/admin.php", "/phpmyadmin/", "/pma/", "/.aws/credentials", "/.ssh/id_rsa",
  "/config.json", "/config.php.bak", "/backup.zip", "/backup.sql", "/db.sql",
  "/.DS_Store", "/server-status", "/actuator/env", "/actuator/health",
  "/api/keys", "/api/v1/tokens", "/debug", "/console", "/.vscode/sftp.json",
  "/credentials.json", "/secrets.yaml", "/dump.sql", "/old/", "/test.php",
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/.npmrc", "/id_rsa",
];

// Hidden form fields a spam bot will fill but a human (CSS-hidden) never sees.
// All equivalent: any plausible-looking field name works as a honeypot.
const HONEYPOT_FIELDS = [
  "website_url", "homepage", "company_url", "url", "fax", "fax_number",
  "phone_ext", "email_confirm", "middle_name", "address_2", "referral_code", "nickname",
];

// Cookie names are just labels — equivalent by construction.
const SESSION_COOKIES = ["sid", "session", "sess", "s", "sess_id", "sc", "_s"];
const CSRF_COOKIES = ["csrf", "csrf_token", "_token", "xsrf", "ct", "_csrf", "anti_csrf"];
const CSRF_FIELDS = ["csrf", "csrf_token", "_token", "authenticity_token", "xsrf_token"];
const CSRF_HEADERS = ["X-CSRF-Token", "X-XSRF-Token", "X-CSRF", "X-Csrf-Header"];

// CSRF patterns — BOTH are stateless and edge-appropriate, hence equivalent for
// a Worker with no session store. (Synchronizer-token is deliberately EXCLUDED:
// it needs server-side state the stateless edge doesn't have — not equivalent,
// so not offered. That exclusion IS the equivalence discipline at work.)
const CSRF_PATTERNS = ["double-submit", "signed-double-submit"];

// Optional non-security headers: each is neutral-to-mildly-hardening, so varying
// their presence never weakens posture. Safe to shuffle in/out freely.
const OPTIONAL_HEADERS = {
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "X-Permitted-Cross-Domain-Policies": "none",
};

// FIXED security headers — one strong value each, ALWAYS present, never varied.
// Only their order among all headers is shuffled (order is semantically free).
const FIXED_HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const PROFILES = {
  minimal:  { decoys: 3, optional: 1 },
  standard: { decoys: 5, optional: 3 },
  paranoid: { decoys: 8, optional: 6 },
};

// ===========================================================================
// Deterministic RNG: an HMAC-SHA256 counter stream keyed by the seed.
// Same seed -> same stream -> same tripwires (reproducible for tests);
// a fresh random seed each real spin -> unpredictable reshuffle.
// ===========================================================================
class Rng {
  constructor(seed) { this.seed = seed; this.ctr = 0; this.block = Buffer.alloc(0); this.off = 0; }
  _more() {
    const ctr = Buffer.alloc(8); ctr.writeUInt32BE(this.ctr++, 4);
    this.block = createHmac("sha256", this.seed).update(ctr).digest(); this.off = 0;
  }
  _byte() { if (this.off >= this.block.length) this._more(); return this.block[this.off++]; }
  _u32() { let x = 0; for (let i = 0; i < 4; i++) x = (x * 256 + this._byte()) >>> 0; return x >>> 0; }
  int(n) { // uniform in [0,n) via rejection sampling (no modulo bias)
    if (n <= 1) return 0;
    const limit = Math.floor(0x100000000 / n) * n;
    let x; do { x = this._u32(); } while (x >= limit);
    return x % n;
  }
  pick(a) { return a[this.int(a.length)]; }
  shuffle(a) { const r = [...a]; for (let i = r.length - 1; i > 0; i--) { const j = this.int(i + 1); [r[i], r[j]] = [r[j], r[i]]; } return r; }
  sample(a, k) { return this.shuffle(a).slice(0, Math.min(k, a.length)); }
}

// ===========================================================================
// The generator — a pure function of (seed, profile, freeze).
// ===========================================================================
export function generate(seedHex, profileName, freeze = []) {
  const profile = PROFILES[profileName] || PROFILES.standard;
  const seed = Buffer.from(seedHex, "hex");
  const rng = new Rng(seed);
  const frozen = [...new Set(freeze.filter(Boolean))];

  // Decoys: sample fresh each spin, never colliding with frozen (durable) paths.
  const decoyPool = DECOY_PATHS.filter((p) => !frozen.includes(p));
  const decoy_paths = rng.sample(decoyPool, profile.decoys).sort();

  const honeypot_field = rng.pick(HONEYPOT_FIELDS);
  const cookie_names = { session: rng.pick(SESSION_COOKIES), csrf: rng.pick(CSRF_COOKIES) };
  const csrf = { pattern: rng.pick(CSRF_PATTERNS), field: rng.pick(CSRF_FIELDS), header: rng.pick(CSRF_HEADERS) };

  const optionalNames = rng.sample(Object.keys(OPTIONAL_HEADERS), profile.optional);
  const optional = Object.fromEntries(optionalNames.map((k) => [k, OPTIONAL_HEADERS[k]]));

  // Order shuffles across ALL headers (fixed + optional); values never change.
  const order = rng.shuffle([...Object.keys(FIXED_HEADERS), ...optionalNames]);

  const shuffle_id = "sf_" + createHash("sha256").update(seed).digest("hex").slice(0, 8);

  return {
    schema: 1,
    shuffle_id,
    generated: new Date().toISOString(),
    profile: profileName,
    decoy_paths,
    honeypot_field,
    canary_asset_paths: frozen,   // durable, distributed canaries — preserved
    cookie_names,
    csrf,
    headers: { fixed: FIXED_HEADERS, optional, order },
    frozen,
  };
}

// ===========================================================================
// CLI
// ===========================================================================
function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[i + 1] : (i >= 0 ? true : fallback);
}

async function loadConfig() {
  try { return parseToml(await readFile("selfedge.toml", "utf8")); } catch { return null; }
}

async function main() {
  const dry = process.argv.includes("--dry-run");
  const cfg = await loadConfig();
  const profile = arg("profile") || (cfg && cfg.moving_target && cfg.moving_target.profile) || "standard";
  const freeze = (cfg && cfg.moving_target && cfg.moving_target.freeze) || [];
  const seedHex = arg("seed") || randomBytes(32).toString("hex");
  if (typeof seedHex !== "string" || !/^[0-9a-f]+$/i.test(seedHex) || seedHex.length % 2 !== 0 || seedHex.length < 32) {
    console.error(`${c.y}--seed must be an even-length hex string of at least 32 characters (16 bytes).${c.x}`);
    process.exit(1);
  }

  const first = !existsSync("tripwire.json");
  const t = generate(seedHex, profile, freeze);

  console.log(`\n${c.B}${first ? "Generating" : "Reshuffling"} your tripwires${c.x} ${c.d}(profile: ${t.profile}, id ${t.shuffle_id})${c.x}\n`);
  console.log(`  decoy paths (${t.decoy_paths.length}):  ${c.d}${t.decoy_paths.join("  ")}${c.x}`);
  console.log(`  honeypot field:      ${c.d}${t.honeypot_field}${c.x}`);
  console.log(`  cookies:             ${c.d}session=${t.cookie_names.session}  csrf=${t.cookie_names.csrf}${c.x}`);
  console.log(`  csrf:                ${c.d}${t.csrf.pattern}, field=${t.csrf.field}, header=${t.csrf.header}${c.x}`);
  console.log(`  headers:             ${c.d}${Object.keys(t.headers.fixed).length} fixed + ${Object.keys(t.headers.optional).length} optional, order shuffled${c.x}`);
  if (t.frozen.length) console.log(`  ${c.b}frozen (kept):${c.x}       ${c.d}${t.frozen.join("  ")}${c.x}`);

  if (dry) { console.log(`\n  ${c.y}(dry-run — nothing written)${c.x}\n`); return; }

  await writeFile("tripwire.json", JSON.stringify(t, null, 2) + "\n");
  console.log(`\n  ${c.g}✓${c.x} wrote tripwire.json`);
  console.log(`  ${c.d}next:  selfedge deploy   (pushes the new tripwires live to your edge)${c.x}`);
  console.log(`  ${c.d}your log tools read this same file, so they stay in sync automatically.${c.x}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
