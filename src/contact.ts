/**
 * contact.ts — the one place the site accepts untrusted input.
 *
 * Defenses, in order: honeypot (name from the current tripwire — silent accept
 * so a bot never learns it tripped), optional Turnstile, strict size limits,
 * then envelope-encrypt the message to R2 and ring a CONTENT-FREE doorbell
 * (the alert says a message arrived and from where — never the message itself,
 * which stays encrypted at rest).
 */
import { seal } from "./crypto";
import { honeypotTripped, type Tripwire } from "./classify";
import { alert } from "./alert";

const jsonRes = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });

async function verifyTurnstile(token: string, secret: string, ip?: string): Promise<boolean> {
  try {
    const body = new FormData();
    body.append("secret", secret);
    body.append("response", token);
    if (ip) body.append("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    const j = (await r.json()) as { success?: boolean };
    return j.success === true;
  } catch { return false; }
}

export async function handleContact(request: Request, env: Env, tw: Tripwire): Promise<Response> {
  const cf = (request as any).cf || {};
  const ip = request.headers.get("cf-connecting-ip") || undefined;

  let form: FormData;
  try {
    // Require a finite, in-range Content-Length. Absent/NaN/oversize is refused
    // BEFORE reading the body — closes the chunked/absent-header bypass where an
    // attacker streams an unbounded body past a header-only size check.
    const len = Number(request.headers.get("content-length"));
    if (!Number.isFinite(len) || len <= 0 || len > 64 * 1024) {
      return jsonRes({ ok: false, error: "invalid or missing content length" }, 413);
    }
    form = await request.formData();
  } catch {
    return jsonRes({ ok: false, error: "bad request" }, 400);
  }

  // Honeypot: if the hidden field is filled, a bot did it. Pretend success and
  // log a tier-3 event; tell the bot nothing.
  if (honeypotTripped(form, tw)) {
    if (env.ALERT_WEBHOOK_URL) await alert(env, `honeypot tripped from ${cf.country || "??"}`);
    return jsonRes({ ok: true });
  }

  if (env.TURNSTILE_SECRET) {
    const token = String(form.get("cf-turnstile-response") || "");
    if (!token || !(await verifyTurnstile(token, env.TURNSTILE_SECRET, ip))) {
      return jsonRes({ ok: false, error: "verification failed" }, 400);
    }
  }

  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  const record = {
    kind: "contact_message",
    ts: new Date().toISOString(),
    id,
    name: String(form.get("name") || "").slice(0, 200),
    email: String(form.get("email") || "").slice(0, 200),
    message: String(form.get("message") || "").slice(0, 8000),
    country: cf.country, asn: cf.asn, ip,
  };

  // Encrypt at rest — the Worker cannot read it back; only the offline key can.
  if (env.PUBLIC_JWK && env.FORENSIC_BUCKET) {
    try {
      const jwk = JSON.parse(env.PUBLIC_JWK);
      const sealed = await seal(jwk, JSON.stringify(record));
      const d = record.ts.slice(0, 10).replace(/-/g, "/");
      await env.FORENSIC_BUCKET.put(`messages/${d}/${id}.json`, JSON.stringify(sealed));
    } catch {
      // storage failure must not break the visitor's experience
    }
  }

  if (env.ALERT_WEBHOOK_URL) await alert(env, `new message from ${record.country || "??"}, id ${id}`);
  return jsonRes({ ok: true, id });
}
