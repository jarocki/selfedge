# SelfEdge — Threat Model

*Status: living document. Started during the first whole-system hardening pass.*

SelfEdge is a self-hosted, self-defending personal website that runs at the edge.
Because it is **published for others to deploy**, a flaw here becomes someone
else's incident. This document is the map we attack the system against, and the
honest statement of what SelfEdge does and does not protect.

---

## 1. Security contract (read this first)

**SelfEdge aims to protect:**

- the **integrity** of your published site (visitors get what you wrote),
- the **confidentiality** of your forensic archive (only your offline key opens it),
- your **operational secrecy** via per-deployment moving-target tripwires,
- you, the operator, from the **common footguns** (leaking a key, breaking your
  own email during a DNS change, shipping an unsafe page).

**SelfEdge does NOT claim to:**

- make you invisible or un-attackable — it is defensive telemetry and hardening,
  not an intrusion-prevention system;
- **demonstrate the absence** of compromise — no defensive tool can (an adaptive
  adversary can produce no signal by design); a clean report means "nothing
  matched," never "you are safe";
- protect a **compromised operator machine** — if your laptop is owned, so is
  everything you deploy from it;
- defend against a **malicious Cloudflare, GitHub, or npm** — those are trusted
  platforms in this model;
- provide legal, warranty, or fitness guarantees (see LICENSE / SECURITY.md).

If you need guarantees beyond this, SelfEdge is the wrong tool, and saying so is
part of the contract.

---

## 2. Assets (what an attacker wants)

| Asset | Where it lives | Impact if lost |
|---|---|---|
| Forensic private key | **offline only** (`~/.selfedge/priv.pem`, 600) | archive decryptable by attacker |
| Cloudflare deploy token | Cloudflare/GitHub secret store | attacker deploys arbitrary code to your site |
| KV-write token | GitHub secret (scoped KV-only) | attacker poisons intel/tripwire data |
| Turnstile secret / webhook URL | secret store | spam bypass / alert spoofing |
| Tripwire config (decoys, honeypot, names) | KV + gitignored `tripwire.json` | MTD defeated for that deployment |
| Published site integrity | edge (Worker + assets) | defacement, visitor compromise |
| Operator machine | your laptop | total compromise (trust root) |

---

## 3. Trust boundaries

```
 UNTRUSTED                    | SEMI-TRUSTED         | TRUSTED
 public internet ── requests ─┼─▶ Worker (edge) ─────┼─▶ KV / R2 (Cloudflare)
                              |     ▲                 |
 visitor form input ─────────┼─────┘                 |
                              |                       |
 malicious website ──rebind──┼─▶ local console ◀──────┼── operator (laptop)
                              |                       |     │
 public template repo ◀──────┼── CI (GitHub) ─deploy─┼─────┤
 (no per-deploy secrets)      |                       |     └─▶ offline key (air-gapped)
```

Every arrow crossing left-to-right is a place we assume hostile input. The
**public template repo** is a boundary too: it must never contain per-deployment
secrets or tripwires (that is the monoculture risk — see §5).

---

## 4. Adversaries

1. **Commodity scanners** — high volume, low skill. Handled by tiered
   classification + decoys; mostly noise.
2. **Targeted attacker** — the reason this exists. Reads the *public* framework,
   then targets a *specific* deployment. Defeated only if per-deployment state
   (tripwires, secrets) is genuinely private. Drives the MTD design.
3. **Supply-chain attacker** — poisons a dependency, a GitHub Action, or wrangler.
   Mitigated by a tiny dependency tree (§5-A), SHA-pinned actions, and a
   dependency-free edge runtime.
4. **Malicious contributor** — once public, submits a poisoned PR. Mitigated by
   review, CI secret-scanning, and PR code never touching deploy secrets.
5. **The operator as accidental adversary** — the non-expert who misconfigures.
   Mitigated by `doctor`, preflight gates, and safe-by-default choices. This is
   the *most likely* threat for most deployments.

---

## 5. Per-component analysis

### A. Supply chain  ✓ strong
- **Footprint:** 8 total packages; `markdown-it` (+6 deps) and `smol-toml` (0 deps).
  0 known vulnerabilities.
- **Blast radius contained:** neither dependency ships to the edge. `markdown-it`
  runs only in the local console; `smol-toml` only in CLI tooling. **The deployed
  Worker has zero third-party dependencies.** A markdown-it compromise could at
  worst poison locally-published HTML — which the verify gate then catches.
- *Residual:* a poisoned `markdown-it` on the operator machine. Mitigation:
  lockfile + pinned versions + the independent verify gate.

### B. Publish pipeline (console → HTML)  ✓ strong
- Two independent layers: **constructive** (markdown-it `html:false` escapes all
  raw HTML) and a **verify gate** that inspects *tag markup only* and refuses
  script elements, inline handlers, and script-URLs. 12/12 XSS vectors neutralized.
- The gate inspects markup not text, so writing *about* XSS (`onerror=`,
  `javascript:`) publishes fine while real unescaped tags are blocked.
- *Residual:* a markdown-it parser bug that emits active content the gate's
  pattern list doesn't name. Mitigation: conservative gate, tiny surface, tests.

### C. Local console  ✓ hardened this pass
- 127.0.0.1 bind + per-run token on every route; page names regex-validated
  (path traversal → 400); console pages run under strict CSP with **no inline JS**.
- **[F1, fixed]** Host-header validation added → DNS-rebinding returns 403.
- Preview frames: server-rendered by the publish pipeline, served with
  `script-src 'none'` + `sandbox=""`. What you preview is what publishes.
- *Residual:* the per-run token appears once in the startup URL; ephemeral and
  local-only. Acceptable.

### D. MTD engine (`spin`)  ✓ strong
- Randomizes only within equal-strength equivalence pools; security-critical
  headers (CSP/HSTS/nosniff/frame-options) are FIXED and always present.
- Seed = 32 crypto-random bytes; HMAC-SHA256 stream; `shuffle_id` is a one-way
  hash (seed not recoverable). **[fixed earlier]** weak/short seeds rejected.
- *The engine is itself a control:* a bug here weakens every deployment. Hence
  property-based tests (determinism, fixed-headers, freeze, distribution).

### E. Config / secret model  ✓ strong
- Three-way split: human config (committable, names only) / referenced secrets
  (platform store) / generated tripwire (gitignored, per-deployment).
- **[F2, fixed]** wizard `.gitignore` now covers `*.pem *.key .env *.env r2.env
  .selfedge/ tripwire.json`.
- **[F3, open]** secret *names* stored as config values (`"TURNSTILE_SECRET"`)
  can trip secret scanners. **Action:** ship a `.gitleaksignore`.

### F. Edge Worker  ⚠ not yet built for SelfEdge
- **[F4, open]** The tripwire *generator* exists; the de-identified *consumer*
  (Worker reading tripwire.json from KV, tiered classification, contact form,
  envelope encryption to R2) is not yet built. **Action:** build + threat-model
  as its own pass. Until then, the edge request-handling surface is UNREVIEWED
  for SelfEdge and must not be considered done.

### G. CI/CD deploy path  ⚠ inherit-from-jarocki, needs template hardening
- The model (least-priv `GITHUB_TOKEN`, tag-gated deploy, SHA-pinned actions,
  gitleaks, no deploy secret in PR context) is proven in jarocki-edge.
- **Action:** the published template must ship this CI *pre-hardened by default*
  so users inherit the posture without knowing to ask.

### H. `golive` DNS cutover  ⚠ design-only
- The one irreversible operation. Design: refuse to proceed unless MX/SPF are
  verified intact (mail-safety gate already in `doctor`), with a documented
  rollback. **Action:** build `golive` with the gate wired as a hard stop.

---

## 6. Findings log

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| F1 | Medium | Console lacked Host-header check (DNS-rebinding) | **Fixed** |
| F2 | Low | Wizard `.gitignore` didn't cover `.env`/cred files | **Fixed** |
| F3 | Low | Secret-name-as-value trips secret scanners | Open → `.gitleaksignore` |
| F4 | — (scope) | SelfEdge edge Worker not built/reviewed | **Built + adversarial pass done** |
| F5 | — (scope) | Template CI not yet hardened-by-default | Open |
| F6 | — (scope) | `golive` cutover not built | Open |

### Worker adversarial pass (F4)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| A1 | **Medium** | Contact body size-gate bypassable via absent/chunked Content-Length → oversized body parsed | **Fixed** (require finite CL ≤ 64KB pre-parse; demonstrated bypass, then closed) |
| A2 | Low | Alert text could carry newlines / `@everyone` into the webhook | **Fixed** (sanitize in `alert()`: collapse newlines, defang mentions, cap length) |
| A3 | Low | tier-2 forensic sealing is a linear RSA+R2 amplifier under a probe flood | Accepted — linear (not exponential), fronted by Cloudflare DDoS + per-request CPU limits; revisit with sampling if abuse is observed |
| A4 | Low | Probe classifier ran regex on unbounded path | **Fixed** (bound path to 512 chars; split the `.*` alternation) |
| A5 | Low | 8-hex message/record id risked collision-overwrite | **Fixed** (widened to 12 hex / 48 bits) |

Proven during the pass: envelope-encryption round-trip + tamper detection; classification tiers; fixed-headers fail-safe (posture holds with empty config); decoy hits return an undisclosed 404 while alerting + sealing; Stream A carries no IP; R2 records are opaque ciphertext.

Residual (needs live Cloudflare to exercise): Turnstile verify call, real KV/R2/Analytics bindings, `request.cf` population.

---

## 7. Residual risks the operator owns

- **Your machine is the trust root.** SelfEdge cannot protect a compromised laptop.
- **Your private key is irreplaceable.** Lose it → the archive is lost forever
  (by design). Back it up offline.
- **"No alert" is not "no intrusion."** Calibrated confidence, always.
- **You choose your captcha/DoS posture at setup;** SelfEdge doesn't absorb a
  determined DDoS (that's Cloudflare's layer, on your plan).

---

## 8. What this project is — and isn't

SelfEdge is an effort to **help people who choose to secure and monitor their
own website**. It is a set of tools, defaults, and documentation offered freely
and in good faith — nothing more. Using it creates no relationship, duty, or
guarantee between you and the authors.

**The security of any site you build with SelfEdge is entirely your own
responsibility.** The authors do not run, audit, monitor, or vouch for your
deployment, and — consistent with the LICENSE — provide the software "as is,"
with no warranty of any kind and no liability for any outcome of its use. If it
misses an attack, fails, or is misconfigured, that risk is yours alone. Deploy
it only if you accept that.

What the authors *try* to do — because it makes the tool genuinely useful, not
because anything is owed — is choose safe defaults, make the dangerous steps hard
to get wrong, keep the dependency surface small, provide a private way to report
issues (`SECURITY.md`), and be honest about limits (§1). These are aspirations,
not promises, and they create no obligation.

We also hold ourselves to one internal rule — for the quality of the work, not
as any assurance to you: a component is not offered to users until it has had its
own adversarial pass, and absence of a review is treated as presence of risk.
Where that work is unfinished, §6 says so plainly. None of this shifts any
responsibility for a live site onto the authors; it stays with the operator.
