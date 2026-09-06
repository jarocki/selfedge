# SelfEdge

**A self-hosted, self-defending personal website that runs at the edge.**

SelfEdge turns a simple personal site into one that is instrumented to notice
when it's being probed — decoy tripwires, encrypted forensics, moving-target
defense — while staying easy for a non-expert to stand up. You own the code,
the keys, and the data end to end. It is *not* a hosted service.

The name is the pre-1900 root of *selvedge*: the self-finished **edge** of woven
cloth that keeps the fabric from unravelling. Also: **self**-hosted,
**self**-owned, **self**-defending, on the **edge**.

---

## ⚠️ THIS IS PRE-RELEASE SOFTWARE (v0.5.0) — READ THIS FIRST

**Do not run this as your only defense, and do not treat it as production-ready.**
This is an early, incomplete release published for review and testing. It has
**known security gaps that are deliberately not yet closed** (see the table
below). It has **not been exercised end-to-end against a live Cloudflare
account**, and several advertised features are stubs.

SelfEdge is defensive telemetry and hardening — **not** an intrusion-prevention
system, and it **cannot demonstrate the absence of compromise**. A clean report
means "nothing matched," never "you are safe." See `docs/THREAT-MODEL.md` §1 for
the full security contract, and `SECURITY.md` for how to report issues.

### Known security gaps (to be addressed before 1.0.0)

| Area | Status in 0.5.0 | Before 1.0.0 |
|---|---|---|
| **Live validation** | Core logic unit/integration-tested; **never run against real Cloudflare** (Turnstile call, KV/R2/Analytics bindings, `request.cf`) | Full live-account validation |
| **`deploy` / `secret` CLI** | Stubs — use `wrangler` directly | First-class commands |
| **`golive` (DNS cutover)** | **Not built.** The one irreversible step has no guided, mail-gated flow yet | Mail-safety-gated cutover with rollback |
| **Hardened CI template** | Not included | SHA-pinned, least-privilege, tag-gated deploy shipped by default |
| **Offline forensic reader** | The Worker *writes* encrypted records; **no shipped tool to decrypt/query them yet** | A decrypt + query tool |
| **Daily threat-intel sync** | `intel_sync` is a flag only; pipeline **not included** | De-identified KEV/CVE enrichment pipeline |
| **Secret-scanner false positives** | ✅ Closed — `.gitleaks.toml` allowlists secret-name references | — |
| **Console DNS-rebinding** | ✅ Closed — Host-header validation | — |
| **Contact size-gate bypass** | ✅ Closed — Content-Length enforced pre-parse | — |

Full findings log with severities: `docs/THREAT-MODEL.md` §6.

---

## What works today

- **Config substrate** — one declarative `selfedge.toml`; secrets by name only.
- **Setup wizard + `doctor`** — plain-language, resumable, reversible; diagnoses
  problems (including a **mail-safety check before any DNS change**) in words a
  non-expert can act on.
- **Moving-target engine (`spin`)** — regenerates per-deployment tripwires
  (decoys, honeypot field, cookie/CSRF names, header set/order) from a random
  seed, choosing only among equal-strength options; the security-critical
  headers are fixed and always present. Property-tested.
- **Themes** — four simple, pure-CSS themes; a validator enforces that a theme
  contains only variables (no scripts, no external fetches, can't hide the
  honeypot). System fonts only — zero external requests.
- **Console editor** — local, token-gated, markdown-first. Publishing runs a
  render-then-verify pipeline (12/12 XSS vectors neutralized) so nothing that
  violates the site's strict CSP can ship.
- **Edge Worker** — tiers each request from the tripwires, serves a believable
  404 for decoy hits, splits telemetry (aggregate Analytics with no IP; full
  records **envelope-encrypted** to R2 that only your offline key can read), and
  rings a content-free doorbell on canary hits. Adversarially reviewed.

Total third-party dependencies: **two** (`markdown-it`, `smol-toml`). The
deployed edge Worker has **zero** third-party dependencies.

---

## Quick start (for evaluation)

> Requires Node 18+, a Cloudflare account, and (to go live) a domain. Because
> 0.5.0 has not been run against a live account, treat this as a dry run.

```bash
npm install
npx selfedge init          # plain-language setup wizard (reversible)
npx selfedge doctor        # confirm your setup is healthy
npx selfedge spin          # generate your unique tripwires
npx selfedge console       # open the local editor
# deploy: for now, use wrangler directly (see Known gaps)
npx wrangler deploy
```

Run the safety tests:

```bash
node console/test-render.mjs   # XSS / publish-safety regression suite
```

---

## Security model (short version)

- Your **private key never leaves your machine**; the edge can seal forensic
  records but never read them.
- **Per-deployment tripwires** live in your KV store and a gitignored
  `tripwire.json` — never in this public template. Reading the source tells an
  attacker nothing about any specific site (no monoculture).
- **Secrets are referenced by name**, set in your platform's store, never in the
  repo.
- **Your machine is the trust root.** SelfEdge cannot protect a compromised
  laptop, and does not defend against a malicious Cloudflare/GitHub/npm.

Read `docs/THREAT-MODEL.md` before deploying anywhere real.

---

## License

MIT, **with no warranty** (see `LICENSE`). Publishing security tooling does not
make its authors responsible for your deployment. You are.
