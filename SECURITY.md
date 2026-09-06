# Security Policy

## ⚠️ Pre-release status

SelfEdge **0.5.x is pre-release software with known, documented security gaps**
(see `README.md` → "Known security gaps" and `docs/THREAT-MODEL.md` §6). It has
not been validated against a live Cloudflare account. Do not rely on it as your
sole defense. There is **no security-support guarantee** for pre-release versions.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.5.x (pre-release) | Best-effort only; no guarantee |
| < 0.5   | No |

Security support begins at **1.0.0**.

## Reporting a vulnerability

Please report privately — **do not open a public issue** for a security bug.

- Preferred: GitHub → this repo → **Security** tab → **Report a vulnerability**
  (private advisory).
- Or contact the maintainer directly (see the repository owner's profile).

Please include: affected component, version/commit, reproduction steps, and
impact. We aim to acknowledge within a few days. Coordinated disclosure is
appreciated; we'll agree a timeline with you before any public write-up.

## Scope

**In scope:** the SelfEdge code in this repository — the edge Worker, the CLI
(`init`/`doctor`/`spin`), the console editor and its render/verify pipeline, the
moving-target engine, and the theme contract.

**Out of scope (by threat model):** a compromised operator machine; malicious
behavior by the underlying platforms (Cloudflare, GitHub, npm); and issues in
third-party dependencies (report those upstream, though we want to hear about
them). See `docs/THREAT-MODEL.md` §1 for the full contract.

## Known-open findings (transparency)

We publish what we know is unfinished rather than hide it:

- No live-account validation yet (Turnstile, KV/R2/Analytics, `request.cf`).
- `deploy` / `secret` / `golive` not yet implemented as guided commands.
- No hardened-by-default CI template shipped yet.
- No shipped offline tool to decrypt/query the forensic archive yet.
- `intel_sync` is a flag; the enrichment pipeline is not included.

Each is tracked toward 1.0.0. Reporting *new* issues beyond these is very welcome.
