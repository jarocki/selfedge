# Changelog

All notable changes to SelfEdge are documented here.
This project adheres to Semantic Versioning. Pre-1.0 releases may change without
notice and carry known, documented security gaps.

## [0.5.0] - 2026-09-05 — first pre-release

**Pre-release. Not production-ready. See README "Known security gaps."**

### Added
- Config substrate: single `selfedge.toml`, secrets referenced by name only.
- Setup wizard (`init`) and diagnostic engine (`doctor`) — plain-language,
  resumable, reversible, with a mail-safety check before any DNS change.
- Moving-target engine (`spin`): seed-driven, equivalence-enforcing tripwire
  generation; security-critical headers fixed. Property-tested.
- Four pure-CSS themes + a theme-safety contract validator.
- Console editor: local, token-gated, markdown-first, render-then-verify publish
  pipeline (12/12 XSS vectors neutralized).
- Edge Worker: request tiering, believable-404 decoys, split telemetry
  (IP-free Analytics; envelope-encrypted R2 forensics), content-free alerts.
- Threat model (`docs/THREAT-MODEL.md`) and security policy (`SECURITY.md`).

### Security (fixed during hardening)
- Console DNS-rebinding (Host-header validation).
- Wizard `.gitignore` coverage for keys/env files.
- Contact-form body size-gate bypass (Content-Length enforced pre-parse).
- Webhook/alert injection (sanitized).
- Probe-classifier regex bound; message-id width widened.
- Secret-scanner false positives (`.gitleaks.toml`).

### Known gaps (tracked toward 1.0.0)
- No live-Cloudflare validation; `deploy`/`secret`/`golive` not implemented;
  no hardened CI template; no shipped forensic reader; `intel_sync` flag only.
