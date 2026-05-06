# Security Policy

Agent Warden is a security product. We take vulnerability reports seriously
and aim to acknowledge every report within 72 hours.

## Reporting a vulnerability

Email **vanteguardlabs@gmail.com** with:

- A description of the issue and the impact you observed.
- Steps to reproduce. A minimal proof-of-concept is appreciated but not
  required if the issue is structural.
- Affected repository, commit hash, and (if applicable) deployment surface
  (proxy mTLS, brain inspection, policy engine, ledger, HIL, identity).
- Whether you would like public credit in the disclosure announcement.

PGP/GPG: not yet available. If you need an encrypted channel, mention it
in your initial email and we will arrange one.

## Scope

In scope:

- All 17 repositories under `github.com/vanteguardlabs/warden-*`.
- The shipped binaries, container images, helm chart, and SBOMs published
  under those repositories' GitHub releases.
- The hash chain integrity properties documented in
  `warden-specs/README.md` and `warden-ledger/README.md`.
- The cross-service wire contracts documented in `CLAUDE.md` (proxy →
  brain / policy / hil / identity, identity → ledger via NATS).

Out of scope:

- Issues in third-party dependencies that are already disclosed in
  `RUSTSEC` and tracked in the repo's `deny.toml` ignore list with a
  documented reason. Re-reporting these is welcome but not novel.
- Self-XSS and clickjacking on the marketing site at
  `vanteguardlabs.com` unless they enable account compromise.
- Denial-of-service findings that require resource limits already
  defaulted by the deployment guide.
- Findings against demo / simulator components (`warden-simulator`,
  `warden-chaos-monkey`) when run outside a production deployment —
  these tools intentionally expose unauthenticated admin surfaces on
  loopback only.

## Safe harbor

We will not pursue civil or criminal action against researchers who:

- Make a good-faith effort to avoid privacy violations, destruction of
  data, and interruption or degradation of our services.
- Only interact with accounts they own or with explicit permission of
  the account holder.
- Give us reasonable time to respond before disclosing publicly.
- Do not exploit a security issue beyond what is necessary to confirm
  it.

## Response targets

- **72 hours**: acknowledgement of the report.
- **7 days**: triage outcome (accepted / duplicate / out-of-scope) and a
  CVE assignment plan if applicable.
- **90 days**: public disclosure, coordinated with the reporter.

We may extend the disclosure window for complex issues that require a
coordinated multi-repo fix; we will tell you in advance and explain why.
