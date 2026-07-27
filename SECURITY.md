# Security Policy

<!-- clavenar-security-policy:v1 -->

**Policy version:** 1.0.0  
**Effective date:** 2026-07-27  
**Canonical contact:** **vanteguardlabs@gmail.com**

This is the canonical vulnerability-disclosure policy for every repository in
the Clavenar release graph. Do not open a public issue for a suspected
vulnerability.

## Reporting a vulnerability

Email the canonical contact with:

- a concise description of the issue and its security impact;
- reproducible steps or a minimal proof of concept;
- the affected repository, commit or immutable release digest, and surface;
- any relevant configuration needed to reproduce the result; and
- whether you want public credit.

Do not include live credentials, personal data, customer data, or unnecessary
production detail. PGP is not currently published; ask in the initial message
if a separate encrypted exchange is required.

## Supported versions

| Source or artifact | Security support |
|---|---|
| Current `main` branch | Receives source fixes and is the source for the next release. It is not, by itself, a claim that a live deployment has updated. |
| Latest immutable release published by the affected repository or stack release | Receives coordinated security fixes. |
| Older releases, mutable tags, untagged snapshots, forks, and downstream modifications | Not supported unless a repository-specific notice says otherwise. |

A repository with no published release supports its current `main` source
only. Security fixes normally land on `main` and then in a new immutable
release; we do not silently rewrite an existing release.

## Scope

In scope:

- all 30 repositories named by the canonical Clavenar stack release policy,
  including their root `SECURITY.md` files;
- source, packages, binaries, container images, Helm artifacts, SBOMs, and
  provenance that belong to an exact published Clavenar release;
- Clavenar-owned public web endpoints and release/download endpoints; and
- documented authentication, authorization, isolation, cryptographic,
  audit-chain, policy-enforcement, update, and recovery boundaries.

Private repositories are in scope for authorized reporters, but this policy
does not authorize attempts to obtain access to them.

Reports about a third-party dependency are welcome when they show a new
Clavenar-specific impact or an unsafe integration/default. A dependency issue
with no new Clavenar impact may be redirected to its upstream maintainer.

## Runtime and deployment boundary

Checked-in source, an immutable released artifact, a configured deployment,
and current externally observed state are distinct evidence states. A source
capability or fix is not a claim that every deployment is configured,
reachable, or updated.

Demo, simulator, development, evaluation, diagnostic, and administrative
surfaces are not customer-production promises. They remain in scope for
authentication, authorization, isolation, and unsafe-default defects when
used as documented. Their exposure may be loopback, container-only,
cluster-internal, or public depending on the exact release and configuration;
this policy never treats loopback placement alone as an authorization
boundary.

Operator-provided infrastructure, credentials, policies, network controls,
forks, and modifications are outside Clavenar's control. A defect in Clavenar
that makes a documented configuration unsafe remains in scope.

## Workflow and release evidence

Only automation checked into the affected repository and receipts bound to an
exact immutable release are evidence that a build, test, audit, SBOM,
provenance, signing, or publication step ran. This policy makes no additional
workflow promise. Repository workflow files and the protected stack-release
receipt are authoritative for the checks they actually execute.

The centrally enforced `clavenar.security-policy/v1` contract rejects a
missing, stale, or divergent root policy across the exact 30-repository release
graph.

## Response process

- **Within 72 hours:** acknowledge receipt and establish a private tracking
  channel.
- **Within 7 days:** provide an initial triage result, affected scope, severity
  direction, and CVE plan when applicable.
- **At least every 14 days while open:** provide a progress update or explain
  why the schedule changed.
- **Target within 90 days:** publish a coordinated fix and disclosure, or agree
  on a revised date with the reporter.

Complex multi-repository or ecosystem fixes may take longer. We will explain
material schedule changes, coordinate credit, and avoid disclosing exploit
details before a fix is reasonably available.

## Safe harbor

We will not pursue civil or criminal action against research that:

- is conducted in good faith on systems and accounts the researcher owns or
  has explicit permission to test;
- avoids privacy violations, persistence, data destruction, service
  degradation, and access beyond what is needed to demonstrate impact;
- stops and reports promptly after encountering sensitive data or unintended
  access; and
- allows reasonable time for remediation before public disclosure.

This safe harbor does not authorize testing third-party systems, social
engineering, physical attacks, denial-of-service or volume testing, credential
stuffing, spam, or violation of applicable law.

## Disclosure

We prefer coordinated disclosure. A published advisory should identify the
affected versions and immutable fixed release, credit the reporter if desired,
and distinguish verified impact from assumptions. Duplicate or already-public
issues remain welcome when the report adds a new affected path or material
impact.
