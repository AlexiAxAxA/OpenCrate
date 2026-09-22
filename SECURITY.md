# Security

Open Crate is pre-release security-sensitive software. Automated tests and
known-answer vectors are evidence for specific properties, not an independent
audit, certification or a guarantee that an integration is secure.

## Reporting a vulnerability

Report privately. Do not open a public issue, pull request or discussion for a
suspected vulnerability, and do not post exploit details, private keys, real
documents or user data anywhere public.

1. **GitHub private vulnerability reporting** (primary route): open
   **Security → Report a vulnerability** on this repository, or go directly to
   `https://github.com/AlexiAxAxA/OpenCrate/security/advisories/new`. The report
   is visible only to the maintainer and to the people you invite. This route
   becomes available the moment the repository is public; the maintainer enables
   it as part of the release procedure and confirms it with a test report before
   announcing the repository.
2. **E-mail**: `security@closecrate.com`. Use it if you have no GitHub account
   or the form is unavailable. The same address is published in
   `https://closecrate.com/.well-known/security.txt`. If both routes fail, open
   a public issue that says only "security report, contact needed" and nothing
   else; the maintainer will reach out.

Please include: the affected crate and version or commit, the property you
believe is violated (for example an invariant from the format documentation),
a minimal reproduction or proof-of-concept, and how you would like to be
credited. Reports in English or Russian are fine.

There is no bug bounty and no contractual response SLA at this stage. The
maintainer aims to acknowledge a report within five working days, agree on a
disclosure plan with the reporter, and publish a fix before or together with the
public advisory. Coordinated disclosure of up to 90 days is requested; longer
or shorter windows can be agreed when the fix needs a format decision or when
the issue is already public.

## Good-faith research

Testing against your own copies of the code, your own containers and your own
keys is welcome and is free under the license regardless of company size.
Research that accesses other people's data, degrades a service you do not own,
or uses social engineering is out of scope. The maintainer will not pursue
legal action for good-faith research that follows this policy and reports
findings privately.

## How fixes and advisories reach you

- Confirmed vulnerabilities are published as **GitHub Security Advisories** on
  this repository, with affected versions, fixed versions and credit. GitHub
  can assign a CVE identifier through the advisory when one is warranted.
- Fixes are released as tagged versions with release notes that link the
  advisory. Once the crates are published on crates.io, advisories are also
  submitted to the [RustSec advisory database](https://rustsec.org/) so that
  `cargo audit` and `cargo deny check advisories` report them to every user.
- To be notified, use **Watch → Custom → Security alerts** (and **Releases**) on
  the repository. Dependabot alerts for third-party dependencies are enabled on
  this repository; they concern the dependency tree, not Open Crate's own code.

## Scope

In scope: `oc-format`, `oc-protocol`, `oc-crypto`, `oc-policy` and `oc-engine`
as published in this repository, including the frozen vectors and the golden
headers under `tests/`.

Out of scope, or handled elsewhere:

- Deterministic fixture keys and known-answer values under `tests/`. They are
  intentionally public; using them for real data is an integration error.
- Third-party dependencies. Report those upstream; the maintainer will pick up
  the advisory through Dependabot and `cargo deny`.
- The Close Crate viewer, server, keystore and hosted service. They are separate
  products with their own reporting route on closecrate.com.
- Missing protections that the threat boundaries below explicitly leave to the
  embedding application.

## Threat boundaries

The libraries authenticate data and evaluate policy from supplied facts. The
embedding application must establish trust, protect keys, provide secure entropy,
validate time and counters, enforce obligations and supply authenticated
transport. Merely passing a value called “trusted” does not establish trust.

No protection is promised against a compromised host that already possesses
plaintext or usable keys. Revocation limits future authorized access subject to
lease and offline windows; it cannot erase extracted plaintext. Hybrid KEM slots
do not make classical signatures post-quantum. All sufficient decryption paths
must meet the required protection profile.

Malformed-input tests and deterministic fixture keys are intentionally public.
Never use fixture secrets for real data. Production integrations should not
enable test-only cryptographic features.
