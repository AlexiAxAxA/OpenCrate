# Security

Open Crate is pre-release security-sensitive software. Automated tests and
known-answer vectors are evidence for specific properties, not an independent
audit, certification or a guarantee that an integration is secure.

## Reporting a vulnerability

Use **Security → Report a vulnerability** on the GitHub repository when private
vulnerability reporting is enabled. Do not post exploit details, private keys,
real documents or user data in public issues. There is no promised response SLA
or bug bounty at this stage.

Release prerequisite: maintainers must enable and test private reporting before
announcing the repository. A working private contact fallback has not yet been
verified for this release candidate.

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
