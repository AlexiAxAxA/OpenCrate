# Architecture

Open Crate is an application library core, not an operating-system kernel.

```mermaid
flowchart TD
    App[Application: I/O, entropy, time, keys, state] --> Engine[oc-engine]
    App --> Protocol[oc-protocol]
    App --> Format[oc-format]
    App --> Policy[oc-policy]
    Engine --> Format
    Engine --> Crypto[oc-crypto]
    Engine --> Policy
    Protocol --> Format
    Protocol --> Crypto
    Protocol --> Policy
    Format --> Crypto
    Format --> Policy
```

`oc-policy` has no package dependencies. `oc-format` verifies cryptographic
authenticity inside parsers where required, so unverified data is not released
between separate parsing and authentication steps. Protocol documents depend
on the container layer; container parsers do not depend on the protocol layer.

The application supplies a cryptographically secure random generator, author
trust policy, device identity, trustworthy time, durable anti-replay state,
network transport and resource limits. The packing engine does not own the
author's signing key. The author signs the transcript of the final header.

## Format compatibility

The magic is `CLOSECR1`, the extension is `.cc`, and current containers use version
5. Domain labels use `CC/v1/`; their string version is not the container version.
Versions 1–4 are rejected. Frozen fixtures must not be regenerated to conceal a
regression. Any intentional wire change needs a version decision and matching
specification, vectors and compatibility policy.

No-I/O does not mean `no_std`. WASM compilation is a portability check, not proof
of every purity property and not a browser product. Source checks and dependency
review remain necessary. Test-only filesystem access loads committed fixtures.
