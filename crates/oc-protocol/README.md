# oc-protocol

Codecs and verification for signed protocol documents.

[Documentation](../../docs/index.md) · [Protocol specification](../../docs/protocol.md) · [Source](src/lib.rs)

Use this crate for the documents around a container: activation, leases,
revocation, access requests, journal evidence and related control messages.
The [protocol specification](../../docs/protocol.md) defines their representation
and the recipient's required checks.

The crate operates on supplied bytes and keys. The application provides
authenticated transport, trusted endpoints, persistent state and orchestration.
Receiving a decoded message does not establish that it belongs to the requested
file, device or policy; enforce the relevant bindings in the integration.

Container layout belongs to `oc-format`; the access decision belongs to
`oc-policy`. See the [dependency graph](../../docs/architecture.md).

From the repository root, build the reference with `cargo doc -p oc-protocol --no-deps`.
