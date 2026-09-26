# oc-protocol

Codecs and verification for signed protocol documents.

[Documentation](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/index.md) · [Protocol specification](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/protocol.md) · [Source](https://github.com/AlexiAxAxA/OpenCrate/blob/main/crates/oc-protocol/src/lib.rs)

Use this crate for the documents around a container: activation, leases,
revocation, access requests, journal evidence and related control messages.
The [protocol specification](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/protocol.md) defines their representation
and the recipient's required checks.

The crate operates on supplied bytes and keys. The application provides
authenticated transport, trusted endpoints, persistent state and orchestration.
Receiving a decoded message does not establish that it belongs to the requested
file, device or policy; enforce the relevant bindings in the integration.

Container layout belongs to `oc-format`; the access decision belongs to
`oc-policy`. See the [dependency graph](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/architecture.md).

From the repository root, build the reference with `cargo doc -p oc-protocol --no-deps`.

## License

Licensed under [MPL-2.0](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE).
