# oc-engine

Packing plans, per-file secrets, recipient slots and header assembly.

[Documentation](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/index.md) · [Packaging guide](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/getting-started.md#packing-integration) · [Source](https://github.com/AlexiAxAxA/OpenCrate/blob/main/crates/oc-engine/src/lib.rs)

Use this crate in a document packaging pipeline. The host provides recipients,
policy and secure randomness to `plan`, streams content encryption, constructs
`SealedInfo` from the actual output, and consumes the session with
`Session::assemble`.

![Where packaging fits in a document's journey](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/assets/document-lifecycle.svg)

Keep the request consistent between planning and assembly. The application
retains responsibility for the author's signing key, signs the final header
transcript and publishes the completed file atomically.

The engine's separation from filesystem, transport and clocks makes its hosting
an application choice. It is a library, rather than a document-sharing server.
Build the reference with `cargo doc -p oc-engine --no-deps` from the repository root.

## License

Licensed under [MPL-2.0](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE).
