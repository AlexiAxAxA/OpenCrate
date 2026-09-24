# Open Crate Rust core

`opencrate` is the one-dependency entry point for the Open Crate core.
It re-exports the five independent libraries under `crypto`, `engine`,
`format`, `policy`, and `protocol`. You may depend on an individual
`oc-*` package instead when you need only that part.

```toml
[dependencies]
opencrate = "=0.0.2"
```

For the bytes of a file of any extension, JSON, or messages, enable the
optional native-host SDK bridge:

```toml
[dependencies]
opencrate = { version = "=0.0.2", features = ["app-data"] }
```

`opencrate::app_data` re-exports [`opencrate-sdk`](https://crates.io/crates/opencrate-sdk).
It seals at most 16 MiB for one recipient into an `OCSB1` envelope. The app
protects the secret key, authenticates the public key, and stores the envelope.
`OCSB1` is not a `.cc` container and provides no lease, policy enforcement or
revocation. The default core stays independent of OS randomness and keeps its
WASM build; `app-data` requires Rust 1.96 and a host OS random source.

This is a pre-release library core, not the Close Crate viewer or server.
The [Open Crate Community License](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE-OPENCRATE) applies.
See the [repository](https://github.com/AlexiAxAxA/OpenCrate) for the
format specification, usage examples, and security policy.
