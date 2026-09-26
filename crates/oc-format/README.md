# oc-format

Container layout, parsing and authenticated header verification.

[Documentation](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/index.md) · [Format specification](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/format.md) · [Source](https://github.com/AlexiAxAxA/OpenCrate/blob/main/crates/oc-format/src/lib.rs)

Use this crate when your application reads or assembles `.cc` container
structures. It owns TLV layout, structural bounds and the checks that must happen
inside parsing before authenticated structures can leave the crate.

## Run the example

From the repository root:

```sh
cargo run --locked -p oc-format --example verify-header -- tests/golden/basic.cc
```

The example verifies a fixture's header and reports an unknown author. Supply
your application's author trust policy before treating an authenticated header
as trusted. The [walkthrough](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/getting-started.md) includes a rejection
control and expected output.

The crate receives bytes; the host owns file access, input-size limits and the
recipient workflow. Generate the API reference with `cargo doc -p oc-format --no-deps`.

## License

Licensed under [MPL-2.0](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE).
