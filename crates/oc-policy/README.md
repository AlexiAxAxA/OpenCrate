# oc-policy

Access decisions from explicit policy and caller-supplied facts.

[Documentation](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/index.md) · [Runnable example](examples/access-policy.rs) · [Source](https://github.com/AlexiAxAxA/OpenCrate/blob/main/crates/oc-policy/src/lib.rs)

The crate has no package dependencies. Its main entry point is
`evaluate(policy, lease, action, context)`: either a denial reason or permission
with obligations. Missing permissions default to denial, and server policy can
only tighten the author's permissions.

![Three decisions from the access-policy example](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/assets/access-decisions.svg)

Run from the repository root:

```sh
cargo run --locked -p oc-policy --example access-policy
```

The [guide](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/getting-started.md) also runs this example in a separate
consumer application. The example's facts are synthetic; production facts must
come from authenticated evidence and protected application state.

The application supplies time, device state and replay counters and enforces
every returned obligation. The crate does not operate a printer, clipboard or
document window. Build its reference with `cargo doc -p oc-policy --no-deps`.

## License

Licensed under [MPL-2.0](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE).
