# Open Crate Rust core

`opencrate` is the one-dependency entry point for the Open Crate core.
It re-exports the five independent libraries under `crypto`, `engine`,
`format`, `policy`, and `protocol`. You may depend on an individual
`oc-*` package instead when you need only that part.

```toml
[dependencies]
opencrate = "0.0.1"
```

This is a pre-release library core, not the Close Crate viewer or server.
The [Open Crate Community License](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE-OPENCRATE) applies.
See the [repository](https://github.com/AlexiAxAxA/OpenCrate) for the
format specification, usage examples, and security policy.
