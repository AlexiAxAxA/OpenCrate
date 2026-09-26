# Contributing

Use English for issues, pull requests and new public documentation. Describe the
problem, the changed behavior and the tests that demonstrate it.

Run `cargo test --locked --workspace` and
`cargo clippy --locked --workspace --all-targets -- -D warnings`.
Run the pure-library gate from CI for changes to library code or dependencies.

Do not update frozen vectors merely to make a failing test pass. A format change
requires a documented compatibility decision. Add dependencies deliberately and
review their licenses, advisories and effect on the no-I/O boundary.

Contribute only code you have the right to license under MPL-2.0.
Explain the reason for a check or constraint in a short comment; keep change
history in commits or design documents. Keep safety contracts and wire formulas
close to the code they constrain.

Formatting is not a repository-wide gate yet: inherited source has existing
formatting differences. Keep edits focused; do not mix bulk reformatting with
security or compatibility changes.
