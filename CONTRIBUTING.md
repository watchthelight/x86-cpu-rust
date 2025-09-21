# Contributing to x86-cpu-rust

Thanks for your interest in contributing! This guide outlines the workflow and standards.

## Environment

- Install Rust (stable) and tools:
  - `rustup toolchain install stable` (MSRV is 1.79)
  - `rustup component add rustfmt clippy`

## Commands

- Format: `cargo fmt --all`
- Lint: `cargo clippy --workspace --all-targets --all-features -D warnings`
- Test: `cargo test --workspace --all-features`
- Docs: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
- Audit: `cargo deny check` (install via `cargo install cargo-deny`)

## Conventional Commits

Use Conventional Commits for messages and PR titles, e.g.:

- `feat(cpu-core): add IRET ring change`
- `fix(mmu-tlb): correct A/D propagation`
- `chore(ci): add msrv job`

## Branching

- Feature branches off `main`. Prefer small, focused PRs.

## Release process (maintainers)

We use `cargo-release` to manage versions and tags across the workspace.

Dry run:

```
cargo release minor --workspace --no-publish --no-push --dry-run
```

Execute (maintainers only, with CI green):

```
cargo release minor --workspace --execute
```

This will create a tag and update CHANGELOG. Publishing to crates.io is optional and guarded.

## Code of Conduct

Please follow our CODE_OF_CONDUCT.md.

