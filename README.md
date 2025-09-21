# x86-cpu-rust

Modular x86 CPU logical simulator implemented in Rust. This workspace provides:

- `cpu-core`: segmentation, privilege checks, IDT/GDT/TSS helpers, paging/TLB glue
- `mmu-tlb`: 32-bit page walker, TLB and paging flags
- `decoder`: pluggable decoder abstraction (optional iced-x86 feature)
- `runner`: CLI scaffolding for running and debugging

Status: pre-1.0. APIs may evolve. See CHANGELOG for details.

![MSRV](https://img.shields.io/badge/MSRV-1.79-blue.svg)
![License](https://img.shields.io/badge/license-MIT--0-green.svg)

## Quick Start

Install Rust (stable), then in workspace root:

```
cargo build
cargo test --workspace
```

Run the CLI:

```
cargo run -p runner -- run --help
```

Minimal example (see `crates/runner/examples/basic.rs`):

```
cargo run -p runner --example basic
```

## MSRV

Minimum Supported Rust Version (MSRV) is `1.79`. CI enforces MSRV builds.

## Features

- Protected-mode segmentation semantics (DPL/CPL/RPL checks, gates, IRET/RETF)
- 32-bit paging with PSE and TLB cache
- Instruction gate resolution helpers (call/jmp/interrupt)
- Pluggable decoding abstraction (`decoder` with optional `iced` feature)

## Safety

This crate is `#![forbid(unsafe_code)]` unless future performance requires otherwise. Current code avoids `unsafe`.

## Contribution

See CONTRIBUTING.md for development workflow, coding style, CI checks, and release process.

## License

MIT-0. See `LICENSE`.
