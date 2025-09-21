# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and Conventional Commits.

## [Unreleased]
- CI: matrix across OS/toolchains, clippy, fmt, tests
- Docs: docs.rs config and README badges
- Maintenance: dependabot, audit (cargo-audit, cargo-deny)
- Governance: templates, CONTRIBUTING, CoC, SECURITY
- Build: rust-toolchain, MSRV pinned to 1.79

## 0.1.0 - Bootstrap
- Initial workspace layout and core crates (`cpu-core`, `mmu-tlb`, `decoder`, `runner`, etc.)
- Protected-mode segmentation helpers and 32-bit paging walker
- Basic tests for arithmetic flags and segmentation flows

