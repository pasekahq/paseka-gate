# 0001. Synchronous Rust stack, one static binary

Status: Accepted
Date: 2026-11-18

## Context
The gate is a security component that a user's agent must be able to audit on install
(ADR 0008). Audit cost grows with code size and dependency count. The sibling projects qb and
ulei already run a synchronous Rust stack with CI budgets, and their audit showed that async
runtimes and large HTTP frameworks dominate both the binary and the dependency tree.

## Decision
- Rust, edition 2024, MSRV pinned in `Cargo.toml`.
- Synchronous code only. `deny.toml` bans tokio, hyper, axum, reqwest, openssl, chrono and pyo3.
- Allowed building blocks: httparse for inbound HTTP/1.1, serde and serde_json, rustix,
  ureq with rustls (ring) for outbound HTTPS, ed25519-dalek, sha2, rusqlite with the bundled
  SQLite for storage.
- Inbound TLS is terminated by Caddy in front of the gate; the gate listens on loopback or a unix
  socket.
- One multicall binary `paseka` (`serve`, `mcp`, `init`, `conformance`, `version`), static musl.
- `unsafe` is forbidden in the core crates (`#![forbid(unsafe_code)]`).
- CI budgets: static binary size, idle RSS, zero wakeups when idle, dependency count. The numbers
  live in `ci/budgets.sh`.

## Consequences
- Concurrency is threads plus `poll()`; no async ecosystem crates.
- A new dependency needs an ADR and must fit the budget.
- Caddy (or another TLS terminator) is part of every internet-facing deployment.
- Time is Unix seconds as integers; no date library.
