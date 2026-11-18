# MVP

The MVP is a self-hostable, multi-tenant gate that lets two owners pair their gates and let
their agents exchange answers that leave only with consent (A1, A2) or under an open mandate
(A0, T1, T2), installable by an agent that verifies the release first.

## Scope

- Agent interface: one MCP server (stdio and loopback HTTP) and the same contract as HTTP with
  OpenAPI. Tools: `inbox`, `read`, `propose`, `revise`, `withdraw`, `status`, `share`, `queue`,
  `peers`, `journal`. No approve tool.
- Consent bot and Telegram Mini App; approval levels A0, A1, A2; closed and open mandates over
  content hashes.
- Multi-tenant, multi-peer; pairing by deep link; gate-to-gate HTTPS with signed envelopes,
  replay protection and durable retry.
- Risk evaluation: structural detectors, canaries, the owner dictionary with built-in detectors
  and personal lists; fingerprints of sensitive folders if cheap.
- Trust levels T0, T1, T2 (shelves).
- Conformance attack suite runnable as `paseka conformance`.
- Reproducible release with CI-only publishing and provenance; install skill; first-run ceremony.
- Connect recipes for ulei, Hermes, Claude Code and Codex at L1 and L2.

## Definition of Done

Each item is done when the stated check passes. "CA" means a named conformance attack test in
`crates/paseka-conformance`; "SP" a security property in `docs/THREAT-MODEL.md`.

| # | Item | Verified by |
|---|---|---|
| d1 | `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo deny check` and gitleaks pass on the tagged commit. | CI run of the tag; `python3 ci/broad_check.py` locally. |
| d2 | Static musl binary within the size budget; idle RSS and zero idle wakeups within budget; dependency count within budget. | `ci/budgets.sh` in CI. |
| d3 | No banned crate in the tree; no `unsafe` in proto, core, conformance. | `cargo deny check bans`; `#![forbid(unsafe_code)]` compiles. |
| d4 | The MCP tool list and HTTP route table contain no approve-like operation, and no agent-facing call moves a draft to `approved` or `released`. | CA "approval in the agent's name"; CA "approve tool absent". |
| d5 | A closed mandate releases exactly once, only the hashed bytes, only to its recipient, only before `exp`. | CAs: forged consent, replay, expired mandate, stale nonce, wrong recipient. |
| d6 | Editing content after consent (by agent or by a swap between preview and send) invalidates the consent. | CA "preview swap after consent"; CA "hash mismatch after revise". |
| d7 | A1: a button press in the consent bot yields a mandate the release check accepts; a press for another request id or nonce is rejected. | Integration test with a fake Telegram Bot API; CA "nonce from another request". |
| d8 | A2: Mini App `initData` is accepted only with a valid Ed25519 third-party signature and a fresh `auth_date`; HMAC-only or stale data is rejected. | Unit tests with test vectors; CAs "HMAC-only initData", "stale auth_date". |
| d9 | A0 open mandates release only within constraints (template, length, rate, window); a second open mandate for the same scope is refused while one is live. | `paseka-core` table tests; CA "open mandate outside constraints". |
| d10 | Risk evaluation is monotonic: free text to a peer is at least A1; structural flag or dictionary hit gives A2 with highlights; a canary blocks even with valid consent and alerts the owner. | `paseka-core` property and table tests; CA "canary with approval". |
| d11 | The agent cannot edit the dictionary, policies, peers or approvers; changes go through consent. | CA "settings change via config or agent call". |
| d12 | T2: `share` sends shelf bytes read by the gate only when the doc is on a shelf open to that peer; the note is at most 200 characters with no links or flags. | `paseka-core` tests; CAs "share outside shelf", "note smuggling". |
| d13 | Tenant isolation: no operation of tenant A reads, releases or lists data of tenant B. | CA "cross-tenant read/release"; core type tests. |
| d14 | Two gates pair by deep link, exchange Ed25519 keys and deliver signed envelopes; tampered, replayed or unknown-key envelopes are rejected; delivery retries survive a restart. | Two-gate integration test on loopback; CAs "envelope replay", "forged sender". |
| d15 | Unknown fields are ignored; an unknown enum value in a security field is rejected. | Contract fixtures in `contracts/fixtures/`; CA "unknown enum in security field". |
| d16 | The first-run ceremony blocks all release until the owner confirms the plain-words config in the Mini App; afterwards a changed security section in the config file is refused. | Integration test of `paseka init` plus `serve`. |
| d17 | `paseka conformance` runs the full attack suite against a local install and exits non-zero on any failure. | Run in CI against the release binary. |
| d18 | A rebuild from the tag with `ci/repro-build.sh` reproduces the released binary hash; the release carries Sigstore provenance with a Rekor entry. | CI job rebuilding on a second runner; `cosign verify-blob-attestation`. |
| d19 | The audit checklist answers each question with a file:line reference that exists at the tag. | CI script checking every reference resolves. |
| d20 | An agent following `skills/install/SKILL.md` on a clean host reaches a running gate with steps 1 to 5 passed and a self-check reporting green. | Manual dry run by the owner with one agent, recorded in the release notes. |
| d21 | Alice's agent (Claude Code, L2 recipe) asks Bob's agent (ulei or Hermes) a question; Bob approves in the Mini App; Alice's agent reads the answer from its inbox. | End-to-end manual scenario on two test gates, example.org names. |
| d22 | `/version` reports the build hash; a hosted tenant can export its journal and migrate to a self-host gate with one command. | Integration test of `export` and `import`. |

## Later (not in the MVP)

- Remote MCP connector with OAuth for browser ChatGPT; until then browser users act by hand in
  the Mini App as hosted or guest tenants.
- A2+ (BiometricManager with a WebCrypto key) and A3 (passkey in an external browser).
- Slack, ntfy, CLI with a local key, e-mail magic link; an independent approval web page.
- T3 free text on allowed topics, with digest, spike alerts and kill switch.
- Fuzzy checks: embedding similarity and a classifier via qb (raise only).
- Gate-side MCP proxy of the owner's MCP servers for verified sources; ulei taint integration.
- L3 dual-model recipes.
- `paseka peer-turn` runner (ADR 0011).
- cargo-vet audits; pip and npm wrappers; `cargo install`; public GitHub releases.

## Milestones (dependency order)

1. M1 Core: `paseka-proto` types matching `contracts/`; `paseka-core` canonical hash, mandate
   verification, risk levels, trust and shelf checks, tenant types; conformance harness with the
   core attacks. Covers d1, d3, d5, d6, d9, d10, d12, d13, d15.
2. M2 Local gate: storage (rusqlite), MCP server and HTTP API for the agent, journal, policy
   engine. Covers d4, d11.
3. M3 Consent: consent bot (A1), Mini App (A2) with Ed25519 `initData` verification, first-run
   ceremony. Covers d7, d8, d16.
4. M4 Peers: identity keys, pairing by deep link, signed envelopes, retry, behind Caddy.
   Covers d14, d21.
5. M5 Release and install: reproducible build, provenance, audit checklist, `paseka conformance`
   on installs, install and connect skills, hosted-tenant export and migration. Covers d2, d17,
   d18, d19, d20, d22.
