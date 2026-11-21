# MVP

The MVP is a self-hostable, multi-tenant gate that lets two owners pair their gates and let
their agents exchange answers that leave only with consent (A1, A2) or under an open mandate
(A0, T1, T2), installable by an agent that verifies the release first.

## Scope

- Agent interface: one MCP server (stdio and loopback HTTP) and the same contract as HTTP with
  OpenAPI. Tools: `inbox`, `read`, `propose`, `revise`, `withdraw`, `status`, `share`, `queue`,
  `peers`, `journal`. No approve tool.
- Consent bot and Telegram Mini App; approval levels A0, A1, A2 and A2+ (Mini App plus PIN);
  closed and open mandates over content hashes.
- Multi-tenant, multi-peer; pairing by deep link; gate-to-gate HTTPS with signed envelopes,
  replay protection and durable retry.
- Risk evaluation: structural detectors, canaries, the owner dictionary with built-in detectors
  and personal lists; the source registry with Allow, Ask or Never per source and peer
  (PROTOCOL §6.4), with the sources of Source coverage below.
- Trust levels T0, T1, T2 (shelves).
- Conformance attack suite runnable as `paseka conformance`.
- Reproducible release with CI-only publishing and provenance; install skill released as a
  separate signed artifact whose hash is published in three places; first-run ceremony.
- Connect recipes for ulei, Hermes, Claude Code and Codex at L1, L2 (separate run started by the
  owner's scheduler) and L3 (OS restrictions); the owner records each agent's level in the Mini
  App and the gate shows it (PROTOCOL §5.4).

## Definition of Done

Each item is done when the stated check passes. "CA" means a named conformance attack test in
`crates/paseka-conformance`; "SP" a security property in `docs/THREAT-MODEL.md`.

| # | Item | Verified by |
|---|---|---|
| d1 | `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo deny check` and gitleaks pass on the tagged commit. | CI run of the tag; `python3 ci/broad_check.py` locally. |
| d2 | Static musl binary within the size budget; idle RSS and zero idle wakeups within budget; dependency count within budget. | `ci/budgets.sh` in CI. |
| d3 | No banned crate in the tree; no `unsafe` in proto, core, conformance. | `cargo deny check bans`; `#![forbid(unsafe_code)]` compiles. |
| d4 | The MCP tool list and HTTP route table contain no approve-like operation, and no agent-facing call moves a draft to `approved` or `released`. | CA-1, CA-2, CA-5, CA-24. |
| d5 | A closed mandate releases exactly once, only the hashed bytes, only to its recipient, only before `exp`. | CA-3, CA-10, CA-12, CA-13, CA-34; core tests of `mandate::verify_received`. |
| d6 | Editing content after consent (by agent or by a swap between preview and send) invalidates the consent. | CA-6, CA-7, CA-8, CA-9. |
| d7 | A1: a button press in the consent bot yields a mandate the release check accepts; a press for another request id or nonce is rejected. | Integration test with a fake Telegram Bot API; CA-4, CA-10, CA-15, CA-47. |
| d8 | A2: Mini App `initData` is accepted only with a valid Ed25519 third-party signature by the configured Telegram key and a fresh `auth_date`; HMAC-only or stale data is rejected. | `paseka-core` `initdata` tests with the documented keys and example (`contracts/fixtures/vectors/telegram-initdata.json`); CA-11, CA-14, CA-16, CA-17. |
| d9 | A0 open mandates release only within constraints (template, length, rate, window); a second open mandate for the same scope is refused while one is live. | `paseka-core` `open` tests; CA-25, CA-26, CA-27, CA-28. |
| d10 | Risk evaluation is monotonic: free text to a peer is at least A1; structural flag or dictionary hit gives A2 with highlights; a canary blocks even with valid consent and alerts the owner; content of a Never source is blocked under consent and open mandates, and Never changes only on the settings page. | `paseka-core` `risk` and `source` tests; CA-18, CA-19, CA-20, CA-21, CA-40, CA-41, CA-54. |
| d11 | The agent cannot edit the dictionary, policies, peers or approvers; changes go through consent. | CA-23, CA-24. |
| d12 | T2: `share` sends shelf bytes read by the gate only when the doc is on a shelf open to that peer; the note is at most 200 characters with no links or flags. | `paseka-core` `shelf` tests; CA-29, CA-30. |
| d13 | Tenant isolation: no operation of tenant A reads, releases or lists data of tenant B. | CA-32, CA-38, CA-39; `TenantMap` tests. |
| d14 | Two gates pair by deep link, exchange Ed25519 keys and deliver signed envelopes; tampered, replayed or unknown-key envelopes are rejected; delivery retries survive a restart. | Two-gate integration test on loopback; CA-12, CA-31, CA-33, CA-35, CA-36, CA-37, CA-46. |
| d15 | Unknown fields are ignored; an unknown enum value in a security field is rejected. | `crates/paseka-proto/tests/contracts.rs` over `contracts/fixtures/`; proto unit tests for authority-bearing enums. |
| d16 | The first-run ceremony blocks all release until the owner confirms the plain-words config in the Mini App with live `initData` whose Ed25519 signature verifies with the configured Telegram key; afterwards a changed security section in the config file is refused. | Integration test of `paseka init` plus `serve`; CA-23. |
| d17 | `paseka conformance` runs the full attack suite against a local install and exits non-zero on any failure. | Run in CI against the release binary; `crates/paseka/tests/cli.rs` locally. |
| d18 | A rebuild from the tag with `ci/repro-build.sh` reproduces the released binary hash; the release carries Sigstore provenance with a Rekor entry. | CI job rebuilding on a second runner; `cosign verify-blob-attestation`. |
| d19 | The audit checklist answers each question with a file:line reference that exists at the tag. | CI script checking every reference resolves. |
| d20 | An agent following the released install skill artifact on a clean host reaches a running gate with steps 0 to 5 passed and a self-check reporting green. | Manual dry run by the owner with one agent, recorded in the release notes. |
| d21 | Alice's agent (Claude Code, L2 recipe) asks Bob's agent (ulei or Hermes) a question; Bob's approval prompt shows the level recorded for Bob's agent; Bob approves in the Mini App; Alice's agent reads the answer from its inbox. | End-to-end manual scenario on two test gates, example.org names. |
| d22 | `/version` reports the build hash; a hosted tenant can export its journal and migrate to a self-host gate with one command. | Integration test of `export` and `import`. |
| d23 | The CLI names tenants only by local names (PROTOCOL §12.1): `paseka init` asks for the name and stores the mapping to the address; with one tenant `--tenant` may be omitted; with several, a missing or unknown `--tenant` exits 2 and lists the names; no message a peer receives carries the name. | `crates/paseka/tests/cli.rs`: `init` with a name, a taken or malformed name refused, an address as `--tenant` refused, `tenant rename`, commands with and without `--tenant` on one and on two tenants; the two-gate test of d14 finds no local name in envelopes or pairing messages. |

## Source coverage

Which sources of the registry (PROTOCOL §6.4) are caught, and by what.

| Source | MVP, built | MVP, to build | After the MVP |
|---|---|---|---|
| Files and folders | S8 exact shingle fingerprints | | MinHash; LLM paraphrase check |
| Agent memory, skills, instruction files, system prompt | S8 fingerprints | | MinHash; LLM paraphrase check |
| Secrets | S4 gitleaks-style rules | | entropy rule |
| Named secrets from a vault | S4 exact value match in body and attachment text | | |
| Private links | S4 link domains and query tokens | | |
| MCP sources (mail, calendar, contacts) | S9 on agent-declared reads | | S9 on reads verified by the gate-side MCP proxy |
| Messages from one peer | S8 fingerprints of that peer's bodies, Allow towards that peer | | MinHash; LLM paraphrase check |
| Other chats and groups | S8 fingerprints of the chat's messages, Allow towards its members | | MinHash; LLM paraphrase check |
| Memory about third parties | S8 fingerprints of tagged entries | | |
| Personal identifiers | S5 cards (Luhn) and IBAN (mod 97) | | phones, addresses, coordinates |
| One-time codes, 2FA, OTP | S4 code detector, decision fixed at Never | | |
| Images | | metadata removal on attach (PROTOCOL §3.1), with attachment handling in M2 | OCR of text in images |

Phones, addresses and coordinates have no S5 validator before the MVP release; long digit runs
get the S2 flag, which is not a registry source.

## Later (not in the MVP)

- Remote MCP connector with OAuth for browser ChatGPT; until then browser users act by hand in
  the Mini App as hosted or guest tenants.
- The biometric A2+ channel (BiometricManager with a WebCrypto key) and A3 (passkey in an
  external browser).
- Owner attestation: the owner's own signature for A2+ and A3, so a receiving gate can verify the
  approval level instead of taking it on the sending gate's word.
- Slack, ntfy, CLI with a local key, e-mail magic link; an independent approval web page.
- T3 free text on allowed topics, with digest, spike alerts and kill switch.
- Fuzzy checks: embedding similarity and a classifier via qb (raise only).
- Gate-side MCP proxy of the owner's MCP servers for verified sources; ulei taint integration.
- Dual-model recipes (a quarantined model turns peer text into a structured question); not a
  protection level.
- `paseka peer-turn` runner (ADR 0011).
- cargo-vet audits; pip and npm wrappers; `cargo install`; public GitHub releases.

## Milestones (dependency order)

1. M1 Core: `paseka-proto` types matching `contracts/`; `paseka-core` canonical hash, mandate
   verification, risk levels, the source registry, trust and shelf checks, tenant types, the PIN kind with its
   default by deployment and the PIN attempt limit; conformance harness with the core attacks.
   M1 stores no PIN. Covers d1, d3, d5, d6, d9, d10, d12, d13, d15.
2. M2 Local gate: storage (rusqlite), MCP server and HTTP API for the agent, journal, policy
   engine, attachment bytes with image metadata removal (PROTOCOL §3.1). CLI tenant names
   (PROTOCOL §12.1): the name prompt in `paseka init`, the mapping from name to address on the gate
   host, `paseka tenant rename`, and the `--tenant` rule, optional with one tenant and a usage
   error listing the names with several. Covers d4, d11, d23.
3. M3 Consent: consent bot (A1), Mini App (A2) with Ed25519 `initData` verification, first-run
   ceremony that does not complete without a live `initData` signature verified with the
   configured Telegram key (PROTOCOL §9.4). The Telegram keys and environment as security
   settings, changed through consent or the local CLI. Consent bot modes (PROTOCOL §7.2): the
   self-host tenant's own bot and the hosted shared bot that resolves the tenant only from the
   signed Telegram user id (TI-5, CA-39). The A2+ PIN channel (PROTOCOL §7.5): the owner sets the PIN at the first-run
   ceremony; the Argon2id verifier lands here, with the ADR for its dependency (size, tree cost,
   budget measurement); the per-tenant PIN pepper (generation from the OS CSPRNG, its file
   outside the database, the missing-pepper error and recovery through the local CLI) and the
   ceremony offering the PIN kind default for the tenant's deployment; PIN change through
   consent with the old PIN and through the local CLI; the attempt limit wired to the owner
   notice. Registered agents with their protection levels (PROTOCOL §5.4): the owner records the
   level when adding an agent and changes it at A2; every approval prompt, the agent view and
   the peer view show it, with the permanent L1 marker. Covers d7, d8, d16.
4. M4 Peers: identity keys, pairing by deep link, signed envelopes, retry, behind Caddy; key
   change and revocation in the gate and Mini App (PROTOCOL §10.6 to §10.8): the owner starts
   them through consent with PIN or password, the gate sends `key.rotate` or `key.revoke` to
   every peer and shows the key-change short authentication string for the separate notice to
   each peer's owner, and the receiving owner confirms a pending key change at A2. Covers d14,
   d21.
5. M5 Release and install: reproducible build, provenance, audit checklist, `paseka conformance`
   on installs, install and connect skills, hosted-tenant export and migration, with the PIN set
   again on import (PROTOCOL §7.5). The install skill artifact (ADR 0008): the release workflow
   builds the tarball of `skills/install/` reproducibly at a `skill-vX.Y.Z` tag, signs it with a
   Sigstore build provenance attestation, attaches it to that GitHub release, and the hash line is
   published in the release notes, the organisation README (`pasekahq/.github`) and the project
   owner's announcement channel. A hosted tenant's own consent bot (PROTOCOL §7.2), kept by
   the migration to self-host. Covers d2, d17, d18, d19, d20, d22.
