# Contracts

JSON Schema (draft 2020-12) for every JSON object that crosses a boundary of the gate. Behaviour
is normative in `docs/PROTOCOL.md`; these files fix the shapes. Schema `$id`s live under
`https://pasekahq.example.org/contracts/v1/` and resolve relative to this directory.

## Layout

| Path | Objects |
|------|---------|
| `common.schema.json` | shared `$defs`: ids, key ids, hashes, levels, states, attachment metadata |
| `mandate/` | `closed`, `open` (JWS payload claims), `jws-header` (protected header of every paseka JWS) |
| `evidence/` | approval evidence: `telegram-button` (A1), `telegram-miniapp` (A2), `open-mandate` (A0), `passkey` (A3, reserved) |
| `agent/` | `<tool>.input` and `<tool>.output` for the ten agent tools, `views` (shared output objects), `error` |
| `wire/` | gate-to-gate `envelope` payload, `receipt` payload, `error` response |
| `pairing/` | `request` and `accept` payloads |
| `fixtures/` | examples and test vectors |

## Fixtures

`fixtures/<schema path without .schema.json>/valid/*.json` MUST validate against that schema;
`fixtures/<...>/invalid/*.json` MUST NOT. The file name states the case. A test in the
implementation SHOULD walk this tree, and the Rust types SHOULD round-trip every valid fixture.

`fixtures/vectors/digests.json` holds byte-exact vectors: release digests (PROTOCOL §3.2),
approval challenges (§3.3), the short authentication string (§11), and signed objects (a closed
mandate as SD-JWT, the envelope carrying it, its receipt, a pair request) made with the test keys
listed in the file. Ed25519 signatures are deterministic, so implementations MUST reproduce the
compact strings exactly from the given claims serialization and seed.

All fixture data is synthetic: alice, bob, carol, example.org.

## Schemas describe writers

A schema states what a conforming writer emits. Readers apply the rules below, which are more
tolerant for informational data and stricter for authority.

## Versioning

Contracts only grow within a major version.

- Allowed in v1: a new optional field; a new schema; a new value of an informational enum; a new
  event type; a new evidence channel.
- Not allowed in v1: removing or renaming a field; changing a type, format or meaning; making an
  optional field required; tightening a constraint on data that peers or agents already send.
  Such a change is a new major version: new `$id` prefix `/v2/`, `"v": 2`, and a v1 receiver
  answers `unsupported`.
- The major version is the `v` field. There are no minor version numbers on the wire; growth is
  detected by presence of fields.

## Tolerant readers

Wire payloads, receipts, mandates, evidence and agent tool outputs:

- Unknown fields MUST be ignored and MUST NOT be interpreted. A reader never grants anything
  because of a field it does not know.
- Unknown values of informational enums MUST map to an `Unknown` variant (in Rust
  `#[serde(other)] Unknown`) and processing continues. Informational enums: draft `state` and
  `reason` and `delivery.state` as read by agents, journal `kind`, receipt `status`, error `code`
  (classified by HTTP status and `retryable`), template field `type`, `telegram_env`.
- Unknown values of authority-bearing fields MUST fail closed: reject the object. Authority-bearing
  fields: JWS `alg` and `typ`, mandate `kind`, `level`, `signed_at_level`, `trust`,
  `proof.channel`, envelope `type`, evidence `channel` and `decision`, and `v`.
- Duplicate JSON keys MUST be rejected.

Agent tool inputs are the exception: the gate rejects unknown input fields with `invalid_input`.
The gate advertises its exact input schemas through MCP `tools/list`, so clients never need to
send fields the gate does not know, and proof-like fields never pass silently.
