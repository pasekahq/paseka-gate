# Contracts

JSON Schema (draft 2020-12) for every JSON object that crosses a boundary of the gate. Behaviour
is normative in `docs/PROTOCOL.md`; these files fix the shapes. Schema `$id`s live under
`https://pasekahq.example.org/contracts/v1/` and resolve relative to this directory.

## Layout

| Path | Objects |
|------|---------|
| `common.schema.json` | shared `$defs`: ids, addresses, key ids, hashes, levels, states, attachment metadata |
| `mandate/` | `closed`, `open` (JWS payload claims), `jws-header` (protected header of every paseka JWS) |
| `evidence/` | approval evidence: `telegram-button` (A1), `telegram-miniapp` (A2), `telegram-miniapp-pin` (A2+), `open-mandate` (A0), `passkey` (A3, reserved) |
| `agent/` | `<tool>.input` and `<tool>.output` for the ten agent tools, `views` (shared output objects), `error` |
| `wire/` | gate-to-gate `envelope` payload, `key-rotate` (`data` of a `key.rotate` envelope), `key-proof` (payload of its proof of possession), `key-revoke` (`data` of a `key.revoke` envelope), `key-replacement` (payload of its replacement signature), `receipt` payload, `error` response |
| `pairing/` | `request` and `accept` payloads |
| `defaults.json` | the defaults table of PROTOCOL §14 as data (not a schema) |
| `fixtures/` | examples and test vectors |

## Tool descriptions

The top-level `description` of `agent/<tool>.input.schema.json`, where present, is the canonical
description of that tool: the MCP server advertises it as the tool's `description` in
`tools/list`, unchanged. Paragraphs are separated by a blank line. In `propose` the paragraph
that starts with `Sources.` holds every rule about sources, the `sources` input and what the
owner's source registry means for a reply, and nothing else.

## Fixtures

`fixtures/<schema path without .schema.json>/valid/*.json` MUST validate against that schema;
`fixtures/<...>/invalid/*.json` MUST NOT. The file name states the case. A test in the
implementation SHOULD walk this tree, and the Rust types SHOULD round-trip every valid fixture.

`fixtures/vectors/digests.json` holds byte-exact vectors: release digests (PROTOCOL §3.2),
approval challenges (§3.3), the short authentication strings of pairing (§11) and key change
(§10.8), and signed objects (a closed mandate as SD-JWT, the envelope carrying it, its receipt, a
pair request, its accept with alice's first commitment, alice's `key.rotate` to that committed
key, and alice's `key.revoke` of her pairing key replaced by that committed key) made with the
test keys listed in the file. Each test key has a seed, SHA-256('paseka test key <name>'),
and an address, the tenant id. Ed25519 signatures are deterministic, so implementations MUST
reproduce the compact strings exactly from the given claims serialization and seed.

The file, the closed mandate inside the `wire/envelope` fixtures, the `mandate/closed`,
`evidence/telegram-button` and `evidence/telegram-miniapp-pin` fixtures,
`evidence/telegram-miniapp/valid/approve-above-available.json`, the `key-rotate` and
`key-revoke` fixtures of `wire/envelope`, the `wire/key-proof` and `wire/key-replacement` fixtures and
`pairing/accept/invalid/key-id-as-next-key.json` are generated, never edited by
hand: `PASEKA_WRITE_VECTORS=1 cargo test -p paseka-core --lib vectors::` writes them from the
seeds, and the same test without the variable fails when a file differs from what the generator
writes.

`fixtures/vectors/telegram-initdata.json` holds what the Telegram Mini Apps documentation,
section "Validating data for Third-Party Use", publishes for initData verification (PROTOCOL
§7.4 steps 1 to 3): the production and test Ed25519 keys in hex and the example of the signed
text with its bot id. The documentation publishes no signed initData; tests sign the example
with the test key `alice` of `digests.json`. The file is written by hand from the documentation.

All fixture data is synthetic: alice, bob, carol, example.org.

## Defaults

`defaults.json` is the machine-readable copy of the defaults table, PROTOCOL §14: `{v, parameters}`
where each parameter is `{name, unit, default, min?, max?, code}`. `unit` is `s`, `days`,
`drafts` or `entries`; `min` and `max` bound an owner setting inclusively, and a parameter
without them is fixed; `code` names the `paseka_core` constants, relative to the crate, that
hold the values. A test in `paseka-core` fails when a constant differs from this file or when
the file and the code do not list the same parameters.

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

## Changelog

### Version 1: address split from key

Made in place in v1 before any release or deployed peer (ADR 0013).

- `iss` and `aud` of `wire/envelope`, `wire/receipt`, `pairing/request` and `pairing/accept`, and
  `iss` and `to` of `mandate/closed` and `mandate/open`, are addresses (`$defs/address`, the
  tenant id) instead of key ids.
- `pairing/request` and `pairing/accept` carry the signer's key in the new required field `key`.
- The pair URI carries the inviter's address `a` next to its key `k`.
- `fixtures/vectors/digests.json` binds addresses into the release digest and adds a pair accept.

### Version 1: key rotation

Additive (ADR 0010, ADR 0013).

- `wire/envelope` gains the type `key.rotate`, whose `data` is the new schema `wire/key-rotate`:
  `new_key`, `next_key_sha256`, `previous_valid_until`, `proof`.
- New schema `wire/key-proof`, the payload of the proof; JWS `typ` gains `paseka-key-proof+jwt`.
- `pairing/request` and `pairing/accept` gain the optional `next_key_sha256`.
- `common` gains `$defs/jws`.
- `fixtures/vectors/digests.json` gains the test keys `alice-2` and `alice-3`, the commitment in
  the pair accept, and a signed `key.rotate`.

### Version 1: key revocation

Additive (ADR 0010, ADR 0013).

- `wire/envelope` gains the type `key.revoke`, whose `data` is the new schema `wire/key-revoke`:
  `revoked_key` and the optional `replacement` of `new_key`, `next_key_sha256`, `proof`.
- New schema `wire/key-replacement`, the payload of the replacement signature; JWS `typ` gains
  `paseka-key-replacement+jwt`.
- `fixtures/vectors/digests.json` gains `key_change_sas` and a signed `key.revoke`.

### Version 1: draft expiry in the release digest

Made in place in v1 before any release or deployed peer (ADR 0014).

- `mandate/closed` gains the required claim `expires`, the draft expiry in Unix seconds.
- The release digest uses the domain string `paseka/release/v2` and binds `u64be(expires)`
  after `in_reply_to` (PROTOCOL §3.2).
- `fixtures/vectors/digests.json` adds `expires` to the release digest inputs; every digest,
  challenge, evidence hash and signed mandate that depends on it is regenerated.

### Version 1: A2+ PIN channel

Additive (ADR 0010, ADR 0015), except the last item, made in place before any release.

- `common` `$defs/channel` gains `telegram-miniapp-pin` (A2+).
- New schema `evidence/telegram-miniapp-pin`: the A2 fields plus `pin_verified_at`; never the
  PIN or anything derived from it.
- `evidence/telegram-button`, `evidence/telegram-miniapp` and `evidence/telegram-miniapp-pin`
  gain the optional `required_level`, present when the request required a level above every
  configured channel (PROTOCOL §6.2).
- `required_level` of `evidence/telegram-miniapp-pin` allows only `A3`: that channel attests
  A2+, so only an A3 requirement is above it.

### Version 1: defaults table and conversation trust without message limit

Made in place in v1 before any release or deployed peer (ADR 0017).

- New data file `defaults.json`, the defaults table of PROTOCOL §14.
- `mandate/open`: a `conversation` mandate no longer requires `rate.max_messages` and may have an
  empty `rate`; `T1` and `T2` keep a non-empty `rate`, and `T3` its `per_day`.
- The fixture `mandate/open/invalid/empty-rate.json`, a conversation mandate, is now
  `mandate/open/valid/conversation-without-message-limit.json`; the new
  `mandate/open/invalid/t1-empty-rate.json` keeps the empty-rate case.

### Version 1: thread trust in agent outputs

Additive (ADR 0010).

- `agent/views` gains `$defs/ThreadTrust` (`active`, `ends_at`, `seconds_left`,
  `new_thread_needs_owner`) and the optional `thread_trust` in `DraftView` and `InboxItem`
  (PROTOCOL §4.4).
- `agent/propose.input` gains a top-level `description`, the tool description for agents.

### Version 1: conversation trust bounded by the source registry

Descriptions only; no shape changes.

- `agent/propose.input`: the `Sources.` paragraph of the tool description says that conversation
  trust releases nothing the source registry does not allow towards the peer (PROTOCOL §4.4).
- `agent/views`: `PeerView.conversation_until` gains a description: the `exp` of the one active
  conversation mandate with the peer; `thread_trust` names the thread.
- `mandate/open`: `constraints.private_sources` gains a description: it only narrows the source
  registry (PROTOCOL §8.3).

### Version 1: pairing verification

Additive (ADR 0010, ADR 0020), except the last item, made in place before any release.

- `agent/views`: `PeerView` gains the optional `verified`, whether the owner confirmed the pairing
  short authentication string (PROTOCOL §11).
- `fixtures/vectors/digests.json`: the `sas` vector input gains `inviter` and `invitee`
  addresses, and its value is regenerated under the domain string `paseka/sas/v2`.

### Version 1: Telegram initData vector

Additive (ADR 0022).

- `fixtures/vectors/telegram-initdata.json`: Telegram's documented initData keys and example.

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
