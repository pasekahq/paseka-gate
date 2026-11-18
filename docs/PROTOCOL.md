# Paseka protocol, version 1

Normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.
JSON shapes are fixed by the schemas in `contracts/`; this file fixes behaviour. Security
properties SP-n and conformance attacks CA-n are defined in `docs/THREAT-MODEL.md`.

## 1. Conventions

- JSON is UTF-8 (RFC 8259). Duplicate object keys MUST be rejected by every parser of untrusted
  input.
- Timestamps are integer Unix seconds (JWT NumericDate). Fields end in `_at`, except JWT claims
  `iat`, `nbf`, `exp`.
- `b64u` is base64url without padding (RFC 4648 §5). Decoders MUST reject padding and non-alphabet
  characters.
- `hex` is lowercase hexadecimal. SHA-256 values in JSON are 64 hex characters.
- `frame(x)` is the 4-byte big-endian length of the byte string `x` followed by `x`. Strings are
  framed as their UTF-8 bytes. `u32be` and `u64be` are big-endian unsigned integers.
- Every top-level contract object carries `"v": 1`.

## 2. Identifiers and keys

| Name | Format | Scope |
|------|--------|-------|
| tenant id | `t_` + 26 Crockford base32 (ULID) | gate-local, opaque |
| draft id | `d_` + ULID | gate-local |
| request id | `r_` + ULID (one per approval request of a draft revision) | gate-local |
| message id | `m_` + ULID (an inbox item) | gate-local |
| event id | `e_` + ULID | global, chosen by the sending gate |
| thread id | `th_` + ULID | global, chosen by the gate that opens the thread |
| mandate id (`jti`) | `md_` + ULID | global, chosen by the issuing gate |
| peer handle | `[a-z0-9][a-z0-9_-]{0,31}` | per tenant, set by the owner |
| key id | `ed25519:` + b64u(32-byte public key) | global |
| nonce | b64u(16 random bytes), 22 characters | gate-local, secret from the agent |
| invite code | b64u(16 random bytes) | single use |

ULIDs MUST carry 80 random bits from the OS CSPRNG, so ids never collide across tenants.

Each tenant has exactly one Ed25519 identity key. The key id is the tenant's address towards
peers. The same key signs envelopes, receipts, pairing messages and mandates; the JWS `typ`
header separates the domains (§8.1). The private key MUST be readable only by the gate's unix
user and MUST NOT be exported through any interface.

## 3. Content and digests

### 3.1 Content

- `body` is a UTF-8 string, at most 65536 bytes, without U+0000. The gate MUST NOT normalize it:
  no Unicode normalization, no newline conversion, no trimming. What the agent proposed (or the
  owner edited) is what is hashed, shown and sent.
- An attachment is `{name, media_type, size, sha256}` plus its bytes. `name` is 1 to 128
  characters without `/`, `\`, control characters or U+0000. At most 8 attachments, each at most
  2 MiB, together at most 4 MiB. Attachment order is significant.
- `content_sha256 = SHA-256(body bytes)`. `attachments[i].sha256 = SHA-256(attachment bytes)`.

### 3.2 Release digest

The release digest binds what leaves to where it goes:

```
release_digest = SHA-256(
  frame("paseka/release/v1") ||
  frame(tenant) || frame(iss) || frame(to) ||
  frame(thread) || frame(in_reply_to or "") ||
  content_sha256 (32 raw bytes) ||
  u32be(n) ||
  for each attachment in order:
    frame(name) || frame(media_type) || u64be(size) || sha256 (32 raw bytes)
)
```

`iss` and `to` are the key ids of the sending and receiving tenant. `in_reply_to` is an event id
or empty. Implementations MUST pass the vectors in `contracts/fixtures/vectors/digests.json`.

### 3.3 Approval challenge

Every approval request has one challenge, which approval channels bind:

```
approval_challenge = SHA-256(
  frame("paseka/approval/v1") ||
  frame(tenant) || frame(request_id) ||
  release_digest (32 raw bytes) ||
  nonce (16 raw bytes) ||
  frame(level)
)
```

`level` is the required level string (`A1`, `A2`, `A2+`, `A3`). A3 and A2+ channels sign these
32 bytes; A1 and A2 evidence records them.

## 4. Drafts

A draft is a candidate outbound message created by `propose` or `share`. It has revisions
numbered from 1. Each revision has its own body, attachments, release digest, evaluated level
and, while it awaits consent, one approval request (request id, nonce, challenge).

### 4.1 States

| State | Meaning | Terminal |
|-------|---------|----------|
| `awaiting_consent` | Evaluated; an approval request is out to the owner | no |
| `approved` | A mandate is issued; release not yet committed | no |
| `released` | The envelope is committed to the outbox | yes |
| `denied` | The owner refused | yes |
| `expired` | The prompt TTL or the mandate `exp` passed | yes |
| `withdrawn` | The agent withdrew it | yes |
| `blocked` | Policy forbids release (canary, unavailable level, hard rule) | yes |

Transitions:

| From | Event | To |
|------|-------|----|
| (new) | evaluation: block | `blocked` |
| (new) | evaluation: A0 under an open mandate | `approved`, then `released` in the same transaction |
| (new) | evaluation: A1 or higher | `awaiting_consent` |
| `awaiting_consent` | agent `revise` | `awaiting_consent` (new revision, new request; old nonce revoked) |
| `awaiting_consent` | owner approves the current request | `approved` |
| `awaiting_consent` | owner edits and approves | `approved` (new revision authored by the owner) |
| `awaiting_consent` | owner denies | `denied` |
| `awaiting_consent` | prompt TTL passes | `expired` |
| `awaiting_consent` | agent `withdraw` | `withdrawn` |
| `awaiting_consent` | re-evaluation after an owner edit blocks | `blocked` |
| `approved` | outbox commit at or before mandate `exp` | `released` |
| `approved` | mandate `exp` passes without commit | `expired` |

The gate MUST perform "consume nonce, issue mandate, commit outbox envelope, move to `released`"
in one database transaction (SP-21). `approved` is then observable only on failure paths.

A released draft carries a delivery sub-state: `pending`, `delivered` (signed receipt stored) or
`failed` (retry horizon passed or a non-retryable error).

### 4.2 Reasons shown to the agent

Terminal states other than `released` carry a coarse `reason`: `owner` (denied), `timeout`
(expired), `agent` (withdrawn), `policy` (any block), `internal`. The agent MUST NOT learn the
required level, detector names, matched spans, canaries, dictionary entries, nonces, request ids,
evidence or mandates (SP-8). The owner sees all of them.

### 4.3 Tripwire mode

A canary hit puts the tenant into tripwire mode: open mandates stop auto-releasing and every new
draft needs at least A2, until the owner clears tripwire mode in the Mini App.

## 5. Agent interface

### 5.1 Transport

- One MCP server per tenant, exposed as tools. Local agents use stdio; others use MCP Streamable
  HTTP on loopback (JSON responses). Non-MCP clients use plain HTTP: `POST /agent/v1/<tool>` with
  the tool input as body and the tool output as response.
- The stdio server is a relay process running as the agent's user. It holds a per-tenant agent
  token and forwards calls over a local socket to the gate process, which holds all authority.
  HTTP clients send the token as `Authorization: Bearer <token>`.
- The agent token selects the tenant (§12). It grants the tools below and nothing else.
- The gate MUST reject inputs with unknown fields (`invalid_input`). Agents read the advertised
  input schemas from `tools/list`, so strictness costs no compatibility, and proof-like fields
  never pass silently (CA-2).
- Text that came from peers is returned in fields named `body` inside items with
  `"origin": "peer"`. It is untrusted data for the agent.

### 5.2 Tools

There is no approve, deny, mandate, pairing, trust, policy, dictionary or settings tool. Their
absence is the contract (SP-1).

| Tool | Input | Output | Effect |
|------|-------|--------|--------|
| `inbox` | `{since?, limit?, peer?}` | `{items: [InboxItem], next}` | none |
| `read` | `{message_id}` | `Message` | marks read |
| `propose` | `{to, body or template, in_reply_to?, attachments?, sources?}` | `DraftView` | creates a draft |
| `revise` | `{draft_id, revision, body or template, attachments?}` | `DraftView` | new revision |
| `withdraw` | `{draft_id}` | `DraftView` | `withdrawn` |
| `status` | `{draft_id}` | `DraftView` | none |
| `share` | `{to, doc, section?, note?, in_reply_to?}` | `DraftView` | creates a draft |
| `queue` | `{states?, limit?, since?}` | `{drafts: [DraftView], next}` | none |
| `peers` | `{}` | `{peers: [PeerView]}` | none |
| `journal` | `{since?, limit?}` | `{entries: [JournalEntry], next}` | none |

Exact shapes: `contracts/agent/*.schema.json`. Rules:

- `propose`: `to` is a peer handle of an active peer. With `in_reply_to` (a message id from the
  inbox) the thread is that message's thread and `to` MUST be its sender. Without it the gate
  opens a new thread. Exactly one of `body` and `template` is present. A template is
  `{id, fields}`; the gate renders the owner-defined template and validates every field against
  its type. `sources` are agent-declared references (`{kind: "agent", ref}`); the gate records
  them as unverified.
- `revise`: `revision` MUST equal the current revision (`revision_conflict` otherwise). Only in
  `awaiting_consent` (`invalid_state` otherwise).
- `withdraw`: only in `awaiting_consent`.
- `share`: `doc` is a document id from `peers`; `section` is a heading slug of that document;
  `note` is at most 200 characters, a single line, without URLs, e-mail addresses, base64 or hex
  runs of 16 or more characters, or digit runs of 6 or more. A doc that does not exist or is not
  on a shelf open to `to` yields `not_found`. The gate reads the bytes itself (§9.3).
- `DraftView.body` is the body of the current revision, so the agent learns an owner edit.
- `inbox`, `queue` and `journal` page by an opaque cursor `next`, passed back as `since`.
  `limit` is 1 to 100, default 20.

### 5.3 Errors

A tool error is an MCP tool result with `isError: true` and structured content
`{"error": {"code", "message", "retryable"}}` (`contracts/agent/error.schema.json`). Plain HTTP
uses the same body with status 400, 404, 409, 413, 429 or 500.

| Code | Meaning | Retryable |
|------|---------|-----------|
| `invalid_input` | schema violation, unknown field, bad note or template field | no |
| `not_found` | no such id in this tenant (also for other tenants' ids) | no |
| `unknown_peer` | `to` is not an active peer | no |
| `invalid_state` | operation not allowed in the draft's state | no |
| `revision_conflict` | `revision` is not current | no |
| `too_large` | body or attachment limits exceeded | no |
| `rate_limited` | agent rate or pending limit reached | yes |
| `unavailable` | gate is not ready (first-run ceremony pending, maintenance) | yes |
| `internal` | unexpected failure; the draft is unchanged | yes |

Default limits: 30 drafts per peer per hour, 20 drafts in `awaiting_consent` per tenant.

## 6. Risk evaluation

### 6.1 Principle

Evaluation computes the required level of a revision. Each stage returns flags and a floor in
the order `none < A1 < A2 < A2+ < A3 < block`. The required level is the maximum of all floors.
No stage can lower another stage's floor (monotonic rule). A classifier verdict "safe" never
releases free text. The agent cannot read or edit any input of evaluation except the candidate.

### 6.2 Stages

| Stage | Kind | Default floor on hit |
|-------|------|----------------------|
| S1 base | exact | free text to a peer: A1; template or shelf share: none |
| S2 structure: URLs, e-mail addresses, base64 runs of 24+ or hex runs of 32+ characters, digit runs of 9+, length above the A1 prompt capacity, attachments, first message to this peer | exact | A2 |
| S3 display safety: bidi controls, zero-width and other invisible or control characters except tab and newline, mixed-script look-alikes | exact | A2 |
| S4 secrets (gitleaks-style rules) | exact | A2 |
| S5 dictionary: built-in PII detectors (cards with Luhn, IBAN with mod 97, phones, addresses, ids), personal lists, topics | exact | A2 |
| S6 per-peer policy: topic denied for this peer | exact | A2 |
| S7 canaries: marker in body or attachment text, raw or inside decoded base64, hex or percent-encoded runs, case-insensitive | exact | block |
| S8 fingerprints of sensitive folders (shingles, MinHash), verbatim or near-verbatim | exact | A2+ |
| S9 sources: MCP proxy log shows reads from sensitive folders during a peer-started turn | exact | A2+ |
| S10 embedding similarity, classifier | fuzzy | A2 at most |
| S11 tripwire mode (§4.3) | exact | A2 |
| S12 open mandate (§9.1) | exact | A0 only if every other stage returned no flag |

Rules:

- The result of S12 replaces S1 only when S2 to S11 returned no flag. Otherwise the required
  level is the maximum floor and the draft goes to the owner with all flags highlighted.
- A fuzzy stage that fails or times out adds the flag `fuzzy_unavailable` and no floor. An exact
  stage that fails blocks the draft with reason `internal`.
- An owner edit is re-evaluated. A canary still blocks (CA-20). If the new level exceeds the
  channel the owner is using, the edit becomes a new revision with a new request.
- If no configured channel satisfies the required level, the draft is `blocked` (reason
  `policy`) and the owner is notified. A weaker channel MUST NOT satisfy a stronger requirement.
  With the MVP channels this blocks S8 and S9 hits until the owner changes the rule.
- The owner can change default floors only through consent in the Mini App (§9.4). The S1 floor
  for free text, the S7 block and the no-flag condition of S12 are not configurable.

### 6.3 Channel strength

| Level | Channels that satisfy it |
|-------|--------------------------|
| A0 | open mandate |
| A1 | `telegram-button`, and every channel below |
| A2 | `telegram-miniapp`, and every channel below |
| A2+ | `telegram-miniapp-biometric`, `passkey` |
| A3 | `passkey` |

## 7. Approval channels and evidence

### 7.1 Approval requests

When a revision enters `awaiting_consent` the gate creates one approval request:
`{tenant, request_id, draft_id, revision, release_digest, level, nonce, challenge, issued_at,
expires_at}`. The nonce comes from the OS CSPRNG. The prompt TTL defaults to 3600 s (owner
setting, 300 to 86400 s). A new revision, withdrawal, denial or expiry revokes the request.
A decision is accepted only when all hold:

1. the request belongs to the tenant resolved from the channel (§12), is unrevoked, unexpired and
   unused;
2. the draft is in `awaiting_consent` and the request's revision is current;
3. the stored release digest equals the digest recomputed from the stored revision;
4. the channel satisfies the request's level (§6.3);
5. the approver is a configured approver of the tenant.

On approval the gate consumes the nonce, stores the evidence object, issues the closed mandate
and commits the release in one transaction.

Evidence objects (`contracts/evidence/`) are serialized once; the exact stored bytes are appended
to the journal and their SHA-256 is the mandate's `proof.evidence_sha256`.

### 7.2 Consent bot

The consent bot is the gate's own Telegram bot. Its token lives only in the gate. It is never the
bot through which the owner talks to the agent. Updates arrive by webhook (the gate MUST compare
`X-Telegram-Bot-Api-Secret-Token` in constant time) or by `getUpdates` over TLS with the gate's
token. The gate MUST deduplicate `update_id`.

### 7.3 A1: `telegram-button`

The prompt is a message in the approver's private chat with the consent bot. It contains the
peer name, the peer key fingerprint (first 8 b64u characters of the key), the thread context,
the flags, and the exact body as plain text (no `parse_mode`). It has buttons Approve
(`callback_data` `pk1:y:<nonce>`), Deny (`pk1:n:<nonce>`) and Review (opens the Mini App). If
the prompt exceeds 4096 characters or the revision has attachments, the gate MUST NOT offer
Approve in chat (Review only), which is why S2 raises those cases to A2.

On a `callback_query` the gate verifies, in addition to §7.1:

1. `from.id` is an approver of the tenant;
2. `message` is present (no `inline_message_id`), `message.chat.type` is `private`,
   `message.chat.id` and `message.message_id` equal those stored when the prompt was sent;
3. `data` parses as `pk1:(y|n):<nonce>` and the nonce maps to the request of that message.

Then it answers the callback and edits the prompt to show the outcome without buttons. The
evidence records bot id, chat id, message id, approver user id, `callback_query.id`, update id,
decision, challenge and receive time. Telegram attests who pressed; the gate attests the binding.

### 7.4 A2: `telegram-miniapp`

The Review button is a `web_app` button that opens `https://<gate origin>/app/v1/review#<request_id>`.
The page fetches the review with the raw `initData` in header `X-Paseka-Init-Data` and shows the
exact body (invisible and control characters rendered as visible escapes, highlights for every
flag), the recipient name and key fingerprint, each attachment with name, type, size and hash,
the sources read during the turn, and the diff to the previous revision. The page computes the
release digest from the bytes it rendered (WebCrypto) and sends it with the decision:
`POST /app/v1/decision` with `{request_id, nonce, release_digest, decision, edited_body?}`.

The gate verifies initData as follows; every step MUST pass:

1. Parse as `application/x-www-form-urlencoded`. Reject duplicate keys. Require `auth_date`,
   `hash`, `signature` and `user`.
2. Build the data-check-string: all pairs except `hash` and `signature`, as `key=value` with
   decoded values, sorted by key bytes, joined with `\n`.
3. Ed25519 (Bot API 8.0 third-party validation): verify `b64u-decode(signature)` over
   `<bot_id>:WebAppData\n<data-check-string>` with Telegram's public key for the configured
   environment, where `bot_id` is the tenant's consent bot id. The keys are pinned in the binary
   from the Bot API documentation (production `e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d`;
   the test environment key only when the gate is configured for it).
4. HMAC: `secret = HMAC-SHA-256(key = "WebAppData", msg = bot_token)`; `hash` MUST equal
   `hex(HMAC-SHA-256(key = secret, msg = data-check-string))`, compared in constant time. The
   HMAC alone is never sufficient (CA-16).
5. Freshness: `now - auth_date <= 300` (owner setting, 60 to 600) and `auth_date <= now + 30`.
6. `user.id` is an approver of the tenant.
7. A decision consumes the initData: the gate records `SHA-256(initData)` until it leaves the
   window and rejects reuse (CA-11). Review fetches do not consume it.
8. `request_id` and `nonce` identify a live request of the tenant (§7.1), `release_digest`
   equals the stored one, and the request's level is A2 or lower.

With `edited_body` the gate creates a new owner-authored revision, re-evaluates it (§6.2), and,
if the new level is A2 or lower and nothing blocks, treats the decision as approval of that
revision; the page MUST then have sent the release digest of the edited content. The evidence
records the raw initData, its hash, `auth_date`, approver user id, bot id, decision, challenge,
whether the content was edited and the edited content hash.

### 7.5 A2+: `telegram-miniapp-biometric` (later)

A non-extractable WebCrypto Ed25519 or P-256 key, created in the Mini App, unlocked through
Telegram `BiometricManager`, registered through an A2 consent. It signs the 32-byte approval
challenge. Evidence: key id, algorithm, signature, and the A2 fields. No hardware attestation.

### 7.6 A3: `passkey` (later)

WebAuthn in an external browser opened through `openLink`. The assertion `challenge` is the
approval challenge; `rpId` is the gate's domain; the gate verifies type `webauthn.get`, origin,
rpId hash, flags UP and UV, the signature over `authenticatorData || SHA-256(clientDataJSON)` with
the registered credential, and a non-decreasing sign count. The full assertion is publicly
verifiable and is presented to peers in the mandate's `proof.evidence`.

## 8. Mandates

### 8.1 Encoding

A mandate is an SD-JWT with zero disclosures: a compact JWS followed by `~`
(`<header>.<payload>.<signature>~`). Header: `{"alg": "EdDSA", "kid": <key id>, "typ": <type>}`.

| typ | Object |
|-----|--------|
| `paseka-mandate+sd-jwt` | closed or open mandate |
| `paseka-envelope+jwt` | gate-to-gate envelope (§10) |
| `paseka-receipt+jwt` | delivery receipt (§10.5) |
| `paseka-pair+jwt` | pairing message (§11) |

Verifiers MUST: accept only `alg` `EdDSA` with an Ed25519 key; reject `crit`, `jwk`, `jku`,
`x5u`, `x5c`; take the key only from local state (own key or a paired peer key), never from the
token; require `kid` equal to the expected key id and `typ` equal to the expected type; reject
any disclosure after the `~` and any `_sd` claim in version 1; verify the signature over the
exact received ASCII of `<header>.<payload>`.

Rationale. The model is AP2 (closed mandate as the cart mandate over exact content, open mandate
as the intent mandate with constraints). A full SD-JWT stack (salted disclosures, key-binding
JWT) buys selective disclosure, which version 1 does not need: every claim is needed by the
verifier, and the private parts of evidence stay in the journal behind `evidence_sha256`. An
SD-JWT with zero disclosures is a valid SD-JWT, costs one JWS implementation in the audited core,
and leaves a direct upgrade: later versions can move evidence fields into disclosures under
`_sd`. The deviation from AP2 is the signer: at A0 to A2 the gate signs on the owner's behalf
with Telegram's attestation as evidence; from A2+ the owner's own key signs the challenge.

### 8.2 Closed mandate

Claims (`contracts/mandate/closed.schema.json`): `v`, `kind: "closed"`, `iss` (sender key id),
`tenant`, `to` (recipient key id), `jti`, `iat`, `exp`, `nonce`, `thread`, `in_reply_to`,
`content_sha256`, `attachments` (metadata in order), `release_digest`, `level`, `proof`
(`channel`, `approved_at`, `evidence_sha256`, optional `open_mandate` (jti of the open mandate
for A0), optional `evidence` (publicly verifiable evidence, A3 only)).

Issuance: `exp = iat + 60`. The nonce is the consumed request nonce, or for A0 a fresh nonce.
The `jti` is unique. The gate issues a closed mandate for every release, including A0 releases
under an open mandate, so every `message` envelope carries exactly one closed mandate.

### 8.3 Open mandate

Claims (`contracts/mandate/open.schema.json`): `v`, `kind: "open"`, `iss`, `tenant`, `to`, `jti`,
`iat`, `nbf`, `exp`, `trust` (`T1`, `T2`, `T3`, `conversation`), `signed_at_level` (A2 or
higher), `constraints`, `proof`.

Constraints: `templates` (template ids), `max_len` (body bytes), `attachments` (`none` or
`shelf`), `private_sources` (`deny` or `allow`), `rate` (`max_messages`, `per_hour`, `per_day`),
`topics`, `shelves` (shelf ids), `thread` (for `conversation`).

Rules:

- The owner creates an open mandate only in the Mini App at A2 or higher; the page states the
  constraints in plain words. Open mandates stay in the issuing gate; peers do not need them.
- At most one active and one pending open mandate per tenant, peer and trust. A new one is
  presented only after the previous one is refused, revoked or expired (AP2 rule, CA-28).
- Maximum lifetimes: `conversation` 24 h (default 30 min or 10 messages), T1 30 days, T2 90 days,
  T3 7 days with renewal.
- Revocation takes effect for every evaluation that starts after it commits (CA-27).
- Counters are consumed in the release transaction.

### 8.4 Verification by the receiving gate

For each `message` event the receiver MUST verify the mandate (SP-14) and reject the event with
`mandate_invalid` unless all hold:

1. §8.1 checks with `typ` `paseka-mandate+sd-jwt` and `kid` equal to the envelope `iss`;
2. `kind` is `closed`; `iss` equals the envelope `iss`; `to` equals the envelope `aud`;
3. `content_sha256` equals SHA-256 of the event body; `attachments` metadata equals the event
   attachments in order and each `sha256` matches the transmitted bytes;
4. `thread` and `in_reply_to` equal those of the event;
5. `release_digest` equals the digest recomputed from the mandate `tenant` and the event (§3.2);
6. `iat <= event iat <= exp`, and `iat <= now + 300`;
7. `level` and `proof.channel` are known and consistent (§6.3); with `proof.evidence` present the
   receiver verifies it;
8. the `jti` was never accepted before from this `iss` (`mandate_replay` otherwise).

The receiver shows the sender's level and channel with the inbox item.

## 9. Trust levels and shelves

### 9.1 Trust levels as open mandates

| Level | Open mandate | Auto-release |
|-------|--------------|--------------|
| T0 | none (default for a new peer) | nothing |
| T1 | `trust: T1`, `templates`, `max_len` | rendered templates whose fields pass validation |
| T2 | `trust: T2`, `shelves`, `attachments: shelf` | shares of docs on those shelves, note per §5.2 |
| T3 (later) | `trust: T3`, `topics`, `rate`, short `exp` | free text on allowed topics |
| conversation | `trust: conversation`, `thread`, `rate.max_messages`, short `exp` | free text in one thread |

An open mandate matches a revision when: it is active (`nbf <= now < exp`, not revoked, tenant
not in tripwire mode); `to` is the revision's recipient; the revision's kind is allowed by the
trust; every constraint holds; and the counters allow one more message. T3 hard blocks always
apply: canaries, fingerprints of shelves not open to that peer, secrets, attachments outside
shelves. A peer whose inbound volume spikes over its limit has its open mandates suspended until
the owner resumes them.

### 9.2 Templates

A template is owner-defined text with typed fields: `enum` (listed values), `int` (range),
`date`, `short_text` (max length, charset letters, digits, space and basic punctuation, no URL,
no digit run of 6 or more). The gate renders the body; the agent supplies only field values.

### 9.3 Shelves

A shelf is an owner-defined collection of documents in the owner's library, opened to peers
through T2 mandates. Doc ids are opaque, issued by the gate, and never paths. On `share` the gate:

1. resolves `doc` in the tenant; checks it is on a shelf named by an active T2 mandate for `to`
   (`not_found` otherwise);
2. reads the document bytes itself and, with `section`, extracts the section under that heading
   slug;
3. builds the revision: body = note (or empty), one attachment = the document or section bytes
   with the document's name and media type;
4. evaluates it (§6). With no flags it releases at A0; otherwise it goes to the owner.

The agent influences only the choice of doc, section and the note.

### 9.4 Security settings

Approvers, peers, trust levels, open mandates, shelves, templates, dictionary, canaries,
fingerprint sources, default floors and windows are security settings. After the first-run
ceremony they change only through an owner decision in the Mini App at A2 or higher, journaled
with evidence. The bootstrap config is read only before the ceremony; later differences are
reported to the owner and ignored (CA-23).

## 10. Gate-to-gate wire

### 10.1 Endpoints

Each tenant has an endpoint URL `https://<host>/<path>` (TLS terminated by Caddy). A gate serves
`POST <endpoint>/v1/inbox` and `POST <endpoint>/v1/pair`. Requests carry
`Content-Type: application/jose` and a body of at most 6 MiB: one compact JWS.

### 10.2 Envelope

The envelope is a JWS with `typ` `paseka-envelope+jwt`, signed by the sender's tenant key.
Payload (`contracts/wire/envelope.schema.json`): `v`, `iss` (sender key id), `aud` (recipient key
id), `id` (event id), `type`, `iat` (event creation time), `data` (per type).

| type | data |
|------|------|
| `message` | `thread`, `in_reply_to`, `body`, `attachments` (metadata plus `data` in b64u), `mandate` |
| `pair.confirmed` | `request_id` (§11) |
| `unpair` | `reason` (free text, at most 200 characters, shown to the owner) |

The envelope is signed once, when the release commits to the outbox. Retries send the identical
bytes. `envelope_sha256` is SHA-256 of the compact JWS ASCII bytes.

### 10.3 Receiver verification

In order; the first failure determines the error:

1. size limit, JWS syntax, header per §8.1 (`malformed`, `too_large`);
2. `aud` names a tenant of this gate and `iss` is an active paired peer of that tenant
   (`not_paired`; the same response for an unknown tenant); `kid` equals `iss`;
3. signature (`bad_signature`);
4. `iat <= now + 300` (`from_future`) and `now - iat <= 604800` (`stale`);
5. event id dedupe per `(tenant, iss, id)`: same `envelope_sha256` seen returns `200` with the
   stored receipt and status `duplicate`; a different one is `conflict`. Seen ids are kept for at
   least 604800 + 300 s;
6. known `type` (`unsupported`); `data` valid (`malformed`);
7. for `message`: §8.4; peer volume limits (`rate_limited`);
8. store the inbox item and the event id in one transaction, then answer with a signed receipt.

### 10.4 Retry

The sender retries on connection failure, any 5xx, `429` and `from_future`, with exponential
backoff from 5 s doubling to a cap of 3600 s, jitter of ±20%, honouring `Retry-After`, until 72 h
after `iat`; then the delivery is `failed` and the owner is notified. Any other 4xx ends the
delivery as `failed` at once. Unknown error codes are classified by HTTP status alone. A `200`
whose receipt does not verify counts as a failed attempt.

### 10.5 Receipt and errors

A `200` response body is a JWS with `typ` `paseka-receipt+jwt` signed by the receiver
(`contracts/wire/receipt.schema.json`): `v`, `iss` (receiver), `aud` (sender), `id` (event id),
`envelope_sha256`, `received_at`, `status` (`accepted` or `duplicate`). The sender stores it
as delivery proof.

Errors are JSON `{"error": {"code", "message", "retryable"}}` with `Content-Type:
application/json` (`contracts/wire/error.schema.json`). They are unsigned and serve only the
retry decision.

| Code | HTTP | Retryable |
|------|------|-----------|
| `malformed` | 400 | no |
| `bad_signature` | 401 | no |
| `not_paired` | 403 | no |
| `pairing_pending` | 403 | yes |
| `conflict` | 409 | no |
| `mandate_replay` | 409 | no |
| `too_large` | 413 | no |
| `stale` | 422 | no |
| `from_future` | 422 | yes |
| `unsupported` | 422 | no |
| `mandate_invalid` | 422 | no |
| `invite_invalid` | 422 | no |
| `rate_limited` | 429 | yes |
| `internal` | 500 | yes |
| `unavailable` | 503 | yes |

## 11. Pairing

Pairing exchanges tenant keys and endpoints between an inviter (alice) and an invitee (bob).
Both keys are pinned by the exchange; each owner consents on their side. The agent has no part
in pairing.

1. Invite. Alice creates an invite in her Mini App. Her gate stores
   `{tenant, code, expires_at (default 24 h, at most 7 days), used: false}` and shows the deep link
   `https://t.me/<consent_bot>?start=pair_<code>`. Alice sends the link to bob out of band.
2. Invite card. Bob opens the link; alice's consent bot receives `/start pair_<code>` from
   Telegram user U. The gate records U (id, username, name) on the invite (first opener only) and
   replies with the pair URI:
   `paseka:pair?v=1&ep=<percent-encoded alice endpoint>&k=<alice key id>&c=<code>`.
3. Request. Bob gives the pair URI to his own gate (Mini App "Add peer", or a message from an
   approver to his consent bot). Bob's Mini App shows alice's endpoint host and key fingerprint;
   bob names the peer and consents at A2. Bob's gate POSTs to `<ep>/v1/pair` a JWS
   `paseka-pair+jwt` signed by bob's key: `{v, type: "pair.request", id, iss: bob key, aud: k,
   code, endpoint: bob endpoint, name_hint, iat}`.
4. Accept. Alice's gate verifies the signature with the key in `iss` (self-certifying), `aud` is
   the tenant that issued the code, `|now - iat| <= 300`, and consumes the code atomically
   (`invite_invalid` if unknown, used or expired). It stores bob as a peer in state
   `pending_owner` and answers `200` with a JWS signed by alice's key: `{v, type: "pair.accept",
   id, iss: alice key, aud: bob key, request_id, request_sha256, endpoint: alice endpoint, iat}`.
5. Bob's gate verifies the accept: signature, `iss` equals `k` from the URI (CA-37), `aud` is
   bob's key, `request_sha256` is SHA-256 of the request JWS bytes. It stores alice as an active
   T0 peer.
6. Alice's owner sees in the Mini App: bob's key fingerprint, endpoint host, name hint (marked as
   claimed by the peer), the Telegram user U who opened the invite, and the short authentication
   string. Alice consents at A2; the peer becomes active at T0. Alice's gate then sends bob an
   envelope `pair.confirmed`. Until then messages from bob get `pairing_pending` (CA-36).

Short authentication string, shown to both owners for optional comparison: the first 4 bytes of
`SHA-256(frame("paseka/sas/v1") || frame(alice key id) || frame(bob key id) || frame(code))` as
an unsigned integer modulo 1000000, as six digits.

The endpoint in the pair URI and in pairing messages MUST be `https`. Unpairing: either owner
removes the peer through consent; the gate sends `unpair` and stops accepting the peer's
envelopes.

## 12. Tenancy

A gate serves one or more tenants with the same code; self-host is the one-tenant case.
Invariants:

- TI-1 Every persisted record carries `tenant`; every query filters by it; keys are composite
  `(tenant, id)`.
- TI-2 The tenant is resolved only from the authenticated channel: the agent token, the consent
  bot plus approver binding, the envelope `aud` key. Never from a payload field.
- TI-3 An id of another tenant behaves exactly like a nonexistent id (`not_found`, same timing
  class).
- TI-4 Identity keys, bot tokens, dictionaries, canaries, shelves, templates, policies, journals
  and counters are per tenant. No cache is shared without the tenant in its key.
- TI-5 A shared consent bot (hosted mode) resolves the tenant from the nonce or request id and
  then requires the Telegram user to be an approver of that tenant (CA-39).
- TI-6 Rate limits, storage quotas and queue sizes are per tenant.
- TI-7 Journal export and migration to self-host export one tenant: its key, settings, peers,
  journal. Peers keep working because the key id stays the same; only the endpoint changes, which
  the gate announces through a later event type.

## 13. Versioning

Contract evolution and reader tolerance (unknown fields ignored, informational enums with an
`Unknown` fallback, authority-bearing values fail closed) are defined in `contracts/README.md`.
