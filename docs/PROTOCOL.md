# Paseka protocol, version 1

Normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.
JSON shapes are fixed by the schemas in `contracts/`; this file fixes behaviour. Security
properties SP-n and conformance attacks CA-n are defined in `docs/THREAT-MODEL.md`.

## 1. Conventions

- JSON is UTF-8 (RFC 8259). Duplicate object keys MUST be rejected by every parser of untrusted
  input.
- Timestamps are integer Unix seconds (JWT NumericDate). Fields end in `_at`, except JWT claims
  `iat`, `nbf`, `exp`.
- `b64u` is base64url without padding (RFC 4648 §5). Decoders MUST reject padding, non-alphabet
  characters and non-zero trailing bits.
- `hex` is lowercase hexadecimal. SHA-256 values in JSON are 64 hex characters.
- `frame(x)` is the 4-byte big-endian length of the byte string `x` followed by `x`. Strings are
  framed as their UTF-8 bytes. `u32be` and `u64be` are big-endian unsigned integers.
- Every top-level contract object carries `"v": 1`.

## 2. Identifiers and keys

| Name | Format | Scope |
|------|--------|-------|
| tenant id, address | `t_` + 26 Crockford base32 (ULID) | global, permanent |
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

The tenant id is the tenant's address towards peers. It never changes, is never derived from a
key, and stays the same across key rotation and migration. Every field that names a tenant
towards a peer (`iss`, `aud`, `to`) holds an address.

Each tenant has exactly one current Ed25519 identity key. Key ids appear only in JWS `kid` and in
fields that name a key (`key` in pairing messages, `k` in the pair URI, `new_key` in `key.rotate`,
`revoked_key` and `new_key` in `key.revoke`).
A peer record holds, per tenant and peer address: the endpoint, the current key, the commitment
`next_key_sha256` to the peer's next key (absent until the peer sends one), the previous key with
its `previous_valid_until`, the `key_revoked` mark, the pending key change (§10.8), and the
pairing state. A key is valid for the peer at `now` when it is the current key and the peer is not
`key_revoked`, or the previous key while `now < previous_valid_until`. The recorded key changes
only by rotation (§10.6), revocation (§10.7) or owner-confirmed change (§10.8). The same key
signs envelopes, receipts, pairing messages and mandates; the JWS `typ` header separates the
domains (§8.1). The private key MUST be readable only by the gate's unix user and MUST NOT be
exported through any interface.

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

The release digest binds what leaves, where it goes and until when the draft may leave:

```
release_digest = SHA-256(
  frame("paseka/release/v2") ||
  frame(tenant) || frame(iss) || frame(to) ||
  frame(thread) || frame(in_reply_to or "") ||
  u64be(expires) ||
  content_sha256 (32 raw bytes) ||
  u32be(n) ||
  for each attachment in order:
    frame(name) || frame(media_type) || u64be(size) || sha256 (32 raw bytes)
)
```

Inputs, in this order:

- `tenant`: the sending tenant id;
- `iss` and `to`: the addresses of the sending and receiving tenant, so `iss` equals `tenant`;
- `thread`: the thread id;
- `in_reply_to`: the event id answered, or the empty string;
- `expires`: the draft expiry (§4), Unix seconds, as 8 bytes big-endian;
- `content_sha256`: SHA-256 of the body (§3.1);
- `n`: the number of attachments, then each attachment's `name`, `media_type`, `size` and
  `sha256` in attachment order.

The suffix of the domain string numbers the digest composition, not the protocol version.
The receiver recomputes the digest from the event and the closed mandate's `tenant` and
`expires` (§8.4). Implementations MUST pass the vectors in
`contracts/fixtures/vectors/digests.json`.

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

`level` is the required level string (`A1`, `A2`, `A2+`, `A3`), also when it is above every
configured channel (§6.2). Key-based channels (A3 passkey, later the biometric A2+ channel) sign
these 32 bytes; A1, A2 and PIN evidence records them. Through `release_digest` the challenge also binds the
draft `expires`, so the owner approves the draft's lifetime with its content. Evidence `level` is
the channel's level; the challenge `level` is the evidence `required_level` when present, and
otherwise the closed mandate's `level` (§6.3).

## 4. Drafts

A draft is a candidate outbound message created by `propose` or `share`. It has revisions
numbered from 1. Each revision has its own body, attachments, release digest, evaluated level
and, while it awaits consent, one approval request (request id, nonce, challenge).

Every draft has an expiry `expires = created_at + lifetime`, fixed at creation and bound into the
release digest of every revision (§3.2). The lifetime is an owner setting from 300 s (5 min) to
604800 s (7 days), default 43200 s (12 h); in code `DRAFT_LIFETIME_RANGE` and
`DRAFT_LIFETIME_DEFAULT` in `paseka_core::draft`. A prompt never outlives the draft: a request's
`expires_at` is at most `expires`. The gate issues no closed mandate for a draft at or after
`expires`, also not for a retry; a draft not yet released moves to `expired` then.

### 4.1 States

| State | Meaning | Terminal |
|-------|---------|----------|
| `awaiting_consent` | Evaluated; an approval request is out to the owner | no |
| `approved` | A mandate is issued; release not yet committed | no |
| `released` | The envelope is committed to the outbox | yes |
| `denied` | The owner refused | yes |
| `expired` | The prompt TTL, the mandate `exp` or the draft `expires` passed | yes |
| `withdrawn` | The agent withdrew it | yes |
| `blocked` | Policy forbids release (canary, hard rule) | yes |

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
| `awaiting_consent` | prompt TTL or draft `expires` passes | `expired` |
| `awaiting_consent` | agent `withdraw` | `withdrawn` |
| `awaiting_consent` | re-evaluation after an owner edit blocks | `blocked` |
| `approved` | outbox commit at or before mandate `exp` and before draft `expires` | `released` |
| `approved` | mandate `exp` or draft `expires` passes without commit | `expired` |

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
uses the same body with status 400, 404, 409, 413, 429, 500 or 503.

| Code | Meaning | Retryable |
|------|---------|-----------|
| `invalid_input` | schema violation, unknown field, bad note or template field | no |
| `not_found` | no such id in this tenant (also for other tenants' ids) | no |
| `unknown_peer` | `to` is not an active peer | no |
| `invalid_state` | operation not allowed in the draft's state | no |
| `revision_conflict` | `revision` is not current | no |
| `too_large` | body or attachment limits exceeded | no |
| `rate_limited` | agent rate or pending limit reached | yes |
| `unavailable` | gate is not ready (first-run ceremony pending, maintenance); HTTP 503 | yes |
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
- Without a matching open mandate the required level is at least A1, for templates and shelf
  shares too: a T0 peer gets nothing without consent.
- A fuzzy stage that fails or times out adds the flag `fuzzy_unavailable` and no floor. An exact
  stage that fails blocks the draft with reason `internal`.
- An owner edit is re-evaluated. A canary still blocks (CA-20). If the channel the owner is
  using cannot decide the new revision's request (§6.3), the edit becomes a new revision with a
  new request.
- A required level is never unavailable. The approval request goes through the weakest
  configured channel that satisfies the level, and only a channel that satisfies the level can
  decide it. If no configured channel satisfies it, the draft is not blocked: the request keeps
  the required level, goes through the strongest configured channel, and is marked as above the
  available channels; only a channel at that channel's level can decide it. A weaker channel
  MUST NOT decide a request that a configured channel satisfies. The owner's prompt shows the
  required level, the channel, and in the marked case that the strongest available protection
  replaces the required one. In the MVP an A3 requirement goes through `telegram-miniapp-pin`
  (A2+).
- The owner can change default floors only through consent in the Mini App (§9.4). The S1 floor
  for free text, the S7 block and the no-flag condition of S12 are not configurable.

### 6.3 Channel strength

| Level | Channels that satisfy it |
|-------|--------------------------|
| A0 | open mandate |
| A1 | `telegram-button`, and every channel below |
| A2 | `telegram-miniapp`, and every channel below |
| A2+ | `telegram-miniapp-pin`, `telegram-miniapp-biometric` (later), and every channel below |
| A3 | `passkey` (later) |

A channel's level is the row that names it. The selection rule of §6.2 is
`paseka_core::channel::Channels::select`. Evidence records the channel's own level; in the
marked case it adds `required_level`, the level the request required. The closed mandate's
`level` is the required level, or in the marked case the level of the strongest configured
channel, so `level` and `proof.channel` always agree (§8.4).

## 7. Approval channels and evidence

### 7.1 Approval requests

When a revision enters `awaiting_consent` the gate creates one approval request:
`{tenant, request_id, draft_id, revision, release_digest, level, nonce, challenge, issued_at,
expires_at}`. The nonce comes from the OS CSPRNG. The prompt TTL defaults to 3600 s (owner
setting, 300 to 86400 s); `expires_at` is `issued_at` plus the TTL, capped at the draft
`expires` (§4). A new revision, withdrawal, denial or expiry revokes the request.
A decision is accepted only when all hold:

1. the request belongs to the tenant resolved from the channel (§12), is unrevoked, unexpired and
   unused;
2. the draft is in `awaiting_consent` and the request's revision is current;
3. the stored release digest equals the digest recomputed from the stored revision;
4. the channel satisfies the request's level (§6.3), or, for a request marked as above the
   available channels (§6.2), the level of the strongest configured channel;
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
   equals the stored one, and `telegram-miniapp` may decide the request (§7.1 item 4).

With `edited_body` the gate creates a new owner-authored revision, re-evaluates it (§6.2), and,
if nothing blocks and the channel may decide the new revision's request, treats the decision as
approval of that revision; the page MUST then have sent the release digest of the edited content. The evidence
records the raw initData, its hash, `auth_date`, approver user id, bot id, decision, challenge,
whether the content was edited and the edited content hash.

### 7.5 A2+: `telegram-miniapp-pin`

The A2 Mini App review plus the owner's PIN or password. The PIN is entered only in the Mini
App, never in chat: the consent bot never asks for it, and the chat prompt of a request that
needs this channel offers Review only, no Approve.

Flow: the Review button opens the page of §7.4. The page shows everything of §7.4, the required
level, the channel, and, for a request marked as above the available channels (§6.2), that the
strongest available protection replaces the required level. After the owner chooses approve or
deny, the page asks for the PIN and sends it with the decision:
`POST /app/v1/decision` with `{request_id, nonce, release_digest, decision, edited_body?, pin}`.
The gate verifies initData by steps 1 to 7 of §7.4, checks the PIN against the tenant's stored
verifier, and then checks §7.1 with channel `telegram-miniapp-pin`. A wrong PIN refuses the
decision, counts against the attempt limit below and leaves the request open. The gate never
stores, logs or journals the PIN itself.

Evidence (`contracts/evidence/telegram-miniapp-pin.schema.json`): the A2 fields of §7.4,
`pin_verified_at` (when the gate accepted the PIN), and `required_level` in the marked case. It
never contains the PIN, the password or any value derived from them.

PIN lifecycle (constants and types in `paseka_core::pin`):

- Kind: a security setting (§9.4) that holds no secret. Six ASCII digits (`PIN_DIGITS`), the
  default, or a password of at least `PASSWORD_MIN_CHARS` (12) characters with no control
  characters (`PinKind`). The gate checks every new PIN against the kind (`PinKind::check`).
- Set: the owner sets the PIN in the Mini App during the first-run ceremony. A tenant without a
  stored verifier has no `telegram-miniapp-pin` channel.
- Storage: the gate stores only an Argon2id verifier (RFC 9106, version 0x13): memory 65536 KiB,
  3 passes, parallelism 4, a fresh 16-byte salt from the OS CSPRNG, a 32-byte tag, in PHC string
  format. The input is the UTF-8 bytes of the PIN as entered; tags are compared in constant time.
  The Argon2 secret input is empty and reserved for a key kept outside the database.
- Change: through consent in the Mini App, where the owner enters the old PIN, checked and
  limited like a decision PIN, and then the new one; or by the local CLI on the gate host, run
  as the gate's unix user (TB-5), which needs no old PIN. A change of kind is a PIN change. The
  journal records each change without the PIN or the verifier.
- Attempt limit: per tenant, `PIN_MAX_FAILURES` (5) wrong entries in a row freeze PIN entry for
  `PIN_FREEZE_SECS` (900 s) from the fifth failure (`PinLimiter`). During the freeze every PIN
  entry is refused unchecked and does not extend it. Entering the freeze sends the owner exactly
  one notice in the consent chat, with the end of the freeze and never the entered value. A
  right PIN resets the count; the freeze ends at its time with a fresh count. Decision PINs and
  old PINs of a change share the count. The limit guards online entry only (THREAT-MODEL A-9).
- Biometrics: when `telegram-miniapp-biometric` arrives, the PIN channel stays as the fallback
  A2+ channel.

Later, `telegram-miniapp-biometric` is a further A2+ channel: a non-extractable WebCrypto Ed25519
or P-256 key, created in the Mini App, unlocked through Telegram `BiometricManager`, registered
through an A2 consent. It signs the 32-byte approval challenge. Evidence: key id, algorithm,
signature, and the A2 fields. No hardware attestation.

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
| `paseka-key-proof+jwt` | proof of possession of a new key (§10.6) |
| `paseka-key-replacement+jwt` | signature of a replacement key in a revocation (§10.7) |

Verifiers MUST: accept only `alg` `EdDSA` with an Ed25519 key; reject `crit`, `jwk`, `jku`,
`x5u`, `x5c`; take the key only from local state (own key or a key valid now for a paired peer's
address, §2), never from the token; require `kid` to name that key and `typ` equal to the expected
type; reject
any disclosure after the `~` and any `_sd` claim in version 1; verify the signature over the
exact received ASCII of `<header>.<payload>`.

Rationale. The model is AP2 (closed mandate as the cart mandate over exact content, open mandate
as the intent mandate with constraints). A full SD-JWT stack (salted disclosures, key-binding
JWT) buys selective disclosure, which version 1 does not need: every claim is needed by the
verifier, and the private parts of evidence stay in the journal behind `evidence_sha256`. An
SD-JWT with zero disclosures is a valid SD-JWT, costs one JWS implementation in the audited core,
and leaves a direct upgrade: later versions can move evidence fields into disclosures under
`_sd`. The deviation from AP2 is the signer: at A0 to A2 the gate signs on the owner's behalf
with Telegram's attestation as evidence; with the biometric A2+ channel and A3 the owner's own
key signs the challenge.

### 8.2 Closed mandate

Claims (`contracts/mandate/closed.schema.json`): `v`, `kind: "closed"`, `iss` (sender address,
equal to `tenant`), `tenant`, `to` (recipient address), `jti`, `iat`, `exp`, `nonce`, `thread`,
`in_reply_to`, `expires` (the draft expiry, §4), `content_sha256`, `attachments` (metadata in
order), `release_digest`, `level`, `proof` (`channel`, `approved_at`, `evidence_sha256`,
optional `open_mandate` (jti of the open mandate for A0), optional `evidence` (publicly
verifiable evidence, A3 only)).

Issuance: `exp = iat + 60` and `iat < expires`. The nonce is the consumed request nonce, or for
A0 a fresh nonce. The `jti` is unique. The gate issues a closed mandate for every release, including A0 releases
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

1. §8.1 checks with `typ` `paseka-mandate+sd-jwt` and `kid` naming a key valid now (§2) for the
   envelope `iss`;
2. `kind` is `closed`; `iss` equals the envelope `iss` and `tenant`; `to` equals the envelope
   `aud`;
3. `content_sha256` equals SHA-256 of the event body; `attachments` metadata equals the event
   attachments in order and each `sha256` matches the transmitted bytes;
4. `thread` and `in_reply_to` equal those of the event;
5. `release_digest` equals the digest recomputed from the mandate `tenant` and `expires` and the
   event (§3.2);
6. `iat <= event iat <= exp`, `exp - iat <= 60`, and `iat <= now + 300`;
7. `iat < expires`: the mandate was issued while the draft was alive;
8. `level` and `proof.channel` are known and consistent (§6.3); with `proof.evidence` present the
   receiver verifies it;
9. the `jti` was never accepted before from this `iss` address (`mandate_replay` otherwise).

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
reported to the owner and ignored (CA-23). The PIN and its kind change only as §7.5 states:
through consent with the old PIN, or by the local CLI on the gate host.

## 10. Gate-to-gate wire

### 10.1 Endpoints

Each tenant has an endpoint URL `https://<host>/<path>` (TLS terminated by Caddy). A gate serves
`POST <endpoint>/v1/inbox` and `POST <endpoint>/v1/pair`. Requests carry
`Content-Type: application/jose` and a body of at most 6 MiB: one compact JWS.

### 10.2 Envelope

The envelope is a JWS with `typ` `paseka-envelope+jwt`, signed by the sender's tenant key.
Payload (`contracts/wire/envelope.schema.json`): `v`, `iss` (sender address), `aud` (recipient
address), `id` (event id), `type`, `iat` (event creation time), `data` (per type).

| type | data |
|------|------|
| `message` | `thread`, `in_reply_to`, `body`, `attachments` (metadata plus `data` in b64u), `mandate` |
| `pair.confirmed` | `request_id` (§11) |
| `unpair` | `reason` (free text, at most 200 characters, shown to the owner) |
| `key.rotate` | `new_key`, `next_key_sha256`, `previous_valid_until`, `proof` (§10.6) |
| `key.revoke` | `revoked_key`, optional `replacement` of `new_key`, `next_key_sha256`, `proof` (§10.7) |

The envelope is signed once, when the release commits to the outbox. Retries send the identical
bytes. `envelope_sha256` is SHA-256 of the compact JWS ASCII bytes.

### 10.3 Receiver verification

In order; the first failure determines the error:

1. size limit, JWS syntax, header per §8.1 (`malformed`, `too_large`);
2. `aud` is the address of a tenant of this gate and `iss` the address of a paired peer of that
   tenant (`not_paired`; the same response for an unknown tenant);
3. `kid` names a key valid now for that peer (§2), and the signature verifies with that key
   (`bad_signature` for either); for `key.rotate` and `key.revoke` the key is the peer's current
   key, `key_revoked` or not, and never the previous key;
4. `iat <= now + 300` (`from_future`) and `now - iat <= 604800` (`stale`);
5. event id dedupe per `(tenant, iss, id)`: same `envelope_sha256` seen returns `200` with the
   stored receipt and status `duplicate`; a different one is `conflict`. Seen ids are kept for at
   least 604800 + 300 s;
6. known `type` (`unsupported`); `data` valid (`malformed`);
7. for `message`: §8.4; for `key.rotate`: §10.6; for `key.revoke`: §10.7; peer volume limits
   (`rate_limited`);
8. store the inbox item and the event id in one transaction, then answer with a signed receipt.

### 10.4 Retry

The sender retries on connection failure, any 5xx, `429` and `from_future`, with exponential
backoff from 5 s doubling to a cap of 3600 s, jitter of ±20%, honouring `Retry-After`, until 72 h
after `iat`; then the delivery is `failed` and the owner is notified. Any other 4xx ends the
delivery as `failed` at once. Unknown error codes are classified by HTTP status alone. A `200`
whose receipt does not verify counts as a failed attempt.

### 10.5 Receipt and errors

A `200` response body is a JWS with `typ` `paseka-receipt+jwt` signed by the receiver
(`contracts/wire/receipt.schema.json`): `v`, `iss` (receiver address), `aud` (sender address),
`id` (event id),
`envelope_sha256`, `received_at`, `status` (`accepted` or `duplicate`). The sender verifies it with
a key valid now for the receiver's address (§2) and stores it as delivery proof.

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

### 10.6 Key rotation

A tenant replaces its key by sending every active peer a `key.rotate` envelope signed with the
key being replaced. Its `data` (`contracts/wire/key-rotate.schema.json`):

- `new_key`: key id of the key that becomes current;
- `next_key_sha256`: SHA-256 of the 32-byte public key that will follow `new_key`, the
  pre-rotation commitment (ADR 0013);
- `previous_valid_until`: `iat + N`, where N is the sender's grace;
- `proof`: proof of possession of `new_key`, a compact JWS with header
  `{"alg": "EdDSA", "kid": <new_key>, "typ": "paseka-key-proof+jwt"}` signed by `new_key`. Its
  payload (`contracts/wire/key-proof.schema.json`) is `{v, iss, new_key, next_key_sha256,
  previous_valid_until}`: `iss` is the envelope `iss`, the other fields equal those of `data`.

The grace N defaults to 7 days, the envelope acceptance window of §10.3, and is an owner setting
of 1 to 30 days (§9.4); in code `paseka_core::peer::DEFAULT_GRACE_DAYS` and
`paseka_core::peer::GRACE_DAYS`. Pairing messages carry the first commitment (§11).

After §10.3 steps 1 to 6 the receiver checks, in order:

1. the envelope verifies with the current key of the `iss` address, `key_revoked` or not; the
   previous key does not count, even in its grace (`bad_signature`);
2. `new_key` names an Ed25519 public key (`malformed`);
3. `proof` passes §8.1 with `typ` `paseka-key-proof+jwt` and the key `new_key`, and its payload
   equals the envelope `iss` and the `new_key`, `next_key_sha256` and `previous_valid_until` of
   `data` (`bad_signature`);
4. if SHA-256 of the 32 bytes of `new_key` equals the `next_key_sha256` on record, it accepts the
   rotation without asking its owner: the current key becomes the previous key with
   `previous_valid_until = min(data.previous_valid_until, iat + 30 days)`, replacing any earlier
   previous key, or, if the peer is `key_revoked`, no key keeps a grace; `new_key` becomes the
   current key; `data.next_key_sha256` becomes the commitment on record; the `key_revoked` mark
   and any pending key change are cleared;
5. otherwise, with no commitment on record or a commitment to another key, the keys on record do
   not change: the current key keeps working unless `key_revoked`, `new_key` is not accepted, and
   `new_key` becomes the pending key change, waiting for the receiving owner's confirmation
   (§10.8).

In cases 4 and 5 the event is stored and answered per §10.3 step 8. Once `now` reaches
`previous_valid_until`, envelopes signed with the previous key fail with `bad_signature` and
mandates signed with it with `mandate_invalid`.

### 10.7 Key revocation

A tenant declares its current key compromised by sending every active peer a `key.revoke`
envelope signed with that key. Its `data` (`contracts/wire/key-revoke.schema.json`):

- `revoked_key`: key id of the sender's current key;
- `replacement` (optional): `new_key`, the key id of the key that becomes current;
  `next_key_sha256`, the commitment to the key that will follow it; and `proof`, a compact JWS
  with header `{"alg": "EdDSA", "kid": <new_key>, "typ": "paseka-key-replacement+jwt"}` signed by
  `new_key`. Its payload (`contracts/wire/key-replacement.schema.json`) is `{v, iss, revoked_key,
  new_key, next_key_sha256}`: `iss` is the envelope `iss`, `revoked_key` that of `data`, the
  other fields those of `replacement`.

The sender names as replacement its pre-committed next key when that key is usable; otherwise it
names a fresh key, which takes effect only through §10.8, or no replacement.

After §10.3 steps 1 to 6 the receiver checks, in order:

1. the envelope verifies with the current key of the `iss` address, `key_revoked` or not; the
   previous key does not count, even in its grace (`bad_signature`);
2. `revoked_key` names that current key (`malformed`);
3. with a replacement: `new_key` names an Ed25519 public key other than `revoked_key`
   (`malformed`), and `proof` passes §8.1 with `typ` `paseka-key-replacement+jwt` and the key
   `new_key`, with a payload equal to the envelope `iss`, `revoked_key` and the `new_key` and
   `next_key_sha256` of `replacement` (`bad_signature`);
4. it marks the peer `key_revoked`: from now on the current key is not valid (§2), the previous
   key's grace ends whatever its `previous_valid_until`, and any pending key change is dropped;
5. with a replacement whose `new_key` has a SHA-256 equal to the `next_key_sha256` on record,
   `new_key` becomes the current key with no previous key, `replacement.next_key_sha256` becomes
   the commitment on record, and the `key_revoked` mark is cleared;
6. with any other replacement, `new_key` becomes the pending key change with no grace for the
   revoked key (§10.8).

A refused revocation changes nothing. A stored one is answered per §10.3 step 8. After step 4
every envelope signed with the revoked key fails §10.3 step 3 with `bad_signature`, except
`key.rotate` and `key.revoke`: those can install only a key matching the commitment on record or
one the receiving owner confirms, so the revoked key adds no authority to them, and the genuine
owner can still complete the change with the committed key. A revocation signed with the
compromised key alone therefore only removes authority: a thief can use it to deny service,
which holding the key already allows, and never to install a key. Once the new key is current,
the sender re-seals undelivered envelopes with it.

### 10.8 Owner-confirmed key change

A `key.rotate` (§10.6 step 5) or `key.revoke` replacement (§10.7 step 6) that the commitment does
not cover becomes the peer's pending key change: `new_key`, its `next_key_sha256`, and the grace
of the replaced key, which is the capped `previous_valid_until` of a rotation received while the
peer is not `key_revoked`, and none otherwise. A peer record holds at most one pending key change;
a later one replaces it, a revocation drops it, and an installed key clears it. Until the owner
confirms it, the current key keeps working unless `key_revoked`, and `new_key` is not accepted.

Receiving side:

1. the gate notifies its owner of the pending key change and shows, in the Mini App, the peer,
   both addresses, the fingerprints of the current and the new key, whether the current key is
   revoked, and the key-change short authentication string;
2. the owner compares the string with the peer's owner through a channel outside the gates and
   confirms at A2 (§7.4); the confirmation names `new_key`. Only the consent path passes it to the
   gate; the agent interface has no such operation (§5.2);
3. if the pending key change still names that `new_key`, `new_key` becomes the current key, the
   replaced key becomes the previous key until the stored grace (none after a revocation),
   `next_key_sha256` becomes the commitment on record and the `key_revoked` mark is cleared;
   otherwise nothing changes and the owner sees the pending key change now on record, if any.

Key-change short authentication string: the first 4 bytes of
`SHA-256(frame("paseka/key-change-sas/v1") || frame(address whose key changes) || frame(address
of the confirming peer) || frame(current key id on record) || frame(new key id))` as an unsigned
integer modulo 1000000, as six digits.

Sending side: the owner starts a key change without a usable commitment, or a revocation, through
consent with PIN or password in the Mini App (ADR 0013). The gate creates the new key and the key
that will follow it, sends every active peer `key.rotate` or `key.revoke` with the replacement,
and shows its owner, per peer, the key-change short authentication string. The owner tells each
peer's owner through a separate channel that the key changed and reads them the string; a notice
sent through the gates proves nothing, because a holder of the old key can send the same one.

## 11. Pairing

Pairing exchanges tenant addresses, keys and endpoints between an inviter (alice) and an invitee
(bob). Each side pins the other's key for the other's address; each owner consents on their side. The agent has no part
in pairing.

1. Invite. Alice creates an invite in her Mini App. Her gate stores
   `{tenant, code, expires_at (default 24 h, at most 7 days), used: false}` and shows the deep link
   `https://t.me/<consent_bot>?start=pair_<code>`. Alice sends the link to bob out of band.
2. Invite card. Bob opens the link; alice's consent bot receives `/start pair_<code>` from
   Telegram user U. The gate records U (id, username, name) on the invite (first opener only) and
   replies with the pair URI:
   `paseka:pair?v=1&ep=<percent-encoded alice endpoint>&a=<alice address>&k=<alice key id>&c=<code>`.
3. Request. Bob gives the pair URI to his own gate (Mini App "Add peer", or a message from an
   approver to his consent bot). Bob's Mini App shows alice's endpoint host and key fingerprint;
   bob names the peer and consents at A2. Bob's gate POSTs to `<ep>/v1/pair` a JWS
   `paseka-pair+jwt` signed by bob's key: `{v, type: "pair.request", id, iss: bob address,
   aud: a, key: bob key id, code, endpoint: bob endpoint, name_hint, iat, next_key_sha256?}`,
   where the optional `next_key_sha256` is bob's first rotation commitment (§10.6).
4. Accept. Alice's gate verifies the signature with the key in `key`, whose id `kid` names
   (self-certifying), `aud` is the tenant that issued the code, `|now - iat| <= 300`, and
   consumes the code atomically (`invite_invalid` if unknown, used or expired). An `iss` that is
   one of its own tenants, or is already recorded for that tenant with another key, is refused
   (`conflict`); a recorded key changes only by rotation, revocation or owner-confirmed change
   (§10.6 to §10.8). Likewise a gate never registers a tenant whose address one of its tenants
   records as a peer. It stores bob's `key` and
   `next_key_sha256` for bob's address as a peer in state `pending_owner` and answers `200` with
   a JWS signed by alice's key: `{v, type: "pair.accept", id, iss: alice address, aud: bob
   address, key: alice key id, request_id, request_sha256, endpoint: alice endpoint, iat,
   next_key_sha256?}`, with alice's first commitment.
5. Bob's gate verifies the accept: `kid` names `k` from the URI and the signature verifies with
   it, `key` equals `k` and `iss` equals `a` (CA-37), `aud` is bob's address, `request_sha256` is
   SHA-256 of the request JWS bytes. It stores key `k` and the accept's `next_key_sha256` for
   address `a` as an active T0 peer, refusing `a` as in step 4.
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
  bot plus approver binding, the envelope `aud` address of a verified envelope. Never from a
  payload field alone.
- TI-3 An id of another tenant behaves exactly like a nonexistent id (`not_found`, same timing
  class).
- TI-4 Identity keys, bot tokens, dictionaries, canaries, shelves, templates, policies, journals
  and counters are per tenant. No cache is shared without the tenant in its key.
- TI-5 A shared consent bot (hosted mode) resolves the tenant from the nonce or request id and
  then requires the Telegram user to be an approver of that tenant (CA-39).
- TI-6 Rate limits, storage quotas and queue sizes are per tenant.
- TI-7 Journal export and migration to self-host export one tenant: its key, settings, peers,
  journal. Peers keep working because the address stays the same; only the endpoint changes,
  which the gate announces through a later event type.

## 13. Versioning

Contract evolution and reader tolerance (unknown fields ignored, informational enums with an
`Unknown` fallback, authority-bearing values fail closed) are defined in `contracts/README.md`.
