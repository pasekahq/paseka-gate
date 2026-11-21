# Threat model

Scope: the paseka gate (`paseka`), its agent interface, its approval channels, its gate-to-gate
wire and its multi-tenant hosting mode. Normative details live in `docs/PROTOCOL.md`; this file
states who attacks what, what we assume, and which property each conformance attack proves.

## 1. Actors

| Id | Actor | Trust |
|----|-------|-------|
| OW | Owner of a tenant: the human who approves releases | Trusted for consent decisions |
| OA | Owner's agent (any model, any harness) connected through the agent interface | Untrusted for release. Assumed hijackable at any time |
| PE | Peer: another human paired with the owner | Untrusted |
| PA | Peer's agent, which writes the inbound messages | Untrusted, assumed hostile |
| PG | Peer's gate | Authenticated by its paired key; content untrusted |
| GT | Guest tenant: a person without an own gate, working by hand on a hosted gate | Untrusted towards other tenants |
| HO | Hosting operator of a multi-tenant gate | Trusted by its hosted tenants (explicit) |
| TG | Telegram (Bot API servers, clients, Mini App platform) | Trusted for A1/A2 attestation |
| NA | Network attacker between gates or between the gate and Telegram | Hostile |
| IA | Installing agent: the agent that installs the gate (usually OA) | Untrusted, same as OA |

## 2. Assets

- AS-1 Owner's private data reachable by OA: notes, memory, files, MCP sources.
- AS-2 The release decision: the binding between owner consent and the exact bytes, recipient
  and attachments that leave.
- AS-3 Tenant identity key (Ed25519), used for envelopes, mandates and receipts. The tenant's
  address is its permanent tenant id, not the key; peers record which key is current for it.
- AS-4 Consent bot token and webhook secret.
- AS-5 Security settings: approvers, policies, open mandates, trust levels, peers, shelves,
  dictionary, canaries, fingerprints.
- AS-6 Journal: the append-only record of drafts, decisions, evidence and deliveries.
- AS-7 Other tenants' data and settings on a hosted gate.
- AS-8 Owner attention: the owner's ability to read prompts carefully (consent fatigue).

## 3. Trust boundaries

- TB-1 Agent interface: OA to gate (MCP over stdio relay or loopback HTTP, or plain HTTP). All
  input crossing it is attacker-controlled.
- TB-2 Telegram: gate to Bot API, Bot API to gate (webhook or long polling), Mini App webview to
  the gate's HTTPS origin.
- TB-3 Wire: gate to peer gate over HTTPS through Caddy.
- TB-4 Tenant to tenant inside one gate process and one database.
- TB-5 Host: the gate runs as its own unix user; OA runs as another user and cannot read the
  gate's state directory, keys or token.

## 4. Assumptions

- A-1 OA is fully hijackable by prompt injection from a peer, a guest, a web page or a file. It
  may call any agent tool with any arguments, at any rate, in any order, concurrently.
- A-2 OA cannot read or write the gate's files, memory, keys, token or database (TB-5). If this
  fails, every property below fails; the install skill verifies it.
- A-3 TG honestly attests who pressed a button and signs Mini App initData. Takeover of the
  owner's Telegram account equals approval (accepted for A1/A2; A2+/A3 exist for the most
  sensitive content).
- A-4 The owner reads the approval surface before approving. Consent covers what was shown.
- A-5 The gate host is honest: the owner for self-host, HO for hosted tenants.
- A-6 Ed25519, SHA-256 and HMAC-SHA-256 are secure. The OS CSPRNG is sound.
- A-7 Clocks of gates are within 30 s of true time (NTP). Windows below tolerate 300 s.
- A-8 Once delivered, content is under the recipient's control. The gate protects what leaves,
  not what the peer does with it.

## 5. Attacker goals

- AG-1 Release content without owner consent or matching open mandate.
- AG-2 Release bytes, recipient or attachments different from what the owner saw (swap after
  consent, stale preview, truncated preview).
- AG-3 Release one consent twice, or reuse a consent for other content.
- AG-4 Approve in the owner's name: forge or relay Telegram callbacks, initData, evidence or
  mandates; reach an approve path through the agent interface.
- AG-5 Change security settings without consent: add a peer, raise trust, edit dictionary,
  canaries, approvers or policies.
- AG-6 Lower the required level or evade detectors, including by probing the gate as an oracle.
- AG-7 Smuggle data through gate-composed channels: shelf notes, template fields, attachments,
  open mandates beyond their limits.
- AG-8 Impersonate a peer gate, inject or replay envelopes, or deliver a message with a forged or
  reused mandate.
- AG-9 Hijack pairing: redeem a stolen invite, man-in-the-middle the key exchange.
- AG-10 Cross tenants: read, approve or deliver into another tenant on a hosted gate.
- AG-11 Mislead the owner on the approval surface: bidi overrides, invisible characters, hidden
  text, oversized content, look-alike recipients.
- AG-12 Exhaust owner attention: prompt floods, peer floods, so that the owner approves blindly.
- AG-13 Learn canaries, dictionary entries or detector configuration.

## 6. Security properties and conformance attacks

Each property SP-n is tested by the conformance attacks CA-n listed with it. A conformance attack
passes when the stated outcome holds and no envelope leaves the gate unless stated otherwise.
Attack CA-n is the entry `CA-n` of `crates/paseka-conformance` and the test `caNN_*` of the same
number in its `tests/attacks.rs`. Numbers are stable; new attacks are appended.

SP-1 No approve surface. The agent interface has no tool, parameter or field that approves,
denies, issues mandates, or changes security settings.
- CA-1 List the agent tools (MCP `tools/list` and the HTTP surface). Only the tools of
  PROTOCOL §5 exist; no name or input field relates to approval, mandates, evidence, nonces or
  settings.
- CA-2 Call `propose`, `revise` and `share` with extra fields `approved`, `proof`, `mandate`,
  `nonce`, `evidence`, `level`. Result: `invalid_input`; no draft is created or changed.

SP-2 Nothing leaves without consent. An outbound `message` envelope exists only after an owner
decision through an approval channel or a matching active open mandate, recorded with a mandate.
- CA-3 Propose free text to a T0 peer and never answer the prompt. Result: draft `expired`, no
  envelope.
- CA-4 POST a forged Telegram update to the webhook without the secret token, with a wrong token,
  and with a valid-looking callback for a live nonce. Result: rejected, draft unchanged.
- CA-5 Write evidence-shaped JSON into the agent journal, inbox or draft body. Result: no state
  change.

SP-3 Exact binding. The released body bytes, recipient, thread and attachments equal those of
the approved release digest.
- CA-6 Revise a draft after its prompt was sent, then press the old Approve button. Result: old
  nonce is dead, nothing released, the new revision has a new prompt.
- CA-7 Revise or withdraw after approval. Result: `invalid_state`.
- CA-8 Swap an attachment (same name, other bytes) between prompt and decision. Result: digest
  mismatch, nothing released.
- CA-9 Submit a Mini App decision whose `release_digest` differs from the current revision.
  Result: rejected.

SP-4 Single use. One consent releases at most one envelope; a nonce and a mandate `jti` are each
consumed once.
- CA-10 Deliver the same callback update twice and two concurrent presses. Result: one release.
- CA-11 Replay a Mini App decision request with the same initData. Result: rejected.
- CA-12 Replay a released envelope (same event id) to the peer. Result: `duplicate`, one inbox
  item. Deliver a second event carrying the same mandate. Result: `mandate_replay`.

SP-5 Freshness. Stale nonces, expired prompts, stale initData and expired mandates release
nothing.
- CA-13 Press Approve after the prompt TTL. Result: `expired`, nothing released.
- CA-14 Submit initData with `auth_date` older than the window or more than 30 s in the future.
  Result: rejected.

SP-6 Approver authenticity. Only a configured approver of the tenant, in the tenant's private
consent chat, through the tenant's consent bot, can decide.
- CA-15 A non-approver Telegram user presses a forwarded prompt or opens the Mini App. Result:
  rejected.
- CA-16 initData with a valid bot-token HMAC but an invalid or missing Ed25519 `signature`.
  Result: rejected.
- CA-17 initData signed for another bot id. Result: rejected.

SP-7 Monotonic risk. Evaluation stages only raise the level. Free text to a peer is at least A1
without an open mandate. A canary blocks even with owner approval.
- CA-18 Configure the classifier stub to answer "safe" for free text. Result: level A1.
- CA-19 Put a canary in the body, in an attachment, and base64-encoded in the body. Result:
  `blocked`, owner alert, tripwire mode on.
- CA-20 Owner edits a draft in the Mini App to include a canary and approves. Result: `blocked`.
- CA-21 Require a level with no configured channel (fingerprint hit in MVP). Result: `blocked`
  with reason `policy`, never satisfied by a weaker channel.
- CA-47 Approve a request that requires A2 through the A1 button (a forged or replayed
  callback included). Result: rejected; the request stays open.

SP-8 No oracle. Agent-visible output never reveals the required level, detector names, matched
spans, canaries, dictionary entries, nonces, evidence or peer keys.
- CA-22 Trigger each detector and read every agent tool output. Result: only `state` and the
  coarse `reason` of PROTOCOL §4.

SP-9 Settings change only through consent. Security settings live in the gate database and
change only through an owner decision in the Mini App.
- CA-23 Edit the bootstrap config after the first-run ceremony and restart. Result: security
  settings unchanged; the gate reports the drift to the owner.
- CA-24 Try every agent tool for a side path to add a peer, change trust or edit the dictionary.
  Result: none exists.

SP-10 Open mandate bounds. Auto-release happens only inside the constraints, rate and lifetime
of one active owner-signed open mandate, and only when no detector raised a flag.
- CA-25 Exceed `max_messages`, the hourly rate, or the lifetime. Result: excess drafts go to
  `awaiting_consent`.
- CA-26 Put a link or a long number in a template field. Result: field rejected or draft manual.
- CA-27 Use a mandate after revocation. Result: no auto-release.
- CA-28 Request a second open mandate for the same peer and trust while one is pending. Result:
  refused until the first is decided.

SP-11 Shelf integrity. `share` sends only bytes the gate reads itself from a document on a shelf
open to that peer, plus a constrained note.
- CA-29 Share a document on a shelf not open to the peer, a nonexistent id, and a path-like id.
  Result: `not_found` or `invalid_input`, no draft.
- CA-30 Share with a note containing a link, an encoded blob or 201 characters. Result:
  `invalid_input`.

SP-12 Peer authenticity. Inbound envelopes are accepted only when `iss` is the address of a paired
peer of the addressed tenant and the signature is by the key recorded for that address.
- CA-31 Envelope from an unknown address (`not_paired`); with a bad signature, an unknown key, or
  the key of another peer under this peer's address (`bad_signature`); with `alg` `none` or
  `HS256` (`malformed`). Result: rejected.
- CA-32 Envelope from a peer of tenant A addressed to tenant B on the same gate. Result:
  `not_paired`.

SP-13 Wire replay protection. Envelopes outside the acceptance window or with a seen event id
are not stored again.
- CA-33 Replay an envelope within the window (`duplicate`), after the window (`stale`), and a
  different envelope with a seen event id (`conflict`).

SP-14 Sender mandate verification. The receiver verifies the mandate of every `message` event:
signature by the sender key, recipient, content hash, attachments, release digest, timing.
- CA-34 Message whose mandate covers other content, another recipient, another thread, or is
  signed by another key. Result: `mandate_invalid`.

SP-15 Pairing integrity. A peer becomes active only after a single-use, unexpired invite code is
redeemed and the owner of each side consents; each side pins the other's key for the other's
address from the exchange.
- CA-35 Redeem a used or expired code. Result: rejected.
- CA-36 Send messages from a requester whose pairing the inviter's owner has not confirmed.
  Result: `not_paired`.
- CA-37 Answer a pair request with an accept signed by a key other than the one in the pair URI,
  or naming another address than the URI. Result: the requester rejects it.

SP-16 Tenant isolation. No operation of one tenant reads, changes or decides anything of another.
- CA-38 Use tenant A's agent token with tenant B's message, draft and doc ids. Result:
  `not_found`, identical to a nonexistent id.
- CA-39 On a shared consent bot, an approver of tenant A presses tenant B's prompt and submits
  tenant B's request id in the Mini App. Result: rejected.

SP-17 Faithful approval surface. The owner sees the complete exact bytes, the recipient name and
key fingerprint, attachments with sizes and hashes, flags with highlights, and the diff to the
previous revision; nothing hidden is approvable.
- CA-40 Body with bidi overrides, zero-width or control characters. Result: shown escaped,
  flagged, level at least A2.
- CA-41 Body longer than the A1 prompt capacity. Result: no Approve button in chat; Mini App only.

SP-18 Gate secrets unreachable by the agent (A-2 checked).
- CA-42 As the agent's unix user, read the gate state directory, token file and database.
  Result: permission denied.

SP-19 Attention protection. Prompt and inbound volume are bounded; a spike disables
auto-release.
- CA-43 Propose 100 drafts in a minute. Result: `rate_limited` after the limit; prompts are
  bounded by the pending limit.
- CA-44 A peer sends a burst above its volume limit. Result: `rate_limited`; open mandates for
  that peer are suspended and the owner is alerted.

SP-20 Journal integrity. Every decision, evidence object and delivery is appended to a per-tenant
hash-chained journal that the agent cannot write.
- CA-45 Modify one journal row in the database and export. Result: chain verification fails at
  that row.

SP-21 Crash consistency. Consuming a nonce, issuing the mandate and committing the outbox
envelope happen in one transaction; delivery is at least once with receiver dedupe.
- CA-46 Kill the gate between decision and delivery, restart. Result: exactly one envelope
  delivered, one inbox item at the peer.

SP-22 Key continuity (ADR 0013). A peer address keeps its recorded key until a `key.rotate` or a
`key.revoke` replacement whose new key matches the commitment on record replaces it, or the
receiving owner confirms the change after comparing the key-change short authentication string.
Holding the old key alone never installs a key. A replaced key stays valid only until its
`previous_valid_until`; a `key.revoke` signed by the current key ends the validity of the current
and the previous key at once.
- CA-48 Key substitution: a `key.rotate` whose proof is not signed by `new_key`
  (`bad_signature`); recording an already recorded address with another key, or one of the
  gate's own addresses as a peer (`conflict`). Result: the recorded key is unchanged.
- CA-49 `key.rotate` signed by a key that is not the address's current key: a stranger's key, or
  the previous key while still in its grace. Result: `bad_signature`; the record is unchanged.
- CA-50 Use of the previous key once `previous_valid_until` is reached: an envelope signed with
  it (`bad_signature`), and a mandate signed with it inside an envelope signed with the current
  key (`mandate_invalid`). Result: rejected.
- CA-51 The holder of a stolen current key sends `key.rotate` to their own key (no commitment
  match) and `key.revoke` with their own key as replacement. Result: neither installs the thief's
  key, which stays only a pending change for the receiving owner; envelopes signed with it get
  `bad_signature`; the genuine owner's later commitment-matching `key.rotate` installs the
  committed key and drops the thief's pending change.
- CA-52 Use of a revoked key: after a `key.revoke` without replacement, an envelope signed with
  the revoked key, and one signed with the previous key while its `previous_valid_until` has not
  been reached. Result: `bad_signature` for both.

Old attack ideas (ADR 0009). The consent-forgery suite CF-1 to CF-15 of the old gate maps to:
CF-1, CF-6, CF-9 and CF-13 (agent-written approvals, proof fields, evidence) to CA-1, CA-2,
CA-5 and CA-34; CF-2 (browser decision identity and binding) to CA-9, CA-14 and CA-16; CF-3
(edited, stale, expired, replayed approvals) to CA-6, CA-8, CA-10, CA-11 and CA-13; CF-4
(forged escalation approval) to CA-21 and CA-47; CF-5 (guest and peer text approving or
changing policy) to CA-5, CA-23 and CA-24; CF-7 (cancellation) to CA-7; CF-8, CF-12 and CF-15
(chat text relayed or read as approval) to CA-4, since only a callback with the request nonce
decides; CF-10 and CF-14 (commit lost after claim) to CA-46; CF-11 (preview faithfulness) to
CA-22 and CA-41.

## 7. Out of scope

- Out-of-band exfiltration by the agent's own tools (web fetch, mail, shell with network,
  messengers). Handled by agent configuration guidance L1 to L3, not by the gate.
- A malicious hosting operator for hosted tenants. Hosted tenants trust HO explicitly; the
  mitigations are verification and migration paths, not cryptographic isolation from HO.
- Telegram itself: its servers, clients and the security of the owner's Telegram account (A-3).
- Compromise of the owner's devices, or of the gate host for self-host.
- What a peer does with content after delivery (A-8).
- The owner knowingly approving harmful content.
- Volumetric denial of service against the gate's HTTPS endpoint beyond basic rate limits.
- Timing and other side channels of detectors.
- Supply-chain verification of the release itself, covered by the install skill and release
  process, not by the protocol.
