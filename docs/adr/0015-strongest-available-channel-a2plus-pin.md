# 0015. A level above every channel goes through the strongest one; A2+ is Mini App plus PIN

Status: Accepted
Date: 2026-11-21

## Context
Fingerprint hits and reads from sensitive folders require A2+ (ADR 0005), and the owner may raise
rules to A3. The concept names A2+ as a biometric-unlocked key and A3 as a passkey, neither of
which is in the MVP, so such drafts could never be released at all. The owner decided (GRILL
decisions 7 and 7a) that high risk is never blocked for a missing channel: the strongest
protection available at that moment is required, and in the MVP the A2+ step is the Mini App plus
a PIN or password. This deviates from `docs/concept/CONCEPT.md`, which lists A2+ as biometric
only, and changes SP-7 of `docs/THREAT-MODEL.md`.

## Decision
- A2+ in the MVP is the channel `telegram-miniapp-pin`: the A2 Mini App review plus the owner's
  PIN or password, entered only in the Mini App, never in chat (PROTOCOL §7.5). A biometric key
  (`telegram-miniapp-biometric`) and owner attestation come later as further A2+ channels, the
  passkey as A3; the PIN stays as a fallback when biometrics arrive.
- Channel selection is a pure function of the required level and the tenant's configured human
  channels (`paseka_core::channel::Channels::select`). When a configured channel satisfies the
  level, the request goes through the weakest such channel and only channels that satisfy the
  level can decide it. When none does, the request goes through the strongest configured channel,
  marked as above the available channels, and only channels at that channel's level can decide
  it. A draft is never blocked because its level is unavailable; `blocked` with reason `policy`
  remains for canaries and hard rules.
- The required level is never lowered. Evaluation still computes the maximum of all floors; the
  approval request keeps that level, and the approval challenge binds it (PROTOCOL §3.3). What
  changes is only which channel may approve when no configured channel reaches the level.
- The owner sees the required level, the channel used, and, when the level is above every
  configured channel, a notice that the strongest available protection is being used instead.
- The evidence records the channel's own level and, in the marked case, the new optional field
  `required_level`. The closed mandate records the level the channel attests, so its `level`
  and `proof.channel` always agree for a receiver (PROTOCOL §8.4); the marker reaches a peer
  only through the evidence behind `proof.evidence_sha256`.
- The PIN evidence records that the gate accepted the PIN and the A2 fields; it never contains
  the PIN, the password or anything derived from them.
- Contract growth only (ADR 0010): a new channel value, a new evidence schema and a new optional
  evidence field.

## Consequences
- ADR 0005's monotonic property holds: no rule lowers the computed level, and the stored request
  level is the computed one. CA-47 holds: a weaker channel never decides a request that a
  configured channel satisfies, because then the floor is the required level itself. CA-21
  checks that an A3 draft is sent through the PIN channel, marked, and refused through the plain
  Mini App.
- An owner who configures a stronger channel later raises the floor of every new request;
  existing requests keep the selection made when they were opened.
- A3 content in the MVP is protected by A2+ only. The owner learns this on every such prompt and
  can deny.
- A receiver cannot tell from a mandate alone that the sender's requirement was higher than its
  `level`; it sees only what the sending gate attests (THREAT-MODEL A-5).
