# 0019. Open mandates never widen the source registry

Status: Accepted
Date: 2026-11-21

## Context
Conversation trust is an open mandate on one thread with no message limit (ADR 0017). An agent
fed instructions in that conversation could otherwise send, for its whole duration, content the
owner marked Ask in the source registry (ADR 0018). The owner decided (GRILL D3, to decision 9
and O9) that a conversation mandate removes the owner's question only for content the registry
already lets go to that peer without asking. The open-mandate constraint `private_sources`
(`deny` or `allow`) predates the registry and had no stated meaning relative to it.
`PeerView.conversation_until` (per peer) overlapped with `thread_trust` (per thread).

## Decision
- Under any open mandate, conversation trust included, a revision with a registry hit leaves
  without the owner only if every hit towards the recipient is Allow and no other stage flagged.
  An Ask hit goes to the owner at the stage floor; a Never hit blocks.
- `private_sources` only narrows the registry. A revision with a registry hit, whatever its
  decision, matches the mandate only under `allow`; under `deny`, or without the constraint, it
  does not match, so even an Allow hit goes to the owner. Under `allow` the registry decides each
  hit. The enum keeps both values (contracts only grow).
- `PeerView.conversation_until` stays: it is the `exp` of the one active conversation mandate with
  that peer (one per tenant, peer and trust, PROTOCOL §8.3), present exactly when `thread_trust`
  of its thread is active. Only `thread_trust` names the thread.

## Consequences
- PROTOCOL §4.4, §6.4 and §8.3, the `propose` tool description and the descriptions of
  `private_sources` and `conversation_until` state the rule. The code already behaved this way:
  S12 releases only without flags, an Ask hit is a flag, and `OpenBook::matches` refuses a
  registry hit unless `private_sources` is `allow`.
- SP-24 covers Ask content under open mandates; CA-55 attacks it under conversation trust.
