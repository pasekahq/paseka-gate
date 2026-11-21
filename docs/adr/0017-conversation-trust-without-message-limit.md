# 0017. Conversation trust has no message limit; defaults live in one table

Status: Accepted
Date: 2026-11-21

## Context
The concept bounds conversation trust by 30 minutes and by a count of 10 messages. The
owner decided otherwise (GRILL items 9 and 11): conversation trust is an open mandate on one
thread for a duration the owner sets, 30 minutes by default, with no message limit; only the
agent's limit of 30 drafts per peer per hour bounds it. The same decision sets 50 pending drafts
per tenant. The protocol stated its defaults in many sections, and two of them disagreed with
the decision.

## Decision
- A `conversation` open mandate needs `thread` and may have an empty `rate`. Its lifetime is the
  owner's duration setting, 30 minutes by default and at most 24 hours. The other trusts keep a
  non-empty `rate`.
- The gate refuses a new draft with `rate_limited` when the tenant has 50 drafts in
  `awaiting_consent` or the agent created 30 drafts to that peer within the last hour. The check
  runs before evaluation, for every draft, under every open mandate; it does not depend on the
  evaluation, so a refusal reveals no level to the agent.
- Every default, limit and window is stated once, in PROTOCOL §14, with its code name. Other
  sections refer to it. `contracts/defaults.json` is its machine-readable copy, and a
  `paseka-core` test fails when a constant differs from that file or either lists a parameter
  the other lacks.
- The open mandate schema drops the `max_messages` requirement and the non-empty `rate` for
  `conversation`. Loosening a writer rule is not listed as growth (ADR 0010), but open mandates
  never leave the issuing gate, so no other reader exists; the change is made in place in
  contract version 1 and recorded in the `contracts/README.md` changelog. The fixture of a
  conversation mandate with an empty `rate` moves from invalid to valid, and a T1 mandate with an
  empty `rate` becomes the invalid case.

## Consequences
- One tap on "send and continue in this thread" lets the agent release up to 30 messages an hour
  in that thread until the duration ends, each still evaluated: any flag sends it to the owner.
- The owner sees at most 50 open prompts per tenant; a further draft is refused as
  `rate_limited`, which the agent may retry.
- A default changes in one table row, one data file entry and one constant, and the test catches
  a row that drifts.
