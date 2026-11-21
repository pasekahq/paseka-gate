# 0016. A canary hit raises a full alarm by default; only an A2+ decision clears it

Status: Accepted
Date: 2026-11-21

## Context
A canary in a draft means the agent tried to send something the owner marked as never to leave.
Tripwire mode stopped open mandates and raised new drafts to A2, and the owner cleared it in the
Mini App at A2. The owner decided (GRILL decision 8) that a hit is a full alarm: the draft is
blocked, every open mandate stops, every draft needs the strongest available protection, A2 plus
the PIN, and the alarm ends only through consent with the PIN. The owner may weaken the reaction,
for example to blocking the draft only, but the default is the full alarm and the agent can
weaken nothing. This changes the S11 floor of PROTOCOL §6.2 and adds a security property to
`docs/THREAT-MODEL.md`.

## Decision
- The tripwire mode setting (`paseka_core::tripwire::TripwireMode`) is a security setting
  (PROTOCOL §9.4) with two values: full alarm, the default, and draft block only. A change needs
  an owner decision at A2 or higher and is refused while tripwire mode is active, so weakening the
  setting is never a way around the clear.
- Under the full alarm a hit enters tripwire mode for the tenant, recording the trigger: peer,
  draft id and revision, canary ids and the MCP journal window of the turn. A further hit keeps
  the earlier triggers, adds its own and revokes a live clear request, so the owner never clears
  an alarm without having seen every trigger.
- While tripwire mode is active the S11 floor is A2+ (`TRIPWIRE_LEVEL`), raised like every floor
  (ADR 0005), and open mandates are inactive. With the MVP channels the selection of ADR 0015
  sends every request through `telegram-miniapp-pin`.
- Clearing needs a decision on a live clear request through a channel that satisfies A2+; in the
  MVP that is the PIN channel, with the PIN attempt limit of PROTOCOL §7.5. A1, A2, open mandates
  and the agent cannot clear it; the agent interface gains nothing.
- Each hit yields one owner notice with the trigger. It names canaries by id and carries no
  canary marker and no body.

## Consequences
- SP-23 and CA-53 cover the clear: A1, A2, open mandate, mode change and agent attempts are
  refused. CA-19 and CA-20 are unchanged.
- During the alarm every draft costs the owner a PIN entry. This is the intended friction; the
  owner who wants less sets draft block only after clearing.
- A tenant without a PIN cannot clear until it sets one by the local CLI on the gate host.
- Delivery of the notice, the clear screen and journal storage belong to the consent bot, the
  Mini App and the journal; the core holds the state and the checks.
