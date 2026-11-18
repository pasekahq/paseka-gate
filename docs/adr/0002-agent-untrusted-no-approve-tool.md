# 0002. Every agent is untrusted; the agent interface has no approve tool

Status: Accepted
Date: 2026-11-18

## Context
A peer's message reaches the owner's agent as text. Prompt injection can take the agent over
completely; this is the normal case, not an edge case. Any release path the agent can call is a
release path the attacker can call. A refused approve tool still teaches the model that approval
is an agent action and invites retries and social engineering of the owner.

## Decision
- Every agent, the owner's own included, is untrusted for release. It may read anything and
  propose; it never approves.
- The agent-facing interface (MCP tools and the equivalent HTTP API) has no approve, release,
  consent or policy-editing operation. The operation is absent from the tool list and the route
  table, not present and refused.
- Consent comes only from an approval channel (ADR 0004) or an owner-signed open mandate
  (ADR 0003), never from a field the agent controls.
- What leaves is the exact bytes the owner saw, to that recipient, once per consent.

## Consequences
- The conformance suite checks that no agent-facing route or tool can change a draft to
  `approved` and that the tool list contains no approve-like tool.
- Owner-side operations (settings, peers, dictionary) use the approval channels too, so the
  agent cannot reach them by editing config files (ADR 0008).
- Out-of-band exfiltration through the agent's other tools is outside the gate; it is handled by
  agent configuration levels L1 to L3 (`docs/AGENT-SETUP.md`).
