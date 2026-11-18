# 0009. Clean slate: no compatibility with the old Python gate

Status: Accepted
Date: 2026-11-18

## Context
An earlier Python gate (agent-peer-protocol, Event 0.2, HMAC-authenticated) exists. Its
shared-secret model, wire format and consent flow differ from the mandate model of ADR 0003.
Compatibility would carry HMAC trust and a second wire format into a security core.

## Decision
- No wire, storage or key compatibility with the old gate.
- Old guests are re-invited manually through pairing links.
- Its consent-forgery tests (CF-1 to CF-10) are used as a source of attack ideas for the
  conformance suite; no code is ported.

## Consequences
- No migration tool. Owners of the old gate run both until their peers are re-invited.
- `docs/THREAT-MODEL.md` §6 maps each old attack idea CF-n to the conformance attacks that
  cover it.
