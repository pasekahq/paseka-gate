# 0010. Contracts only grow; readers are tolerant

Status: Accepted
Date: 2026-11-18

## Context
Gates of different versions talk to each other, and agents of different kinds talk to the gate.
The ulei and qb audit showed that strict readers turn every additive change into an outage, while
silently accepting unknown values in security fields hides attacks.

## Decision
- Contracts in `contracts/` only grow. Fields are added as optional; nothing is renamed or
  removed without a new version and an ADR.
- Readers ignore unknown fields. Enums have an `Unknown` fallback variant.
- Security decisions never accept `Unknown`: an unknown mandate kind, level, channel or algorithm
  is a rejection, not a default. Tolerance applies to parsing, not to authorization.
- Hashed and signed content is never re-serialized for verification; the gate verifies over the
  received bytes per the canonicalization in `docs/PROTOCOL.md`.

## Consequences
- Each contract change updates the schema, a valid and an invalid fixture, and `paseka-proto`.
- Conformance includes an "unknown enum value in a security field" attack.
