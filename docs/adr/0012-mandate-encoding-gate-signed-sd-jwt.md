# 0012. Mandates are gate-signed SD-JWTs with zero disclosures; evidence stays behind a hash

Status: Accepted
Date: 2026-11-18

## Context
The concept asks for mandates in the AP2 / SD-JWT style and requires an ADR for any deviation.
AP2 signs mandates with the user's own key and carries selective disclosures. At A1 and A2 the
owner has no key: Telegram attests who pressed, and the gate holds the only signing key. The
channel evidence (raw `initData`, chat and message ids) is private to the owner and useless to
the receiving gate, which cannot verify Telegram's attestation of another tenant's bot.

## Decision
- A mandate is an SD-JWT with zero disclosures: a compact JWS (`alg` `EdDSA`, `kid` the id of the
  tenant's current key, `typ` `paseka-mandate+sd-jwt`) followed by `~`. No `_sd` claims and no key-binding JWT
  in version 1.
- The issuing gate signs every closed mandate with the tenant key on the owner's behalf, after
  the decision passed the approval-request checks (PROTOCOL §7.1), and for A0 releases under an
  open mandate.
- `proof` carries `channel`, `approved_at` and `evidence_sha256`; the evidence object itself
  stays in the issuing gate's journal. Publicly verifiable evidence (A3 passkey assertions) MAY
  be carried inline in `proof.evidence`.
- The closed mandate binds a release digest over tenant, the addresses of both tenants (ADR
  0013), thread, reply target, the draft expiry (ADR 0014), content hash and attachment metadata
  (PROTOCOL §3.2), not only the content hash.
- Open mandates never leave the issuing gate.

## Consequences
- One JWS implementation in the audited core; the test vectors in
  `contracts/fixtures/vectors/digests.json` fix the bytes.
- A receiving gate trusts the sender gate's statement about consent; it verifies binding,
  freshness and single use, not the human act. Owner-key signatures arrive with A2+ and A3.
- A later version can move evidence fields into disclosures under `_sd` without changing the
  outer format.
