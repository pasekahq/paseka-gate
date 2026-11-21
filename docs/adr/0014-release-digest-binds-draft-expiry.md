# 0014. The release digest binds the draft expiry; the closed mandate carries it

Status: Accepted
Date: 2026-11-21

## Context
The owner approves a draft for a limited time: every draft has a lifetime, an owner setting from
5 minutes to 7 days with a default of 12 hours, and a closed mandate may be issued again on a
retry without asking the owner, but only while the draft is alive (GRILL items 3, 6 and 11).
Without the expiry inside what the owner approves, the sending gate could keep issuing mandates
for an approved draft indefinitely, and the receiver could not tell. The receiver can only check
what it can recompute, so it needs the expiry as a claim.

## Decision
- Every draft has `expires = created_at + lifetime`, fixed at creation. Prompts are capped at
  `expires`; no closed mandate is issued at or after it, also not for a retry, and a draft not
  yet released moves to `expired`.
- The release digest keeps its composition (tenant, both addresses, thread, reply target, content
  hash, attachment metadata) and adds `u64be(expires)` after the reply target (PROTOCOL §3.2).
  The approval challenge binds the digest, so the owner's consent covers the expiry.
- The digest uses the new domain string `paseka/release/v2`, so a digest of the previous
  composition can never be taken for one of the new composition. Only the new formula exists in
  code; there is no dual path.
- The closed mandate gains the required claim `expires`. The receiver recomputes the digest with
  it and refuses with `mandate_invalid` a mandate whose `iat` is not before `expires`
  (PROTOCOL §8.4).
- The change is made in place in contract version 1, as with ADR 0013. Making a new claim required
  is not additive (ADR 0010), but no release, tag or deployed peer exists, so no reader of the
  previous shape exists either. `contracts/README.md` records it in the changelog. After the first
  release such a change needs a new major version.

## Consequences
- A sender cannot stretch an approved draft's life: a changed `expires` breaks the digest, and a
  mandate issued after `expires` is refused by every receiver.
- A receiver learns the draft expiry of each message, which reveals the sender owner's lifetime
  setting to the peer; it carries no content.
- The digest vectors, the approval challenge, the evidence, the signed closed mandate and the
  envelope fixtures carrying it all depend on `expires`; the generator in `paseka-core` writes
  them from the seeds, never by hand.
