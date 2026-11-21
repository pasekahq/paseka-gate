# 0020. Pairing SAS binds addresses; unverified peers are capped at T1

Status: Accepted
Date: 2026-11-21

## Context
Pairing pins each side's key for the other's address (ADR 0013). A gate or relay that substitutes
a key or an address during pairing is caught only if the owners compare something out of band.
The pairing short authentication string covered both key ids and the invite code but not the
addresses, which are what the owners agree to pair. The owner decided (GRILL decision 10) that
the comparison is offered by default and skipped with one tap, that a skipped comparison marks
the peer not verified, that trust above T1 then needs verification, and that the owner may turn
that requirement off (weakening only through consent). GRILL does not place conversation trust
relative to T1.

## Decision
- The SAS uses the domain string `paseka/sas/v2` and binds the inviter's address and key, the
  invitee's address and key, and the invite code, in that order. It is a display value, not a
  wire field; the vector is regenerated in place before any release.
- Each gate records per peer whether its own owner confirmed the SAS. The owner can confirm later
  through a decision at A2. The agent cannot, and sees the state as the optional
  `PeerView.verified`.
- While the tenant's verification requirement is on, the default, the gate refuses to present or
  sign an open mandate of trust T2, T3 or `conversation` for a peer that is not verified. T1 and
  T0 never need verification.
- Conversation trust counts as above T1: it releases free text the owner has not read, where T1
  releases only rendered templates the owner wrote.
- The requirement is a security setting changed only on the settings page at A2 or higher.
  Turning it on does not end active open mandates; the owner revokes them.

## Consequences
- PROTOCOL §11 describes the flow, the SAS and the rule; §9.1 and §9.4 point to it.
- `contracts/agent/views` gains the optional `PeerView.verified`; `digests.json` adds both
  addresses to the `sas` vector input and changes its value.
- `paseka_core::open::OpenBook::present` and `activate` take a
  `paseka_core::pairing::VerificationCheck`.
- SP-15 covers the rule; CA-56 attacks it.
