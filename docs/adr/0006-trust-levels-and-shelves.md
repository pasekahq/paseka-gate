# 0006. Per-peer trust levels T0 to T3; shelves share by pointer

Status: Accepted
Date: 2026-11-18

## Context
Owners want to be liberal with some peers without approving every message. Letting the agent
send free text freely is unsafe under hijack; letting it send documents by content invites
smuggling.

## Decision
- Trust is expressed as open mandates per peer:
  - T0: nothing without consent. Default for a new peer.
  - T1: templates and structured answers.
  - T2: shelves. The owner opens collections of the library to a peer. The agent calls
    `share {doc, section, note}`; the gate checks the doc is on a shelf open to that peer, reads
    the bytes from the shelf itself and sends them. The note is at most 200 characters and must
    have no links and no structural flags.
  - T3 (later): free text without consent on allowed topics, scoped by peer, topics, expiry with
    renewal and daily volume; hard blocks still apply (canaries, fingerprints of shelves not open
    to that peer, secrets, attachments outside shelves go to manual); evening digest, revoke,
    kill switch, spike alerts and automatic fallback to manual.
- T2 is the main way to be liberal; MVP ships T0 to T2.

## Consequences
- The agent never supplies shelf bytes, so it cannot alter or extend what a shelf share sends.
- Shelf membership and peer grants change only through consent.
- T3 is the owner's conscious risk and ships after the MVP with its own conformance attacks.
