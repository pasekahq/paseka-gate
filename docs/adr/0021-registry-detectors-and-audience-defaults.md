# 0021. Registry detectors for codes, vault secrets, private links and chats; audience defaults

Status: Accepted
Date: 2026-11-21

## Context
The source registry (ADR 0018) listed sources without a detector: one-time codes (whose decision
was already fixed at Never), named vault secrets, private links, and other chats and groups. The
owner decided (GRILL O9) how each is caught: a code detector, an exact value match, link domains
plus tokens in the query, and "content of group X is sensitive for everyone not in X". A quote of
what peer P sent, going back to P, is no leak. ADR 0018 made every source without a decision Ask
towards every peer, which would ask the owner before a chat member sees the chat's own content
or before P sees a quote of P. The repository has no regex dependency.

## Decision
- One-time codes: the built-in source `OneTimeCodes` gets a hand-written detector in S4. A code
  of 4 to 8 digits (not a year) or two groups of 3 or 4 digits counts within four words of a code
  keyword in English or Russian, unless a qualifier such as `zip` or `error` names a code that
  grants nothing; an `otpauth:` URI always counts. The decision stays Never for every peer.
- Named vault secrets: a registered kind `VaultSecret`, one source per value of at least 8
  characters, caught in S4 by an exact case-sensitive match in the body or in attachment text.
  Flags, notices and the journal name the source and never carry the value.
- Private links: a built-in source `PrivateLinks`, caught in S4 by a listed domain (defaults in
  PROTOCOL §6.4, the owner adds more) or an access parameter in the query or fragment. The S2
  link flag still applies.
- Other chats and groups: a registered kind `Chat` with its member peers, caught in S8 by
  fingerprints of its messages. `PeerInbound` names the peer whose messages it holds.
- A registered source without an owner decision has its kind's default: `Chat` is Allow towards
  its members, `PeerInbound` is Allow towards its own peer, every other source is Ask. An owner
  decision replaces the default for that peer, through the rules of ADR 0018: Never only on the
  settings page, one-time codes never changed.
- Image attachments lose their metadata when attached; the stripped bytes are hashed, evaluated
  and sent (PROTOCOL §3.1). The implementation lands with attachment handling (MVP M2).

The defaults keep the monotonic rule of ADR 0005 and hard rule 2 as ADR 0018 argues for Allow:
the default is part of S8's own floor for that source and peer, set when the owner registers the
source at A2, and no other stage's floor is lowered. A chat member or the author receives only
what they already have; every peer outside that audience stays at Ask.

## Consequences
- `paseka_core::source::SourceRegistry::towards` fills in the kind defaults under the owner's
  decisions; `risk::OwnerRules` holds vault values and private link entries; `risk::Draft`
  carries attachment text.
- A one-time code detector with a keyword window has false negatives (a bare code without a
  keyword) and false positives (a number near the word "code"); a false positive blocks the
  draft.
- SP-24 states the audience defaults and that vault values are never echoed; CA-57 attacks
  one-time codes and a Never vault secret under an owner approval and an open mandate.
- MinHash, OCR and an LLM paraphrase check stay later detectors of the same registry.
