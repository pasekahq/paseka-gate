# 0018. A source registry decides Allow, Ask or Never per source and peer

Status: Accepted
Date: 2026-11-21

## Context
Risk evaluation marked folders as sensitive. A fingerprint of such a folder (S8) or a read
from one (S9) gave A2+, and a secret (S4) or a personal identifier (S5) gave A2, the same for
every peer. The owner decided (GRILL O9 and the cross-cutting rule) to replace the sensitive mark
on folders with a registry of sources: for every pair of source and peer the owner sets Allow, Ask or Never.
Defaults are secure, weakening goes only through consent and never through the agent, Never is
lifted only in the settings, one-time codes are always Never, and under Ask the gate picks the
approval channel by risk. This deviates from `docs/concept/CONCEPT.md`, which names fingerprints
of and reads from folders marked sensitive, and adds the security property SP-24 to
`docs/THREAT-MODEL.md`.

## Decision
- A source is either the one source of a built-in detector (secrets, personal identifiers,
  one-time codes) or a source the owner registers with a kind and a gate id: files and folders,
  the agent's context (memory, skills, instruction files, system prompt), an MCP source, the
  messages of one peer, memory about third parties. PROTOCOL §6.4 lists every kind of the O9
  table with the detector that catches it; `docs/MVP.md` lists which detectors exist, which come
  before the MVP release and which after it.
- The registry holds one decision per tenant, source and peer address: Allow, Ask or Never. A
  source without a decision is Ask. One-time codes, 2FA and OTP are Never for every peer, and no
  decision changes that.
- The stages S4 (secrets), S5 (personal identifiers), S8 (fingerprints) and S9 (source reads)
  report the source they matched. The decision towards the recipient sets the stage's result:
  Never blocks the draft; Ask gives the stage's floor (A2 for S4 and S5, A2+ for S8 and S9) and
  a flag, so the open mandate stage S12 cannot release it; Allow gives no floor and no flag, and
  the owner still sees the hit marked as allowed. Every other stage runs as before: an allowed
  secret that is also a long base64 run still gets the S2 flag.
- Under Ask the required level goes through channel selection (PROTOCOL §6.3, ADR 0015), so the
  floor of the stage, not the owner, picks the channel.
- A registry decision is a security setting (PROTOCOL §9.4): only an owner decision in the Mini
  App at A2 or higher changes it. Allow and Ask may be decided on the settings page or from an
  approval prompt. A change that sets or lifts Never is accepted only from the settings page,
  never from an approval prompt, an open mandate or anything the agent reaches. The agent
  interface gains no operation (ADR 0002).

Allow does not break the monotonic rule of ADR 0005 and hard rule 2. The decision is part of
the stage: S4, S5, S8 and S9 compute their own floor from what matched and the owner's decision
for that source and peer, as every stage computes its floor from owner settings. The maximum
over all stages is taken afterwards, so an Allow lowers no level that another stage computed:
structure, display safety, dictionary, canaries, fuzzy checks and tripwire mode still raise.
Allow never releases free text because a detector found nothing: free text still needs A1
without an open mandate, and A0 still needs an owner-signed open mandate whose S12 sees no flag.
Only the owner sets Allow, through consent, for one source towards one peer.

## Consequences
- `paseka_core::source::SourceRegistry` stores registered sources and decisions per tenant;
  `Decisions` is one tenant's view towards one peer and the input of `risk::assess`. A decision
  for one peer never applies to another peer or tenant.
- Fingerprints and source reads carry a source id instead of a sensitive mark. The owner's
  screen names the source of each hit.
- SP-24 and its attack CA-54 state that content of a Never source does not leave through an owner
  approval or an open mandate, and that Never is not lifted outside the settings page.
- New detectors join the registry as reporters of further sources without changing its
  semantics: one-time codes, vault secrets by exact value, private links, other chats and groups,
  later MinHash, OCR and paraphrase detection.
- Content that no built detector catches is not protected by its decision; the owner's prompt
  and the other stages remain the protection for it.
