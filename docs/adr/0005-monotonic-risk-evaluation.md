# 0005. Risk evaluation only raises the approval level

Status: Accepted
Date: 2026-11-18

## Context
Classifiers and similarity scores are fuzzy and can be fooled by the same injection that
hijacked the agent. If a "safe" verdict could release free text, the classifier would become the
release path.

## Decision
- Checks only raise friction; they never replace the human. Free text to a peer is at least A1.
  A0 is possible only under a matching owner-signed open mandate (T1 templates, T2 shelf shares,
  a conversation window) and only when no check raised a flag; without one, templates and
  shares need A1 too.
- The owner's dictionary lives in the gate and the agent cannot edit it: built-in detectors
  (gitleaks-like secret rules, card numbers, IBAN, phones, addresses, IDs), personal lists built
  in the first-run ceremony, per-peer policy.
- Exact checks for any agent: structure (links, base64 or hex blobs, long numbers, length,
  attachments, new recipient), canaries, fingerprints of sensitive folders (shingles or MinHash).
  Fuzzy checks (embedding similarity, a classifier model, local or via qb) may only raise.
- Default rules: free text gives A1; a structural flag or dictionary hit gives A2 with
  highlights; a fingerprint hit or a read from a sensitive folder per the MCP proxy log gives A2+
  or A3; a canary blocks even with approval and alerts the owner.
- Level computation is `max` over all rule outputs; no rule returns a level below its input.

## Consequences
- The monotonic property is a unit-tested invariant of `paseka-core`.
- Until A2+ and A3 exist, a draft that needs them is blocked with reason `policy` and the owner
  is notified. The owner may lower that rule's floor to A2 through consent; the gate never falls
  back to a lower level silently.
- Source provenance is "agent says" for plain agents, verified for data read through the gate's
  MCP proxy, and full taint for ulei.
