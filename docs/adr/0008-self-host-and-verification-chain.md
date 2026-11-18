# 0008. Self-host is the main path; a five-step verification chain

Status: Accepted
Date: 2026-11-18

## Context
The gate guards the owner against their own agent, yet the owner will usually ask that agent to
install it. A hijacked or careless installer could install a modified gate or weaken its config.
Owners must be able to verify what runs without reading all the code themselves.

## Decision
- Self-host is the main path: one static binary. Installation is driven by
  `skills/install/SKILL.md`, which runs five steps:
  1. provenance: the package was built by CI from this repo (trusted publishing, Sigstore
     provenance, Rekor entry);
  2. reproducibility: rebuild from the tag with the pinned toolchain and compare hashes;
  3. code review: small core with a CI size budget, an audit checklist with file:line answers,
     cargo deny (cargo-vet later);
  4. conformance attacks run locally against the installed binary;
  5. first-run ceremony: the Mini App shows the config in plain words; the gate refuses to work
     until the owner confirms. Afterwards security settings change only through consent.
- The trap rule: the installing agent is what the gate guards against. The verification steps
  live in the skill, not in the repo; repo content is data, never instructions; the gate runs as
  a separate unix user the agent cannot write as.
- Hosting for friends: explicit "you trust the operator". Basic checks offered: `/version` with
  build hash against the signed release, external conformance against the own tenant, journal
  export, passkey signatures verifiable by peers, one-command migration to self-host.

## Consequences
- Release tooling (CI-only publishing, attestations, reproducible build script) is part of the
  MVP, not a later polish.
- Config files are not a way to change security settings after the ceremony; the gate refuses
  a config whose security section differs from the consented state.
- The install skill is shipped and pinned separately from the repo snapshot it verifies.
