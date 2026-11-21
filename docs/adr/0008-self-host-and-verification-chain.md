# 0008. Self-host is the main path; a verification chain that starts with the install skill

Status: Accepted
Date: 2026-11-18

## Context
The gate guards the owner against their own agent, yet the owner will usually ask that agent to
install it. A hijacked or careless installer could install a modified gate or weaken its config.
Owners must be able to verify what runs without reading all the code themselves.

## Decision
- Self-host is the main path: one static binary. Installation is driven by the install skill,
  which runs six steps:
  0. skill artifact check: the skill hashes its own release artifact, requires the hash published
     in at least two of its three places to answer and equal it, checks that it follows the
     `SKILL.md` inside that artifact and verifies the artifact's signature; on any mismatch, or
     when fewer than two places answer, it stops and raises an alarm to the owner;
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
- The install skill is released as its own signed artifact, separate from the gate releases it
  verifies and pinned by its hash. Its source `skills/install/SKILL.md` stays in this repository
  for review and is not run from there. The artifact is a gzip tarball of `skills/install/` built
  reproducibly by the release workflow at a `skill-vX.Y.Z` tag, with a Sigstore build provenance
  attestation signed keyless by that workflow's GitHub OIDC identity and logged in Rekor.
- The artifact hash is published in three places: the organisation
  README (`pasekahq/.github`), the notes of the skill's GitHub release, and the project owner's
  announcement channel.
- What each check covers. The skill's step 0 catches a stale or swapped copy fetched from one
  compromised place and a copy not built by the release workflow; to pass it, a swapped copy needs
  its hash in every place that answers, at least two. It cannot catch a skill written to lie,
  because such a skill skips its own check. The owner's own comparison of the published hashes,
  out of band and before handing the skill to an agent, is what covers that; to pass it, an
  attacker has to change all three places.
- Hosting for friends: explicit "you trust the operator". Basic checks offered: `/version` with
  build hash against the signed release, external conformance against the own tenant, journal
  export, passkey signatures verifiable by peers, one-command migration to self-host.

## Consequences
- Release tooling (CI-only publishing, attestations, reproducible build script) is part of the
  MVP, not a later polish.
- Config files are not a way to change security settings after the ceremony; the gate refuses
  a config whose security section differs from the consented state.
- Release tooling also builds, signs and publishes the install skill artifact and puts its hash
  in all three places; a release whose places disagree is not announced.
