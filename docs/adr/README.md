# Architecture decision records

One file per decision: `NNNN-short-title.md`, numbered in order, never renumbered. Template:

```
# NNNN. Title

Status: Proposed | Accepted | Superseded by NNNN
Date: YYYY-MM-DD

## Context
## Decision
## Consequences
```

An ADR is required for: a new crate, a new dependency, a contract change that is not purely
additive, and any deviation from `docs/concept/CONCEPT.md`. A superseded ADR stays; its Status line
points to the successor.

| ADR | Decision |
|---|---|
| [0001](0001-sync-rust-stack.md) | Synchronous Rust stack, one static binary |
| [0002](0002-agent-untrusted-no-approve-tool.md) | Every agent is untrusted; the agent interface has no approve tool |
| [0003](0003-ap2-style-mandates.md) | Consent is an AP2-style mandate over a content hash |
| [0004](0004-approval-levels-telegram-evidence.md) | Approval levels A0 to A3; Telegram evidence verified by Ed25519 |
| [0005](0005-monotonic-risk-evaluation.md) | Risk evaluation only raises the approval level |
| [0006](0006-trust-levels-and-shelves.md) | Per-peer trust levels T0 to T3; shelves share by pointer |
| [0007](0007-multi-tenant-from-day-one.md) | Multi-tenant from day one |
| [0008](0008-self-host-and-verification-chain.md) | Self-host is the main path; a five-step verification chain |
| [0009](0009-clean-slate.md) | Clean slate: no compatibility with the old Python gate |
| [0010](0010-tolerant-readers.md) | Contracts only grow; readers are tolerant |
| [0011](0011-peer-turn-launch-profile.md) | Peer turns run under a separate agent launch profile |
| [0012](0012-mandate-encoding-gate-signed-sd-jwt.md) | Mandates are gate-signed SD-JWTs with zero disclosures; evidence stays behind a hash |
| [0013](0013-tenant-address-and-key-rotation.md) | A tenant's address is its permanent id; keys rotate under it |
| [0014](0014-release-digest-binds-draft-expiry.md) | The release digest binds the draft expiry; the closed mandate carries it |
| [0015](0015-strongest-available-channel-a2plus-pin.md) | A level above every channel goes through the strongest one; A2+ is Mini App plus PIN |
| [0016](0016-tripwire-full-alarm-cleared-with-pin.md) | A canary hit raises a full alarm by default; only an A2+ decision clears it |
| [0017](0017-conversation-trust-without-message-limit.md) | Conversation trust has no message limit; defaults live in one table |
| [0018](0018-source-registry-allow-ask-never.md) | A source registry decides Allow, Ask or Never per source and peer |
| [0019](0019-open-mandates-never-widen-the-source-registry.md) | Open mandates, conversation trust included, never widen the source registry |
