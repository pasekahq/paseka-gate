# 0003. Consent is an AP2-style mandate over a content hash

Status: Accepted
Date: 2026-11-18

## Context
Approval channels differ (button, Mini App, passkey later), but the release path must check one
kind of proof. Google AP2 v0.2 defines mandates as signed, verifiable consent objects in an
SD-JWT style. Reusing its shape keeps the design familiar and leaves room for interoperability.

## Decision
- Closed mandate: consent for one message: the exact content (`content_sha256`, `attachments[]`
  bound into a release digest), one recipient, a `level`, a `proof` of the channel, a gate-issued
  `nonce` and `exp` 60 seconds after issue. Single use. The claims are listed in PROTOCOL §8.2.
- Open mandate: consent in advance for a class of actions: one recipient, a trust, `constraints`
  (templates, length, attachments, private sources, rate, topics, shelves, thread), `nbf`/`exp`
  and `signed_at_level` (PROTOCOL §8.3). A new open mandate for the same peer and trust cannot be
  presented until the previous one is refused, revoked or expired (AP2 rule). Lifetimes are
  minimal.
- The hash covers the exact bytes, the recipient and the attachments. The encoding is fixed by
  ADR 0012 and PROTOCOL §8.1.
- Any edit of the content produces a new hash and needs new consent.

## Consequences
- Release is a pure check in `paseka-core`: the approval-request checks on the sending side
  (`draft::Draft::decide`) and mandate verification on the receiving side
  (`mandate::verify_received`). All channels feed the same checks.
- Deviations from AP2 / SD-JWT need their own ADR.
- Replay, preview swap and stale nonce attacks become conformance tests against this check.
