# 0003. Consent is an AP2-style mandate over a content hash

Status: Accepted
Date: 2026-11-18

## Context
Approval channels differ (button, Mini App, passkey later), but the release path must check one
kind of proof. Google AP2 v0.2 defines mandates as signed, verifiable consent objects in an
SD-JWT style. Reusing its shape keeps the design familiar and leaves room for interoperability.

## Decision
- Closed mandate: consent for one message. Fields: `kind: closed`, `tenant`, `to`,
  `content_sha256`, `attachments[]`, `level`, `proof {channel, ...evidence}`, `nonce` issued by
  the gate, `exp` about 60 seconds after issue. Single use.
- Open mandate: consent in advance for a class of actions. Fields: `kind: open`, `to`,
  `constraints {templates, max_len, attachments, private_sources, rate, topics}`, `window`/`exp`,
  `signed_at_level`. A new open mandate for the same scope cannot be presented until the
  previous one is refused or expired (AP2 rule). Lifetimes are minimal.
- The hash covers the exact bytes, the recipient and the attachments. Canonicalization and the
  wire encoding (full SD-JWT or a compatible compact JWS profile) are fixed in `docs/PROTOCOL.md`.
- Any edit of the content produces a new hash and needs new consent.

## Consequences
- Release is a pure check in `paseka-core`: signature, level, hash, recipient, nonce, expiry,
  single use. All channels feed the same check.
- Deviations from AP2 / SD-JWT need their own ADR.
- Replay, preview swap and stale nonce attacks become conformance tests against this check.
