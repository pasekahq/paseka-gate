# 0004. Approval levels A0 to A3; Telegram evidence verified by Ed25519

Status: Accepted
Date: 2026-11-18

## Context
Owners need low friction for routine answers and strong evidence for sensitive ones. Telegram is
where owners already are, and it attests who pressed a button. The bot-token HMAC of Mini App
`initData` can be forged by anyone holding the token; Bot API 8.0 adds an Ed25519 third-party
signature that can be verified with Telegram's public key alone.

## Decision
- A0: open mandate or policy (templates, time- and count-limited conversation windows,
  allowlists). No human interaction per message.
- A1: inline button in the gate's own consent bot. The bot token lives only in the gate; it is
  never the bot the owner uses to talk to the agent. The nonce comes from the gate.
- A2: Telegram Mini App showing exact bytes, recipient, attachments and diff; edits allowed and
  produce a new hash. `initData` is verified by the Ed25519 third-party signature, not only the
  HMAC; `auth_date` must be fresh within a strict window; the gate binds request id, content hash
  and nonce.
- A2+: Mini App plus a second factor. In the MVP the owner's PIN or password, entered only in
  the Mini App (ADR 0015). Later a BiometricManager-unlocked non-extractable WebCrypto key that
  signs hash and nonce, with the PIN as fallback. No hardware attestation is claimed.
- A3 (later): WebAuthn passkey in an external browser opened through `openLink`; the signature
  covers the hash.
- MVP ships A0, A1, A2 and A2+ with PIN. Later channels (Slack, ntfy, CLI with a local key held away from the
  agent, e-mail magic link as a weak fallback) produce the same proof format.
- Approval surfaces are non-agentic: no model renders or summarizes what the owner approves.

## Consequences
- Telegram is a trusted party for A1 and A2; a Telegram account takeover equals approval. This is
  accepted for the threat model; the most sensitive content is routed to A2+, and a level above
  every configured channel goes through the strongest one (ADR 0015).
- The consent bot token is a gate secret with the same protection as the gate signing key.
