# 0022. Telegram keys are config settings checked live at the ceremony; consent bot modes

Status: Accepted
Date: 2026-11-21

## Context
Mini App initData is trusted only through Telegram's Ed25519 third-party signature (ADR 0004).
The protocol pinned the production key in the binary and named the test key only as an option.
A key Telegram replaces would then need a new release, and a gate set up with the wrong key or
environment would fail only at the first real approval. A hosted gate serves many tenants; a
shared consent bot that resolved the tenant from a nonce or request id let a payload field pick
the tenant before the approver check. The owner decided (GRILL O3, O4) that the keys live in the
config, change only through consent or the local CLI, are checked live at the first-run
ceremony, and that a shared bot resolves the tenant strictly by the signed Telegram user id.

## Decision
- The gate config holds the Telegram environment of each consent bot and one Ed25519 key per
  environment, with the keys of the Telegram Mini Apps documentation as defaults (PROTOCOL
  §7.4). InitData is verified with the key of the bot's environment only.
- The keys and the environment are security settings (PROTOCOL §9.4). They change through an
  owner decision at A2 or higher, verified with the current key, or through the local CLI on
  the gate host. Every consent decision depends on the key, so consent alone cannot repair a
  wrong key; the local CLI breaks that circle. Editing the config after the ceremony changes
  nothing (CA-23).
- The first-run ceremony completes only on a live decision whose initData verifies with the
  configured key and bot id.
- Consent bot modes (PROTOCOL §7.2): self-host has its own bot; a hosting gate has one shared
  bot that resolves the tenant only from the signed Telegram user id and the approver binding,
  with each Telegram user an approver of at most one tenant on it (TI-5, CA-39); a hosted
  tenant may connect its own bot instead.
- `paseka_core::initdata::InitData::verify` implements PROTOCOL §7.4 steps 1 to 3 without
  a new dependency. The documentation publishes no signed initData, so the test vector holds
  the documented keys and example text, and tests sign that text with a synthetic test key.

## Consequences
- A key change by Telegram is a settings change, not a release.
- A misconfigured key, environment or bot id stops the setup instead of every approval.
- A person who approves for two hosted tenants needs a tenant's own bot for the second one.
- No test proves a signature made by Telegram's key until a live ceremony runs against it.
