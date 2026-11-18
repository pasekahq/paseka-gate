# 0011. Peer turns run under a separate agent launch profile

Status: Accepted
Date: 2026-11-18

## Context
The concept recommends L2 "peer turn mode": during a turn started by a peer, the agent reads
everything but its other outbound tools are off. Most agents (Claude Code, Codex, Hermes) cannot
switch tool sets reliably in the middle of a running session, and hooks that inspect each tool
call can be bypassed by tools the hook does not understand (for example a shell with network).
The concept does not fix how a recipe enters peer turn mode.

## Decision
- A peer turn SHOULD be a separate agent invocation with its own launch profile: the same
  memory and notes read-only, an allowlist of read tools plus the paseka MCP server, outbound
  tools removed, memory writes redirected to a quarantine directory.
- The recommended trigger is a small runner (`paseka peer-turn`, later) or the owner's
  scheduler that starts the agent with that profile when `inbox` has peer messages. Hooks are
  defense in depth, not the enforcement mechanism.
- OS-level controls (separate unix user, read-only bind of notes, egress limited to the model
  API) are the strongest form of L2 and are documented as such.

## Consequences
- `docs/AGENT-SETUP.md` recipes describe a main profile and a peer-turn profile per agent.
- The gate cannot verify which profile an agent ran under; the approval screen shows the
  profile the agent declared as unverified.
