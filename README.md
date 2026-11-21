# paseka-gate

[![CI](https://github.com/pasekahq/paseka-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/pasekahq/paseka-gate/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pasekahq/paseka-gate/badge)](https://scorecard.dev/viewer/?uri=github.com/pasekahq/paseka-gate)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue)](LICENSE)

Status: pre-alpha draft. Not released, not ready for real data. Nothing here is
installable yet; documents describe the target design.

paseka-gate (binary `paseka`) is a consent firewall between your AI agent and other people's
agents. Your agent keeps all its knowledge. Nothing it writes reaches anyone else unless you saw
those exact bytes and agreed, or you signed a narrow rule in advance that allows it.

## Example

Alice's agent asks Bob's agent: "What does Bob think about the new office plan?"

1. Bob's gate receives the question from Alice's gate and puts it in the inbox of Bob's main
   agent, the one with Bob's notes, memory and context.
2. Bob's agent drafts an answer and proposes it to the gate. It cannot send it.
3. Bob gets a Telegram message from his own consent bot. He opens it and sees the exact text,
   the recipient (Alice), any attachments, and flags such as "contains a phone number" or
   "mentions a topic you marked private".
4. Bob approves, edits, or denies. Only on approval does the gate send the exact bytes Bob saw,
   to Alice only, once.

If a cleverly worded question takes over Bob's agent, step 4 still does not happen without Bob.

## The main rule

Every agent is untrusted for release, your own included. An agent may read anything and propose
anything. It can never approve: the agent interface has no approve tool at all. What leaves is
bound to a hash of the exact content you approved, the recipient, and a one-time nonce.

To be less strict with someone, you give that peer an open mandate in advance: templates,
structured answers, or shelves (collections of your documents the gate itself sends by
reference). Automatic checks only ever add friction; they never release free text on their own.

## Works with any agent

One MCP server serves every agent: a custom Rust agent (ulei), Hermes, Claude Code, Codex, or
any model with a tool loop. Non-MCP clients use the same contract over HTTP. Connecting is
described in [docs/AGENT-SETUP.md](docs/AGENT-SETUP.md), including what each setup can and
cannot guarantee.

## Two ways to run it

Self-host (main path). One static Rust binary behind Caddy, with a Telegram consent bot you
create. Your agent installs it with the install skill, released as a separate signed artifact
(source for review: [skills/install/SKILL.md](skills/install/SKILL.md)). Before you hand it over,
compare its hash in the places it is published. The skill first checks its own hash against those
places, then verifies the release before trusting it: CI provenance, a reproducible rebuild, an
audit checklist, local attack tests, and a first-run ceremony where you confirm the configuration
in plain words. After that, security settings change only with your consent.

Hosted. A tenant on a gate run by the pasekahq operator, for people who do not want a server.
You trust the operator: they could read your traffic. You can check the running build against
the signed release, run attack tests against your own tenant, export your journal, and move to
self-host with one command.

## Documents

- [docs/concept/CONCEPT.md](docs/concept/CONCEPT.md): owner decisions, binding.
- [docs/MVP.md](docs/MVP.md): scope, Definition of Done, milestones.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and [docs/PROTOCOL.md](docs/PROTOCOL.md): security
  properties and the normative protocol.
- [docs/adr/](docs/adr/): decisions.
- [AGENTS.md](AGENTS.md): rules for coding agents working on this repository.

## Conformance attacks

`paseka conformance` runs the 57 conformance attacks CA-1 to CA-57 of the threat model. 44 run
and pass; 13 are Pending until the part they need exists: the gate daemon (CA-5, CA-38 in M2;
CA-23 in M3; CA-44, CA-46 in M4), the journal (CA-45, M2), the consent bot and Mini App (CA-4,
CA-11, CA-14, CA-16, CA-17, M3), invite codes (CA-35, M4) and an installed gate (CA-42, M5).
The milestones are those of [docs/MVP.md](docs/MVP.md); the table is in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §6.

## License

Copyright (C) 2026 the paseka-gate contributors.

Licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (SPDX: `AGPL-3.0-only`).
If you run a modified gate for users over a network, section 13 asks you to offer them its source.

Contributions are accepted under the same license with a DCO sign-off; see
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).
