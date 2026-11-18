# Connecting agents

How the owner's agents connect to the gate, and what each setup can and cannot guarantee.
Executable recipes live in `skills/connect/`; this page explains the levels and their limits.
Names and paths are illustrative (owner alice, gate user `paseka`, socket
`/run/paseka/agent.sock`).

## What the gate guarantees for every agent

These hold at every level, for every agent, even when the agent is fully hijacked:

- Nothing the agent proposes reaches a peer without the owner's consent for those exact bytes
  and that recipient, or an open mandate the owner signed in advance.
- The agent cannot approve, change policies, peers, shelves or the dictionary.
- Canaries block release even with consent.

What the gate does not guarantee: an agent with other outbound tools (web fetch, mail,
messengers, a shell with network) can leak through those tools, outside the gate. The levels
below reduce that risk by configuring the agent. The gate cannot verify which level an agent
runs at.

## How an agent reaches the gate

- MCP over stdio: the agent starts `paseka mcp --socket /run/paseka/agent.sock`, which forwards
  to the running gate. The socket is group `paseka-agent`; the owner's user is in that group and
  never in the `paseka` group.
- MCP over loopback HTTP, or the same contract as plain HTTP with OpenAPI, for agents that
  cannot spawn a process: `http://127.0.0.1:8641/agent/v1`, with a per-agent token the owner
  creates in the Mini App.
- Each connected agent is registered by name in the Mini App. The name is shown on approval
  screens and is the agent's claim, not a verified identity.

Tools: `inbox`, `read`, `propose`, `revise`, `withdraw`, `status`, `share`, `queue`, `peers`,
`journal`. There is no approve tool. Exact inputs and outputs: `docs/PROTOCOL.md`.

## Levels

L1, connected. The agent has the paseka MCP server next to its usual tools. Answers leave only
with consent. A hijacking peer message can still make the agent leak through its other tools.
Use for agents without outbound tools, or for trying the gate.

L2, peer turn mode (recommended). While a turn started by a peer runs, the agent may read all
its notes and memory but has no other outbound tool, writes memory only to a quarantine
directory the owner reviews, and answers only through the gate. Two ways to get there:

- Separate launch profile (preferred, ADR 0011): peer messages are handled by a separate agent
  invocation whose configuration lists only read tools and the paseka server.
- Session taint via hooks: in the normal session, once the agent reads a peer message, a hook
  blocks every tool not on an allowlist for the rest of that session. Weaker: depends on the hook
  mechanism seeing every tool call and on the agent not being able to edit the hook config.

The strongest L2 adds OS controls: run peer turns as another unix user with notes mounted
read-only and egress limited to the model API.

L3, dual model. A quarantined model without tools turns the peer's text into a structured
question; the main agent sees only that structure. This removes most injection, at the cost of
nuance. Native in ulei later; for other agents it is a later recipe, not part of the MVP.

## Per agent

| Agent | L1 | L2 | L3 | Recipe |
|---|---|---|---|---|
| ulei | MCP | native peer turn mode (planned in ulei) | native, taint tracking (later) | `skills/connect/recipes/ulei.md` |
| Hermes | MCP | separate profile with a reduced toolset | later | `skills/connect/recipes/hermes.md` |
| Claude Code | MCP | separate profile (`claude -p` with own settings), or session-taint hooks | later | `skills/connect/recipes/claude-code.md` |
| Codex | MCP | separate `CODEX_HOME` with read-only sandbox | later | `skills/connect/recipes/codex.md` |
| ChatGPT in a browser | no (hosted tenant by hand now; OAuth connector later) | not reachable: the owner cannot switch off its tools from the gate | no | `skills/connect/recipes/chatgpt.md` |

Recipes use configuration keys of the agents' current versions as understood when written.
Agents change their config formats; the connect skill tells the agent to check its own
documentation before applying a recipe.

## Approval screen and sources

The Mini App shows exact bytes, recipient, attachments, flags (links, numbers, encoded chunks,
sensitive topics) and the sources read during the turn. Sources are "agent says" for plain
agents and verified only when reads went through the gate's MCP proxy (later) or ulei taint
tracking. The level the agent declares is shown as unverified.
