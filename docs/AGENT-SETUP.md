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
below reduce that risk by configuring the agent. They are a recommendation (ADR 0011): the gate
cannot verify which level an agent runs at, and the owner of the agent that reads incoming peer
messages carries the risk.

## How an agent reaches the gate

- Every registered agent has its own agent token, which the Mini App shows once when the owner
  registers the agent. The gate attributes drafts to agents by it (`docs/PROTOCOL.md` §5.1).
- MCP over stdio: the agent starts
  `paseka mcp --socket /run/paseka/agent.sock --token-file ~/.config/paseka/<agent>.token`,
  which presents the agent's token and forwards to the running gate. The owner saves the token
  to that file, mode 0600. The socket is group `paseka-agent`; the owner's user is in that group
  and never in the `paseka` group.
- MCP over loopback HTTP, or the same contract as plain HTTP with OpenAPI, for agents that
  cannot spawn a process: `http://127.0.0.1:8641/agent/v1`, with the agent's token in the
  agent's secret store.
- The agent token selects the tenant, so `paseka mcp` takes no `--tenant`. Commands the owner
  runs on the gate host name the tenant by the local name chosen at `paseka init` and need
  `--tenant <name>` only on a gate with several tenants (`docs/PROTOCOL.md` §12.1).
- Each connected agent is registered in the Mini App with a name and the protection level the
  owner chose (`docs/PROTOCOL.md` §5.4). The name is the agent's claim, not a verified identity.

Tools: `inbox`, `read`, `propose`, `revise`, `withdraw`, `status`, `share`, `queue`, `peers`,
`journal`. There is no approve tool. Exact inputs and outputs: `docs/PROTOCOL.md`.

## Threads and conversation trust

A thread is a chain of messages linked by `in_reply_to`, as in e-mail. An agent answers a message
by calling `propose` with `in_reply_to` set to that message's id from `inbox`; the answer joins
its thread. A message without `in_reply_to` opens a new thread, and the owner sees the thread
named by its first message.

The owner can trust one conversation in the Mini App: the agent's free-text replies in that one
thread with that one peer then leave without asking the owner, unless the gate's checks hold one
for the owner, for 30 minutes unless the owner sets another duration (at most 24 hours). This is an
open mandate on one thread (`docs/PROTOCOL.md` §4.4). It never widens the source registry: a reply
with content of a source that is Ask towards that peer still goes to the owner, and one with a
Never source is blocked. It never covers another thread or another peer, so free text that opens a
new thread goes to the owner even while a conversation is trusted. The agent cannot ask for, extend
or end conversation trust.

The agent sees the state in the `thread_trust` object of every `propose` output and `inbox` item:
`active` tells whether a conversation mandate covers the thread, `ends_at` when it ends and
`seconds_left` how much time is left; `new_thread_needs_owner` says that free text in a new
thread goes to the owner. The `propose` tool description tells the agent the same, in
`contracts/agent/propose.input.schema.json`.

## Levels

The levels describe how the agent that reads incoming peer messages is set up. The connect skill
asks the owner for one, and the owner records it in the Mini App with the agent.

L3, OS restrictions. The agent runs as a separate unix user whose network reaches only the model
API and the gate; notes and memory are mounted read-only, memory writes go to a quarantine
directory. Works for any agent. Recipe: `skills/connect/recipes/os-restrictions.md`.

L2, separate run. Peer messages are handled by a separate run through `paseka peer-turn`, with
only read tools and the paseka server, and memory writes only to a quarantine directory the owner
reviews. Fits any CLI agent. Where the agent can, the run starts from a fork of the owner's main
session, so it has the full context; otherwise it starts fresh from the notes. Until the runner
ships (after the MVP), the owner's scheduler starts the same run with the command in the agent's
recipe.

L1, risk accepted. The agent has the paseka MCP server next to its usual tools. Answers leave
only with consent, but a hijacking peer message can make the agent leak through its other tools.
The owner accepts that knowingly; the gate marks such an agent with "Incoming messages from
peers are read without protection."

Session-taint hooks (after the agent reads a peer message, a hook blocks every tool not on an
allowlist for the rest of the session) are defense in depth. They depend on the hook mechanism
seeing every tool call and on the agent not being able to edit the hook config, so alone they
leave the agent at L1; at L2 or L3 they add a layer.

## Per agent

| Agent | L1 | L2 | L3 | Recipe |
|---|---|---|---|---|
| ulei | MCP | separate run with a reduced configuration (native support planned in ulei) | OS restrictions | `skills/connect/recipes/ulei.md` |
| Hermes | MCP | separate run from its own `HERMES_HOME` with a reduced toolset | OS restrictions | `skills/connect/recipes/hermes.md` |
| Claude Code | MCP; session-taint hooks as defense in depth | separate `claude -p` run with its own settings, forked from the main session | OS restrictions | `skills/connect/recipes/claude-code.md` |
| Codex | MCP | separate run from its own `CODEX_HOME` with a read-only sandbox | OS restrictions | `skills/connect/recipes/codex.md` |
| ChatGPT in a browser | no (hosted tenant by hand now; OAuth connector later, L1 only) | not reachable: the owner cannot switch off its tools from the gate | not reachable | `skills/connect/recipes/chatgpt.md` |

Recipes use configuration keys of the agents' current versions as understood when written.
Agents change their config formats; the connect skill tells the agent to check its own
documentation before applying a recipe.

## Approval screen and sources

The Mini App shows exact bytes, recipient, attachments, flags (links, numbers, encoded chunks,
sensitive topics) and the sources read during the turn. Sources are "agent says" for plain
agents and verified only when reads went through the gate's MCP proxy (later) or ulei taint
tracking. The protection level the owner recorded for the agent is shown on every approval
prompt and in the Mini App peer and agent views as the owner's statement, with the L1 marker
where it applies (`docs/PROTOCOL.md` §5.4).
