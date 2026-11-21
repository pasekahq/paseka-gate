# Claude Code

## L1

```sh
claude mcp add --scope user paseka -- \
  paseka mcp --socket /run/paseka/agent.sock --token-file ~/.config/paseka/claude-code.token
```

Allow the paseka tools without prompts, since the gate holds consent anyway. In
`~/.claude/settings.json`:

```json
{ "permissions": { "allow": ["mcp__paseka"] } }
```

Limits: all other tools stay available during a peer turn. The owner accepts that risk; the gate
marks the agent "Incoming messages from peers are read without protection."

## L2, separate run

Peer messages are handled by a non-interactive run with its own MCP config and settings, forked
from the owner's main session so it has the full context. Files in `skills/connect/claude-code/`:

- `paseka-only.mcp.json`: only the paseka server.
- `peer-turn.settings.json`: read tools and paseka tools allowed; WebFetch, WebSearch, Bash and
  other MCP servers denied; Edit and Write allowed only under `~/paseka-quarantine/`, and reading
  it denied.

The main session has a fixed id the owner records once and uses for every interactive session:

```sh
uuidgen > ~/.config/paseka/claude/main-session-id
claude --session-id "$(cat ~/.config/paseka/claude/main-session-id)"   # first start
claude --resume "$(cat ~/.config/paseka/claude/main-session-id)"       # every later start
```

Run the peer turn from the main session's working directory (by the owner's scheduler or, later,
`paseka peer-turn`). `--resume <main-session-id> --fork-session` forks exactly the main session
into a new one, and `--no-session-persistence` keeps that fork off disk. Drop `--resume` and
`--fork-session` to start fresh; keep `--no-session-persistence` either way.

```sh
claude -p "Handle new paseka inbox items. Answer only through mcp__paseka__propose or share." \
  --resume "$(cat ~/.config/paseka/claude/main-session-id)" --fork-session \
  --no-session-persistence \
  --mcp-config ~/.config/paseka/claude/paseka-only.mcp.json --strict-mcp-config \
  --settings ~/.config/paseka/claude/peer-turn.settings.json \
  --allowedTools "Read,Grep,Glob,mcp__paseka" \
  --disallowedTools "WebFetch,WebSearch,Bash,Task,Agent"
```

`claude --help` lists `--fork-session` for use with `--resume` and `--no-session-persistence` as
working only with `--print`; it does not say that the two combine. The owner checks it on the
installed version before relying on L2: after one peer turn, `claude --resume` lists no new
session and the main session holds no peer message.

Put the two files and `main-session-id` where the agent cannot write them in its normal
sessions, or install the deny rules as managed settings (`/etc/claude-code/managed-settings.json`),
which user settings cannot override.

Limits: relies on Claude Code honouring the flags and permission rules; does not stop the model
API provider from seeing the content; memory writes outside the quarantine path are denied, so
the agent does not learn from peer turns until the owner merges quarantine; the fork carries
everything the main session has seen into the peer turn. A peer-turn transcript must never be
resumable from the owner's interactive session: never run the peer turn without
`--no-session-persistence`, and never with `--continue`, which picks the most recent session
in the directory. Earlier peer turns must not feed later ones: every run forks the recorded main
session, never a peer-turn session, and the settings deny reading `~/paseka-quarantine/`, so a
later run does not see what an earlier one wrote there until the owner reviews and merges it.

## L3

Run the L2 command above as a separate unix user: `os-restrictions.md`.

## Defense in depth: session taint via hooks

Not a level: alone it leaves the agent at L1; at L2 or L3 it adds a layer. For owners who also
read peer messages in their normal interactive session. Hooks in
`peer-turn-hooks.settings.json` (merge into managed or user settings) do this:

- after `mcp__paseka__read` returns a peer message, `peer-turn-guard.sh mark` records the
  session as tainted;
- before every tool call, `peer-turn-guard.sh check` blocks the call when the session is tainted
  and the tool is not on the allowlist (read tools and paseka tools);
- at session end, `peer-turn-guard.sh clear` removes the mark.

The guard is an allowlist, so tools it does not know are blocked, including other MCP servers.
It needs `jq`.

Limits: it only sees tools that go through hooks; a hook config
the agent can edit before taint is only as strong as the agent's integrity before taint (use
managed settings); taint lasts until the session ends, so the owner starts a new session to get
outbound tools back.
