# Claude Code

## L1

```sh
claude mcp add --scope user paseka -- paseka mcp --socket /run/paseka/agent.sock
```

Allow the paseka tools without prompts, since the gate holds consent anyway. In
`~/.claude/settings.json`:

```json
{ "permissions": { "allow": ["mcp__paseka"] } }
```

Limits: all other tools stay available during a peer turn.

## L2, separate profile (preferred)

Peer messages are handled by a non-interactive run with its own MCP config and settings. Files
in `skills/connect/claude-code/`:

- `paseka-only.mcp.json`: only the paseka server.
- `peer-turn.settings.json`: read tools and paseka tools allowed; WebFetch, WebSearch, Bash and
  other MCP servers denied; Edit and Write allowed only under `~/paseka-quarantine/`.

Run (by the owner's scheduler or, later, `paseka peer-turn`):

```sh
claude -p "Handle new paseka inbox items. Answer only through mcp__paseka__propose or share." \
  --mcp-config ~/.config/paseka/claude/paseka-only.mcp.json --strict-mcp-config \
  --settings ~/.config/paseka/claude/peer-turn.settings.json \
  --allowedTools "Read,Grep,Glob,mcp__paseka" \
  --disallowedTools "WebFetch,WebSearch,Bash,Task"
```

Put the two files where the agent cannot write them in its normal sessions, or install the deny
rules as managed settings (`/etc/claude-code/managed-settings.json`), which user settings cannot
override.

Limits: relies on Claude Code honouring the flags and permission rules; does not stop the model
API provider from seeing the content; memory writes outside the quarantine path are denied, so
the agent does not learn from peer turns until the owner merges quarantine.

## L2, session taint via hooks

For owners who handle peer messages in their normal interactive session. Hooks in
`peer-turn-hooks.settings.json` (merge into managed or user settings) do this:

- after `mcp__paseka__read` returns a peer message, `peer-turn-guard.sh mark` records the
  session as tainted;
- before every tool call, `peer-turn-guard.sh check` blocks the call when the session is tainted
  and the tool is not on the allowlist (read tools and paseka tools);
- at session end, `peer-turn-guard.sh clear` removes the mark.

The guard is an allowlist, so tools it does not know are blocked, including other MCP servers.

Limits: weaker than a separate profile. It only sees tools that go through hooks; a hook config
the agent can edit before taint is only as strong as the agent's integrity before taint (use
managed settings); taint lasts until the session ends, so the owner starts a new session to get
outbound tools back.
