# Hermes

## L1

Add the server to the `mcp_servers` section of the Hermes config:

```yaml
mcp_servers:
  paseka:
    command: paseka
    args: ["mcp", "--socket", "/run/paseka/agent.sock"]
```

The consent bot must be a different Telegram bot from the one Hermes uses for chat. Never give
Hermes the consent bot token.

Limits: all Hermes toolsets (web, terminal, messaging gateway) stay available in a peer turn.
The owner accepts that risk; the gate marks the agent "Incoming messages from peers are read
without protection."

## L2, separate run from its own HERMES_HOME

Run peer turns as a separate run (by the owner's scheduler or, later, `paseka peer-turn`) from a
separate Hermes home whose config enables only file reading, the memory
read path and the paseka MCP server; web, browser, terminal, messaging and delegation toolsets
are disabled; memory writes go to a quarantine directory instead of the main memory files.

```sh
HERMES_HOME=~/.hermes-peer hermes chat --toolsets file,paseka \
  -q "Handle new paseka inbox items. Answer only through the paseka propose or share tools."
```

Copy the main memory files into the peer home read-only (or bind-mount them) so the agent keeps
its knowledge. The run starts fresh, not from a fork of the main session.

Limits: toolset names and the `HERMES_HOME` override must be checked against the installed
Hermes version; disabling the terminal toolset is required, since a shell has network; the
model provider sees the content.

## L3

Run the L2 command above as a separate unix user: `os-restrictions.md`. This also stops a
hijacked run from uploading data to a file-sharing site through any toolset the L2 config missed.
