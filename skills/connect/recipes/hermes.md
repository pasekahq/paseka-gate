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

## L2, separate profile

Run peer turns from a separate Hermes home whose config enables only file reading, the memory
read path and the paseka MCP server; web, browser, terminal, messaging and delegation toolsets
are disabled; memory writes go to a quarantine directory instead of the main memory files.

```sh
HERMES_HOME=~/.hermes-peer hermes chat --toolsets file,paseka \
  -q "Handle new paseka inbox items. Answer only through the paseka propose or share tools."
```

Copy the main memory files into the peer home read-only (or bind-mount them) so the agent keeps
its knowledge.

Limits: toolset names and the `HERMES_HOME` override must be checked against the installed
Hermes version; disabling the terminal toolset is required, since a shell has network; the
model provider sees the content.
