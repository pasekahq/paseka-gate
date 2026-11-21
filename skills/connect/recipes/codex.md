# Codex

## L1

In `~/.codex/config.toml`:

```toml
[mcp_servers.paseka]
command = "paseka"
args = ["mcp", "--socket", "/run/paseka/agent.sock"]
```

Limits: all other tools and the sandbox settings of the normal session stay as they are. The
owner accepts that risk; the gate marks the agent "Incoming messages from peers are read without
protection."

## L2, separate run from its own CODEX_HOME

Peer turns run as a separate run (by the owner's scheduler or, later, `paseka peer-turn`) with their own Codex home whose config has only the paseka server and a
read-only sandbox (shell commands get no network and no writes). `~/.codex-peer/config.toml`:

```toml
model = "<same model as the main config>"
sandbox_mode = "read-only"
approval_policy = "never"

[tools]
web_search = false

[mcp_servers.paseka]
command = "paseka"
args = ["mcp", "--socket", "/run/paseka/agent.sock"]
```

Copy the authentication of the main home once (`codex login` with `CODEX_HOME=~/.codex-peer`).
The run starts fresh, not from a fork of the main session, since sessions live in the main
home. Run from the directory with the owner's notes:

```sh
CODEX_HOME=~/.codex-peer codex exec --cd ~/notes \
  "Handle new paseka inbox items. Answer only through the paseka propose or share tools."
```

Limits: relies on the Codex sandbox (Landlock and seccomp on Linux) for shell isolation; the
read-only sandbox means no memory writes at all, so there is no quarantine to merge; the model
provider sees the content; check the key names against the installed Codex version.

## L3

Run the L2 command above as a separate unix user: `os-restrictions.md`.
