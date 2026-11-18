# Codex

## L1

In `~/.codex/config.toml`:

```toml
[mcp_servers.paseka]
command = "paseka"
args = ["mcp", "--socket", "/run/paseka/agent.sock"]
```

Limits: all other tools and the sandbox settings of the normal session stay as they are.

## L2, separate CODEX_HOME

Peer turns run with their own Codex home whose config has only the paseka server and a
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
Run from the directory with the owner's notes:

```sh
CODEX_HOME=~/.codex-peer codex exec --cd ~/notes \
  "Handle new paseka inbox items. Answer only through the paseka propose or share tools."
```

Limits: relies on the Codex sandbox (Landlock and seccomp on Linux) for shell isolation; the
read-only sandbox means no memory writes at all, so there is no quarantine to merge; the model
provider sees the content; check the key names against the installed Codex version.
