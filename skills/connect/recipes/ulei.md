# ulei

Not yet available: no transport that ulei and the gate both implement exists today.

- ulei's MCP client speaks only MCP Streamable HTTP to an `http://` URL on a loopback host
  (`127.0.0.1`, `[::1]` or `localhost`). It cannot start a stdio server: an
  `[engine.mcp.<name>]` section has the keys `url`, `env_file`, `timeout`, `connect_timeout` and
  `tools.include`, `tools.resources`, `tools.prompts`, and no `command`. The stdio relay
  `paseka mcp --socket ... --token-file ...` of the other recipes therefore does not work with
  ulei.
- The gate's loopback HTTP transport (`docs/PROTOCOL.md` §5.1, `docs/AGENT-SETUP.md`) is not
  implemented yet, and neither are `paseka serve` and `paseka mcp`.

Connecting ulei needs one of two changes, and which one is still to be decided: an HTTP listen
mode for the paseka MCP server (the gate's loopback Streamable HTTP endpoint, or `paseka mcp`
listening on loopback), or a stdio transport in ulei. Until one ships, tell the owner that ulei
cannot be connected and stop; do not fall back to a `command` key or a wrapper.

## L1

Once the HTTP endpoint exists, the ulei config takes this shape (not yet available; take the
URL from the gate's documentation at that time):

```toml
[engine]
mcp_servers = "paseka"

[engine.mcp.paseka]
url = "http://127.0.0.1:8641/agent/v1"
env_file = "<ulei secrets directory>/paseka.env"
```

ulei sends each `NAME=value` line of the env-file as a request header to that server only. The
owner puts the agent token there, mode 0600, as the header the gate expects of HTTP clients:

```sh
Authorization=Bearer <agent token>
```

Limits: ulei's other outbound tools stay available in a peer turn. The owner accepts that risk;
the gate marks the agent "Incoming messages from peers are read without protection."

## L2, separate run

Needs the L1 connection above, so it is not yet available either.

Peer messages are handled by a separate ulei run (by the owner's scheduler or, later,
`paseka peer-turn`) from a separate configuration that offers only read tools and the paseka
server, with memory writes going to a quarantine directory the owner reviews. The run starts
fresh from the owner's notes.

The target contract for native support in ulei (not yet available):

- ulei starts a peer turn as a separate run when its input comes from `paseka inbox`, forked from
  the main session where ulei can;
- in that run its outbound tools are not offered to the model, memory writes go to quarantine,
  and the answer goes only to `propose` or `share`;
- taint tracking (CaMeL-like) records which sources fed the answer; ulei attaches that record to
  `propose`, and the gate shows it as verified provenance only once the gate can check it.

Limits: until native support exists, the guarantees are whatever the separate configuration
removes; check the configuration keys against the installed ulei version.

## L3

Run the L2 run above as a separate unix user: `os-restrictions.md`. The user's network must
still reach the gate's loopback HTTP endpoint.
