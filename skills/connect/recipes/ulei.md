# ulei

## L1

Configure the paseka MCP server in ulei's tool configuration with the command
`paseka mcp --socket /run/paseka/agent.sock`.

Limits: ulei's other outbound tools stay available in a peer turn. The owner accepts that risk;
the gate marks the agent "Incoming messages from peers are read without protection."

## L2, separate run

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

Run the L2 run above as a separate unix user: `os-restrictions.md`.
