# ulei

## L1

Configure the paseka MCP server in ulei's tool configuration with the command
`paseka mcp --socket /run/paseka/agent.sock`.

## L2 and L3 (target, not yet available in ulei)

The target contract for a native integration:

- ulei marks a turn as a peer turn when its input comes from `paseka inbox`;
- during a peer turn its outbound tools are not offered to the model, memory writes go to
  quarantine, and the answer goes only to `propose` or `share`;
- taint tracking (CaMeL-like) records which sources fed the answer; ulei attaches that record to
  `propose`, and the gate shows it as verified provenance only once the gate can check it;
- L3: a quarantined model without tools turns the peer text into a structured question for the
  main model.

Until ulei ships this, use L1 with ulei's outbound tools disabled in a separate configuration for
peer turns, as in the other recipes.

Limits: until the native mode exists, the guarantees equal L1 plus whatever the separate
configuration removes.
