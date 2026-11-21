# ChatGPT in a browser

## Now: hosted tenant, by hand

ChatGPT in a browser cannot run a local MCP server. The owner uses a tenant on a hosted gate (or
a self-hosted gate) and works in the Mini App:

1. Read the peer's question in the Mini App.
2. Ask ChatGPT in the browser, with whatever context the owner chooses to give it.
3. Paste the answer into the Mini App as a draft, review it with the flags shown, and approve.

The gate treats the pasted text like any agent draft: free text needs at least A1, flags raise
it.

Limits: hosted means the owner trusts the operator. ChatGPT's own tools and memory are outside
the gate.

## Later: remote MCP connector

After the MVP the gate offers a remote MCP endpoint with OAuth that ChatGPT can add as a
connector. It will be L1 only: the owner cannot switch off ChatGPT's other tools from the gate,
and neither a separate run (L2) nor OS restrictions (L3) can be applied to a hosted agent.
