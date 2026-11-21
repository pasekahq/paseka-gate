# L3: OS restrictions (any agent)

The agent that reads incoming peer messages runs as a separate unix user whose network reaches
only the model API and the gate. Works for any agent, including one whose own tool settings
cannot be trusted. Names are illustrative: owner `alice`, peer-turn user `alice-peer`, notes in
`/srv/alice/notes`.

1. Create the user and give it the gate socket, nothing else of the owner's:

   ```sh
   sudo useradd --create-home --home-dir /var/lib/alice-peer --shell /usr/sbin/nologin alice-peer
   sudo usermod -aG paseka-agent alice-peer
   ```

   `alice-peer` is never in group `paseka` and never in a group that can write the owner's files.
   Copy the agent's token file to `/var/lib/alice-peer/.config/paseka/`, owned by `alice-peer`
   with mode 0600, so the relay's `--token-file ~/.config/paseka/<agent>.token` finds it.

2. Notes and memory read-only, writes to quarantine. Mount the owner's notes and the agent's
   memory read-only inside the user's home (for example `mount --bind -o ro`, or
   `BindReadOnlyPaths=` in the unit below) and point the agent's memory writes at
   `/var/lib/alice-peer/quarantine/`, which the owner reviews and merges.

3. Network only to the model API and the gate. Drop every outbound packet of `alice-peer` except
   loopback, and run an allowlisting HTTPS proxy on loopback that lets through only the model
   API host:

   ```
   table inet paseka_peer {
     chain out {
       type filter hook output priority 0; policy accept;
       meta skuid "alice-peer" oif "lo" accept
       meta skuid "alice-peer" drop
     }
   }
   ```

   Set `HTTPS_PROXY=http://127.0.0.1:3128` for the agent; the proxy allows `CONNECT` only to the
   model API host. The gate is reached over its unix socket or loopback HTTP.

4. Run the agent as that user, with the agent's own L2 run when it has one (see its recipe), for
   example from a systemd unit started by the owner's scheduler:

   ```ini
   [Service]
   User=alice-peer
   BindReadOnlyPaths=/srv/alice/notes:/var/lib/alice-peer/notes
   ProtectHome=tmpfs
   Environment=HTTPS_PROXY=http://127.0.0.1:3128
   ExecStart=/usr/local/bin/handle-peer-inbox
   ```

5. Check: as `alice-peer`, `curl https://example.org/` fails, writing into
   `/var/lib/alice-peer/notes` fails, and the paseka tools answer.

Limits: other loopback services stay reachable from `alice-peer`, so bind them to other
addresses or add them to the drop rule; the model API provider sees the content; the agent's
credentials for the model API live in the peer user's home and are usable by a hijacked run;
the proxy must reject `CONNECT` to any host but the model API.
