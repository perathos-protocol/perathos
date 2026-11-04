# Perathos quickstart

Five minutes from install to a verified evidence pack.

## 1. Install and create your key

```bash
pip install 'perathos[anchor]'
perathos keygen
```

`keygen` writes `~/.perathos/keys/signing.key` (private) and `verify.key` (public). Give the
public key to anyone who will check your records.

## 2. Turn on recording for your agent

Pick one:

```bash
perathos hooks install --guard --anchor                  # Claude Code (.claude/settings.json)
perathos hooks install --agent cursor --guard --anchor   # Cursor (.cursor/hooks.json)
```

For any MCP client, wrap the server command (see the README section "Any MCP client"):

```bash
perathos mcp-proxy --name db --guard --anchor -- <real MCP server command>
```

- `--guard` blocks destructive commands unless a person signed a precondition.
- `--anchor` timestamps each checkpoint with an RFC 3161 authority (needs network; failures
  never block the agent, and `perathos session anchor` can add timestamps later).

## 3. Work normally

Each tool call adds two receipts to `.perathos/sessions/<session id>.jsonl`; each turn ends with
a signed checkpoint. Only hashes are stored, never arguments or outputs.

If the agent tries something destructive, it is blocked with instructions. To allow it, a person
runs a check that proves the safeguard holds, for example that a backup restores:

```bash
perathos precondition add --scope pg-data --check "pg_restore --list backups/pg-data.dump"
```

The precondition is signed and expires after 30 minutes (`--ttl`). The agent cannot create one.

## 4. Check and share the record

```bash
perathos session list
perathos session show <session id>
perathos session verify <session id> --verify-key <your public key> --require-anchor
perathos session export <session id> --out evidence-pack
```

Send `evidence-pack.zip` and your public key (through a separate channel) to the reviewer. They
run `perathos evidence verify evidence-pack.zip --verify-key <key>`, or drop the zip into
https://perathos-protocol.github.io/perathos/verify/.

## 5. See it end to end

```bash
git clone https://github.com/perathos-protocol/perathos && cd perathos
python examples/pocketos_replay/replay.py
```

Replays the April 2026 incident where an agent deleted a production volume and its backups,
without and with Perathos, in a throwaway folder.
