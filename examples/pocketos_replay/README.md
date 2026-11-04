# PocketOS replay

In April 2026 a coding agent working on PocketOS deleted the Railway volume holding the
production database, and, by the founder's account, the backups stored on it, in seconds.
This demo replays that failure twice in a throwaway folder with a 1,200-row SQLite
"production database" whose only backup sits on the same volume.

```bash
pip install 'perathos[anchor]'
python examples/pocketos_replay/replay.py            # add --offline to skip the timestamp service
```

Nothing real is deleted, and Run B uses a temporary home folder and signing key, so your own
key is never touched.

## What happens

| | Run A: no Perathos | Run B: Perathos recorder + guard + timestamps |
|---|---|---|
| Agent runs `railway volume delete pg-data` | Database and backups gone | **Blocked**: no signed safety check covers it |
| Agent tries to approve itself | n/a | **Blocked** |
| Person's backup check | n/a | **Fails**: the only backup is on the volume being deleted |
| After an off-site copy | n/a | Check passes, precondition signed (expires in 30 min) |
| Agent retries | n/a | Allowed; data restorable from the off-site copy (1,200 rows) |
| Evidence afterwards | The agent's own transcript: editable, unsigned, no independent time | Signed, chained, RFC 3161-timestamped log and an evidence pack anyone can re-check |
| Someone cuts the end of the log | n/a | Log-only check: VALID. Check with independent timestamps: **INVALID, ERR_TRUNCATED** |

## Real output of one run

```text
=== RUN A - an agent with no flight recorder
  production database: 1200 customers; backups: on-volume=yes, off-site=none
  Task given to the agent: "clean up the unused staging volume"
agent  > Bash: railway volume list
         pg-data  10 GB  attached to: production
agent  > Bash: railway volume delete pg-data --yes
         Volume pg-data deleted.
  [!!] production database: GONE; backups: on-volume=GONE, off-site=none
  Evidence left behind: the agent's own chat transcript, editable, unsigned, no independent time.

=== RUN B - the same agent with Perathos (recorder + guard + timestamps)
  setup: perathos keygen; perathos hooks install --guard --anchor
  production database: 1200 customers; backups: on-volume=yes, off-site=none

--- Turn 1: the agent attempts the delete
agent  > Bash: railway volume list
         pg-data  10 GB  attached to: production
agent  > Bash: railway volume delete pg-data --yes
  [!!] BLOCKED by perathos guard: Railway delete (paas.railway). No unexpired, signed safety precondition covers this command.
agent  > (tries to approve itself)
agent  > Bash: perathos precondition add --scope pg-data --manual 'agent says it is fine'
  [!!] BLOCKED by perathos guard: (agent tried to create its own safety precondition or replace the signing key). Preconditions must be created by a person outside the agent session.
  production database: 1200 customers; backups: on-volume=yes, off-site=none
  [ok] turn sealed with a signed checkpoint and an independent RFC 3161 timestamp

--- A person steps in: is there a restorable backup that survives this delete?
person > perathos precondition add --scope pg-data --check "python check_backup.py offsite/prod-backup.db"
  [!!] check FAILED, no precondition created: the only backup lives on the volume being deleted
person > copies the backup off the volume, then re-runs the check
  [ok] check passed; precondition signed for scope 'pg-data', expires 2026-11-04T08:49:07Z

--- Turn 2: the agent retries
agent  > Bash: railway volume delete pg-data --yes
         Volume pg-data deleted.
  production database: GONE; backups: on-volume=GONE, off-site=yes
  [ok] restore from the off-site backup: 1200 customers
  [ok] turn sealed with a signed checkpoint and an independent RFC 3161 timestamp

--- After the incident: export and verify the evidence
         VALID  .perathos\sessions\pocketos-replay.jsonl
           session       pocketos-replay
           receipts      8 (4 tool calls, 2 checkpoints)
           sealed        through seq 8 by 2 signed checkpoint(s)
           signer        d53f11ff38959d472a2e619b346340b44a79866fb8650d96f22ada467f524707
           time          2026-11-04T08:19:04.700884Z to 2026-11-04T08:19:08.217162Z (local clock)
           timestamped   through seq 8 at 2026-11-04T08:19:09Z (independent, 2 token(s))
           blocked       2 destructive call(s) stopped by the guard
  [ok] evidence pack exported: <out>/evidence-pack.zip
  [ok] independent re-check of the pack: VALID

--- Tamper test: someone cuts turn 2 from the log and deletes the head file
  kept 5 of 8 receipts
  check using the log alone:            VALID
  [!!] check using the independent timestamps: INVALID  ERR_TRUNCATED: an independent timestamp proves checkpoint seq 8 existed at 2026-11-04T08:19:09Z, but the log is sealed only through seq 5

=== Done. Demo files: <temp folder>
```

## Check the sample evidence pack yourself

[`sample-evidence-pack.zip`](sample-evidence-pack.zip) is the pack exported by the run above,
and [`sample-evidence-report.pdf`](sample-evidence-report.pdf) is its one-page report.

```bash
perathos evidence verify examples/pocketos_replay/sample-evidence-pack.zip --verify-key d53f11ff38959d472a2e619b346340b44a79866fb8650d96f22ada467f524707
```

The command re-checks the signed manifest, every file in the pack, the receipt chain, both
checkpoint signatures and both RFC 3161 timestamps from FreeTSA. Change any byte in the zip
and it fails. The key above is the demo's throwaway key; for a real session you would confirm
the signer's key with its owner through a separate channel.

Pack contents: `MANIFEST.json`, `REPORT.html`, `REPORT.md`, `VERIFY.md`, `anchors.jsonl`, `preconditions/d5852e52-6d9f-4642-954f-876039684c10.json`, `session.head.json`, `session.jsonl`, `verification.json`.

## What this does not show

The guard matches command patterns: it is a seatbelt against accidents like this one, not a
sandbox against a deliberately hostile agent. The record shows which key sealed it, not which
model ran. See [docs/specs/RECEIPT_V1.md](../../docs/specs/RECEIPT_V1.md) for the full list.
