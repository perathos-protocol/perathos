# Perathos agent receipt format, v1 (`perathos.receipt/v1`)

Status: draft, implemented in `perathos/recorder.py`. Intended to be simple
enough to re-implement a verifier in any language in an afternoon.

## Log

A session log is a UTF-8 JSON Lines file, one receipt per line, append-only.
Claude Code logs live at `<cwd>/.perathos/sessions/<session_id>.jsonl`; Cursor
logs at `<first workspace root>/.perathos/sessions/<conversation_id>.jsonl`;
MCP proxy logs at `<project>/.perathos/sessions/<session>.jsonl` (default
session name `mcp-<name>-<UTC timestamp>`).

## Receipt fields

| Field | Type | In which kinds | Meaning |
|---|---|---|---|
| `v` | string | all | Always `perathos.receipt/v1` |
| `kind` | string | all | `pre`, `post` or `checkpoint` |
| `session_id` | string | all | Agent session id (`[A-Za-z0-9._-]`, max 128) |
| `agent` | string | all | Recording integration: `claude-code`, `cursor` or `mcp-proxy` |
| `seq` | integer | all | 1 for the first receipt, then +1 per receipt |
| `ts` | string | all | UTC, ISO 8601, microseconds, `Z` suffix; local clock |
| `prev_hash` | hex string | all | `receipt_hash` of the previous receipt; 64 zeros for the first |
| `tool` | string | pre, post | Tool name |
| `tool_use_id` | string or null | pre, post | Id linking a call to its result |
| `args_hash` | hex string | pre, post | SHA-256 of the tool arguments |
| `result_hash` | hex string | post | SHA-256 of the tool result (or of the error) |
| `status` | string | post | `ok` or `error` |
| `event` | string | checkpoint | What sealed it: `Stop`, `SubagentStop`, `SessionEnd` (Claude Code hook events); `stop`, `subagentStop`, `sessionEnd` (Cursor hook events); `mcp-periodic` (MCP proxy, every `--seal-every` tool calls) and `mcp-end` (MCP proxy, when the client disconnects or the server exits) |
| `model` | string or null | checkpoint | Model named in the transcript (Claude Code) or hook payload (Cursor); self-reported. Always null from the MCP proxy |
| `signer` | hex string | signed checkpoint | Ed25519 public key (32 bytes), bound into the hash |
| `signer_error` | string | unsigned checkpoint (optional) | Present only when the recorder's configured signer failed, so the checkpoint was written without `signer` and `signature`. The value is the error's class name (for example `SignerError`). See "Signer failures" |
| `receipt_hash` | hex string | all | See below |
| `signature` | object | signed checkpoint | `{algorithm: "ed25519", verify_key, signature}`; not hashed |
| `guard` | object | pre (optional) | The guard's decision on this call: `{decision, rule, precondition, approval?}`. See "The `guard` field" |

Receipts written by Cursor may also carry `result_from: "payload"` on a `post`
receipt (the result hash was taken over the hook payload because Cursor sent
no output field). A verifier must hash every field it finds, known or not.

### The `guard` field

Present on a `pre` receipt when the destructive-action guard matched a rule
for the call (and, in the Claude Code and Cursor hooks and the MCP proxy, when
the guard itself failed). It is inside the hashed body.

| Key | Type | Meaning |
|---|---|---|
| `decision` | `"allow"` or `"deny"` | What the guard decided. `deny` means the call never ran |
| `rule` | string | Id of the rule that matched, for example `db.dropdb`. Prefixed `script:` when the match was inside a script the command runs, or `write:` when a script being written contained it. `guard.error` means the guard itself raised an error and the call was denied (the guard fails closed) |
| `precondition` | hex string or null | `precondition_hash` of the signed precondition the guard relied on to allow the call; null when there was none |
| `approval` | hex string (optional) | `receipt_hash` of the Perathos Gate receipt ([GATE_V1.md](GATE_V1.md)) when a person approved the call with a passkey. The receipt's `request.args_hash` equals this receipt's `args_hash`; `perathos evidence verify` checks that, and that the receipt is in the pack and is an approve decision. (Approvals of Cursor shell commands made by perathos 1.4.1 or earlier were bound to the hash of `{"command": ...}` and not to the receipt's hash of the command string, so they fail this check) |

An `allow` written by `perathos` always names its authority: a `precondition`
or an `approval`. A call that matched no rule has no `guard` field.

## Hashing

* **Content hashes** (`args_hash`, `result_hash`): SHA-256 of the UTF-8 bytes
  if the value is a string, else of its canonical JSON. `null` hashes as the
  bytes `null`.
* **Canonical JSON**: keys sorted, no whitespace (`,` and `:` separators),
  UTF-8, non-ASCII characters unescaped, NaN and Infinity forbidden. Receipt
  bodies contain only ASCII keys, strings, integers, booleans and null, so
  this coincides with RFC 8785 (JCS).
* **`receipt_hash`**: SHA-256 of the canonical JSON of every field except
  `receipt_hash` and `signature`.
* **Signature**: Ed25519 over the 32 raw bytes of `receipt_hash` (not its hex
  text). `signature.verify_key` must equal the receipt's `signer`.

## Verification rules

A log is valid when every line is a JSON object and:

1. `v` is `perathos.receipt/v1` and `kind` is known.
2. `seq` values are exactly 1, 2, 3, ... in file order.
3. Each `prev_hash` equals the previous receipt's `receipt_hash`; the first
   equals 64 zeros.
4. Each `receipt_hash` recomputes.
5. `session_id` is the same on every receipt; `ts` never decreases.
6. Every checkpoint's signature verifies and its key equals `signer`.
7. Unless the verifier explicitly allows unsigned logs: at least one
   checkpoint exists and every checkpoint is signed.
8. If the verifier pins a key or a trust set, every signer is in it.
9. If a head witness (`<session_id>.head.json`, holding the latest
   checkpoint's `seq` and `receipt_hash`) is present, the log contains that
   checkpoint.

Receipts after the last checkpoint are reported as an unsealed tail, not an
error: the session may still be running.

A `pre` receipt whose `guard.decision` is `deny` is a call that never ran, so
no `post` follows it.

### Signer failures

The recorder never blocks the agent because signing failed. If the configured
signer cannot be loaded or fails while signing (for example a Vault or KMS
outage, or a malformed local key), the checkpoint is still appended, without
`signer` and `signature`, and with `signer_error` set inside the hashed body.
The recorder also prints a warning on stderr and appends a line to
`~/.perathos/errors.log`.

Such a checkpoint is an unsigned checkpoint, so rule 7 applies: the log fails
verification with `ERR_UNSIGNED` unless the verifier explicitly allows unsigned
logs, even if later checkpoints are signed. The reference verifier names the
cause in that error ("the recorder's signer failed when it was sealed"),
counts such checkpoints as `signer_failures` in its report, and with
"allow unsigned" reports them as a warning. `signer_error` is the recorder's
own statement and proves nothing by itself: it explains a missing signature,
it does not excuse one. A missing local key that was never created is not a
signer failure: those checkpoints are unsigned with no `signer_error`. The
browser verifier reports a plain `ERR_UNSIGNED` without naming the cause.

`signer_error` is optional and additive: hash rules are unchanged (every
field except `receipt_hash` and `signature` is hashed), and logs written
before it existed verify as before.

## Anchors (`perathos.anchor/v1`)

Independent RFC 3161 timestamps live in a separate JSON Lines file
(default `~/.perathos/anchors/<session_id>.jsonl`), one object per anchored
checkpoint:

| Field | Meaning |
|---|---|
| `v` | `perathos.anchor/v1` |
| `session_id`, `seq`, `receipt_hash` | The checkpoint this anchors |
| `tsa` | URL of the Time Stamping Authority |
| `gen_time` | Time the TSA asserted |
| `token` | Base64 DER `TimeStampResp` |

The TSA request's message imprint is SHA-256 over the 32 raw bytes of
`receipt_hash`. A token is valid only if it chains to a pinned TSA root; the
certificates embedded in the token are never used as trust anchors.

Additional rules when anchors are checked:

10. Every anchor names a checkpoint present in the log with the same
    `receipt_hash`. An anchor whose `seq` is past the log's last checkpoint
    proves the log was truncated.
11. Every token verifies over its checkpoint hash against a pinned root.
12. With "require anchor", the last checkpoint must be anchored.

## Preconditions (`perathos.precondition/v1`)

Signed safety checks in `<cwd>/.perathos/preconditions/<id>.json`:
`id`, `kind`, `scope` (a target name that must appear in the command as a
whole token, or `*`),
`check` (command run) and `check_exit_code` (always 0), `check_output_hash`,
or instead `manual_reason`, then `created`, `expires`, `signer`,
`precondition_hash` (SHA-256 of the canonical body without the hash and the
signature) and `signature` (Ed25519 over the raw hash bytes). The guard
accepts one only if it is unmodified, unexpired, signed by a trusted key, and
its scope appears in the command as a whole token. The trusted keys are the
approvers listed in `~/.perathos/approvers.json`; only when no approver is
listed is the local recorder key trusted instead (and with no key at all,
nothing is). The standalone
specification, with validity and binding rules, is
[PRECONDITION_V1.md](PRECONDITION_V1.md).

## What a valid log proves, and what it does not

Proves: the holder of the signing key sealed this exact sequence of receipts,
and no receipt up to the last checkpoint was edited, removed, inserted or
reordered since. Whoever holds a tool call's original arguments or output can
show it matches the recorded hash.

Does not prove (v1):
* that nothing was cut after the last checkpoint, if the head witness was
  also removed and no anchor copy is held elsewhere;
* the real time of each event, unless the checkpoint is anchored (local clock);
* which model ran (the `model` field is self-reported);
* that the recorder was running for the whole session. A gap where hooks were
  disabled, or where a hook failed to write a receipt, is not visible in the
  log (a failed write is noted in the local, unsigned `~/.perathos/errors.log`);
* that short, guessable arguments stay private: their hash can be confirmed
  by hashing guesses.
