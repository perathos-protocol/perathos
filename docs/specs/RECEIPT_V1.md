# Perathos agent receipt format, v1 (`perathos.receipt/v1`)

Status: draft, implemented in `perathos/recorder.py`. Intended to be simple
enough to re-implement a verifier in any language in an afternoon.

## Log

A session log is a UTF-8 JSON Lines file, one receipt per line, append-only.
Claude Code logs live at `<cwd>/.perathos/sessions/<session_id>.jsonl`.

## Receipt fields

| Field | Type | In which kinds | Meaning |
|---|---|---|---|
| `v` | string | all | Always `perathos.receipt/v1` |
| `kind` | string | all | `pre`, `post` or `checkpoint` |
| `session_id` | string | all | Agent session id (`[A-Za-z0-9._-]`, max 128) |
| `agent` | string | all | Recording integration, e.g. `claude-code` |
| `seq` | integer | all | 1 for the first receipt, then +1 per receipt |
| `ts` | string | all | UTC, ISO 8601, microseconds, `Z` suffix; local clock |
| `prev_hash` | hex string | all | `receipt_hash` of the previous receipt; 64 zeros for the first |
| `tool` | string | pre, post | Tool name |
| `tool_use_id` | string or null | pre, post | Id linking a call to its result |
| `args_hash` | hex string | pre, post | SHA-256 of the tool arguments |
| `result_hash` | hex string | post | SHA-256 of the tool result (or of the error) |
| `status` | string | post | `ok` or `error` |
| `event` | string | checkpoint | Hook event that sealed it: `Stop`, `SubagentStop`, `SessionEnd` |
| `model` | string or null | checkpoint | Model named in the transcript; self-reported |
| `signer` | hex string | signed checkpoint | Ed25519 public key (32 bytes), bound into the hash |
| `receipt_hash` | hex string | all | See below |
| `signature` | object | signed checkpoint | `{algorithm: "ed25519", verify_key, signature}`; not hashed |

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

## What a valid log proves, and what it does not

Proves: the holder of the signing key sealed this exact sequence of receipts,
and no receipt up to the last checkpoint was edited, removed, inserted or
reordered since. Whoever holds a tool call's original arguments or output can
show it matches the recorded hash.

Does not prove (v1):
* that nothing was cut after the last checkpoint, if the head witness was
  also removed (external timestamping of checkpoints addresses this);
* the real time of each event (local clock);
* which model ran (the `model` field is self-reported);
* that the recorder was running for the whole session. A gap where hooks were
  disabled is not visible;
* that short, guessable arguments stay private: their hash can be confirmed
  by hashing guesses.
