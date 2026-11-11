# `perathos.receipt/v1` test vectors

Session logs written by the reference recorder (`perathos/recorder.py`), for
checking an independent verifier of [RECEIPT_V1.md](../../RECEIPT_V1.md)
against ours. They are produced by our writer, not hand-written, by
[`scripts/make_receipt_v1_vectors.py`](../../../../scripts/make_receipt_v1_vectors.py).
Re-running it gives byte-identical files (fixed key, session id and clock);
`tests/test_receipt_v1_vectors.py` checks that and every verdict below.

Each case folder holds exactly what `perathos session verify` reads:

* `receipt-v1-vector.jsonl`: the session log (LF line endings);
* `receipt-v1-vector.head.json`: the head witness (rule 9), found next to the
  log by name.

`expected.json` lists, per case, the files, the verdict, and each error with
its code, the `seq` where it fires and the reference verifier's exact message.
The key to pin is `verify_key` in `expected.json`:
`dbe821f7158ff4475b90d537b3b75d67c9bb655dce38c78500362fa9d5878414`.

| Case | What it is | Rule | Expected |
|---|---|---|---|
| `01-valid` | 2 tool calls, a signed `Stop` checkpoint (seq 5), 1 tool call, a signed `SessionEnd` checkpoint (seq 8), as the recorder wrote them | all | `VALID` |
| `02-broken-prev-hash` | seq 3's `prev_hash` is not seq 2's `receipt_hash` (last hex digit changed). Its `receipt_hash` and all later receipts were recomputed and both checkpoints re-signed with the real key, so the chain link is the only thing wrong | 3 | `INVALID`, `ERR_CHAIN` at seq 3 |
| `03-forged-checkpoint-signature` | The seq 5 checkpoint's `signature.signature` is a well-formed 128-hex Ed25519 signature over its `receipt_hash`, made with a different key; `verify_key` and `signer` still name the real key | 6 | `INVALID`, `ERR_BAD_SIGNATURE` at seq 5 |
| `04-unsigned-checkpoint` | The seq 8 checkpoint was written by the recorder while its remote signer was failing: no `signer` or `signature`, `"signer_error": "SignerError"` in the hashed body. seq 5 is signed | 7, "Signer failures" | `INVALID`, `ERR_UNSIGNED` at seq 8 (`VALID` with `--allow-unsigned`) |

Each negative case fails on exactly one error and no warnings.

## Running the reference verifier

```
pip install perathos
perathos session verify 01-valid/receipt-v1-vector.jsonl \
  --verify-key dbe821f7158ff4475b90d537b3b75d67c9bb655dce38c78500362fa9d5878414
```

Exit code 0 is valid, 1 invalid. Without `--verify-key` a valid log prints
`VALID_UNCONFIRMED_SIGNER` instead of `VALID`. Actual output (errors go to
stderr):

```
01-valid                        VALID
02-broken-prev-hash             [ERROR] ERR_CHAIN at seq 3 (line 3): prev_hash does not match the previous receipt
03-forged-checkpoint-signature  [ERROR] ERR_BAD_SIGNATURE at seq 5 (line 5)
04-unsigned-checkpoint          [ERROR] ERR_UNSIGNED at seq 8 (line 8): checkpoint has no signature: the recorder's signer failed when it was sealed ('SignerError')
```

## No anchors

The vectors carry no RFC 3161 anchors. `session verify` does not require
anchors by default; do not pass `--require-anchor`. It does look for an
anchors file at `~/.perathos/anchors/receipt-v1-vector.jsonl` and checks it if
one exists, so keep no file by that name.

## The signing key is a published test key

The checkpoints are signed with a FIXED TEST KEY that is published on purpose
(`test_signing_key` in `expected.json`, derived in the generator). Anyone can
sign with it. Never use it, or trust it, for anything real.

## Line endings

Compare these files byte for byte. `.gitattributes` here turns off line-ending
conversion, so a Windows checkout keeps LF.
