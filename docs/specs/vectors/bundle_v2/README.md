# Bundle v2 commerce-event test vectors

Proof bundles (`bundle_version` `"2.0"`) that model **NEXUS commerce events**,
for checking an independent Bundle v2 implementation (NEXUS's TypeScript port)
against ours. They are produced by
[`scripts/make_bundle_v2_vectors.py`](../../../../scripts/make_bundle_v2_vectors.py),
which builds each bundle field by field from public functions
(`canonical_bytes`, `PERATHOS_NAMESPACE`, `sign_hash`, `kid_for`,
`TrustStore.to_jwks`). `create_bundle` is not used and not changed: it reads
the clock and fixes the model descriptor. Re-running the script gives
byte-identical files (fixed keys, fixed `issued_at`, fixed payloads, and
deterministic Ed25519); `tests/test_bundle_v2_vectors.py` checks that and every
verdict below.

## The mapping

| Field | Value |
|---|---|
| `model` | `nexus.commerce.event/1` |
| `_trace.model_descriptor` | `nexus-platform:nexus.commerce.event:v1` (so `ai_id` = sha256 of it) |
| `answer` | the canonical JSON string of the event payload; `output_hash` = sha256 of it |
| `input_text` (not stored) | the previous event's `bundle_id` for the same order, or `""` for the first event; `input_hash` = sha256 of it |
| `issued_at` | an opaque string; these vectors use the JavaScript `toISOString()` form |

There is no `verification` block, so no `verdict` or `verification_hash`.

## Files

* `<case>/bundle.json`: one bundle, exactly what `perathos verify --file` reads;
* `jwks.json`: the trusted key (`keys.trusted` in `expected.json`), for `--trust-jwks`;
* `expected.json`: per case, every intermediate value of the honest build
  (payload, its canonical bytes as a string and as hex, `input_text`, `_trace`
  and its canonical form, `trace_hash`, `ai_id`, `input_hash`, `output_hash`,
  the integrity payload and its canonical bytes, `integrity_hash`, `bundle_id`,
  the signature), the mutation applied after it (tampered cases), and the
  verdict and error code from Python and from NEXUS. `chains` lists the case
  order of the valid chain and the broken one.

## Python checks one bundle at a time

`perathos verify --file` and `verify_bundle` check one bundle: its hashes, id,
`answer` against `output_hash`, and its signature (and signer, with
`--trust-jwks`). They know nothing about chains, and they check `answer` only
when it is present. NEXUS adds two rules of its own, so two cases are valid in
Python and invalid for NEXUS, and a third fails in both with different codes
(`python` and `nexus` differ in `expected.json`):

* `answer` is required for model `nexus.commerce.event/1` (`ERR_ANSWER_REQUIRED`);
* a chain check: `seq` runs 1, 2, 3, ...; the first `input_hash` is sha256(`""`);
  each later `input_hash` is sha256 of the previous `bundle_id` (`ERR_CHAIN`);
* number tokens: NEXUS parses bundle text and rejects any number written with
  `.`, `e`, `E`, or as `-0` (`ERR_MALFORMED_BUNDLE`) before hashing. Python
  reads `0.0` as a float and canonicalises it as `0.0`, so the hash fails
  there instead (`ERR_TRACE_HASH_MISMATCH` in case 20). A JavaScript verifier
  that let `JSON.parse` turn `0.0` into `0` would hash the original bytes and
  wrongly say VALID; refusing the token keeps NEXUS from ever saying VALID
  where Python says invalid.

## Cases

| Case | What it is | Python | NEXUS |
|---|---|---|---|
| `01-order-confirmed` | seq 1, `input_text` `""` | `VALID` | `VALID` |
| `02-order-shipped` | seq 2, `input_text` = 01's `bundle_id` | `VALID` | `VALID` |
| `03-order-delivered` | seq 3, `input_text` = 02's `bundle_id` | `VALID` | `VALID` |
| `04-dispute-closed` | seq 4, `order.dispute_closed` with `"outcome": "won"`, `input_text` = 03's `bundle_id` | `VALID` | `VALID` |
| `10-answer-edited` | 01 with `answer` changed | `ERR_ANSWER_MISMATCH` | same |
| `11-output-hash-edited` | 01 with `output_hash` changed | `ERR_INTEGRITY_HASH_MISMATCH` | same |
| `12-trace-edited` | 01 with `_trace.output_length` changed | `ERR_TRACE_HASH_MISMATCH` | same |
| `13-bundle-id-edited` | 01 with `bundle_id` changed | `ERR_BUNDLE_ID_MISMATCH` | same |
| `14-forged-signature` | 01 with a signature from the forger key; `verify_key` unchanged | `ERR_BAD_SIGNATURE` | same |
| `15-signature-removed` | 01 with no `provider_signature` | `ERR_UNSIGNED` (signatures required) | same |
| `16-algorithm-changed` | 01 with `algorithm` `"ed448"` | `ERR_UNSUPPORTED_ALGORITHM` | same |
| `17-untrusted-signer` | 01 rebuilt and signed by the outsider key, not in `jwks.json` | `ERR_UNTRUSTED_SIGNER` | same |
| `18-answer-stripped` | 01 with `answer` removed | `VALID` | `ERR_ANSWER_REQUIRED` |
| `19-chain-broken` | seq 2 signed correctly, but `input_text` is not 01's `bundle_id`; checked as the chain [01, 19] | `VALID` | `ERR_CHAIN` |
| `20-trace-float-encoding` | 01 with `_trace.input_length` written as `0.0` in the file text (numerically equal) | `ERR_TRACE_HASH_MISMATCH` | `ERR_MALFORMED_BUNDLE` |

Python verdicts are from `verify_bundle(bundle, trust_store=TrustStore.from_jwks(jwks), require_signed=True)`.
Each failing case fails on exactly one code.

Cases 01 to 04 form one chain for one order. They do not model which event
sequences are allowed (a real order would record `order.dispute_opened` before
`order.dispute_closed`); the chain rules above are about links and `seq` only.

## Running the reference verifier

```
pip install perathos
perathos verify --file 01-order-confirmed/bundle.json --trust-jwks jwks.json
```

Exit code 0 is valid, 1 invalid. Always pass `--trust-jwks` (or
`--verify-key`): without it the CLI shows only that *some* key signed the
bundle. Actual output (errors go to stderr):

```
01-order-confirmed     VALID_SIGNED  01-order-confirmed/bundle.json
02-order-shipped       VALID_SIGNED  02-order-shipped/bundle.json
03-order-delivered     VALID_SIGNED  03-order-delivered/bundle.json
04-dispute-closed      VALID_SIGNED  04-dispute-closed/bundle.json
10-answer-edited       [ERROR] INVALID  ERR_ANSWER_MISMATCH
11-output-hash-edited  [ERROR] INVALID  ERR_INTEGRITY_HASH_MISMATCH
12-trace-edited        [ERROR] INVALID  ERR_TRACE_HASH_MISMATCH
13-bundle-id-edited    [ERROR] INVALID  ERR_BUNDLE_ID_MISMATCH
14-forged-signature    [ERROR] INVALID  ERR_BAD_SIGNATURE
15-signature-removed   [ERROR] UNSIGNED  bundle has no signature, so its issuer is unproven
16-algorithm-changed   [ERROR] INVALID  ERR_UNSUPPORTED_ALGORITHM
17-untrusted-signer    [ERROR] INVALID  ERR_UNTRUSTED_SIGNER
18-answer-stripped     VALID_SIGNED  18-answer-stripped/bundle.json
19-chain-broken        VALID_SIGNED  19-chain-broken/bundle.json
20-trace-float-encoding  [ERROR] INVALID  ERR_TRACE_HASH_MISMATCH
```

## The signing keys are published test keys

The bundles are signed with the RFC 8032 section 7.1 TEST 1 key (`trusted`);
the forger and outsider keys are TEST 2 and TEST 3. All three are in
`expected.json` on purpose. Anyone can sign with them. Never use them, or
trust them, for anything real.

## Line endings

Compare these files byte for byte. Case 20's file is not what `json.dumps`
would write (the generator patches one number token), so parse the file text
itself; do not re-serialise it. `.gitattributes` here turns off line-ending
conversion, so a Windows checkout keeps LF.
