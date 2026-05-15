# Perathos

Cryptographic proof layer for AI outputs. Every AI response gets a tamper-evident bundle — a hash chain + optional Ed25519 signature — that can be verified offline with no network calls.

## Install

```bash
pip install perathos
```

## Usage

```bash
# Generate a signing keypair
perathos keygen

# Prove an AI output (unsigned)
perathos prove "The capital of France is Paris."

# Prove with signature
perathos prove "The capital of France is Paris." --sign

# Verify a bundle
perathos verify <bundle_id>

# Inspect a bundle (human-readable)
perathos inspect <bundle_id>

# List stored bundles
perathos list
```

## What's in a bundle

Each bundle captures:

| Field | Description |
|---|---|
| `bundle_id` | UUIDv5 derived from `integrity_hash` — deterministic, reconstructable |
| `ai_id` | SHA-256 of the model descriptor — identifies which model produced the output |
| `input_hash` | SHA-256 of the prompt / request |
| `output_hash` | SHA-256 of the AI response text |
| `trace_hash` | SHA-256 of execution metadata |
| `integrity_hash` | SHA-256 of the canonical integrity payload — the tamper-evident root |
| `provider_signature` | Optional Ed25519 signature over `integrity_hash` |

Bundles are stored locally at `~/.perathos/bundles/`.

## Python API

```python
from perathos import prove, verify, sign

bundle = prove("The capital of France is Paris.", input_text="What is the capital of France?")
bundle = sign(bundle)           # attach Ed25519 signature
valid, err = verify(bundle)     # True, ""
```

## How it works

```
input_text  ──SHA256──► input_hash ─┐
output_text ──SHA256──► output_hash ─┤
trace_dict  ──canonical_json──SHA256──► trace_hash ─┤
                                     └─► integrity_payload ──SHA256──► integrity_hash
                                                                              │
                                                               uuid5(namespace, integrity_hash)
                                                                              │
                                                                         bundle_id
```

Each bundle is **tamper-evident**: if any field in the integrity payload (input hash, output hash, trace, model ID, timestamp) is changed, the integrity_hash changes, the bundle_id changes, and verification fails. Verifiers need only recompute the hashes from the stored data — no network calls, no external authority.

Optional Ed25519 signatures allow the **provider** (the AI service) to cryptographically commit to a bundle's integrity_hash, enabling end-to-end proof of provenance.

## Error Handling

Both `verify()` and `verify_signature()` return a tuple `(valid: bool, error_code: str)`.

### `verify()` error codes

Returned by `perathos.verify(bundle)` and `perathos.bundle.verify_bundle(bundle)`:

| Error Code | Meaning | Action |
|---|---|---|
| `""` (empty) | Bundle is valid | No error; first element is `True` |
| `ERR_MISSING_TRACE` | Bundle is missing the `_trace` field | Bundle is corrupted or incomplete; reject |
| `ERR_TRACE_HASH_MISMATCH` | Recomputed trace hash doesn't match stored `trace_hash` | Execution metadata was tampered with; reject |
| `ERR_INTEGRITY_HASH_MISMATCH` | Recomputed integrity hash doesn't match stored `integrity_hash` | One or more bundle fields (ai_id, input_hash, output_hash, etc.) were tampered with; reject |
| `ERR_BUNDLE_ID_MISMATCH` | Reconstructed bundle_id doesn't match the stored one | bundle_id was manually changed; reject |
| `ERR_MISSING_FIELD:<field>` | A required field is absent from the bundle | Bundle structure is invalid; reject |

Example:
```python
from perathos import verify

bundle = {...}
valid, err = verify(bundle)
if not valid:
    if "ERR" in err:
        print(f"Bundle verification failed: {err}")
        # handle tamper detection
```

### CLI error messages from `perathos verify`

The `perathos verify` command prints status to stdout and errors to stderr:

| Output | Meaning | Exit Code |
|---|---|---|
| `VALID_UNSIGNED <bundle_id>` | Bundle hash chain is valid, no signature present | 0 |
| `VALID_SIGNED <bundle_id>`<br/>`verify_key <hex>` | Bundle hash chain is valid and signature is valid | 0 |
| `INVALID <error_code>` | Hash chain verification failed (see verify() codes above) | 1 |
| `ERROR: Bundle not found: <id>` | Bundle ID not in local storage | 1 |
| `ERROR: Invalid JSON in <path>: <error>` | --file path contains invalid JSON | 1 |
| `ERROR: Specify either BUNDLE_ID or --file, not both.` | Both BUNDLE_ID and --file were given | 2 |
| `ERROR: Specify either BUNDLE_ID or --file.` | Neither BUNDLE_ID nor --file was given | 2 |

Example CLI session:
```bash
$ perathos verify 550e8400-e29b-41d4-a716-446655440000
VALID_UNSIGNED  550e8400-e29b-41d4-a716-446655440000

$ perathos verify nonexistent-id
ERROR: Bundle not found: nonexistent-id
Run: perathos list
$ echo $?
1
```

### `verify_signature()` error codes

Returned by `perathos.verify_signature(integrity_hash, provider_signature)`:

| Error Code | Meaning | Action |
|---|---|---|
| `""` (empty) | Signature is valid | No error; first element is `True` |
| `ERR_BAD_SIGNATURE` | Signature is invalid (doesn't match the integrity_hash) | Provider signature is forged or the hash was tampered after signing; reject |
| `ERR_MISSING_SIG_FIELD:<field>` | A required signature field is missing (`verify_key` or `signature`) | Signature structure is invalid; reject |
| `ERR_INVALID_VERIFY_KEY:<error>` | The verify_key is not a valid 64-char hex string | Signature structure is corrupt; reject |
| `ERR_INVALID_HASH:<error>` | The integrity_hash is not a valid 64-char hex string | Bundle is corrupted; reject |
| `ERR_INVALID_SIGNATURE:<error>` | Signature format is invalid or cryptographic check failed | Key or signature encoding is wrong; reject |

Example:
```python
from perathos import verify, verify_signature

bundle = {...}
valid, err = verify(bundle)
if valid and "provider_signature" in bundle:
    sig_valid, sig_err = verify_signature(bundle["integrity_hash"], bundle["provider_signature"])
    if sig_valid:
        print(f"Signature valid. Provider: {bundle['provider_signature']['verify_key']}")
    else:
        print(f"Signature verification failed: {sig_err}")
```

### CLI error messages from `perathos prove --sign`

The `perathos prove --sign` command requires a signing key. If it is missing:

```bash
$ perathos prove "some text" --sign
ERROR: No signing key found.
Run: perathos keygen
Then use: perathos prove TEXT --sign
$ echo $?
1
```

Always run `perathos keygen` first to create the signing key in `~/.perathos/keys/signing.key`.

## License

MIT
