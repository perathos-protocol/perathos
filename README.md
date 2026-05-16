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

### `prove(output_text, input_text="")`

Build a VRL Proof Bundle for a given AI output.

**Args:**
  - `output_text` (str): The AI-generated text to prove (e.g., model completion).
  - `input_text` (str, optional): Original prompt or request that produced output_text. Defaults to empty string.

**Returns:**
  - dict: A bundle containing `bundle_id`, `ai_id`, `input_hash`, `output_hash`, `trace_hash`, `integrity_hash`, `issued_at`, `proof_system`, and `_trace`.

**Example:**
```python
from perathos import prove

bundle = prove(
    output_text="The capital of France is Paris.",
    input_text="What is the capital of France?"
)
print(bundle["bundle_id"])
```

### `sign(bundle, signing_key_hex)`

Attach an Ed25519 provider_signature over integrity_hash.

**Args:**
  - `bundle` (dict): A bundle dict from `prove()` (or compatible structure).
  - `signing_key_hex` (str): 64-character hex-encoded Ed25519 signing key.

**Returns:**
  - dict: A new dict with all fields from bundle plus a `provider_signature` field containing `algorithm`, `verify_key`, and `signature`.

**Raises:**
  - `ValueError`: If `signing_key_hex` is not a valid 64-character hex string.

**Example:**
```python
from perathos import prove, sign
from perathos.signing import generate_keypair

sk, vk = generate_keypair()
bundle = prove("The answer is 42.")
signed_bundle = sign(bundle, sk)
print(f"Signed with key: {signed_bundle['provider_signature']['verify_key']}")
```

### `verify(bundle)`

Recompute all hashes from stored data and check they match.

**Args:**
  - `bundle` (dict): A bundle dict from `prove()` (optionally with signature).

**Returns:**
  - tuple[bool, str]: A tuple `(valid, error_code)` where:
    - `valid` is `True` and `error_code` is `""` on successful verification.
    - `valid` is `False` and `error_code` is a string like `"ERR_TRACE_HASH_MISMATCH"` or `"ERR_MISSING_TRACE"` on failure.

**Example:**
```python
from perathos import prove, verify

bundle = prove("Output text here.")
valid, err = verify(bundle)

if valid:
    print("Bundle is valid!")
else:
    print(f"Verification failed: {err}")
```

### `inspect(bundle)`

Pretty-print a bundle in human-readable form.

**Args:**
  - `bundle` (dict): Bundle dict from `prove()` or loaded via `perathos.storage.load_bundle()`.

**Returns:**
  - None (prints to stdout)

**Example:**
```python
from perathos import prove, inspect

bundle = prove("Hello world.")
inspect(bundle)
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

### `verify_signature()` error codes

Returned by `perathos.verify_signature(integrity_hash, provider_signature)`:

| Error Code | Meaning | Action |
|---|---|---|
| `""` (empty) | Signature is valid | No error; first element is `True` |
| `ERR_BAD_SIGNATURE` | Signature is invalid (doesn't match the integrity_hash) | Provider signature is forged or the hash was tampered after signing; reject |
| `ERR_MISSING_SIG_FIELD:<field>` | A required signature field is missing (`verify_key` or `signature`) | Signature structure is invalid; reject |
| `ERR_INVALID_VERIFY_KEY:<error>` | The verify_key is not a valid 64-character hex string | Key format is invalid; reject |
| `ERR_INVALID_SIGNATURE:<error>` | The signature is not a valid 128-character hex string or cryptographic verification raised an exception | Signature format or key encoding is invalid; reject |

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

## License

MIT
