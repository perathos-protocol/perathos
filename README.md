# Perathos

Cryptographic proof layer for AI outputs. Every AI response gets a tamper-evident bundle — a hash chain + optional Ed25519 signature — that can be verified offline with no network calls.

## What Problem Does This Solve?

When an AI system generates critical output (legal advice, medical information, financial recommendations), you need proof that:
1. The output hasn't been tampered with after creation (integrity).
2. You can verify this proof offline, without trusting a central authority (deterministic hashing).
3. Optionally, the AI provider cryptographically committed to the output (Ed25519 signature).

Perathos solves this by creating a tamper-evident bundle for each output. If any field changes after the bundle is created, the hash chain breaks and verification fails.

## Quick Start

Get a proof bundle in 5 steps:

```bash
# 1. Install
pip install perathos

# 2. Generate a signing keypair (one-time setup)
perathos keygen

# 3. Prove an AI output
perathos prove "The capital of France is Paris."
# Output: bundle_id 550e8400-e29b-41d4-a716-446655440000 saved

# 4. Verify the bundle
perathos verify 550e8400-e29b-41d4-a716-446655440000
# Output: VALID_UNSIGNED  550e8400-e29b-41d4-a716-446655440000

# 5. Inspect it (human-readable)
perathos inspect 550e8400-e29b-41d4-a716-446655440000
```

To add a cryptographic signature:
```bash
perathos prove "The answer is 42." --sign
```

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

## CLI Design

The Perathos CLI follows standard Unix conventions for exit codes and output formatting:

### Exit Codes

All commands respect the following exit code contract:

| Exit Code | Meaning | Examples |
|-----------|---------|----------|
| `0` | Success — bundle valid, operation completed | `perathos verify <id>` returns VALID; `perathos prove` creates bundle |
| `1` | Bundle or file error — verification failed, bundle corrupted, file not found | Hash mismatch detected; bundle missing fields; JSON file invalid |
| `2` | Usage error — invalid arguments or conflicting options | `perathos verify` with both BUNDLE_ID and `--file`; missing required argument |

Example exit code usage in scripts:

```bash
#!/bin/bash
perathos verify "550e8400-e29b-41d4-a716-446655440000"
case $? in
  0) echo "✓ Bundle is valid" ;;
  1) echo "✗ Bundle verification failed (tampered or corrupted)" ; exit 1 ;;
  2) echo "✗ Usage error (check arguments)" ; exit 2 ;;
esac
```

### Output Formatting

By default, Perathos truncates long hashes (SHA-256 digests are 64 hex characters) to the first 8 characters plus "..." for readability in the terminal. Use `--verbose` to display full hashes.

#### Truncated Output (default)

Useful for human review and terminal readability:

```bash
$ perathos prove "The capital of France is Paris."
bundle_id      550e8400...
ai_id          7f9c2ba4...
input_hash     e3b0c442...
output_hash    a665a459...
trace_hash     d4735e3a...
integrity_hash 2cf24dba...
issued_at      2024-01-15T14:30:45.123456+00:00
saved          /home/user/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json
```

#### Full Hash Output (`--verbose`)

For scripting, verification, and audit logs, use `--verbose` to display complete hashes:

```bash
$ perathos prove "The capital of France is Paris." --verbose
bundle_id      550e8400-e29b-41d4-a716-446655440000
ai_id          7f9c2ba4e88fb81860ea5e70f527f31fa7f9c2ba4e88fb81860ea5e70f527f31f
input_hash     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
output_hash    a665a45920422f9d417e4867efdc4fb8a067e80b0456b3a9c52c1e4e81e2f4de
trace_hash     d4735e3a265e16eee03f59718b9b5d03c3d5e41ffa31f52c3e7d8e3b0f9a4b1c
integrity_hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
issued_at      2024-01-15T14:30:45.123456+00:00
saved          /home/user/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json
```

#### Verification with `--verbose`

When verifying, `--verbose` also displays the full public key for signed bundles:

```bash
$ perathos verify 550e8400-e29b-41d4-a716-446655440000 --verbose
VALID_SIGNED  550e8400-e29b-41d4-a716-446655440000
              verify_key a7f9c2ba4e88fb81860ea5e70f527f31fa7f9c2ba4e88fb81860ea5e70f527f31f
```

Without `--verbose`, the key is truncated:

```bash
$ perathos verify 550e8400-e29b-41d4-a716-446655440000
VALID_SIGNED  550e8400-e29b-41d4-a716-446655440000
              verify_key a7f9c2ba...
```

## CLI Examples

### Basic workflow

```bash
# 1. Generate a keypair (one-time setup)
$ perathos keygen
signing key  /home/user/.perathos/keys/signing.key
verify key   /home/user/.perathos/keys/verify.key
verify_key   a7f9c2ba4e88fb81860ea5e70f527f31f...

# 2. Prove an unsigned bundle
$ perathos prove "The capital of France is Paris."
bundle_id      550e8400-e29b-41d4-a716-446655440000
ai_id          7f9c2ba4e88fb81860ea5e70f527f31f...
input_hash     e3b0c44298fc1c149afbf4c8996fb92427...
output_hash    a665a45920422f9d417e4867efdc4fb8a...
trace_hash     d4735e3a265e16eee03f59718b9b5d03c...
integrity_hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1...
issued_at      2024-01-15T14:30:45.123456+00:00
saved          /home/user/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json

# 3. Verify the bundle
$ perathos verify 550e8400-e29b-41d4-a716-446655440000
VALID_UNSIGNED  550e8400-e29b-41d4-a716-446655440000

# 4. Inspect for human readability
$ perathos inspect 550e8400-e29b-41d4-a716-446655440000

  Bundle ID : 550e8400-e29b-41d4-a716-446655440000
  Issued    : 2024-01-15 14:30:45 UTC
  Model     : sha256-deterministic v1 (perathos-demo-model)
  Signature : UNSIGNED

  Hash Chain
    input     : e3b0c442...
    output    : a665a459...
    trace     : d4735e3a...
    integrity : 2cf24dba...

  Trace
    step 1 · hash_input    → e3b0c442...
    step 2 · hash_output   → a665a459...
    step 3 · hash_trace    → d4735e3a...
    step 4 · integrity     → 2cf24dba...
    step 5 · bundle_id     → uuid5(550e8400...)
```

### Signed bundles

```bash
# Prove with Ed25519 signature attached
$ perathos prove "Answer to life, universe, everything." --sign
bundle_id      a1b2c3d4-e5f6-41d4-a716-446655440000
ai_id          7f9c2ba4e88fb81860ea5e70f527f31f...
input_hash     e3b0c44298fc1c149afbf4c8996fb92427...
output_hash    8ac76b3e93bafcccb12adc14c9b58c1f...
trace_hash     d4735e3a265e16eee03f59718b9b5d03c...
integrity_hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1...
issued_at      2024-01-15T14:35:20.654321+00:00
signature      9d8f4c2a7e1b9c5d3f8a6b2e4d7c1a9b2...
verify_key     a7f9c2ba4e88fb81860ea5e70f527f31f...
saved          /home/user/.perathos/bundles/a1b2c3d4-e5f6-41d4-a716-446655440000.json

# Verify signed bundle (checks both hash chain + signature)
$ perathos verify a1b2c3d4-e5f6-41d4-a716-446655440000
VALID_SIGNED  a1b2c3d4-e5f6-41d4-a716-446655440000
              verify_key a7f9c2ba4e88fb81860ea5e70f527f31f...
```

### With input prompt

```bash
# Include the original prompt/input in the bundle
$ perathos prove "Paris." --input "What is the capital of France?"
bundle_id      c5d6e7f8-a9b0-41d4-a716-446655440000
ai_id          7f9c2ba4e88fb81860ea5e70f527f31f...
input_hash     3a6eb0790484a6b6fade7e7f45bb43db...
output_hash    6e85c630ee3a3fd26f65c8f8ff9b1c4a...
...
```

### JSON output

```bash
# Output full bundle as JSON (useful for piping or storage)
$ perathos prove "Output text" --sign --json
{
  "ai_id": "7f9c2ba4e88fb81860ea5e70f527f31f...",
  "bundle_id": "550e8400-e29b-41d4-a716-446655440000",
  "input_hash": "e3b0c44298fc1c149afbf4c8996fb92427...",
  "integrity_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1...",
  "issued_at": "2024-01-15T14:30:45.123456+00:00",
  "output_hash": "a665a45920422f9d417e4867efdc4fb8a...",
  "proof_system": "sha256-deterministic",
  "provider_signature": {
    "algorithm": "ed25519",
    "signature": "9d8f4c2a7e1b9c5d3f8a6b2e4d7c1a9b2...",
    "verify_key": "a7f9c2ba4e88fb81860ea5e70f527f31f..."
  },
  "trace_hash": "d4735e3a265e16eee03f59718b9b5d03c...",
  "_trace": {
    "input_length": 0,
    "model_descriptor": "perathos-demo-model:sha256-deterministic:v1",
    "output_length": 11,
    "proof_system": "sha256-deterministic"
  }
}
```

### Verify from external file

```bash
# Verify a bundle exported from another system
$ perathos verify --file /path/to/bundle.json
VALID_UNSIGNED  /path/to/bundle.json

# Verify and display full bundle
$ perathos verify --file bundle.json --json
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
| `_trace` | Execution metadata dict (model descriptor, proof system, input/output lengths) |

Bundles are stored locally as JSON files at `~/.perathos/bundles/{bundle_id}.json`.

### Directory Structure

Perathos stores all data under `~/.perathos/` with the following layout:

```
~/.perathos/
├── bundles/              (JSON proof bundles)
│   ├── 550e8400-...json  (one file per bundle_id UUID)
│   ├── a1b2c3d4-...json
│   └── ...
└── keys/                 (Ed25519 keypair)
    ├── signing.key       (private key, mode 0o600)
    └── verify.key        (public key)
```

**Bundles:** Each bundle is a JSON file named after its UUID (the `bundle_id` field). Files are human-readable and self-contained; you can copy a bundle file to another system and verify it offline without any network calls or local state.

**Keys:** The `signing.key` file contains your private Ed25519 key (64 hex characters). On Unix-like systems, it is stored with restrictive permissions (mode 0o600, readable only by the owner) for security. The `verify.key` file contains the public key and can be shared.

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

### Storage API

The `perathos.storage` module provides functions to save and load bundles from disk, as well as manage signing keys.

#### `save_bundle(bundle)`

Save a bundle to JSON file in `~/.perathos/bundles/`.

**Args:**
  - `bundle` (dict): A bundle dict from `prove()` (optionally signed).

**Returns:**
  - `Path`: Path object pointing to the saved JSON file.

**Example:**
```python
from perathos import prove
from perathos.storage import save_bundle, load_bundle

bundle = prove("The capital of France is Paris.")
path = save_bundle(bundle)  # Saves to ~/.perathos/bundles/{bundle_id}.json
print(f"Saved to {path}")

# Later, load it back:
loaded = load_bundle(bundle["bundle_id"])
print(f"Loaded: {loaded['bundle_id']}")
```

#### `load_bundle(bundle_id)`

Load a bundle from disk by its UUID.

**Args:**
  - `bundle_id` (str): The bundle's UUID (e.g., `"550e8400-e29b-41d4-a716-446655440000"`).

**Returns:**
  - dict: The parsed bundle dict with all fields.

**Raises:**
  - `FileNotFoundError`: If no bundle file exists for the given ID.
  - `json.JSONDecodeError`: If the JSON file is corrupted.

**Example:**
```python
from perathos.storage import load_bundle
from perathos import verify, inspect

bundle = load_bundle("550e8400-e29b-41d4-a716-446655440000")
valid, err = verify(bundle)
if valid:
    inspect(bundle)
```

#### `list_bundles()`

List all locally stored bundles, newest first.

**Returns:**
  - list[Path]: List of Path objects for all `.json` files in `~/.perathos/bundles/`, sorted by modification time (newest first).

**Example:**
```python
from perathos.storage import list_bundles, load_bundle
from perathos import inspect

bundles = list_bundles()
if bundles:
    most_recent_path = bundles[0]
    bundle_id = most_recent_path.stem  # filename without .json
    bundle = load_bundle(bundle_id)
    inspect(bundle)
else:
    print("No bundles found. Run: perathos prove 'output text'")
```

#### `generate_keypair()` and key management

Generate a signing keypair and load it from disk.

**Example:**
```python
from perathos.signing import generate_keypair
from perathos.storage import save_keypair, load_signing_key, load_verify_key
from perathos import prove, sign

# Generate a new keypair
sk, vk = generate_keypair()
sk_path, vk_path = save_keypair(sk, vk)
print(f"Keys saved to {sk_path.parent}")

# Later, load and use the key:
sk = load_signing_key()
bundle = prove("Some output")
signed = sign(bundle, sk)
print(f"Signed with key: {signed['provider_signature']['verify_key']}")
```

#### File Permissions & Security

The signing key file (`~/.perathos/keys/signing.key`) is your private key and should be protected carefully. Perathos enforces this with:

**Unix-like systems (Linux, macOS):**
  - The `keys/` directory is created with mode `0o700` (drwx------), readable/writable/executable by owner only.
  - The `signing.key` file is created with mode `0o600` (-rw-------), readable/writable by owner only.
  - If you see a PermissionError when loading the key, verify the file is readable: `chmod 600 ~/.perathos/keys/signing.key`

**Windows:**
  - The `keys/` directory permissions are enforced by NTFS filesystem ACLs (not POSIX mode).
  - Ensure your user account has exclusive read/write access to the `%USERPROFILE%\.perathos\keys\` directory.
  - File permissions are best-effort; contact your system administrator if you encounter permission issues.

**Why 0o600?**
  - Mode `0o600` means the file is readable and writable by the owner only.
  - This prevents other users on the same system from reading your private key via filesystem access.
  - If another user gains access to your private key, they can forge signatures claiming to come from your key.
  - Always treat your private key as you would treat a password or SSH private key: keep it secret and protected.

**Never share your signing key.** The `verify.key` file (public key) can be shared freely and used by others to verify your signatures. The `signing.key` file (private key) must be kept secret.

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

## Troubleshooting

### "Signing key not found" error

**Symptom:** When running `perathos prove --sign`, you get:
```
ERROR: Signing key not found.
Run: perathos keygen
```

**Cause:** You haven't generated a keypair yet, or the key file was deleted.

**Solution:** Generate a keypair with:
```bash
perathos keygen
```
This creates `~/.perathos/keys/signing.key` and `~/.perathos/keys/verify.key`.

**In Python:**
```python
from perathos.storage import load_signing_key

try:
    sk = load_signing_key()
except FileNotFoundError:
    from perathos.signing import generate_keypair
    from perathos.storage import save_keypair
    sk, vk = generate_keypair()
    save_keypair(sk, vk)
    print("Keypair generated and saved.")
```

### "Bundle not found" error

**Symptom:** When running `perathos verify <bundle_id>` or `perathos inspect <bundle_id>`, you get:
```
ERROR: Bundle not found: 550e8400-e29b-41d4-a716-446655440000
Run: perathos list
```

**Cause:** The bundle UUID doesn't exist in `~/.perathos/bundles/`, or you mistyped the UUID.

**Solution:** List all available bundles:
```bash
perathos list
```
Copy the correct UUID from the output and use it with `verify` or `inspect`.

**In Python:**
```python
from perathos.storage import load_bundle, list_bundles

try:
    bundle = load_bundle("550e8400-e29b-41d4-a716-446655440000")
except FileNotFoundError:
    print("Bundle not found. Available bundles:")
    for path in list_bundles():
        print(f"  {path.stem}")
```

### "Invalid JSON" error

**Symptom:** When running `perathos verify --file bundle.json`, you get:
```
ERROR: Invalid JSON in /path/to/bundle.json: Expecting value: line 1 column 1 (char 0)
```

**Cause:** The file is not valid JSON, is empty, or is corrupted.

**Solution:**
1. Check the file exists and is readable:
   ```bash
   cat /path/to/bundle.json | head -20
   ```
2. Validate the JSON syntax using a tool:
   ```bash
   python -m json.tool /path/to/bundle.json > /dev/null
   ```
   If no error, the JSON is valid.
3. Ensure the file was exported correctly from `perathos prove --json` or another Perathos instance.

**In Python:**
```python
import json
from pathlib import Path

try:
    bundle = json.loads(Path("/path/to/bundle.json").read_text())
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
    print("Try: perathos prove 'output text' --json > bundle.json")
```

### Bundle or key file corruption

**Symptom:** A bundle file is missing fields, has malformed JSON, or a key file is truncated. Examples:

```
ERROR: Invalid JSON in ~/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json: ...
ERROR: Bundle verification failed: ERR_MISSING_FIELD:output_hash
```

**Cause:** Bundle or key files can become corrupted due to:
- Disk write errors, power loss, or I/O failure during save.
- Manual editing that introduced syntax errors or deleted fields.
- File truncation due to process interruption.
- Filesystem corruption (rare, but possible on unreliable storage).

**Solution:** Manually inspect and recover from corrupted files.

#### Inspect a potentially corrupted bundle

Use Python or `jq` to check the file structure:

```bash
# View the raw file:
cat ~/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json

# Validate JSON syntax:
python -m json.tool ~/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json

# Or use jq (if installed):
jq . ~/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json
```

If the file is valid JSON but is missing required fields (like `integrity_hash`, `_trace`, `bundle_id`), the bundle is corrupted and **cannot be recovered**. The original AI output is lost.

#### Recover by re-creating the bundle

If the bundle is corrupted and you have the original input and output text:

```bash
# Recreate the bundle:
perathos prove "<original output text>" --input "<original input text>" --sign

# The bundle will have a new bundle_id but the same integrity_hash
# (since it's derived from the same input/output).
```

#### Inspect a potentially corrupted key file

Key files should be 64-character hex strings (for Ed25519 keys). Check the file:

```bash
# View the file:
cat ~/.perathos/keys/signing.key

# Check it's 64 hex characters:
wc -c ~/.perathos/keys/signing.key  # Should be 65 (64 chars + newline)
hex_string=$(cat ~/.perathos/keys/signing.key)
echo "${#hex_string}")  # Should be 64
echo "$hex_string" | grep -E '^[0-9a-f]{64}$'  # Should match
```

If the key file is truncated (fewer than 64 characters) or contains non-hex characters, it's corrupted:

```bash
# Regenerate the keypair (this will lose the old key):
rm ~/.perathos/keys/signing.key ~/.perathos/keys/verify.key
perathos keygen

# Warning: Any bundles signed with the old key cannot be verified with the new key.
```

#### Prevention

To prevent corruption:

1. **Use reliable storage.** Avoid network filesystems with latency or flaky connections.
2. **Keep backups.** Regularly backup `~/.perathos/keys/` (your private key is irreplaceable).
   ```bash
   cp -r ~/.perathos/keys ~/perathos-keys-backup
   ```
3. **Do not edit bundle files manually.** Only Perathos should modify bundles.
4. **Check disk health.** If corruption happens repeatedly, run filesystem checks:
   ```bash
   sudo fsck /  # On Linux (unmounted)
   # Or use Disk Utility on macOS
   ```
5. **Monitor disk space.** Ensure your home directory has sufficient free space to avoid incomplete writes:
   ```bash
   df -h ~
   ```
6. **Use checksums.** For critical bundles, store a separate SHA-256 checksum:
   ```bash
   sha256sum ~/.perathos/bundles/550e8400-e29b-41d4-a716-446655440000.json > bundle.sha256
   # Later, verify:
   sha256sum -c bundle.sha256
   ```

### Bundle verification fails with "ERR_TRACE_HASH_MISMATCH"

**Symptom:** When running `perathos verify <bundle_id>`, you get:
```
INVALID  ERR_TRACE_HASH_MISMATCH
```

**Cause:** The `_trace` dict in the bundle was manually modified or corrupted.

**Solution:** Do not manually edit bundle JSON files. Always use `perathos prove` to create new bundles. If you need to recover the original output, check your AI service's logs or re-run the prompt.

### Bundle verification fails with "ERR_INTEGRITY_HASH_MISMATCH"

**Symptom:** When running `perathos verify <bundle_id>`, you get:
```
INVALID  ERR_INTEGRITY_HASH_MISMATCH
```

**Cause:** One or more fields in the bundle (ai_id, input_hash, output_hash, issued_at, etc.) were modified after the bundle was created.

**Solution:** Do not manually edit bundle files. Bundles are read-only once created. If you need a different output, create a new bundle with `perathos prove`.

### Signature verification fails with "ERR_BAD_SIGNATURE"

**Symptom:** When running `perathos verify <bundle_id>`, you get:
```
INVALID  ERR_BAD_SIGNATURE
```

**Cause:** The bundle's `provider_signature` doesn't match the `integrity_hash`, or the signature was tampered with.

**Solution:** Do not manually edit bundle files. If you suspect the bundle was modified after signing, contact the provider and ask for the original bundle. Verify the provider's public key (listed in the error output) matches your trusted key.

**In Python:**
```python
from perathos import verify, verify_signature
from perathos.storage import load_bundle

bundle = load_bundle("550e8400-e29b-41d4-a716-446655440000")
valid, err = verify(bundle)
if valid and "provider_signature" in bundle:
    sig_valid, sig_err = verify_signature(bundle["integrity_hash"], bundle["provider_signature"])
    if not sig_valid:
        print(f"Signature verification failed: {sig_err}")
        print(f"Provider key: {bundle['provider_signature']['verify_key']}")
        print("Do not trust this bundle. Contact the provider to confirm.")
```

### Keys directory has wrong permissions

**Symptom:** On Unix/Linux, the file `~/.perathos/keys/signing.key` is readable by other users, which is a security risk.

**Cause:** The key file was created with incorrect permissions (not 0o600).

**Solution:** Manually fix permissions:
```bash
chmod 600 ~/.perathos/keys/signing.key
chmod 700 ~/.perathos/keys
```

**In Python:**
```python
import os
from perathos.storage import keys_dir

sk_path = keys_dir() / "signing.key"
os.chmod(sk_path, 0o600)
os.chmod(keys_dir(), 0o700)
print("Permissions fixed.")
```

### Bundle is too old or issued_at is in the future

**Symptom:** You notice a bundle was issued at a timestamp that seems wrong (very old, or in the future).

**Cause:** The system clock was wrong when the bundle was created, or you're verifying a bundle from a different system.

**Action:** The `issued_at` field is part of the integrity hash, so changing it will break verification. Perathos doesn't enforce time windows; bundle validity depends only on the hash chain, not on the timestamp. If you need time-based validation, add your own checks:
```python
from datetime import datetime, timezone
from perathos.storage import load_bundle

bundle = load_bundle("550e8400-e29b-41d4-a716-446655440000")
issued = datetime.fromisoformat(bundle["issued_at"])
now = datetime.now(timezone.utc)
age = (now - issued).total_seconds()
if age > 86400:  # older than 1 day
    print(f"Warning: Bundle is {age / 86400:.1f} days old.")
```

## License

MIT
