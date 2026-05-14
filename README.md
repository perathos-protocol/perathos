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

## License

MIT
