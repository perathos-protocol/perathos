# Security Policy

## Reporting a vulnerability

Email **security@perathos.io** (or open a private security advisory on the
GitHub repository). Please include a description, affected version/commit, and a
reproduction. We aim to acknowledge within 3 business days. Do not open public
issues for security reports.

## Scope

In scope: the `perathos` package (bundle construction, signing, verification,
canonical serialization, the verifier pipeline) and its CLI. Out of scope: the
optional NLI model weights (third-party), and the autonomous-agent harness under
`org/orchestration/` (operational tooling, not part of the verification trust
base).

## Security model in one paragraph

A Perathos proof bundle is **tamper-evident**: every semantically significant
field is folded into a SHA-256 `integrity_hash`, the `bundle_id` is derived from
it, and an optional Ed25519 signature covers it. Verification recomputes the
chain and validates the signature offline. The cryptographic core (Ed25519,
signer pinning, hash-chain binding, canonical serialization) is the trust base.
See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full model, including
the assumptions a deployment must satisfy (notably: **pin the signer's public
key out of band** — a bare signature does not establish identity).

## Cryptography

- Hashing: SHA-256.
- Signatures: Ed25519 (PyNaCl / libsodium, constant-time).
- Serialization: deterministic canonical JSON (sorted string keys, compact,
  UTF-8, no NaN/Infinity) for reproducible, cross-language verification.

## Key handling

- Private signing keys are written atomically and restricted to the owner
  (POSIX `0o600`; Windows owner-only ACL, best-effort with a warning on failure).
- Keys are stored as cleartext hex under `~/.perathos/keys/`. For production,
  hold the key in a KMS/HSM and inject signing rather than using on-disk keys.

## Supported versions

Pre-1.0: only the latest `main` is supported. Pin a commit for reproducibility.

## What a `PASS` does and does not mean

A `PASS` verdict means the configured verifiers found no problem given the
available evidence. It is **evidence, not a guarantee of truth**; detection has
false negatives and confidence is calibrated, not absolute. `INCONCLUSIVE`
means "not enough evidence" and must not be treated as `PASS`.
