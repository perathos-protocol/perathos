# Changelog

All notable changes to Perathos. Pre-1.0: pin a commit SHA for reproducibility.
This project aims to follow [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **Key management & trust anchoring** (`perathos.keytrust`), the canonical VRL
  key layer (open-core consolidation, stage 1): a pluggable `Signer` —
  `LocalSigner` and `KmsSigner` (private key never leaves a KMS/HSM via an
  injected sign function) — plus a `TrustStore` of trusted keys by derived `kid`,
  exportable/importable as JWKS. `sign_bundle()` now accepts a `Signer`;
  `verify_bundle(..., trust_store=...)` and `verify --trust-jwks <file>` reject
  any signer not in the trusted set (`ERR_UNTRUSTED_SIGNER`). Signature format is
  unchanged, so existing bundles still verify; KMS-signed bundles are
  shape-identical to locally-signed ones.

## [0.2.0] - 2026-06-16

### Added
- **Multi-verifier pipeline** bound into the signed proof bundle: verdict
  records + aggregate verdict are folded into `integrity_hash` (tamper-evident).
  Reference verifiers: Cross-Examiner (122, self-consistency) and
  Claim-Entailment (124, claim decomposition + entailment).
- **Real NLI entailment backend** (`perathos.verifiers_nli`, optional `[nli]`
  extra) that plugs into Claim-Entailment via the `entailment_fn` hook; verified
  to label supported/contradicted against evidence with a real transformers
  cross-encoder. Core `import perathos` remains torch-free.
- **Confidence calibration** (`perathos.calibration`): temperature scaling,
  reliability binning, and Expected Calibration Error — so `confidence_bps` is
  fit and measured, not assumed.
- **Evidence binding**: each verdict records SHA-256 digests of the exact
  samples/documents it judged (reproducible verification).
- **Signer pinning**: `verify_bundle(..., expected_verify_key=...)` and
  `verify --verify-key` reject signer substitution (`ERR_UNEXPECTED_SIGNER`).
- Enterprise docs: `docs/THREAT_MODEL.md`, `SECURITY.md`,
  `docs/ENTERPRISE_FAQ.md`, and a cited training-data dossier
  (`docs/research/TRAINING_DATA.md`).
- CLI verification: `prove --evidence/--evidence-text/--sample/--sample-text/--nli/--mode`
  runs the pipeline and binds verdicts; `perathos doctor` diagnostic.
- `verify` policy gates: `--require-signed` and `--require-pass` enforce a
  deployment policy (signed + pinned + PASS) in one call.
- Runnable harness in `scripts/`: `calibrate.py` (fit + ECE) and
  `train_entailment.py` (fine-tune the NLI model); `train` extra.
- Secure release workflow (`.github/workflows/release.yml`) with a clean-install
  smoke gate and PyPI trusted publishing (OIDC, no API token).

### Fixed (security / correctness)
- `verify()` now validates the Ed25519 signature when present — a forged
  signature on an intact chain previously passed.
- Signature with a non-`ed25519` algorithm is rejected (`ERR_UNSUPPORTED_ALGORITHM`).
- Canonical serialization rejects NaN/Infinity and non-string keys; strict
  lowercase hex for signatures (no serialization malleability).
- `verify_bundle` returns `ERR_MALFORMED_BUNDLE` instead of crashing on hostile
  input; `inspect` is fully type-guarded and markup-safe.
- Atomic writes (tempfile + fsync + `os.replace`) for bundles and keys;
  owner-only key ACL on Windows; `list_bundles` tolerates concurrent deletion.
- `perathos prove` crash, keygen cp1252 crash, and other earlier fixes.

### Changed
- `verify_output(output_text, input_text='', *, verifiers=..., context=...)` —
  argument order now matches `create_bundle`/`prove`.
- CI parity in the agent harness (ruff gate before pytest); resilient git-push
  handling; globbed source context; workflow concurrency groups; version-bounded
  agent deps.

### Quality
- Test suite expanded to 183 (adversarial tamper, malformed-bundle robustness,
  aggregation, calibration, NLI decision, gated real-model integration).
- Hardened against an internal 37-agent audit (18 findings fixed; cryptographic
  core found sound — no critical/high).
