# Changelog

All notable changes to Perathos. Pre-1.0: pin a commit SHA for reproducibility.
This project aims to follow [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.2.3] - 2026-06-23

### Changed
- **TemporalConsistency timeline expanded (~50 modern terms)** — the checker
  could only flag anachronisms for terms in its curated dict, so an off-timeline
  term like `"smartwatch in 1850"` was silently skipped (counted as a miss).
  Added unambiguous, conservatively-dated 20th/21st-century terms (smartwatch,
  bluetooth, wi-fi, usb, qr code, blog, podcast, crispr, blockchain, chatgpt, …);
  homographs (tablet/drone/stream) are deliberately omitted so word-boundary
  matching can't false-fire on everyday words. Per-call `ctx.timeline` still
  extends/overrides for domain terms, so coverage isn't a fixed dict. Closes
  engine gap #3 from training-ops `docs/ENGINE_GAPS.md` — the last documented gap.

## [0.2.2] - 2026-06-23

### Fixed
- **HallucinationDetector now matches specifics like-with-like** — it previously
  flattened all sources into one digit-soup and checked bare digits, so a
  fabricated duration `"90 days"` was wrongly grounded by an unrelated `"$90"`
  elsewhere in the source (a substring collision). Each specific (money, %, year,
  duration) is now extracted per kind from the sources and a claim is grounded
  only by a token of its OWN kind, with numeric values compared (so `$1000` still
  matches `$1,000.00`) and durations matched on (number, unit-family). Closes
  engine gap #2 from training-ops `docs/ENGINE_GAPS.md`.

## [0.2.1] - 2026-06-23

### Fixed
- **SymbolicSolver now handles modulo (`%`)** — the equation regex omitted `%`,
  so `"17 % 5 = 2"` misparsed as `"5 = 2"` and false-positived a correct answer.
  Added `%` to the char class (the evaluator already supported `ast.Mod`); a bare
  percentage like `"3.2%"` can't form a binary expression, so it is skipped, not
  flagged. Closes engine gap #1 from training-ops `docs/ENGINE_GAPS.md`.

### Changed
- **Crypto backend unified on `cryptography` (pyca)** instead of PyNaCl
  (open-core consolidation, decision #1). Ed25519 signing/verification in
  `signing.py` and `keytrust.py` now use the industry-standard `cryptography`
  library — the same backend as the gateway — so signers are shareable across
  the VRL stack. Signature format and behavior are unchanged (Ed25519 is
  interoperable); existing signed bundles still verify. Core deps: `click` +
  `cryptography` (was `pynacl`); `doctor` now reports `cryptography`.

### Added
- **Proof Bundle v2** (open-core consolidation, stage 3 — the unified format).
  v2 keeps perathos's hash-chain integrity and adds: a `computed` flag on each
  verdict (only engine-computed verdicts count as independently verified), a
  top-level `verdict` + `model` (bound/cross-checked), and an optional
  `answer` (hash-only by default; bound to output_hash). `create_bundle` emits
  v2 by default; `verify_bundle` **dual-reads** by `bundle_version`, so every
  existing v1 bundle still verifies. New checks: `ERR_VERDICT_MISMATCH`,
  `ERR_ANSWER_MISMATCH`. `prove` gained `--model`, `--include-answer`,
  `--schema`, and now runs the full engine suite (Symbolic/Hallucination/
  Schema/Temporal + Cross-Examiner + Claim-Entailment) when verifying.
- **Real verifier engines** (`perathos.engines`), the canonical core's
  deterministic, model-free engines (open-core consolidation, stage 2 — ported
  from the gateway): `SymbolicSolver` (123, recompute arithmetic),
  `HallucinationDetector` (125, extractive grounding vs sources + optional
  entailment hook), `SchemaValidator` (126, jsonschema with remote-$ref refused),
  `TemporalConsistency` (127, anachronism detection). With CrossExaminer (122)
  and ClaimEntailment (124) that is 6 of the 7 named verifiers. Each runs behind
  the INCONCLUSIVE-safe wrapper and binds a reproducible evidence digest.
  `VerificationContext` gained `sources`, `schema`, `timeline`. SchemaValidator
  needs the `schema` extra.
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
