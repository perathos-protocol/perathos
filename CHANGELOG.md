# Changelog

All notable changes to Perathos. Pre-1.0: pin a commit SHA for reproducibility.
This project aims to follow [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.3.1] - 2026-06-23

### Added — Legal Citation Verifier M1 (coverage + reproducibility protocol)
- **Multi-reporter coverage.** The parser now recognizes the major federal /
  SCOTUS reporters (`F.2d`, `F.3d`, `F.4th`, `F. Supp.`, `F. Supp. 2d`,
  `F. Supp. 3d`, `S. Ct.`, `L. Ed.`, `L. Ed. 2d`) with their real published
  volume ranges. An out-of-range volume (e.g. `1500 F.3d`, past the series' final
  volume 999) is now caught as a fabrication even where individual cases are not
  indexed. A plausible in-range cite we do not hold stays INCONCLUSIVE — so the
  Mata v. Avianca-class fake (`925 F.3d 1339`) is honestly reported as
  unverifiable, not falsely flagged. Year parentheticals with a court
  (`(11th Cir. 2019)`) parse correctly.
- **Complete-coverage existence mechanism.** A snapshot may declare
  `complete_volumes` per reporter; within a complete range a non-resolving cite
  becomes a fabrication (if it were real we would hold it). Shipped empty (this is
  a curated, not exhaustive, snapshot) — the mechanism is the on-ramp for the
  data investment that turns INCONCLUSIVE into FAIL for nonexistent-but-plausible
  cites.
- **End-to-end signed bundle binding.** `perathos cite-check --sign --out
  brief.bundle.json` emits a Proof Bundle whose `integrity_hash` binds the
  citation verdict AND the `corpus_hash`, re-verifiable offline
  (`perathos verify --file ...`) by a counterparty; tampering with a bound verdict
  breaks verification. This makes the cross-party, tamper-evident citation record
  concrete.
- Snapshot updated to `us-caselaw-v1.1-2026.06`; `RULES_VERSION` -> 1.1.0.

## [0.3.0] - 2026-06-23

### Added — Legal Citation Verifier (engine 128), M0
The first **domain** verifier and the chosen wedge into the regulated-AI buyer:
deterministically check that the U.S. legal citations in an AI output exist and
are attributed to the right case. Real, named pain (lawyers sanctioned for
AI-fabricated citations).
- New `perathos.legal` subpackage: a regex citation parser, a pinned
  **content-addressed** public case-law snapshot (`CitationCorpus`, M0 = curated
  landmark SCOTUS), and `CitationVerifier` (engine 128).
- **No network at verify time** — resolution is a pure function of (output,
  snapshot); the `corpus_hash` + `engine_rules_version` are bound into the
  VerdictRecord evidence, so a verdict is reproducible offline by a counterparty.
- **Honesty-first verdicts:** impossible-volume and name↔cite misattribution →
  FAIL; a cite outside the snapshot → INCONCLUSIVE (never a false fabrication
  flag); no cites → NOT_APPLICABLE. Cardinal rule upheld: zero false positives on
  real, in-coverage citations (enforced by a red-team test).
- New CLI: `perathos cite-check brief.txt` (exits non-zero on a fabrication).
- `perathos[legal]` extra (pure stdlib today). See docs/specs/CITATION_VERIFIER.md.

## [0.2.7] - 2026-06-23

### Security / hardened (trust anchor — TrustStore.from_jwks)
A probe of the trust layer confirmed the verify-time gate is **sound** — an
untrusted signer and a JWKS kid-spoof (claiming a trusted kid while embedding an
attacker key) are both rejected, because verification re-derives the kid from the
actual key bytes and byte-compares. `from_jwks` is now hardened to match:
- **Validates every JWKS entry** instead of crashing on malformed input — a
  non-object JWKS, non-list `keys`, non-object entries, missing/non-string
  `kid`/`x`, invalid base64url, or a non-32-byte key now raise a clear
  `ValueError` (previously `KeyError`/`TypeError`/`binascii.Error`).
- **Strict base64url** (`validate=True`) — a garbage `x` like `"@@@@"` is rejected
  instead of silently decoding to an empty key.
- **kid must match `kid_for(x)`** — a tampered/kid-spoofed entry is rejected at
  load time rather than stored as an inert entry, surfacing a bad JWKS early.

## [0.2.6] - 2026-06-23

### Fixed (crypto-core hardening — verify_bundle must never raise)
An adversarial probe pass against the verification path found 5 hostile bundles
that made `verify_bundle()` **raise** instead of returning its documented
`(valid, error_code)` — a contract break and, for a verification gateway taking
attacker-controlled bundles, a denial-of-service.
- **Non-string `answer`** (`{"answer": 1234}`) crashed the `.encode()` cross-check
  (AttributeError) — now type-checked → `ERR_MALFORMED_BUNDLE`.
- **Non-dict `verification`** (a forged, self-consistent bundle with
  `verification: "…"`) crashed the `.get()` verdict cross-check (AttributeError)
  — now rejected early → `ERR_MALFORMED_BUNDLE`.
- **Deeply-nested `_trace` / `verification`** crafted to exhaust the stack during
  canonicalization raised RecursionError (a DoS) — now caught → `ERR_MALFORMED_BUNDLE`.
The signature path (`verify_signature`) was probed too and already handled
non-dict signatures, bad hex, algorithm-confusion, and missing fields cleanly.

## [0.2.5] - 2026-06-23

### Fixed
- **SymbolicSolver no longer over-skips a result followed by a sentence comma.**
  The 0.2.4 ambiguous-comma guard was too eager: a trailing punctuation comma
  (`"17 * 23 = 391, confirmed"`) was treated as a decimal/grouping comma and the
  correct claim was skipped. The guard now only fires on a comma *between digits*
  (`\d,(?=\d)`), so trailing punctuation is ignored while `3,5` is still skipped.
  (Caught by the training-ops cross-repo engine tests against 0.2.4.)

## [0.2.4] - 2026-06-23

### Fixed (adversarial hardening — format / encoding / evasion / injection)
An adversarial probe pass against the engines surfaced 9 real weaknesses; all are
fixed here, with the cardinal rule upheld: an engine must **fail closed** to
NOT_APPLICABLE/INCONCLUSIVE on ambiguity, never false-FAIL a correct answer.
- **SymbolicSolver no longer false-flags ambiguous numerals.** Scientific
  notation (`2e3 = 2000`), caret powers (`10^3 = 1000`), and decimal commas
  (`3,5 * 2 = 7`) were being parsed as fragments (`"3 = 2000"`) and reported as
  wrong. The engine now skips a match glued to a letter/`.`/`^` or carrying an
  ambiguous comma (not a clean thousands group) instead of misreading it.
  Legitimate thousands separators and `x`-multiplication still verify.
- **HallucinationDetector checks non-`$` currencies** (`€`, `£`, `¥`) — a
  fabricated `€900` is now caught instead of being silently uncheckable.
- **SchemaValidator rejects non-finite numbers** — the json stdlib's `NaN` /
  `Infinity` / `-Infinity` extension is refused (it is not valid JSON and must
  not satisfy a `{"type": "number"}` schema).
- **TemporalConsistency is morphology-tolerant** — plurals (`smartwatches`,
  `cars`) and hyphen variants (`smart-watch`) no longer evade the anachronism
  check, while staying word-safe (`cares`/`cards` still don't match `car`).

### Documented (scope limit, by design)
- Extractive grounding checks a specific's PRESENCE, not its polarity, so a
  negated claim whose value still appears in the source (`"NOT within 30 days"`)
  is not caught extractively. This is the entailment layer's job — pass an
  `entailment_fn` (or use the ClaimEntailment verifier) to catch contradictions.

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
