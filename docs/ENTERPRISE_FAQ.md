# Perathos Enterprise FAQ

_Last updated: 2026-06-16._ Procurement- and security-review-level answers. For
the formal model see [THREAT_MODEL.md](THREAT_MODEL.md); for reporting see
[SECURITY.md](../SECURITY.md).

## What it is

**Q: In one sentence, what does Perathos do?**
It produces a tamper-evident, cryptographically signed, offline-verifiable
*proof bundle* for an AI output — binding the output's digest, independent
verifier verdicts about it, a model identifier, and a signature.

**Q: What does it actually guarantee?**
That a bundle cannot be altered without detection, and that its verdicts are
reproducible and bound to a specific output. It does **not** guarantee the
output is true. Verifier findings are *evidence with calibrated confidence*, not
a certification of correctness. This boundary is deliberate and load-bearing.

**Q: Why is "evidence, not guarantee" stated so insistently?**
Because overclaiming is the failure mode that destroys trust in a verification
product. A `PASS` means "the configured verifiers found no problem with the
evidence they had." Detection has false negatives; `INCONCLUSIVE` is a
first-class result meaning "not enough evidence."

## Integrity & verification

**Q: How is tamper-evidence achieved?**
Every significant field is folded into a SHA-256 `integrity_hash`; `bundle_id` is
`uuid5(integrity_hash)`; an optional Ed25519 signature covers the canonical
serialization. Verification recomputes the chain and validates the signature.
Editing, adding, or removing any verdict, digest, or the verification block flips
the recomputation → `ERR_INTEGRITY_HASH_MISMATCH`.

**Q: Can I verify without calling your servers?**
Yes. Verification is fully offline: bundle bytes + the signer's public key. No
network, no central authority.

**Q: Are proofs reproducible across machines/languages?**
Yes by construction. Canonical serialization sorts object keys, uses compact
separators and UTF-8, forbids NaN/Infinity, and rejects non-string keys, so the
same logical data yields identical bytes everywhere — the basis for a signature
any implementation can re-verify.

**Q: A signature is present and `verify` says valid — does that prove who signed?**
Only if you **pin the expected public key** (`verify --verify-key <hex>` or
`verify_bundle(..., expected_verify_key=...)`). A bare signature proves *some*
key signed the hash; an attacker can re-sign with their own key. Pinning is the
deployment's responsibility. Mismatch → `ERR_UNEXPECTED_SIGNER`.

**Q: What signature/hash algorithms?** Ed25519 (libsodium, constant-time) and
SHA-256. A signature claiming any other algorithm is rejected
(`ERR_UNSUPPORTED_ALGORITHM`).

## The verifiers (detection quality)

**Q: What verifiers ship today?**
- **Cross-Examiner (122)** — self-consistency: compares the output to additional
  samples; wide disagreement signals hallucination (SelfCheckGPT-style).
- **Claim-Entailment (124)** — decomposes the output into atomic claims and
  labels each supported / contradicted / unverifiable against retrieved evidence
  (FActScore/SAFE-style). A real transformers NLI model is available via the
  `nli` extra; a deterministic lexical default ships for offline/no-dep use.

**Q: Are the defaults "real AI"?**
The default similarity/entailment functions are **deterministic lexical
placeholders, clearly labelled as such** — so the pipeline runs with zero heavy
dependencies and is fully testable offline. For production, inject a real model
(`pip install perathos[nli]`, `nli_entailment_fn()`). We do not dress up the
placeholder as a model.

**Q: How are multiple verifiers combined?**
A configurable aggregate verdict (conjunction / quorum). Any `FAIL` fails the
aggregate under conjunction; `INCONCLUSIVE`/`NOT_APPLICABLE` are excluded from
the PASS/FAIL denominator (an abstention is never counted as agreement).

**Q: What stops a buggy verifier from silently passing bad output?**
Every verifier runs behind a wrapper that converts any exception — or a verifier
given no evidence — into `INCONCLUSIVE` with confidence 0. A verifier never
crashes the pipeline and never defaults to `PASS`.

**Q: Is the evidence itself bound into the proof?**
Yes. Each verdict records SHA-256 digests of the exact samples/documents it
judged, so a consumer can re-check the verdict against the same evidence. We bind
digests, not raw evidence (size + privacy).

## Confidence & calibration

**Q: What does a confidence number mean?**
`confidence_bps` (0–1000) is a calibrated estimate, not a raw model score. We
provide temperature-scaling and binning calibrators plus Expected Calibration
Error (ECE) so the promise "0.8 ≈ 80% correct" is *fit on held-out data and
measured*, not assumed. The honest default confidence is 0 ("no stated
confidence").

**Q: How do we calibrate for our domain?**
Collect held-out labeled `(score, correct)` pairs from your traffic, fit a
calibrator, and report ECE per domain. See
[research/TRAINING_DATA.md](research/TRAINING_DATA.md).

## Training data & compliance

**Q: What data trains the verifiers, and is it licence-clean for commercial use?**
See the cited dossier in [research/TRAINING_DATA.md](research/TRAINING_DATA.md).
Headlines: prefer permissive sets (FActScore — MIT; RAGTruth — MIT; DocNLI —
BSD-3; SAFE/LongFact — Apache/CC-BY). **Avoid** non-commercial sets (ANLI,
SciFact, AVeriTeC, FELM — CC BY-NC) and **AggreFact (no LICENSE file — grants no
rights)**. Treat the FEVER family / VitaminC / SelfCheckGPT as CC BY-SA
(share-alike) — usable only if copyleft redistribution is acceptable.

## Deployment & operations

**Q: What are the runtime dependencies?**
Core: `click`, `pynacl` only — small and pure. The NLI model (`transformers`,
`torch`) and the agent harness (`httpx`, `anthropic`) are **optional extras**;
`pip install perathos` pulls neither.

**Q: Does it work on Windows?**
Yes — verified on Windows 11. CLI Unicode output degrades gracefully on cp1252
consoles; key files get an owner-only ACL.

**Q: Is data written safely under concurrency/crashes?**
Bundles and keys are written atomically (tempfile + fsync + `os.replace`);
listing tolerates concurrent deletion. No torn/empty files.

**Q: How is quality enforced in the codebase?**
CI runs `ruff` + the full pytest suite on every push/PR. The suite includes
adversarial tamper tests, malformed-bundle robustness tests, aggregation tests,
and calibration tests. The package was hardened against an internal 37-agent
audit (18 findings fixed; the cryptographic core was found sound — no
critical/high).

**Q: How do we pin a known-good version?**
Pin a commit SHA (pre-1.0). A CHANGELOG tracks notable changes.

## Limitations (stated up front)

- Signer pinning is opt-in (out-of-band key trust required).
- No built-in KMS/HSM, key revocation, trusted timestamping, TEE attestation, or
  transparency log yet — see the roadmap in [THREAT_MODEL.md](THREAT_MODEL.md).
- Bundles are tamper-evident, **not** encrypted (no confidentiality).
