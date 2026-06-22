# Perathos Threat Model

_Last updated: 2026-06-16 (covers the proof layer at this commit)._

This document states precisely what Perathos protects, what it does **not**,
and the assumptions a deployment must satisfy. It is written so a security
reviewer can decide what to trust without reading the source.

## 1. What Perathos is (and is not)

Perathos is a **cryptographic attestation layer**. It binds an AI output to:
its digest, the verifier verdicts about it, a deterministic model identifier,
and a signature — into a tamper-evident **proof bundle** that anyone can verify
offline.

Perathos is **not** a hallucination detector, a guarantee of truth, or an
oracle. It makes verifier findings **verifiable, reproducible, and bound to the
output**. The findings themselves are *evidence*, produced by the verifier
modules (which are pluggable), and carry calibrated — not absolute — confidence.

> Two independent properties, never to be conflated:
> - **Attestation integrity** (this document's subject): the bundle cannot be
>   altered undetected. Cryptographic.
> - **Detection quality**: how good the verifiers are at catching bad outputs.
>   Statistical, model-dependent, and explicitly *not* a guarantee.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Proof bundle integrity | A consumer's decision rests on the bound verdicts/digests |
| Signer private key (`signing.key`) | Whoever holds it can issue authentic-looking bundles |
| The mapping `verify_key → real-world signer` | Provenance: "who attested this" |
| Audit/verdict records | The evidence trail a consumer audits |

## 3. Adversary capabilities considered

We assume an adversary who can **read and modify bundles in transit or at rest**,
craft arbitrary bundles, and submit hostile/malformed bundles to a verifier. We
consider whether they can: forge a valid bundle, silently alter a verdict, strip
or swap a signature, impersonate a signer, or crash a verifier (DoS).

## 4. What is protected (and how)

| Threat | Protected? | Mechanism |
|---|---|---|
| Editing output digest, verdicts, AI-ID, timestamps | ✅ | All fields are folded into `integrity_hash`; `bundle_id` is `uuid5(integrity_hash)`; verify recomputes |
| Editing/adding/removing the verification block | ✅ | `verification_hash` is in the integrity payload **iff** verification is present; any change flips recomputation → `ERR_INTEGRITY_HASH_MISMATCH` |
| Forging a signature on an intact chain | ✅ | `verify()` validates the Ed25519 signature when present → `ERR_BAD_SIGNATURE` |
| Algorithm-confusion (claiming non-Ed25519) | ✅ | Signature with `algorithm != "ed25519"` is rejected → `ERR_UNSUPPORTED_ALGORITHM` |
| Signature/serialization malleability | ✅ | Strict lowercase-hex; deterministic JCS-style canonical serialization (sorted keys, no whitespace, `allow_nan=False`, string keys only) |
| Hostile/malformed bundle crashing the verifier | ✅ | `verify_bundle` returns `ERR_MALFORMED_BUNDLE`; `inspect` is fully type-guarded; verifiers degrade to `INCONCLUSIVE` |
| Torn/empty bundle file on crash or concurrent write | ✅ | Atomic writes (tempfile + fsync + `os.replace`) |

## 5. What is NOT protected — explicit assumptions

1. **Signer identity must be pinned out of band.** A bare signature only proves
   *some* key signed the hash. An attacker can strip a signature and re-sign the
   same hash with **their own** key; `verify()` will report it valid **under the
   attacker's key**. The consumer MUST pin the expected public key
   (`verify_bundle(..., expected_verify_key=...)` / `verify --verify-key`).
   Without pinning, provenance is not established.
2. **Private key custody is the deployer's responsibility.** Perathos stores
   `signing.key` with owner-only permissions (POSIX `0o600`; Windows ACL via
   icacls, best-effort with a warning on failure) but does not provide an HSM/KMS.
   For production, hold the key in a KMS/HSM and inject signing.
3. **Verifier verdicts are evidence, not truth.** A `PASS` means the configured
   verifiers did not find a problem with the available evidence — not that the
   output is correct. Detection has false negatives; confidence is calibrated,
   not certain. `INCONCLUSIVE` ("not enough evidence") is a first-class outcome
   and must not be read as PASS.
4. **Evidence quality bounds verifier quality.** The Claim-Entailment verifier
   is only as good as the retrieved evidence and the NLI model; the
   Cross-Examiner only as good as the resamples provided.
5. **The model identifier (AI-ID) is as trustworthy as its inputs.** It binds an
   output to a *claimed* model descriptor; it does not by itself prove which
   weights ran (that needs TEE attestation, out of scope here).
6. **No confidentiality.** Bundles are tamper-evident, not encrypted. Do not put
   secrets in an output you expect to remain private; store sensitive inputs
   separately.
7. **No revocation/timestamping authority.** There is no built-in key-revocation
   or trusted-time service; `issued_at` is self-asserted.

## 6. Cryptographic choices

- **Hash:** SHA-256 (collision-resistant; the binding primitive).
- **Signature:** Ed25519 (PyNaCl/libsodium; constant-time).
- **Serialization:** deterministic canonical JSON (sorted keys, compact
  separators, UTF-8, `allow_nan=False`, string keys only) so identical logical
  data produces identical bytes across languages/platforms — the basis for
  reproducible signatures and offline verification.

## 7. Residual risks / roadmap

- Signer pinning is opt-in; a future bundle version may bind `verify_key` into
  the signed payload to make substitution detectable without out-of-band pinning.
- No TEE/remote-attestation binding of the execution environment yet.
- No transparency log (e.g. Merkle inclusion proofs) for issued bundles yet.

See [SECURITY.md](../SECURITY.md) for reporting and [ENTERPRISE_FAQ.md](ENTERPRISE_FAQ.md)
for procurement-level Q&A.
