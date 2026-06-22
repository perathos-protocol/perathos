# Proof Bundle v2 — unification spec

**Status: IMPLEMENTED in perathos** (Stage 3). Decisions signed off: perathos
owns v2; `answer` is hash-only by default; signature expiry deferred. v2 is the
default `create_bundle` output and `verify_bundle` dual-reads v1. Stage 4 (the
training-ops gateway importing perathos for v2) remains.

## Why

Two VRL implementations use incompatible bundle/signing formats:

| | perathos (core) | training-ops (gateway) |
|---|---|---|
| Integrity | hash-chain: `integrity_hash` -> `uuid5` `bundle_id` | flat schema + detached signed envelope |
| Verdicts | `VerdictRecord` (verifier_id, verdict, **confidence_bps**, method, **evidence_digests**) | `VerifierResult` (verifier name, status, **method: computed/asserted**, evidence) |
| Honesty | INCONCLUSIVE-safe, calibrated confidence | `independently_verified()` (only computed passes count) |
| Signing | sign `integrity_hash`; `{algorithm, verify_key, signature}` | sign envelope `{alg,kid,signed_at,expires_at,bundle}` |
| Answer | stored as `output_hash` only (privacy) | stored verbatim (replayable), redactable |

A bundle from one will not validate in the other. v2 is the single format both
adopt; perathos is the canonical implementation (open-core).

## v2 = perathos's structure + training-ops's best ideas

Keep perathos's **hash-chain integrity** as the spine (it is the cleaner,
already-audited integrity anchor) and fold in training-ops's three best ideas:
the **computed/asserted** distinction, **kid + expiry** in the signature, and an
**optional replayable answer**.

### Decisions (my recommendation in **bold**)

1. **Integrity model** — **keep hash-chain** (`integrity_hash` -> `bundle_id`).
   The verification block is already folded into `integrity_hash` (done).
2. **Verdict record** — **keep perathos `VerdictRecord`** (richer: confidence +
   evidence digests) and add an explicit **`computed: bool`** field. All
   perathos verifiers set `computed=true` (the pipeline always runs the
   verifier); a future ingest path for model-self-reported results would set
   `false`. Adds `independently_verified()` semantics for free.
3. **Verdict vocabulary** — **keep** PASS/FAIL/WARN/INCONCLUSIVE/NOT_APPLICABLE
   (a superset; training-ops `skipped`->NOT_APPLICABLE, `error`->INCONCLUSIVE).
4. **Signing** — **keep signing `integrity_hash`**, and bind **optional**
   `kid` + `expires_at` by including them in the signed payload *only when
   present* (back-compatible; rotation/expiry become first-class). TrustStore/
   JWKS already shipped (stage 1).
5. **Answer storage** — **add an optional `answer` field** (default off; hash
   only) with a `redact_answer` switch, matching the gateway's replay/redaction.
6. **Top-level aggregate** — **add `verdict`** (the aggregate) and `model` at the
   top level so a consumer reads one field; keep the detailed records nested.

### v2 bundle shape (illustrative)

```jsonc
{
  "bundle_version": "2.0",
  "bundle_id": "<uuid5(integrity_hash)>",
  "model": "<model id>",              // new (top-level)
  "ai_id": "<deterministic model id>",
  "answer": "<text>",                 // new, OPTIONAL (redactable)
  "output_hash": "sha-256:...",
  "input_hash": "sha-256:...",
  "trace_hash": "sha-256:...",
  "verdict": "PASS|FAIL|WARN|INCONCLUSIVE",   // new (top-level aggregate)
  "verification": {
    "schema": "vrl/verification/2",
    "aggregate": { "verdict": "...", "confidence_bps": 0, "...": "..." },
    "verdict_records": [
      { "verifier_id": 123, "verifier_name": "Symbolic Solver",
        "verdict": "FAIL", "computed": true, "confidence_bps": 1000,
        "method": "computed:arithmetic-recompute", "detail": "...",
        "evidence_digests": ["sha-256:..."] }
    ]
  },
  "integrity_hash": "sha-256:...",    // binds everything above (minus signature)
  "signature": {                       // optional
    "algorithm": "ed25519", "verify_key": "<hex>", "signature": "<hex>",
    "kid": "ed25519-...", "expires_at": "2026-..Z"   // optional (bound when present)
  }
}
```

## Backward compatibility (v1 -> v2)

- `verify_bundle` detects `bundle_version` (absent/`"1.0"` => v1 path; `"2.0"` =>
  v2). **All existing v1 bundles keep verifying unchanged.**
- New bundles are emitted as v2. A `migrate_v1_to_v2()` helper re-wraps an old
  bundle (it cannot recover a redacted answer, only re-key the structure).
- The gateway (training-ops) switches to import perathos for v2 build/verify in
  Stage 4; it keeps reading its own v1 bundles via the compat path.

## Rollout

- **Stage 3a** — implement v2 in perathos behind `bundle_version`, dual-read in
  `verify_bundle`, full test matrix (v1 still green, v2 round-trips, cross-checks).
- **Stage 3b** — add `computed`, top-level `verdict`/`model`, optional `answer`.
- **Stage 4** — training-ops depends on perathos; gateway builds/validates v2 via
  perathos; its old bundles still validate via the compat path.

## Open questions for sign-off

- OK to make perathos the canonical v2 implementer and have training-ops depend
  on it (vs. duplicating v2 in both)?
- Default for `answer`: store hash-only (recommended) or include verbatim?
- Do we need signature **expiry** in v2 now, or defer (TrustStore already covers
  trust)?
