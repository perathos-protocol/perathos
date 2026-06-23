# Spec: Legal Citation Verifier (engine 128)

Status: **draft / proposed** · Owner: TBD · Target: perathos `0.3.0`

A deterministic verifier that checks whether the legal authorities an AI output
cites **actually exist** and **say what the output claims** — against a pinned,
content-addressed snapshot of a public case-law/statute corpus. It is the first
*domain* verifier and the chosen wedge into the regulated-AI buyer.

---

## 1. Why this feature

**The pain is named, escalating, and lands on a high-liability buyer.** Lawyers
have been sanctioned (real, on the public record) for filing briefs containing
AI-fabricated case citations — citations that look perfectly formatted but refer
to cases that do not exist, or that exist but hold the opposite of what was
claimed. The downstream buyers (litigation firms, in-house legal, legal-tech
vendors, and their malpractice insurers) feel this as direct liability, not a
vitamin.

**It is the right wedge for the moat thesis** (see the moat teardown), because it
is:
- **Deterministic** — existence is a lookup; it preserves recomputability, the
  one property incumbents' "trust my dashboard" tools don't offer.
- **Demoable in one screen** — paste a brief, get fabricated cites flagged.
- **Cross-party by nature** — opposing counsel / a court / an insurer can
  independently re-run the verdict against the same pinned snapshot and get the
  identical answer, without trusting the producer. That is the gap no incumbent
  occupies.
- **Honest** — it reports *evidence* (this cite is/ isn't in the corpus), never a
  guarantee of legal correctness, matching the existing `verdict` discipline.

**Why it is hard to replicate** — see §11. Short version: the raw corpus is
public, so the moat is *not* secret data; it is the well-maintained, normalized,
**content-addressed, reproducibly-snapshotted index** plus the citation-resolution
logic and the becoming-the-trusted-reference network effect. That is expensive to
build and maintain well, and it compounds.

---

## 2. Scope

**In scope (v1):**
- **Citation extraction** — find legal citations in free text (case reporters,
  statutes, a constrained set of common formats).
- **Existence check** — does the cited authority resolve to a real record in the
  pinned snapshot? (the fabrication detector — the core value.)
- **Quote/support check (conservative)** — when the output puts a *quoted* string
  in the citation's mouth, does that quote appear in the authority's text?

**Out of scope (v1), explicitly:**
- Judging whether a (real) case actually *supports the legal argument* — that is
  paraphrase-level entailment and a matter of legal interpretation. We **degrade
  to INCONCLUSIVE**, never FAIL, on non-quoted propositions. (Optional
  `entailment_fn` hook may upgrade this later; the verdict must still bind the
  model version — see §9.)
- Overruled / good-law / Shepardizing status (a later, separate signal).
- Non-US jurisdictions (v1 is US federal + a few states; coverage is a corpus
  question, not an engine question — see §6).

---

## 3. Fit with the existing architecture

Implemented as a `Verifier` subclass in `perathos/engines.py`, exactly like
123–127, so it inherits the INCONCLUSIVE-safe `run()` wrapper (any exception →
INCONCLUSIVE, never a false PASS) and the evidence-digest binding.

```
class CitationVerifier(_Engine):
    verifier_id = 128
    verifier_name = "Legal Citation Verifier"
    verifier_version = "1.0.0"
    method = "computed:citation-resolution"

    def __init__(self, corpus: "CitationCorpus | None" = None,
                 entailment_fn=None): ...
    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord: ...
```

- **Input** comes from the answer text plus an optional `ctx.corpus` handle (a
  `CitationCorpus` — §6). With no corpus available the verifier returns
  **NOT_APPLICABLE** ("no citation corpus configured"), never PASS — same pattern
  as `SchemaValidator` with no schema.
- **Verdict mapping** uses the existing constants: `PASS` / `FAIL` /
  `INCONCLUSIVE` / `NOT_APPLICABLE`.
- It is **packaged behind an optional extra** (`perathos[legal]`) because the
  corpus index pulls heavier deps; the core install stays small.

---

## 4. The core design constraint (and the key idea)

A citation checker needs an external authority (case law). A naïve design makes a
**live network call** per citation — which would break three things perathos
depends on at once: determinism, offline verifiability, and the SSRF guarantee
(the same class of risk `SchemaValidator` already refuses remote `$ref` for).

**Key idea: never call the network at verify time. Resolve against a pinned,
content-addressed snapshot, and bind the snapshot hash into the verdict.**

- The corpus is a **versioned, immutable snapshot** with a `corpus_version`
  (e.g. `us-caselaw-2026.06`) and a `corpus_hash` (SHA-256 of the snapshot
  manifest).
- Verification is a **pure function of (output, corpus snapshot)**. No I/O beyond
  reading the local/pinned index.
- The `corpus_version` + `corpus_hash` are **written into the VerdictRecord
  evidence** (and therefore, via `verification_hash`, into the bundle's
  `integrity_hash`). So a third party who fetches the *same* snapshot recomputes a
  **bit-identical verdict**, and a verdict made against a different/forged corpus
  is detectable.

This is what makes the feature reinforce the moat instead of eroding it: it stays
deterministic, offline, reproducible, and SSRF-free, and the snapshot hash makes
the verdict **portable across distrusting parties**.

---

## 5. Verdict semantics (honesty-first)

For each extracted citation the engine produces a per-cite finding; the aggregate
verdict is the worst finding (FAIL > INCONCLUSIVE > PASS), with NOT_APPLICABLE if
nothing checkable was found.

| Per-cite outcome | Condition | Verdict contribution |
|---|---|---|
| **fabricated** | citation parses but resolves to **no** record in the snapshot | **FAIL** (high confidence — the core signal) |
| **misquote** | citation resolves, but a quoted string attributed to it is **absent** from the authority text | **FAIL** |
| **pinpoint-miss** | resolves, but the pin-cited page/section is outside the authority's range | **FAIL** |
| **grounded** | resolves, and any attributed quote is found verbatim/near-verbatim | **PASS** |
| **unverifiable-support** | resolves, but the proposition is a paraphrase (no quote) | **INCONCLUSIVE** (never FAIL — interpretation is out of scope) |
| **unparseable / out-of-coverage** | not a recognized citation, or jurisdiction not in snapshot | skip; if *all* cites skip → **NOT_APPLICABLE** |

**Cardinal rule (inherited):** false positives are the worst outcome. A correct
citation must **never** be flagged. Anything ambiguous degrades to INCONCLUSIVE.
"Out of coverage" (a real cite we simply don't have) must be **INCONCLUSIVE/skip,
not FAIL** — we cannot prove non-existence outside our snapshot, and we must say
so. This is the make-or-break honesty line; over-claiming non-existence would be
worse than missing.

---

## 6. The reference-data layer (the moat lives here)

`CitationCorpus` is an interface over a pinned snapshot:

```
class CitationCorpus:
    version: str            # "us-caselaw-2026.06"
    content_hash: str       # sha-256 of the manifest
    def resolve(self, key: NormalizedCite) -> CaseRecord | None: ...
    def text_of(self, key: NormalizedCite) -> str | None: ...   # for quote check
    def covers(self, jurisdiction: str, year: int) -> bool: ...  # honesty: known gaps
```

- **Source data is public.** US case law is available (Harvard Caselaw Access
  Project / Free Law Project's CourtListener; US Code/statutes are public). **We
  must not pretend the data is proprietary** — the defensibility is in the
  *index*, not the bytes (see §11).
- **Snapshot, don't stream.** Build periodic immutable snapshots; publish the
  `content_hash` and a manifest so anyone can mirror and re-verify. (This is the
  on-ramp to the Certificate-Transparency-style log.)
- **`covers()` makes gaps explicit.** The engine asks coverage before asserting
  non-existence, so an out-of-coverage cite becomes INCONCLUSIVE, not a false
  FAIL. Coverage is data, expandable without engine changes.
- **Distribution:** snapshots are mirrorable and content-addressed, so a
  customer's auditor can pin the exact snapshot the producer used.

The index, normalization, coverage breadth, freshness cadence, and the
reproducible-snapshot protocol are the expensive, compounding asset.

---

## 7. Citation extraction & normalization (deterministic)

- **Parser** over a defined citation grammar: reporter cites (`410 U.S. 113`,
  `347 U.S. 483 (1954)`), parallel cites, statutes (`42 U.S.C. § 1983`), with
  pinpoint pages (`410 U.S. 113, 164`). Start with the high-frequency forms; the
  grammar is data-extensible.
- **Normalization** to a canonical `NormalizedCite` (volume, reporter
  abbreviation normalized via a reporter table, page, year, pin). Normalization
  rules are deterministic and content-addressed alongside the corpus.
- **Reuse the engine discipline:** like the temporal/hallucination engines,
  prefer precise patterns over greedy ones; an unrecognized string is *skipped*,
  not guessed at. No false fabrication flag from a parser miss.

## 8. The two checks

1. **Existence** — `corpus.resolve(normalized)`:
   - hit → candidate grounded/needs-quote-check.
   - miss **and** `corpus.covers(jurisdiction, year)` → **fabricated → FAIL**.
   - miss **and not** covered → **INCONCLUSIVE** ("outside snapshot coverage").
2. **Quote/support** — only when the output attributes a quoted string to the
   cite: deterministic verbatim / whitespace-normalized substring match against
   `corpus.text_of()`. Found → PASS; absent → **misquote → FAIL**. A paraphrase
   (no quote) → **INCONCLUSIVE** unless an `entailment_fn` is supplied (and then
   the model id+version is bound into evidence — §9).

## 9. Evidence & reproducibility binding

The VerdictRecord `evidence` carries (and thus binds, via the bundle's
`verification_hash` → `integrity_hash`):

```
{
  "corpus_version": "us-caselaw-2026.06",
  "corpus_hash": "sha-256:…",
  "citations": [
    {"raw": "410 U.S. 113", "normalized": "...", "status": "grounded"},
    {"raw": "999 U.S. 1234", "normalized": "...", "status": "fabricated"},
    {"raw": "...", "status": "unverifiable-support"}
  ],
  "engine_rules_hash": "sha-256:…"   // citation grammar + reporter table version
}
```

Because `corpus_hash` and `engine_rules_hash` are bound, the verdict is
**reproducible**: same snapshot + same rules → identical verdict, re-checkable
offline by any party. This is the property that makes the signed bundle worth more
than a log line.

## 10. Adversarial / abuse considerations

- **Plausible-but-fake cite** (right format, nonexistent case) → the core FAIL.
- **Real cite, wrong holding** (paraphrase) → INCONCLUSIVE (we do *not* over-claim
  to judge holdings); a *misquoted* quotation → FAIL.
- **Pinpoint hallucination** (real case, page that doesn't exist) → FAIL.
- **Coverage-gap exploitation** (cite a real but out-of-snapshot case to dodge the
  check) → INCONCLUSIVE + surfaced, never silently PASS. `covers()` makes the gap
  auditable.
- **SSRF / DoS** — no network at verify time; inputs are length-bounded and the
  citation count is capped (mirror `SymbolicSolver`'s 100-equation cap). Corpus
  reads are local/pinned.
- **Corpus substitution** — a forged verdict against a fake corpus is detectable
  because `corpus_hash` is bound and publishable.

## 11. Why this is hard to replicate (moat tie-in)

The raw law is public, so honesty demands we say the moat is **not secret data**.
It is the combination:
1. **A well-maintained, normalized, broad-coverage, content-addressed index** with
   a published reproducibility protocol — months of unglamorous engineering and
   ongoing freshness work a fast-follower underestimates.
2. **The reproducible-snapshot + binding protocol** (§4, §9) that makes verdicts
   portable across distrusting parties — the cross-party property incumbents'
   single-tenant tools structurally lack.
3. **Becoming the reference auditors/courts/insurers point at** — a
   trust/standard/network position (the transparency-log on-ramp), which is
   adoption, not code, and compounds.

A bigger neural model buys *none* of these and costs determinism. This feature
deepens exactly the axes the teardown said were defensible: domain depth +
cross-party verifiability + a compounding corpus.

## 12. Honesty boundaries (what it does NOT claim)

- It does **not** certify a brief is legally correct or that an argument wins.
- It does **not** prove a case is good law / not overruled (v1).
- It does **not** assert a real cite is fake when it is merely outside coverage —
  it says "outside snapshot," and means it.
- A PASS means "these citations resolve in snapshot X and quoted text matches,"
  nothing more. Evidence, not guarantee.

## 13. Build plan

- **M0 — demoable MVP (~1–2 wks):** parser for US reporter + `U.S.C.` cites;
  `CitationCorpus` over a CourtListener/CAP US-Supreme-Court snapshot (small,
  high-value, fully public); existence + verbatim-quote checks; engine 128 +
  red-team set; CLI `perathos cite-check brief.txt`. Demo: paste a brief, fake
  cites flagged, `corpus_hash` bound, re-verify offline.
- **M1 — coverage + reproducibility protocol:** federal circuits + a few states;
  publish snapshot manifests + `content_hash`; pin into bundles end-to-end.
- **M2 — cross-party proof + transparency log:** selective-disclosure proof ("I
  checked these cites against snapshot X" without revealing the brief) and an
  append-only log of verification commitments. (Separate spec.)

## 14. Metrics (the gate, same discipline as the engines)

- A **citation red-team**: real cites (must PASS), fabricated cites (must FAIL),
  real-but-out-of-coverage (must be INCONCLUSIVE, **not** FAIL), misquotes (FAIL),
  paraphrase (INCONCLUSIVE). Scored by an extended `verifier_catch_rate`.
- **Cardinal gate:** `false_positive_rate == 0` on real, in-coverage citations.
  A flagged-real-citation is a release blocker — same rule as the existing engines.
- Track catch-rate on fabricated cites and the INCONCLUSIVE rate (coverage proxy).

## 15. Open questions / risks

- **Quote matching robustness** — OCR/formatting variance in the corpus text;
  needs whitespace/quote normalization, possibly fuzzy-but-deterministic matching
  with a bound threshold (never a model at the core).
- **Citation grammar coverage** vs. false-skip rate — too strict misses real
  cites (lowers value, not safety); too loose risks a parser-driven false FAIL
  (unacceptable). Bias to skip.
- **Corpus freshness** vs. immutability — new opinions appear; snapshots must
  version forward without retro-changing a pinned verdict.
- **Licensing** of any non-public enrichment (headnotes etc.) — v1 deliberately
  uses only public text to keep the snapshot freely mirrorable.
