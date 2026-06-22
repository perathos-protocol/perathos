"""Optional real NLI entailment backend for ClaimEntailmentVerifier (124).

Replaces the lexical placeholder with a learned Natural Language Inference
model (a transformers cross-encoder). This is an OPTIONAL extra
(`pip install perathos[nli]`) and is deliberately NOT imported by the core
package, so `import perathos` never requires torch.

Usage:
    from perathos.verifiers import ClaimEntailmentVerifier, VerificationContext
    from perathos.verifiers_nli import nli_entailment_fn
    fn = nli_entailment_fn()                       # loads the model once
    verifier = ClaimEntailmentVerifier(entailment_fn=fn)

The returned callable matches the entailment_fn hook: (claim, evidence_list) ->
"supported" | "contradicted" | "unverifiable". For each evidence document the
model scores NLI(premise=evidence, hypothesis=claim); the decision aggregates
over documents: any document that entails -> supported; else any that
contradicts -> contradicted; else unverifiable (abstain).

The model labels are read from `config.id2label`, so any 3-way NLI checkpoint
(contradiction / entailment / neutral) works. Defaults to a small DeBERTa NLI
cross-encoder for speed.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

SUPPORTED = "supported"
CONTRADICTED = "contradicted"
UNVERIFIABLE = "unverifiable"

DEFAULT_MODEL = "cross-encoder/nli-deberta-v3-xsmall"


def decide(
    best_entail: float,
    best_contra: float,
    entail_threshold: float = 0.5,
    contradict_threshold: float = 0.5,
) -> str:
    """Pure decision rule (no model) — easy to unit-test.

    Entailment wins ties (a claim a document supports is supported even if
    another reading looks contradictory); contradiction must both clear its
    threshold and exceed entailment; otherwise we abstain.
    """
    if best_entail >= entail_threshold and best_entail >= best_contra:
        return SUPPORTED
    if best_contra >= contradict_threshold and best_contra > best_entail:
        return CONTRADICTED
    return UNVERIFIABLE


class NLIEntailmentModel:
    """Lazily loads a transformers NLI cross-encoder and scores claim/evidence."""

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        device: Optional[str] = None,
        entail_threshold: float = 0.5,
        contradict_threshold: float = 0.5,
        max_length: int = 512,
    ):
        import torch  # imported lazily so the core package needs no torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
        self.model.eval()
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        # Canonical role -> column index, read from the checkpoint's own labels.
        self._role_index = {
            v.lower(): int(k) for k, v in self.model.config.id2label.items()
        }
        self.entail_threshold = entail_threshold
        self.contradict_threshold = contradict_threshold
        self.max_length = max_length

    def _probs(self, premise: str, hypothesis: str) -> Dict[str, float]:
        torch = self._torch
        with torch.no_grad():
            inputs = self.tokenizer(
                premise, hypothesis,
                return_tensors="pt", truncation=True, max_length=self.max_length,
            ).to(self.device)
            logits = self.model(**inputs).logits[0]
            probs = torch.softmax(logits, dim=-1).tolist()
        out = {}
        for role, idx in self._role_index.items():
            out[role] = float(probs[idx])
        return out

    def _aggregate(self, claim: str, evidence: List[str]) -> "tuple[float, float]":
        best_entail = best_contra = 0.0
        for doc in evidence:
            p = self._probs(doc, claim)
            best_entail = max(best_entail, p.get("entailment", 0.0))
            best_contra = max(best_contra, p.get("contradiction", 0.0))
        return best_entail, best_contra

    def predict(self, premise: str, hypothesis: str) -> "tuple[str, float, Dict[str, float]]":
        """NLI prediction for a single pair: (predicted_role, confidence, probs).

        confidence is the probability mass on the predicted class — the raw
        signal a calibrator turns into an honest confidence_bps.
        """
        probs = self._probs(premise, hypothesis)
        role = max(probs, key=probs.get)
        return role, probs[role], probs

    def label(self, claim: str, evidence: List[str]) -> str:
        if not evidence:
            return UNVERIFIABLE
        be, bc = self._aggregate(claim, evidence)
        return decide(be, bc, self.entail_threshold, self.contradict_threshold)

    def entailment_score(self, claim: str, evidence: List[str]) -> float:
        """Max entailment probability across evidence — a raw score for calibration."""
        if not evidence:
            return 0.0
        return self._aggregate(claim, evidence)[0]


def nli_entailment_fn(model_name: str = DEFAULT_MODEL, **kwargs) -> Callable[[str, List[str]], str]:
    """Build an entailment_fn(claim, evidence) -> label backed by a real NLI model."""
    model = NLIEntailmentModel(model_name=model_name, **kwargs)

    def fn(claim: str, evidence: List[str]) -> str:
        return model.label(claim, evidence)

    return fn
