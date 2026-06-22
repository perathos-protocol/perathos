"""Tests for the optional NLI entailment backend.

The decision rule is unit-tested without any model. A full integration test that
actually loads a transformers checkpoint is included but skips automatically
when torch/transformers are unavailable (the `nli` extra is not installed) or
the model cannot be downloaded.
"""
import pytest

from perathos.verifiers_nli import (
    CONTRADICTED,
    SUPPORTED,
    UNVERIFIABLE,
    decide,
)


def test_decide_supported():
    assert decide(best_entail=0.9, best_contra=0.1) == SUPPORTED


def test_decide_contradicted():
    assert decide(best_entail=0.1, best_contra=0.9) == CONTRADICTED


def test_decide_abstains_when_unsure():
    assert decide(best_entail=0.3, best_contra=0.3) == UNVERIFIABLE


def test_decide_entailment_wins_ties():
    assert decide(best_entail=0.6, best_contra=0.6) == SUPPORTED


def test_decide_thresholds_respected():
    # high contradiction but below threshold -> abstain
    assert decide(best_entail=0.2, best_contra=0.45, contradict_threshold=0.5) == UNVERIFIABLE


@pytest.mark.integration
def test_real_nli_model_labels_correctly():
    pytest.importorskip("torch")
    pytest.importorskip("transformers")
    try:
        from perathos.verifiers_nli import NLIEntailmentModel
        model = NLIEntailmentModel()  # downloads a small checkpoint on first use
    except Exception as exc:  # network/offline/model unavailable
        pytest.skip(f"NLI model unavailable: {exc}")

    evidence = ["The Eiffel Tower is a wrought-iron lattice tower in Paris, France."]
    assert model.label("The Eiffel Tower is in Paris.", evidence) == SUPPORTED
    assert model.label("The Eiffel Tower is in Berlin.", evidence) in (CONTRADICTED, UNVERIFIABLE)
