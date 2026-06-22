# Verifier benchmarks

Measured on the exact pipeline in this directory. Reproduce with the commands
shown; numbers are from a CPU run on 2026-06-16.

## Setup

- **Backend:** `cross-encoder/nli-deberta-v3-xsmall` (3-way NLI cross-encoder).
- **Data:** SNLI via `prepare_nli.py` — 2,500 train / 800 validation examples.
- **Eval:** `evaluate.py` — accuracy + Expected Calibration Error (ECE) of the
  model's confidence, before and after temperature scaling.

## Results

| Model | Accuracy (800) | ECE raw | ECE calibrated | Temp T |
|---|---|---|---|---|
| Base (stock NLI) | **0.9225** | 0.0368 | **0.0152** | 1.464 |
| Fine-tuned (1 epoch, 2.5k SNLI, CPU) | 0.9175 | 0.0455 | 0.0163 | 1.494 |

Wired into the verifier, the fine-tuned checkpoint behaves correctly:
`"capital of France is Paris"` → **PASS**, `"...is Berlin"` (vs Paris evidence)
→ **FAIL**.

## Honest interpretation

- The **stock NLI backend is already strong (~92%) and well-calibrated** (ECE
  ~0.037, halving to ~0.015 after temperature scaling). Calibration is the
  clear, repeatable win and is what makes `confidence_bps` honest.
- The **short 1-epoch fine-tune on a generic SNLI subset did not improve** over
  the base (92.25% → 91.75%, within noise, slightly down). This is expected: a
  tiny fine-tune has nothing to add to an already NLI-tuned model and can mildly
  perturb it. We report it as-is rather than cherry-pick — *evidence, not
  spin*.
- **To actually move the needle**, fine-tune on the *task-relevant*, permissive
  datasets from [../docs/research/TRAINING_DATA.md](../docs/research/TRAINING_DATA.md)
  — RAGTruth (MIT) and FActScore (MIT), which match the claim-vs-retrieved-
  evidence task (RAGTruth uniquely separates `contradicted` from
  `unverifiable`) — for more epochs on a GPU, and calibrate on a held-out
  in-domain split.

## Reproduce

```bash
pip install perathos[train]
python scripts/prepare_nli.py --out-dir data --train 2500 --eval 800
python scripts/evaluate.py data/eval.jsonl --model cross-encoder/nli-deberta-v3-xsmall
python scripts/train_entailment.py data/train.jsonl --eval data/eval.jsonl \
    --base cross-encoder/nli-deberta-v3-xsmall --out entailment-ckpt --epochs 1
python scripts/evaluate.py data/eval.jsonl --model ./entailment-ckpt --calib-out calib.json
```
