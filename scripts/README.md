# Verifier training & calibration scripts

Runnable harnesses for making the Claim-Entailment verifier (124) real and its
confidence honest. Both are standalone and run against a checkout.

## `calibrate.py` — fit honest confidence (no heavy deps)

A verifier's raw score is not the probability its verdict is correct. Fit a
calibrator on held-out, in-domain `(score, correct)` pairs and measure ECE.

```bash
python scripts/calibrate.py labeled.jsonl --method temperature --out calib.json
```
`labeled.jsonl` lines: `{"score": 0.87, "label": 1}` (label = was the verdict
correct). Apply the result:
```python
import json
from perathos import TemperatureCalibrator
cal = TemperatureCalibrator.from_dict(json.load(open("calib.json")))
cal.confidence_bps(raw_score)   # honest confidence in basis points
```

## `train_entailment.py` — fine-tune the NLI model

```bash
pip install perathos[train]
python scripts/train_entailment.py train.jsonl --eval eval.jsonl \
    --base microsoft/deberta-v3-base --out ./entailment-ckpt --epochs 3
# Validate the harness without real training:
python scripts/train_entailment.py train.jsonl --max-steps 2
```
Data lines: `{"premise": "<evidence>", "hypothesis": "<claim>", "label": "entailment|neutral|contradiction"}`.
Plug the checkpoint in:
```python
from perathos.verifiers_nli import nli_entailment_fn
fn = nli_entailment_fn(model_name="./entailment-ckpt")
```

## Recommended recipe (commercial-safe)

Per [../docs/research/TRAINING_DATA.md](../docs/research/TRAINING_DATA.md):

1. **Base on permissive, evidence-grounded data:** FActScore (MIT) + RAGTruth
   (MIT) + DocNLI (BSD-3). RAGTruth uniquely separates `contradicted` from
   `unverifiable`, matching the verifier's label set.
2. **Robustness add-on (if copyleft is acceptable):** VitaminC (CC-BY-SA).
3. **AVOID in any shipped model:** AggreFact (no LICENSE file → no rights),
   and the CC-BY-NC sets — ANLI, SciFact, AVeriTeC, FELM.
4. **Calibrate** on a held-out in-domain split + a small gold set built from
   real verifier traffic (2–3 annotators, κ ≥ 0.7); report ECE per domain.

Map each source's labels to `{entailment, neutral, contradiction}` before
training (e.g. FEVER SUPPORTS→entailment, REFUTES→contradiction, NEI→neutral).
