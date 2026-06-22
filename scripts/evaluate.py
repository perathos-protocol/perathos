#!/usr/bin/env python
"""Evaluate an NLI checkpoint as the Claim-Entailment verifier's backend, and
fit + report confidence calibration.

Reports accuracy on a {premise,hypothesis,label} JSONL eval set and the
Expected Calibration Error (ECE) of the model's confidence before and after
temperature scaling. Use it to compare a base vs fine-tuned checkpoint and to
produce a calibrator the verifier can apply.

Usage:
    pip install perathos[train]
    python scripts/evaluate.py data/eval.jsonl --model cross-encoder/nli-deberta-v3-xsmall
    python scripts/evaluate.py data/eval.jsonl --model ./entailment-ckpt --calib-out calib.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from perathos.calibration import TemperatureCalibrator, expected_calibration_error  # noqa: E402


def load(path: Path):
    rows = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        raw = raw.strip()
        if raw:
            rows.append(json.loads(raw))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("data", type=Path, help="eval JSONL {premise,hypothesis,label}")
    ap.add_argument("--model", default="cross-encoder/nli-deberta-v3-xsmall")
    ap.add_argument("--calib-out", type=Path, default=None)
    ap.add_argument("--limit", type=int, default=0, help="cap examples (0 = all)")
    args = ap.parse_args()

    from perathos.verifiers_nli import NLIEntailmentModel

    model = NLIEntailmentModel(model_name=args.model)
    rows = load(args.data)
    if args.limit:
        rows = rows[: args.limit]

    correct, scores, labels = 0, [], []
    for r in rows:
        role, conf, _ = model.predict(r["premise"], r["hypothesis"])
        hit = int(role == r["label"])
        correct += hit
        scores.append(conf)
        labels.append(hit)

    n = len(rows)
    acc = correct / n if n else 0.0
    ece_before = expected_calibration_error(scores, labels)
    cal = TemperatureCalibrator().fit(scores, labels)
    ece_after = expected_calibration_error([cal.calibrate(s) for s in scores], labels)

    print(f"model        : {args.model}")
    print(f"examples     : {n}")
    print(f"accuracy     : {acc:.4f}")
    print(f"ECE before   : {ece_before:.4f}")
    print(f"ECE after    : {ece_after:.4f}  (temperature T={cal.temperature:.3f})")
    if args.calib_out:
        args.calib_out.write_text(json.dumps(cal.to_dict(), indent=2), encoding="utf-8")
        print(f"calibrator   : {args.calib_out}")


if __name__ == "__main__":
    main()
