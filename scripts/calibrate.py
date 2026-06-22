#!/usr/bin/env python
"""Fit and report a confidence calibrator for a Perathos verifier.

Input: a JSON Lines file where each line is {"score": <0..1 float>, "label": 0|1}
— `score` is the verifier's raw confidence (e.g. an NLI entailment probability)
and `label` is 1 if the verdict was actually correct on that example, else 0.

Output: prints Expected Calibration Error (ECE) before/after, and writes the
fitted calibrator to JSON (loadable with TemperatureCalibrator.from_dict /
BinningCalibrator.from_dict). Use it to turn a raw score into an honest
confidence_bps: `TemperatureCalibrator.from_dict(json).confidence_bps(score)`.

Usage:
    python scripts/calibrate.py labeled.jsonl --method temperature --out calib.json
    python scripts/calibrate.py labeled.jsonl --method binning --bins 15

Pure-Python; no heavy deps. See docs/research/TRAINING_DATA.md for how to build
the held-out, in-domain labeled set this needs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from a checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from perathos.calibration import (  # noqa: E402
    BinningCalibrator,
    TemperatureCalibrator,
    expected_calibration_error,
)


def load_pairs(path: Path):
    scores, labels = [], []
    for i, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
            scores.append(float(rec["score"]))
            labels.append(int(rec["label"]))
        except (ValueError, KeyError, TypeError) as exc:
            raise SystemExit(f"line {i}: bad record ({exc}): {raw[:120]}")
    if not scores:
        raise SystemExit("no (score,label) pairs found")
    return scores, labels


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("data", type=Path, help="JSONL of {'score','label'} pairs")
    ap.add_argument("--method", choices=["temperature", "binning"], default="temperature")
    ap.add_argument("--bins", type=int, default=10, help="bins for binning / ECE")
    ap.add_argument("--out", type=Path, default=None, help="write fitted calibrator JSON")
    args = ap.parse_args()

    scores, labels = load_pairs(args.data)
    n = len(scores)
    before = expected_calibration_error(scores, labels, args.bins)

    if args.method == "temperature":
        cal = TemperatureCalibrator().fit(scores, labels)
        detail = f"temperature T={cal.temperature:.4f}"
    else:
        cal = BinningCalibrator(n_bins=args.bins).fit(scores, labels)
        detail = f"binning n_bins={args.bins}"

    after = expected_calibration_error([cal.calibrate(s) for s in scores], labels, args.bins)

    print(f"samples           : {n}")
    print(f"method            : {detail}")
    print(f"ECE before        : {before:.4f}")
    print(f"ECE after         : {after:.4f}")
    print(f"improvement       : {before - after:+.4f}")
    print(f"example: score 0.90 -> {cal.confidence_bps(0.90)} bps (calibrated)")

    if args.out:
        args.out.write_text(json.dumps(cal.to_dict(), indent=2), encoding="utf-8")
        print(f"saved calibrator  : {args.out}")


if __name__ == "__main__":
    main()
