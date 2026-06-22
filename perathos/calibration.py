"""Confidence calibration for verifier scores.

A verifier's raw score (e.g. an NLI entailment probability) is NOT the same as
the probability the verdict is correct. confidence_bps makes an honesty promise
— "0.8 means ~80% right" — and that promise has to be *fit and measured*, not
assumed. This module fits a mapping from raw score -> calibrated probability
using held-out labeled (score, correct) pairs, and reports Expected Calibration
Error (ECE) so the promise is testable.

Pure-Python (math only), no heavy dependencies, so it lives in the core package.
Persist with to_dict()/from_dict() and store the calibrator alongside the
verifier version that produced the scores.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Sequence, Tuple

_EPS = 1e-6


def _clamp01(p: float) -> float:
    return min(1.0 - _EPS, max(_EPS, p))


def expected_calibration_error(
    scores: Sequence[float], labels: Sequence[int], n_bins: int = 10
) -> float:
    """Binned ECE: weighted average gap between confidence and accuracy."""
    if not scores:
        return 0.0
    n = len(scores)
    total = 0.0
    for b in range(n_bins):
        lo, hi = b / n_bins, (b + 1) / n_bins
        idx = [i for i, s in enumerate(scores) if (s > lo or (b == 0 and s >= lo)) and s <= hi]
        if not idx:
            continue
        conf = sum(scores[i] for i in idx) / len(idx)
        acc = sum(labels[i] for i in idx) / len(idx)
        total += (len(idx) / n) * abs(conf - acc)
    return total


@dataclass
class TemperatureCalibrator:
    """One-parameter temperature scaling on the logit of a [0,1] score.

    calibrate(p) = sigmoid(logit(p) / T). T is fit by minimizing log-loss over
    labeled data via a 1-D ternary search. T>1 softens overconfident scores.
    """

    temperature: float = 1.0

    def calibrate(self, score: float) -> float:
        p = _clamp01(float(score))
        logit = math.log(p / (1.0 - p))
        return 1.0 / (1.0 + math.exp(-logit / self.temperature))

    def confidence_bps(self, score: float) -> int:
        return int(round(self.calibrate(score) * 1000))

    def _nll(self, scores: Sequence[float], labels: Sequence[int], t: float) -> float:
        total = 0.0
        for s, y in zip(scores, labels):
            p = _clamp01(self.__class__(temperature=t).calibrate(s))
            total += -(y * math.log(p) + (1 - y) * math.log(1.0 - p))
        return total / max(1, len(scores))

    def fit(self, scores: Sequence[float], labels: Sequence[int]) -> "TemperatureCalibrator":
        if not scores:
            return self
        lo, hi = 0.05, 20.0
        for _ in range(60):  # ternary search converges quickly on a convex-ish NLL
            m1 = lo + (hi - lo) / 3.0
            m2 = hi - (hi - lo) / 3.0
            if self._nll(scores, labels, m1) < self._nll(scores, labels, m2):
                hi = m2
            else:
                lo = m1
        self.temperature = (lo + hi) / 2.0
        return self

    def to_dict(self) -> dict:
        return {"method": "temperature", "temperature": self.temperature}

    @classmethod
    def from_dict(cls, d: dict) -> "TemperatureCalibrator":
        return cls(temperature=float(d["temperature"]))


@dataclass
class BinningCalibrator:
    """Reliability-binning calibrator: map a score to the empirical accuracy of
    its bin on the fit data. Isotonic-free, robust on small samples."""

    n_bins: int = 10
    bin_accuracy: List[float] = None  # type: ignore[assignment]

    def fit(self, scores: Sequence[float], labels: Sequence[int]) -> "BinningCalibrator":
        acc = []
        for b in range(self.n_bins):
            lo, hi = b / self.n_bins, (b + 1) / self.n_bins
            idx = [i for i, s in enumerate(scores) if (s > lo or (b == 0 and s >= lo)) and s <= hi]
            acc.append(sum(labels[i] for i in idx) / len(idx) if idx else (b + 0.5) / self.n_bins)
        self.bin_accuracy = acc
        return self

    def calibrate(self, score: float) -> float:
        if not self.bin_accuracy:
            return _clamp01(float(score))
        b = min(self.n_bins - 1, max(0, int(float(score) * self.n_bins)))
        return self.bin_accuracy[b]

    def confidence_bps(self, score: float) -> int:
        return int(round(self.calibrate(score) * 1000))

    def to_dict(self) -> dict:
        return {"method": "binning", "n_bins": self.n_bins, "bin_accuracy": self.bin_accuracy}

    @classmethod
    def from_dict(cls, d: dict) -> "BinningCalibrator":
        c = cls(n_bins=int(d["n_bins"]))
        c.bin_accuracy = list(d["bin_accuracy"])
        return c


def reliability(scores: Sequence[float], labels: Sequence[int], n_bins: int = 10) -> Tuple[float, float]:
    """Convenience: (ECE before, ECE after) temperature calibration on the data."""
    before = expected_calibration_error(scores, labels, n_bins)
    cal = TemperatureCalibrator().fit(scores, labels)
    after = expected_calibration_error([cal.calibrate(s) for s in scores], labels, n_bins)
    return before, after
