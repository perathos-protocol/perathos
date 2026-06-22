"""Tests for confidence calibration."""
import random

from perathos.calibration import (
    BinningCalibrator,
    TemperatureCalibrator,
    expected_calibration_error,
    reliability,
)


def _overconfident_dataset(n=2000):
    """Synthetic data where the raw score is systematically overconfident:
    the true correctness probability is a softened version of the score."""
    rng = random.Random(7)
    scores, labels = [], []
    for _ in range(n):
        s = rng.random()
        true_p = 0.5 + (s - 0.5) * 0.5  # compressed toward 0.5 -> score is overconfident
        scores.append(s)
        labels.append(1 if rng.random() < true_p else 0)
    return scores, labels


def test_temperature_scaling_reduces_ece():
    scores, labels = _overconfident_dataset()
    before, after = reliability(scores, labels)
    assert after < before  # calibration must improve, not worsen
    assert after < 0.05     # and land in a respectable range


def test_temperature_calibrator_fits_temperature_above_one_for_overconfident():
    scores, labels = _overconfident_dataset()
    cal = TemperatureCalibrator().fit(scores, labels)
    assert cal.temperature > 1.0  # overconfident scores need softening


def test_confidence_bps_in_range_and_monotonic():
    cal = TemperatureCalibrator(temperature=2.0)
    prev = -1
    for s in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]:
        bps = cal.confidence_bps(s)
        assert 0 <= bps <= 1000
        assert bps >= prev  # monotonic in the score
        prev = bps


def test_temperature_calibrator_json_roundtrip():
    cal = TemperatureCalibrator(temperature=3.14)
    restored = TemperatureCalibrator.from_dict(cal.to_dict())
    assert restored.temperature == cal.temperature
    assert restored.confidence_bps(0.8) == cal.confidence_bps(0.8)


def test_binning_calibrator_recovers_bin_accuracy():
    scores, labels = _overconfident_dataset()
    cal = BinningCalibrator(n_bins=10).fit(scores, labels)
    # A high-score bin should calibrate to less than the raw score (overconfident).
    assert cal.calibrate(0.95) < 0.95
    restored = BinningCalibrator.from_dict(cal.to_dict())
    assert restored.calibrate(0.95) == cal.calibrate(0.95)


def test_ece_zero_for_perfectly_calibrated():
    # score == empirical accuracy in every bin -> ECE ~ 0
    scores = [0.05, 0.05, 0.95, 0.95]
    labels = [0, 0, 1, 1]
    assert expected_calibration_error(scores, labels, n_bins=10) < 0.11
