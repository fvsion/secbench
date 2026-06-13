"""Unit tests for the analysis primitives (entropy, MAD, EWMA, Pareto, trends)."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from linux_secbench.analysis.statistics import (
    ewma, median, median_absolute_deviation, modified_z_scores,
    normalized_entropy, shannon_entropy,
)


def test_entropy_distinguishes_secret_from_prose():
    prose = "the quick brown fox jumps over the lazy dog"
    secret = "aZ3kP9xQ2mL7vB4nR8wT1yU6"
    assert normalized_entropy(secret) > normalized_entropy(prose)
    assert shannon_entropy("aaaaaaaa") == 0.0  # zero entropy: all identical


def test_mad_is_robust_to_outliers():
    data = [10, 11, 12, 11, 10, 12, 1000]  # one wild outlier
    mad = median_absolute_deviation(data)
    # MAD should stay small (~1) despite the 1000 — that is the whole point.
    assert mad < 5
    scores = modified_z_scores(data)
    # The outlier should be the only one flagged beyond 3.5.
    flagged = [abs(s) > 3.5 for s in scores]
    assert flagged == [False, False, False, False, False, False, True]


def test_ewma_tracks_and_smooths():
    series = [100, 100, 100, 50]  # a sudden drop
    smoothed = ewma(series, alpha=0.4)
    assert len(smoothed) == 4
    # Smoothed last point should sit between the prior level and the new value.
    assert 50 < smoothed[-1] < 100
    with pytest.raises(ValueError):
        ewma([1, 2], alpha=0)


def test_median_even_and_odd():
    assert median([3, 1, 2]) == 2
    assert median([4, 1, 3, 2]) == 2.5
    assert median([]) == 0.0


def test_bocpd_detects_shift_not_noise():
    from linux_secbench.analysis.statistics import bocpd
    assert bocpd([90, 91, 89, 90, 90, 91, 89, 90, 91]) == []      # steady → quiet
    assert bocpd([90, 91, 90, 89, 90, 70, 68, 69, 67, 70])         # abrupt drop → fires
    # The detected change should land at/after the actual drop (index 5).
    assert min(bocpd([95, 94, 96, 95, 94, 95, 96, 80, 78, 79])) >= 6


def test_noisy_or():
    from linux_secbench.analysis.bayes import noisy_or
    assert noisy_or([]) == 0.0
    assert noisy_or([1.0]) == 1.0
    # Two independent 0.5 chances → 0.75, and adding more never decreases it.
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert noisy_or([0.5, 0.5, 0.5]) > noisy_or([0.5, 0.5])


def test_dempster_shafer_fusion():
    from linux_secbench.analysis.evidence import combine, fuse_secret_signals
    # Corroborating clues raise belief above any single clue.
    b = fuse_secret_signals(secret_keyword=True, high_entropy=True, sensitive_location=True)
    assert b.is_secret()
    assert b.secret > 0.5
    # A placeholder signal pulls belief down (evidence against).
    weak = fuse_secret_signals(secret_keyword=True, looks_like_placeholder=True)
    assert weak.secret < b.secret
    # Empty evidence → pure uncertainty, not a finding.
    none = combine([])
    assert none.uncertain == 1.0 and not none.is_secret()


def test_pareto_marks_vital_few():
    from linux_secbench.analysis.trends import pareto
    from linux_secbench.core.model import (
        CheckMetadata, CheckResult, Severity, Status,
    )

    def finding(section, risk):
        md = CheckMetadata(id=section + "-x", title="t", section=section, severity=Severity.HIGH)
        r = CheckResult(metadata=md, status=Status.FAIL)
        r.risk_score = risk
        return r

    results = [finding("A", 80), finding("B", 15), finding("C", 5)]
    items = pareto(results, cutoff=0.8)
    labels = {i.label: i for i in items}
    assert labels["A"].is_vital_few          # 80% alone reaches the cutoff
    assert labels["A"].share == pytest.approx(0.8)
    assert items[0].label == "A"             # sorted by risk desc
