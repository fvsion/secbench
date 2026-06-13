"""Cross-scan trend analysis and Pareto prioritization.

Two questions a single scan cannot answer:

1. *Is the host drifting?* Re-scanned over time, compliance should hold or
   climb. A quiet regression — someone loosened a permission, a package
   downgrade re-enabled a service — shows up as downward drift. We borrow the
   EWMA + control-chart approach from statistical process control: smooth the
   history, then flag the latest point if it falls below a control limit
   derived from the series' own variability (not an arbitrary constant).

2. *Where is the risk concentrated?* The Pareto principle (the vital few vs the
   trivial many) almost always holds for findings: a small number of sections
   carry most of the risk. Ranking sections by cumulative risk tells an
   operator where remediation effort buys the most posture.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional, Sequence

from ..core.model import CheckResult, ScanResult
from .statistics import bocpd, cusum, ewma, median, median_absolute_deviation


@dataclasses.dataclass
class TrendPoint:
    """One historical data point in the compliance/risk time series."""

    scan_id: str
    timestamp: str
    compliance: float
    total_risk: float
    findings: int
    ewma_compliance: float = 0.0


@dataclasses.dataclass
class ParetoItem:
    """A section and its share of total risk, with running cumulative share."""

    label: str
    risk: float
    findings: int
    share: float          # this item's fraction of total risk (0–1)
    cumulative: float     # cumulative fraction including this item (0–1)
    is_vital_few: bool    # within the ~80% cumulative-risk cohort


class TrendAnalyzer:
    """Builds a smoothed time series from scan history and detects drift."""

    def __init__(self, alpha: float = 0.4, sensitivity: float = 3.0) -> None:
        #: EWMA responsiveness.
        self.alpha = alpha
        #: How many robust deviations below the median counts as a regression.
        self.sensitivity = sensitivity

    def series(self, history: Sequence[ScanResult]) -> List[TrendPoint]:
        """Chronological compliance/risk series with an EWMA overlay.

        ``history`` is expected oldest-first; callers that store newest-first
        should reverse before passing. The EWMA column lets a report draw the
        smoothed trend alongside the noisy raw points.
        """
        points = [
            TrendPoint(
                scan_id=s.scan_id,
                timestamp=s.finished_at or s.started_at,
                compliance=round(s.compliance_score(), 2),
                total_risk=round(s.total_risk(), 2),
                findings=len(s.findings),
            )
            for s in history
        ]
        if points:
            smoothed = ewma([p.compliance for p in points], alpha=self.alpha)
            for p, sm in zip(points, smoothed):
                p.ewma_compliance = round(sm, 2)
        return points

    def detect_regression(self, history: Sequence[ScanResult]) -> Optional[Dict[str, object]]:
        """Flag the latest scan if its compliance drifted abnormally low.

        Uses a robust lower control limit: median minus ``sensitivity`` × MAD
        of the *prior* points. Robust statistics are deliberate here — a couple
        of bad historical scans should not widen the band so far that a genuine
        regression hides inside it. Returns None when there is too little
        history or no regression.
        """
        if len(history) < 4:
            return None
        prior = [s.compliance_score() for s in history[:-1]]
        latest = history[-1].compliance_score()
        med = median(prior)
        mad = median_absolute_deviation(prior)
        # Scale MAD to a standard-deviation-equivalent (0.6745 factor).
        spread = (mad / 0.6745) if mad else 0.0
        lower_limit = med - self.sensitivity * spread
        if spread == 0.0:
            # No historical variation: any drop at all is a regression.
            regressed = latest < med
        else:
            regressed = latest < lower_limit
        if not regressed:
            return None
        return {
            "latest": round(latest, 2),
            "baseline_median": round(med, 2),
            "lower_control_limit": round(lower_limit, 2),
            "drop": round(med - latest, 2),
        }

    def detect_changepoints(self, history: Sequence[ScanResult]) -> List[Dict[str, object]]:
        """Flag points where compliance shifted down, using two complementary
        detectors.

        - **CUSUM** is best at a slow, steady erosion that never trips a single
          -scan limit but adds up over many rescans.
        - **BOCPD** is best at an abrupt drop to a new level, and adapts when
          there have been several changes over time.

        We run both and report each flagged scan once, noting which detector(s)
        raised it. Only *downward* moves are reported — a rise in compliance is
        good news, not a finding.
        """
        series = [s.compliance_score() for s in history]
        if len(series) < 4:
            return []
        flagged: Dict[int, set] = {}
        for idx in cusum(series):
            flagged.setdefault(idx, set()).add("CUSUM")
        for idx in bocpd(series):
            # Only keep BOCPD changes that are downward (compare short windows).
            before = series[max(0, idx - 2):idx] or [series[idx]]
            after = series[idx:idx + 2]
            if sum(after) / len(after) < sum(before) / len(before):
                flagged.setdefault(idx, set()).add("BOCPD")
        out: List[Dict[str, object]] = []
        for idx in sorted(flagged):
            out.append({
                "scan_id": history[idx].scan_id,
                "timestamp": history[idx].finished_at or history[idx].started_at,
                "compliance": round(series[idx], 2),
                "detectors": sorted(flagged[idx]),
            })
        return out


def pareto(results: Sequence[CheckResult], key: str = "section", cutoff: float = 0.8) -> List[ParetoItem]:
    """Rank groups of findings by risk share (Pareto / 80-20 analysis).

    ``key`` selects the grouping dimension ("section" or "framework"). The
    ``cutoff`` marks the "vital few": the smallest set of groups whose
    cumulative risk reaches the cutoff fraction. Those are where remediation
    effort pays off most.
    """
    buckets: Dict[str, Dict[str, float]] = {}
    for r in results:
        if not r.is_finding:
            continue
        label = r.metadata.section if key == "section" else r.metadata.framework
        b = buckets.setdefault(label, {"risk": 0.0, "findings": 0})
        b["risk"] += r.risk_score
        b["findings"] += 1

    total = sum(b["risk"] for b in buckets.values()) or 1.0
    ordered = sorted(buckets.items(), key=lambda kv: kv[1]["risk"], reverse=True)

    items: List[ParetoItem] = []
    cumulative = 0.0
    reached = False
    for label, b in ordered:
        share = b["risk"] / total
        cumulative += share
        # An item is part of the vital few if the cutoff had not yet been
        # reached *before* adding it.
        is_vital = not reached
        if cumulative >= cutoff:
            reached = True
        items.append(
            ParetoItem(
                label=label,
                risk=round(b["risk"], 2),
                findings=int(b["findings"]),
                share=round(share, 4),
                cumulative=round(cumulative, 4),
                is_vital_few=is_vital,
            )
        )
    return items
