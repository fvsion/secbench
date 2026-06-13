"""Risk scoring — turning a pile of findings into a defensible priority order.

A raw pass/fail percentage treats a world-readable shadow file and a missing
MOTD banner as equal. They are not. The model here borrows the shape of CVSS
(severity bands that grow super-linearly) and the spirit of FAIR (risk is
likelihood × impact, not impact alone) to produce a per-finding score that:

* grows steeply with severity, so one CRITICAL outranks many LOWs;
* scales down by confidence, so a heuristic "possible" finding cannot outweigh
  a deterministic certainty;
* is zero for anything that is not actually a finding (pass/skip/info),

then aggregates into a posture grade an executive can read at a glance and a
ranked list an engineer can work top-down.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, Iterable, List

from ..core.model import CheckResult, Confidence, Severity, Status


@dataclasses.dataclass(frozen=True)
class RiskModel:
    """Tunable weights for the scoring function.

    Defaults are calibrated so the bands are visibly distinct (each step up in
    severity roughly doubles weight) without any single finding being able to
    dwarf the whole report. Exposed as data so an operator can re-weight for
    their environment without touching logic.
    """

    severity_weight: Dict[Severity, float] = dataclasses.field(
        default_factory=lambda: {
            Severity.INFO: 0.0,
            Severity.LOW: 1.0,
            Severity.MEDIUM: 4.0,
            Severity.HIGH: 8.0,
            Severity.CRITICAL: 16.0,
        }
    )
    status_factor: Dict[Status, float] = dataclasses.field(
        default_factory=lambda: {
            Status.FAIL: 1.0,
            Status.WARN: 0.5,
            # A MANUAL item carries residual, unquantified risk — small but
            # non-zero so it does not vanish from prioritization entirely.
            Status.MANUAL: 0.15,
        }
    )
    confidence_factor: Dict[Confidence, float] = dataclasses.field(
        default_factory=lambda: {
            Confidence.CERTAIN: 1.0,
            Confidence.LIKELY: 0.7,
            Confidence.POSSIBLE: 0.4,
        }
    )

    def finding_risk(self, result: CheckResult) -> float:
        sf = self.status_factor.get(result.status, 0.0)
        if sf == 0.0:
            return 0.0
        sev = self.severity_weight.get(result.severity, 0.0)
        cf = self.confidence_factor.get(result.confidence, 1.0)
        return round(sev * sf * cf, 4)

    def max_finding_risk(self) -> float:
        return max(self.severity_weight.values()) * max(self.status_factor.values())


class RiskScorer:
    """Applies a RiskModel to results and derives aggregate posture metrics."""

    #: Letter-grade cut-offs on the 0–100 posture score (inclusive lower bound).
    _GRADE_BANDS = [(95, "A"), (85, "B"), (75, "C"), (60, "D"), (0, "F")]

    def __init__(self, model: RiskModel = None) -> None:
        self.model = model or RiskModel()

    def score(self, result: CheckResult) -> float:
        """The score for a single finding — used as the runner's score_fn."""
        return self.model.finding_risk(result)

    def posture(self, results: Iterable[CheckResult]) -> Dict[str, object]:
        """Compute aggregate posture metrics over a set of scored results.

        The posture score blends compliance (how many controls pass) with the
        residual-risk burden (how bad the failures are), because two hosts can
        share a pass rate while one is failing only cosmetic controls and the
        other is failing critical ones. Returns a dict the reporters render.
        """
        results = list(results)
        scored = [r for r in results if r.status.is_scored]
        findings = [r for r in results if r.is_finding]

        compliance = (
            100.0 * sum(1 for r in scored if r.status.is_compliant) / len(scored)
            if scored else 0.0
        )
        total_risk = sum(self.model.finding_risk(r) for r in findings)

        # Normalize the risk burden against a worst-case ceiling (every scored
        # control failing at its own severity), so the penalty is comparable
        # across hosts of different size. Capped at 100.
        ceiling = sum(self.model.severity_weight.get(r.severity, 0.0) for r in scored) or 1.0
        risk_burden = min(100.0, 100.0 * total_risk / ceiling)

        # Posture = compliance discounted by how concentrated/severe the misses
        # are. A host passing 90% of controls but failing several criticals
        # should not score 90.
        posture_score = round(max(0.0, compliance - 0.5 * risk_burden), 1)

        return {
            "compliance": round(compliance, 1),
            "total_risk": round(total_risk, 2),
            "risk_burden": round(risk_burden, 1),
            "posture_score": posture_score,
            "grade": self._grade(posture_score),
            "findings": len(findings),
            "critical": sum(1 for r in findings if r.severity is Severity.CRITICAL),
            "high": sum(1 for r in findings if r.severity is Severity.HIGH),
        }

    def ranked_findings(self, results: Iterable[CheckResult]) -> List[CheckResult]:
        """Findings sorted by risk descending — the remediation work-list."""
        findings = [r for r in results if r.is_finding]
        for r in findings:
            if r.risk_score == 0.0:
                r.risk_score = self.model.finding_risk(r)
        return sorted(findings, key=lambda r: (r.risk_score, r.severity), reverse=True)

    def _grade(self, score: float) -> str:
        for threshold, letter in self._GRADE_BANDS:
            if score >= threshold:
                return letter
        return "F"
