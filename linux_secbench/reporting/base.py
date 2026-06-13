"""The shared report bundle and the Reporter interface.

A :class:`ReportBundle` is the scan plus everything the analysis layer derives
from it — posture, the ranked work-list, the Pareto breakdown, and (when scan
history is available) the trend series and any regression flag. Computing it
once and handing the same bundle to every renderer is what keeps the formats
consistent and the renderers dumb (they format, they do not analyse).
"""

from __future__ import annotations

import abc
import dataclasses
import datetime as _dt
from typing import List, Optional, Sequence

from ..core.model import CheckResult, ScanResult, Status
from ..analysis.risk import RiskScorer
from ..analysis.trends import ParetoItem, TrendAnalyzer, TrendPoint, pareto
from ..analysis.attack import AttackTarget, attacker_targets
from ..analysis.attack_graph import AttackGraphAnalysis, analyze as analyze_attack_graph
from ..analysis.bayes import CompromiseEstimate, compromise_estimate

# Attacker tactics that belong to the *foothold* lens of the report. Only genuine
# initial access; credential access presupposes a shell, so it falls to the
# escalation lens (base.py derives that as everything not in this set).
_FOOTHOLD_TACTICS = {"initial_access"}


_DISTRO_LABEL = {"ubuntu": "Ubuntu", "debian": "Debian", "rhel": "RHEL"}


def benchmark_note(facts: dict) -> str:
    """A one-line, plain-text statement of which CIS benchmark applied.

    Reads the ``benchmark`` descriptor ({os, line, version, exact}) baked into the
    scan's host_facts by the runner. Falls back to the legacy ``cis_supported``
    flag for scans recorded before editions existed. Returns "" when the host maps
    to a benchmark exactly (no caveat needed).
    """
    bm = facts.get("benchmark")
    if isinstance(bm, dict):
        label = _DISTRO_LABEL.get(bm.get("line"), str(bm.get("line", "")).upper())
        if bm.get("exact"):
            return ""  # exact match — nothing to caveat
        hostver = facts.get("version_id", "?")
        return (f"CIS mapping approximate — nearest benchmark is {label} {bm.get('version')}, "
                f"host is {bm.get('os', '?')} {hostver}")
    # Legacy scans (pre-editions): keep the old Ubuntu-only caveat.
    if not facts.get("cis_supported"):
        return "CIS mapping approximate — host is not a covered benchmark edition"
    return ""


def _scope_summary(scorer: RiskScorer, results: List[CheckResult]) -> dict:
    """Posture + counts for a subset of results (used per framework scope)."""
    posture = scorer.posture(results)
    counts = {s.value: 0 for s in Status}
    for r in results:
        counts[r.status.value] += 1
    return {**posture, "counts": counts, "total": len(results)}


@dataclasses.dataclass
class ReportBundle:
    """Everything a renderer needs, precomputed and analysis-complete."""

    scan: ScanResult
    posture: dict
    ranked: List[CheckResult]
    attack_targets: List[AttackTarget]
    foothold_targets: List[AttackTarget]
    escalation_targets: List[AttackTarget]
    attack_graph: AttackGraphAnalysis
    compromise: CompromiseEstimate
    pareto_sections: List[ParetoItem]
    trend_points: List[TrendPoint]
    regression: Optional[dict]
    changepoints: List[dict]
    generated_at: str
    suppressed: List[CheckResult] = dataclasses.field(default_factory=list)
    scope_summaries: dict = dataclasses.field(default_factory=dict)

    @property
    def host(self) -> str:
        return self.scan.host


def build_bundle(
    scan: ScanResult,
    history: Optional[Sequence[ScanResult]] = None,
    scorer: Optional[RiskScorer] = None,
    generated_at: Optional[str] = None,
    suppressions=None,
) -> ReportBundle:
    """Assemble a ReportBundle, running all analysis exactly once.

    ``history`` is the host's prior scans oldest-first for trend/regression.
    ``suppressions`` is an optional SuppressionStore: matching findings are
    tagged and excluded from scoring/analysis (an overlay — the raw ``scan`` is
    never modified in place beyond the transient suppressed flag), and surfaced
    in their own section. ``generated_at`` is injectable for deterministic tests.
    """
    scorer = scorer or RiskScorer()
    for r in scan.results:
        if r.is_finding and r.risk_score == 0.0:
            r.risk_score = scorer.score(r)

    # Apply the suppression overlay: tag matches, partition active vs suppressed.
    suppressed: List[CheckResult] = []
    active: List[CheckResult] = []
    for r in scan.results:
        sup = suppressions.match(r.id, r.host) if suppressions is not None else None
        if sup is not None and r.is_finding:
            r.suppressed = True
            r.suppression_kind = sup.kind
            r.suppression_reason = sup.reason
            suppressed.append(r)
        else:
            active.append(r)

    # All analysis runs on the ACTIVE set. Build a scan view over it so the
    # attack graph / compromise estimate (which take a ScanResult) see only
    # active findings; the original scan record is untouched.
    active_scan = dataclasses.replace(scan, results=active)

    hist = list(history or [])
    if not hist or hist[-1].scan_id != scan.scan_id:
        hist = hist + [scan]

    analyzer = TrendAnalyzer()
    ranked = scorer.ranked_findings(active)
    all_targets = attacker_targets(active, limit=40)
    foothold = [t for t in all_targets if t.tactic_key in _FOOTHOLD_TACTICS][:10]
    escalation = [t for t in all_targets if t.tactic_key not in _FOOTHOLD_TACTICS][:10]

    # Per-scope summaries (composite + each framework) over the active set, for
    # the report's client-side scope selector.
    frameworks = sorted({r.metadata.framework for r in active})
    scope_summaries = {"All": _scope_summary(scorer, active)}
    for fw in frameworks:
        scope_summaries[fw] = _scope_summary(scorer, [r for r in active if r.metadata.framework == fw])

    return ReportBundle(
        scan=scan,
        posture=scorer.posture(active),
        ranked=ranked,
        attack_targets=all_targets[:10],
        foothold_targets=foothold,
        escalation_targets=escalation,
        attack_graph=analyze_attack_graph(active_scan),
        compromise=compromise_estimate(active_scan),
        pareto_sections=pareto(active, key="section"),
        trend_points=analyzer.series(hist),
        regression=analyzer.detect_regression(hist),
        changepoints=analyzer.detect_changepoints(hist),
        generated_at=generated_at or _dt.datetime.now().replace(microsecond=0).isoformat(),
        suppressed=suppressed,
        scope_summaries=scope_summaries,
    )


class Reporter(abc.ABC):
    """Renders a ReportBundle to a string (and optionally writes a file)."""

    #: Default file extension for this format.
    extension: str = "txt"
    #: Whether this format is meant for a terminal (affects CLI default).
    interactive: bool = False

    @abc.abstractmethod
    def render(self, bundle: ReportBundle) -> str:
        ...

    def write(self, bundle: ReportBundle, path: str) -> str:
        content = self.render(bundle)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path
