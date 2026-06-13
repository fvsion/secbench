"""Machine-readable JSON report — the canonical export for CI, diffing, and APIs."""

from __future__ import annotations

import json

from ..analysis.trends import ParetoItem, TrendPoint
from .base import ReportBundle, Reporter


class JsonReporter(Reporter):
    extension = "json"

    def render(self, bundle: ReportBundle) -> str:
        payload = {
            "generated_at": bundle.generated_at,
            "host": bundle.host,
            "target": str(bundle.scan.target),
            "posture": bundle.posture,
            "scan": bundle.scan.to_dict(),
            "attack_targets": [t.to_dict() for t in bundle.attack_targets],
            "compromise_estimate": bundle.compromise.to_dict() if bundle.compromise else None,
            "prevent_foothold": [t.to_dict() for t in bundle.foothold_targets],
            "prevent_escalation": [t.to_dict() for t in bundle.escalation_targets],
            "attack_graph": bundle.attack_graph.to_dict() if bundle.attack_graph else None,
            "ranked_finding_ids": [r.id for r in bundle.ranked],
            "pareto_sections": [_pareto_dict(p) for p in bundle.pareto_sections],
            "trend": [_trend_dict(t) for t in bundle.trend_points],
            "regression": bundle.regression,
            "changepoints": bundle.changepoints,
            "scope_summaries": bundle.scope_summaries,
            "suppressed": [
                {"id": r.id, "kind": r.suppression_kind, "reason": r.suppression_reason,
                 "title": r.metadata.title}
                for r in bundle.suppressed
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=False)


def _pareto_dict(p: ParetoItem) -> dict:
    return {
        "label": p.label, "risk": p.risk, "findings": p.findings,
        "share": p.share, "cumulative": p.cumulative, "vital_few": p.is_vital_few,
    }


def _trend_dict(t: TrendPoint) -> dict:
    return {
        "scan_id": t.scan_id, "timestamp": t.timestamp, "compliance": t.compliance,
        "total_risk": t.total_risk, "findings": t.findings, "ewma_compliance": t.ewma_compliance,
    }
