"""Analysis layer: risk scoring and cross-domain statistics.

Deliberately dependency-free (pure standard library) so the tool runs on a
minimal target with no pip install. The techniques are borrowed from fields
outside security because they solve problems the security domain shares:

* **Information theory** — Shannon entropy to tell a random secret from prose.
* **Robust statistics** — the median absolute deviation (astronomy/quality
  control) to flag anomalous accounts without being fooled by outliers the way
  a mean/stddev would be.
* **Quantitative finance / SPC** — an exponentially weighted moving average and
  a control-chart rule to detect compliance *drift* across rescans.
* **Economics** — Pareto (80/20) analysis to point remediation at the vital
  few sections carrying most of the risk.
"""

from __future__ import annotations

from .statistics import (
    shannon_entropy,
    normalized_entropy,
    median,
    median_absolute_deviation,
    modified_z_scores,
    ewma,
    cusum,
    bocpd,
)
from .risk import RiskModel, RiskScorer
from .trends import TrendAnalyzer, TrendPoint, ParetoItem, pareto
from .attack import AttackTarget, Tactic, TACTICS, attacker_targets, attack_ids
from .attack_graph import (
    AttackGraph,
    AttackGraphAnalysis,
    AttackPath,
    EscalationEdge,
    analyze as analyze_attack_graph,
)

__all__ = [
    "shannon_entropy",
    "normalized_entropy",
    "median",
    "median_absolute_deviation",
    "modified_z_scores",
    "ewma",
    "cusum",
    "bocpd",
    "RiskModel",
    "RiskScorer",
    "TrendAnalyzer",
    "TrendPoint",
    "ParetoItem",
    "pareto",
    "AttackTarget",
    "Tactic",
    "TACTICS",
    "attacker_targets",
    "attack_ids",
    "AttackGraph",
    "AttackGraphAnalysis",
    "AttackPath",
    "EscalationEdge",
    "analyze_attack_graph",
]
