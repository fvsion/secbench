"""Probabilistic compromise estimate (noisy-OR).

Adding up risk scores tells you *how bad* the findings are, but it does not
answer the question a defender actually asks: *how likely is it that this host
gets taken over?* Several independent weaknesses don't add — they each give the
attacker another roll of the dice. The right way to combine "any one of these
could work" is the **noisy-OR**: the chance none of them works is the product
of each one failing, so the chance at least one works is one minus that.

We split the estimate to match the two ways a host gets owned, which is also
the two-lens view the report shows:

* **P(foothold)** — the chance an attacker gets *onto* the box at all, combined
  over the entry weaknesses (exposed services, weak/empty credentials).
* **P(escalate)** — the chance that, *given* a foothold, they reach root,
  combined over the privilege-escalation weaknesses.
* **P(compromise)** = P(foothold) × P(escalate).

These are deliberately rough, calibrated probabilities meant for comparison and
trend, not a literal actuarial number — and the report says so.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Sequence

from ..core.model import CheckResult, Confidence, Severity, ScanResult, Status
from .attack import _classify

# Per-finding "chance this one weakness is exploitable" by severity. These are
# starting points an operator can tune, not measured frequencies.
_SEVERITY_PROB = {
    Severity.CRITICAL: 0.9,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.4,
    Severity.LOW: 0.15,
    Severity.INFO: 0.05,
}
_CONFIDENCE_SCALE = {Confidence.CERTAIN: 1.0, Confidence.LIKELY: 0.8, Confidence.POSSIBLE: 0.55}
_STATUS_SCALE = {Status.FAIL: 1.0, Status.WARN: 0.6, Status.MANUAL: 0.35}

# "Chance an attacker can get in" counts ONLY demonstrated, network-reachable
# entry weaknesses — a sensitive service exposed on a non-loopback socket
# (EXT-NET-1/2) or a remotely brute-forceable login. This is the same tag gate
# the attack graph uses for its attacker->local edge, so the two agree.
# Deliberately NOT counted as entry:
#   - Surface/hardening that merely *reduces* exposure (firewall, ufw, SSH
#     hardening, lockout policy) — valuable, but not a demonstrated way in.
#   - Local credential access (keys/secrets/history/in-memory creds) — it
#     presupposes a shell, so it counts under escalation/lateral movement.
from .attack_graph import _FOOTHOLD_TAGS  # {"exposure", "database", "brute-force"}

_ESCALATION_TACTICS = {"credential_access", "privilege_escalation", "exploitation",
                       "persistence", "defense_evasion"}


def noisy_or(probabilities: Sequence[float]) -> float:
    """Probability that at least one independent event occurs.

    1 − ∏(1 − p_i). Returns 0 for an empty list. Inputs are clamped to [0, 1].
    """
    prod = 1.0
    for p in probabilities:
        prod *= (1.0 - min(1.0, max(0.0, p)))
    return 1.0 - prod


def _finding_prob(r: CheckResult) -> float:
    base = _SEVERITY_PROB.get(r.severity, 0.1)
    return base * _CONFIDENCE_SCALE.get(r.confidence, 1.0) * _STATUS_SCALE.get(r.status, 0.0)


@dataclasses.dataclass
class CompromiseEstimate:
    foothold: float            # P(attacker gets onto the host)
    escalation: float          # P(reaches root | has a foothold)
    overall: float             # P(foothold) × P(escalation)
    foothold_assumed: bool     # True when no entry weakness was found
    foothold_drivers: int      # how many findings fed the foothold estimate
    escalation_drivers: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "foothold": round(self.foothold, 3),
            "escalation": round(self.escalation, 3),
            "overall": round(self.overall, 3),
            "foothold_assumed": self.foothold_assumed,
            "foothold_drivers": self.foothold_drivers,
            "escalation_drivers": self.escalation_drivers,
        }

    @staticmethod
    def pct(p: float) -> str:
        return f"{round(100 * p)}%"


def compromise_estimate(scan: ScanResult) -> CompromiseEstimate:
    """Combine findings into foothold / escalation / overall probabilities."""
    foothold_probs: List[float] = []
    escalation_probs: List[float] = []
    for r in scan.results:
        if r.status not in _STATUS_SCALE:
            continue
        if set(r.metadata.tags) & _FOOTHOLD_TAGS:
            foothold_probs.append(_finding_prob(r))      # demonstrated network entry
        elif _classify(r).key in _ESCALATION_TACTICS:
            escalation_probs.append(_finding_prob(r))     # post-foothold (privesc / cred access)

    foothold = noisy_or(foothold_probs)
    escalation = noisy_or(escalation_probs)

    # If nothing lets an attacker *in* was found, we don't claim the host is
    # unreachable — entry may come from phishing or an app we don't see. For the
    # "assume foothold" lens we treat getting a shell as a given.
    assumed = not foothold_probs
    foothold_for_overall = foothold if foothold_probs else 1.0

    return CompromiseEstimate(
        foothold=foothold,
        escalation=escalation,
        overall=foothold_for_overall * escalation,
        foothold_assumed=assumed,
        foothold_drivers=len(foothold_probs),
        escalation_drivers=len(escalation_probs),
    )
