"""Attacker-perspective prioritization — the "Top Penetration-Tester Targets".

The risk model in :mod:`risk` answers *what is most broken* (severity × status
× confidence). That is the right lens for remediation, but it is **not** how an
attacker prioritizes. A passwordless account or a readable private key is a
first move regardless of its CVSS-style severity, while a missing login banner
is a compliance fail with essentially zero offensive value.

This module re-ranks the same findings by **offensive value**: each is mapped
to an ATT&CK-style tactic (credential access, privilege escalation, exploitation
of unpatched code, initial access, …), weighted by how much that capability is
worth to an attacker, then scaled by exploitability (status × confidence ×
severity). The result is the list a red-teamer would actually work down.

Mapping is driven by the tags checks already carry, so it stays in sync as
checks are added without a second registry to maintain.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Sequence, Tuple

from ..core.model import CheckResult, Confidence, Severity, Status


@dataclasses.dataclass(frozen=True)
class Tactic:
    """An attacker objective, with how much it is worth and why."""

    key: str
    label: str       # display name (kill-chain / ATT&CK flavour)
    weight: float    # offensive value, 0–10
    framing: str     # one line: why an attacker prizes this class of weakness

    @property
    def attack_id(self) -> str:
        """The MITRE ATT&CK tactic id for this objective (TA00xx), or ''."""
        return _TACTIC_ATTACK.get(self.key, "")


# Ordered by attacker value. When a finding matches several tactics the
# highest-weight one wins — an attacker labels a target by its best use.
TACTICS: Dict[str, Tactic] = {
    "credential_access": Tactic(
        "credential_access", "Credential Access", 10.0,
        "Harvestable credentials — frequently reusable for direct access, lateral movement, or instant escalation."),
    "privilege_escalation": Tactic(
        "privilege_escalation", "Privilege Escalation", 9.0,
        "Turns a local foothold into root; the payoff step of most intrusions."),
    "exploitation": Tactic(
        "exploitation", "Vulnerable Software", 8.5,
        "Unpatched code is a known-exploit target needing no misconfiguration to abuse."),
    "initial_access": Tactic(
        "initial_access", "Initial Access", 8.0,
        "A network-reachable entry point an attacker can attack from outside."),
    "persistence": Tactic(
        "persistence", "Persistence", 6.0,
        "A foothold to survive reboots and regain entry after eviction."),
    "defense_evasion": Tactic(
        "defense_evasion", "Defense Evasion", 5.0,
        "Lets an intruder act and persist without being logged or detected."),
    "hardening": Tactic(
        "hardening", "Hardening Gap", 2.0,
        "Defense-in-depth weakness with limited standalone offensive value."),
}

# MITRE ATT&CK tactic id per attacker objective. Only the unambiguous ones are
# mapped; "exploitation" maps to Privilege Escalation (our exploitation tag is
# local/kernel patching) and "hardening" has no single tactic.
_TACTIC_ATTACK = {
    "credential_access": "TA0006",
    "privilege_escalation": "TA0004",
    "exploitation": "TA0004",
    "initial_access": "TA0001",
    "persistence": "TA0003",
    "defense_evasion": "TA0005",
}

# Conservative tag → ATT&CK *technique* mapping, used when a check does not
# declare explicit techniques. Derived from the check's security category, so it
# is honest (not a per-check guess) and covers the whole catalogue.
_TAG_ATTACK = {
    "services": ("T1046",), "attack-surface": ("T1046",),
    "cleartext": ("T1040",), "client": ("T1078",),
    "database": ("T1190",), "exposure": ("T1190",),
    "ssh": ("T1021.004",),
    "sudo": ("T1548.003",), "nopasswd": ("T1548.003",),
    "suid": ("T1548.001",), "capabilities": ("T1548",),
    "world-writable": ("T1574",), "sticky-bit": ("T1574",), "path": ("T1574.007",),
    "backdoor": ("T1136",), "uid": ("T1078",),
    "credentials": ("T1552.001",), "secrets": ("T1552.001",),
    "history": ("T1552.003",), "keys": ("T1552.004",), "proc": ("T1552",),
    "memory": ("T1003",), "mimipenguin": ("T1003",),
    "audit": ("T1562.001",), "auditd": ("T1562.001",), "logging": ("T1562.001",),
    "immutable": ("T1562.001",), "retention": ("T1562.001",),
    "firewall": ("T1562.004",), "default-deny": ("T1562.004",),
    "kernel-hardening": ("T1068",), "patching": ("T1068",),
    "updates": ("T1068",), "vulnerability": ("T1068",),
    "cron": ("T1053.003",),
    "brute-force": ("T1110",), "lockout": ("T1110",),
    "password-policy": ("T1110",), "password-aging": ("T1110",),
    "removable-media": ("T1091",), "usb": ("T1091",), "wireless": ("T1011.001",),
    "shortcuts": ("T1546",), "autostart": ("T1547",), "persistence": ("T1547",),
}

# Tag → tactic. A check's tags are matched against these sets; see _classify.
_TAG_TACTIC: List[Tuple[str, frozenset]] = [
    ("credential_access", frozenset({
        "credentials", "secrets", "keys", "mimipenguin", "history", "proc",
        "memory", "entropy", "password"})),
    ("privilege_escalation", frozenset({
        "backdoor", "suid", "nopasswd", "privilege", "capabilities",
        "world-writable", "sticky-bit", "path", "kernel-hardening", "uid"})),
    ("exploitation", frozenset({"patching", "updates", "vulnerability"})),
    ("initial_access", frozenset({
        "exposure", "attack-surface", "ssh", "firewall", "default-deny",
        "database", "brute-force", "wireless", "lockout"})),
    ("persistence", frozenset({"cron", "shell"})),
    ("defense_evasion", frozenset({
        "audit", "auditd", "immutable", "retention", "logging"})),
]

# How exploitable / actionable the finding is, by result status. Anything not
# here (PASS/SKIP/INFO/ERROR) is not a target.
_STATUS_FACTOR = {Status.FAIL: 1.0, Status.WARN: 0.6, Status.MANUAL: 0.35}

# Attackers chase even uncertain leads, so confidence is discounted more gently
# than in the remediation risk model.
_CONF_FACTOR = {Confidence.CERTAIN: 1.0, Confidence.LIKELY: 0.85, Confidence.POSSIBLE: 0.6}


@dataclasses.dataclass
class AttackTarget:
    """One finding viewed as an attacker objective, with its offensive value."""

    rank: int
    check_id: str
    title: str
    tactic: str          # human label
    tactic_key: str      # stable key for styling
    attacker_value: float
    severity: str
    status: str
    summary: str
    framing: str
    remediation: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "rank": self.rank,
            "check_id": self.check_id,
            "title": self.title,
            "tactic": self.tactic,
            "tactic_key": self.tactic_key,
            "attacker_value": self.attacker_value,
            "severity": self.severity,
            "status": self.status,
            "summary": self.summary,
            "framing": self.framing,
            "remediation": self.remediation,
        }


def attack_ids(result: CheckResult) -> tuple:
    """MITRE ATT&CK technique ids for a finding.

    Uses the check's explicit ``metadata.attack`` when set, otherwise derives a
    conservative set from its tags. Returns a de-duplicated, order-stable tuple.
    """
    if result.metadata.attack:
        return tuple(result.metadata.attack)
    out: list = []
    for tag in result.metadata.tags:
        for tech in _TAG_ATTACK.get(tag, ()):
            if tech not in out:
                out.append(tech)
    return tuple(out)


def _classify(result: CheckResult) -> Tactic:
    """Pick the highest-value tactic whose tag-set intersects the check's tags."""
    tags = set(result.metadata.tags)
    best: Tactic = TACTICS["hardening"]
    for key, tagset in _TAG_TACTIC:
        if tags & tagset:
            candidate = TACTICS[key]
            if candidate.weight > best.weight:
                best = candidate
    return best


def attacker_value(result: CheckResult, tactic: Tactic) -> float:
    """Offensive value = tactic worth × exploitability (status × conf × severity)."""
    sf = _STATUS_FACTOR.get(result.status, 0.0)
    if sf == 0.0:
        return 0.0
    cf = _CONF_FACTOR.get(result.confidence, 1.0)
    # Severity nudges value up to 1.5× (CRITICAL) without dominating the tactic.
    sev = 1.0 + result.severity.value / 8.0
    return round(tactic.weight * sf * cf * sev, 2)


def attacker_targets(results: Sequence[CheckResult], limit: int = 10) -> List[AttackTarget]:
    """Rank findings by offensive value and return the top ``limit`` targets.

    Only actionable results (fail/warn/manual) are eligible; passes and skips
    are not targets. Ties break toward higher severity so the more dangerous of
    two equally-scored targets surfaces first.
    """
    scored: List[Tuple[float, Tactic, CheckResult]] = []
    for r in results:
        if r.status not in _STATUS_FACTOR:
            continue
        tactic = _classify(r)
        value = attacker_value(r, tactic)
        if value <= 0.0:
            continue
        scored.append((value, tactic, r))

    scored.sort(key=lambda t: (t[0], t[2].severity.value), reverse=True)

    targets: List[AttackTarget] = []
    for i, (value, tactic, r) in enumerate(scored[:limit], start=1):
        targets.append(AttackTarget(
            rank=i,
            check_id=r.id,
            title=r.metadata.title,
            tactic=tactic.label,
            tactic_key=tactic.key,
            attacker_value=value,
            severity=r.severity.name,
            status=r.status.value,
            summary=r.summary,
            framing=tactic.framing,
            remediation=r.metadata.remediation,
        ))
    return targets
