"""The data model shared by every layer.

These types are intentionally plain: enums and frozen-ish dataclasses with
``to_dict`` / ``from_dict`` round-tripping so the persistence and reporting
layers never need to know how a check produced a result. Keeping the model
free of behaviour (no system access, no I/O) is what lets the same objects be
serialized to a results store and rehydrated for trend analysis.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any, Dict, List, Optional, Sequence


class Status(enum.Enum):
    """Outcome of a single check evaluation.

    The distinction between ``ERROR`` (we tried and could not determine the
    answer) and ``SKIP`` (the check does not apply here) matters: errors are a
    tooling problem to investigate, skips are expected and benign. ``MANUAL``
    flags controls the benchmark itself marks as requiring human judgement.
    """

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    MANUAL = "manual"
    SKIP = "skip"
    ERROR = "error"
    INFO = "info"

    @property
    def is_compliant(self) -> bool:
        """Whether this status counts toward the compliance numerator."""
        return self is Status.PASS

    @property
    def is_scored(self) -> bool:
        """Whether this status participates in the compliance denominator.

        Skips, manual reviews, informational notes and tooling errors are
        excluded so they neither inflate nor deflate the percentage.
        """
        return self in (Status.PASS, Status.FAIL, Status.WARN)


class Severity(enum.IntEnum):
    """Impact ranking, ordered so comparisons and sorting work naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown severity: {value!r}") from exc


class Confidence(enum.IntEnum):
    """How sure the check is about a finding.

    Feeds risk scoring: a high-severity finding from a low-confidence heuristic
    should not outrank a medium-severity certainty. Deterministic CIS controls
    are ``CERTAIN``; entropy/anomaly heuristics are ``LIKELY`` or ``POSSIBLE``.
    """

    POSSIBLE = 1
    LIKELY = 2
    CERTAIN = 3


class Level(enum.IntEnum):
    """CIS profile hardening level."""

    L1 = 1
    L2 = 2


class Profile(enum.Enum):
    """System role the benchmark is being evaluated against."""

    SERVER = "server"
    WORKSTATION = "workstation"

    @classmethod
    def parse(cls, value: Any) -> "Profile":
        if isinstance(value, cls):
            return value
        return cls(str(value).strip().lower())


@dataclasses.dataclass(frozen=True)
class ProfileTarget:
    """The (role, level) pair a scan is run against, e.g. L1 Server.

    A check is in-scope when the target's level is >= the check's minimum level
    and the target's role is among the check's applicable profiles.
    """

    profile: Profile
    level: Level

    def includes(self, levels: Sequence[Level], profiles: Sequence[Profile]) -> bool:
        # L2 is a superset of L1: a control tagged for L1 is also evaluated at
        # L2. So the target is in-scope when its level meets the check's lowest
        # required level and its role is one the check applies to.
        level_ok = self.level >= min(levels)
        profile_ok = self.profile in profiles
        return level_ok and profile_ok

    def __str__(self) -> str:
        return f"L{self.level.value} {self.profile.value.capitalize()}"


@dataclasses.dataclass(frozen=True)
class CheckMetadata:
    """Everything static about a check — its identity and how to act on it.

    Separated from the runtime :class:`CheckResult` so the catalogue can be
    introspected, filtered and listed without running anything.
    """

    id: str
    title: str
    section: str
    severity: Severity = Severity.MEDIUM
    levels: Sequence[Level] = (Level.L1, Level.L2)
    profiles: Sequence[Profile] = (Profile.SERVER, Profile.WORKSTATION)
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    automated: bool = True
    framework: str = "CIS"
    references: Sequence[str] = ()
    tags: Sequence[str] = ()
    #: Explicit MITRE ATT&CK technique ids (e.g. "T1548.001"). When empty, an
    #: id is derived from the check's tags (see analysis.attack.attack_ids).
    attack: Sequence[str] = ()
    #: Platform applicability tokens (OR-matched). Empty = portable (every Linux).
    #: Tokens: a distro id ("ubuntu", "debian", "rhel"); a family ("debian-family",
    #: "rhel-family"); or a version-pinned edition ("ubuntu:24.04", "rhel:9",
    #: "debian:12" — version is matched as a prefix). See system.platform.platform_matches.
    platforms: Sequence[str] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "section": self.section,
            "severity": self.severity.name,
            "levels": [lv.value for lv in self.levels],
            "profiles": [p.value for p in self.profiles],
            "description": self.description,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "automated": self.automated,
            "framework": self.framework,
            "references": list(self.references),
            "tags": list(self.tags),
            "attack": list(self.attack),
            "platforms": list(self.platforms),
        }


@dataclasses.dataclass
class Outcome:
    """What a check function returns: a verdict plus supporting evidence.

    Lightweight by design — checks build these inline. The runner enriches an
    Outcome with metadata and timing to produce the persisted CheckResult.
    """

    status: Status
    summary: str = ""
    evidence: List[str] = dataclasses.field(default_factory=list)
    actual: Any = None
    expected: Any = None
    confidence: Confidence = Confidence.CERTAIN

    @classmethod
    def passed(cls, summary: str = "Compliant", **kw: Any) -> "Outcome":
        return cls(Status.PASS, summary, **kw)

    @classmethod
    def failed(cls, summary: str, **kw: Any) -> "Outcome":
        return cls(Status.FAIL, summary, **kw)

    @classmethod
    def warn(cls, summary: str, **kw: Any) -> "Outcome":
        return cls(Status.WARN, summary, **kw)

    @classmethod
    def manual(cls, summary: str, **kw: Any) -> "Outcome":
        return cls(Status.MANUAL, summary, **kw)

    @classmethod
    def skip(cls, summary: str, **kw: Any) -> "Outcome":
        return cls(Status.SKIP, summary, **kw)

    @classmethod
    def info(cls, summary: str, **kw: Any) -> "Outcome":
        return cls(Status.INFO, summary, **kw)

    def add_evidence(self, *lines: str) -> "Outcome":
        self.evidence.extend(l for l in lines if l)
        return self


@dataclasses.dataclass
class CheckResult:
    """A single evaluated check, ready to persist or render."""

    metadata: CheckMetadata
    status: Status
    summary: str = ""
    evidence: List[str] = dataclasses.field(default_factory=list)
    actual: Any = None
    expected: Any = None
    confidence: Confidence = Confidence.CERTAIN
    duration_ms: float = 0.0
    error: Optional[str] = None
    risk_score: float = 0.0
    host: str = "localhost"
    # Report-time overlay (set when a suppression matches; never persisted to
    # the scan record — the raw scan stays immutable truth).
    suppressed: bool = False
    suppression_kind: str = ""
    suppression_reason: str = ""

    @property
    def id(self) -> str:
        return self.metadata.id

    @property
    def severity(self) -> Severity:
        return self.metadata.severity

    @property
    def is_finding(self) -> bool:
        """A finding is anything that should draw a reviewer's attention."""
        return self.status in (Status.FAIL, Status.WARN)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "status": self.status.value,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "actual": _jsonable(self.actual),
            "expected": _jsonable(self.expected),
            "confidence": self.confidence.value,
            "duration_ms": round(self.duration_ms, 3),
            "error": self.error,
            "risk_score": round(self.risk_score, 4),
            "host": self.host,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckResult":
        md = data["metadata"]
        metadata = CheckMetadata(
            id=md["id"],
            title=md["title"],
            section=md["section"],
            severity=Severity[md["severity"]],
            levels=tuple(Level(v) for v in md.get("levels", [1, 2])),
            profiles=tuple(Profile(v) for v in md.get("profiles", ["server", "workstation"])),
            description=md.get("description", ""),
            rationale=md.get("rationale", ""),
            remediation=md.get("remediation", ""),
            automated=md.get("automated", True),
            framework=md.get("framework", "CIS"),
            references=tuple(md.get("references", ())),
            tags=tuple(md.get("tags", ())),
            attack=tuple(md.get("attack", ())),
            platforms=tuple(md.get("platforms", ())),
        )
        return cls(
            metadata=metadata,
            status=Status(data["status"]),
            summary=data.get("summary", ""),
            evidence=list(data.get("evidence", [])),
            actual=data.get("actual"),
            expected=data.get("expected"),
            confidence=Confidence(data.get("confidence", Confidence.CERTAIN.value)),
            duration_ms=data.get("duration_ms", 0.0),
            error=data.get("error"),
            risk_score=data.get("risk_score", 0.0),
            host=data.get("host", "localhost"),
        )


@dataclasses.dataclass
class ScanResult:
    """The full output of one scan run across one host.

    Carries enough metadata (target, host facts, timestamps, the partial-run
    marker) for the persistence layer to support resume and the analysis layer
    to compute trends. Aggregate metrics are computed lazily from ``results``
    so they never drift out of sync with the underlying findings.
    """

    scan_id: str
    host: str
    target: ProfileTarget
    started_at: str
    finished_at: Optional[str] = None
    results: List[CheckResult] = dataclasses.field(default_factory=list)
    host_facts: Dict[str, Any] = dataclasses.field(default_factory=dict)
    completed: bool = False
    tool_version: str = ""

    # ---- aggregate views (computed, never stored as source of truth) -------

    def counts(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Status}
        for r in self.results:
            out[r.status.value] += 1
        return out

    @property
    def scored(self) -> List[CheckResult]:
        return [r for r in self.results if r.status.is_scored]

    @property
    def passed(self) -> List[CheckResult]:
        return [r for r in self.results if r.status is Status.PASS]

    @property
    def findings(self) -> List[CheckResult]:
        return [r for r in self.results if r.is_finding]

    def compliance_score(self) -> float:
        """Percentage of scored controls that pass (0–100)."""
        scored = self.scored
        if not scored:
            return 0.0
        return 100.0 * sum(1 for r in scored if r.status.is_compliant) / len(scored)

    def total_risk(self) -> float:
        return sum(r.risk_score for r in self.results)

    def by_section(self) -> Dict[str, List[CheckResult]]:
        out: Dict[str, List[CheckResult]] = {}
        for r in self.results:
            out.setdefault(r.metadata.section, []).append(r)
        return out

    def completed_ids(self) -> set:
        return {r.id for r in self.results}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "host": self.host,
            "target": {"profile": self.target.profile.value, "level": self.target.level.value},
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "completed": self.completed,
            "tool_version": self.tool_version,
            "host_facts": self.host_facts,
            "results": [r.to_dict() for r in self.results],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        tgt = data["target"]
        return cls(
            scan_id=data["scan_id"],
            host=data["host"],
            target=ProfileTarget(Profile(tgt["profile"]), Level(tgt["level"])),
            started_at=data["started_at"],
            finished_at=data.get("finished_at"),
            completed=data.get("completed", False),
            tool_version=data.get("tool_version", ""),
            host_facts=data.get("host_facts", {}),
            results=[CheckResult.from_dict(r) for r in data.get("results", [])],
        )


def _jsonable(value: Any) -> Any:
    """Coerce check-supplied actual/expected values into JSON-safe forms."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, enum.Enum):
        return value.value
    return str(value)
