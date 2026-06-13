"""The Check abstraction and the ``@check`` decorator.

A check is metadata plus a pure-ish function ``fn(ctx) -> Outcome``. Wrapping a
function rather than subclassing per control keeps the ~hundreds of checks
compact and uniform while the framework owns the cross-cutting concerns:
applicability filtering, timing, and turning any exception into a clean
``ERROR`` result instead of crashing a scan that may have taken minutes.

Authoring a check looks like::

    @check(
        id="1.5.1",
        title="Ensure ASLR is enabled",
        section="1.5 Process Hardening",
        severity=Severity.MEDIUM,
        levels=(Level.L1,),
    )
    def aslr_enabled(ctx):
        val = ctx.sysctl("kernel.randomize_va_space")
        if val == "2":
            return Outcome.passed(f"ASLR fully enabled (={val})", actual=val, expected="2")
        return Outcome.failed(f"ASLR not fully enabled (={val})", actual=val, expected="2")
"""

from __future__ import annotations

import time
import traceback
from typing import TYPE_CHECKING, Callable, Optional, Sequence

from .model import (
    CheckMetadata,
    CheckResult,
    Confidence,
    Level,
    Outcome,
    Profile,
    ProfileTarget,
    Severity,
    Status,
)

if TYPE_CHECKING:  # avoid an import cycle; ctx is duck-typed at runtime
    from ..system.context import SystemContext

CheckFn = Callable[["SystemContext"], Outcome]


class Check:
    """A runnable check: static metadata bound to an evaluation function."""

    __slots__ = ("metadata", "_fn")

    def __init__(self, metadata: CheckMetadata, fn: CheckFn) -> None:
        self.metadata = metadata
        self._fn = fn

    @property
    def id(self) -> str:
        return self.metadata.id

    def applies_to(self, target: ProfileTarget, ctx: "SystemContext") -> bool:
        """Whether this check should run for the given target and host.

        Two gates, both must pass:
        - **scope** — the target's level/role is in the check's declared range
          (``ProfileTarget.includes``);
        - **platform** — if the check pins ``platforms`` tokens, the host must
          match one (``system.platform.platform_matches``). An empty ``platforms``
          means portable: it runs on every Linux. Version-pinned tokens
          ("ubuntu:24.04") are further narrowed to the host's *active* benchmark
          edition by the runner, but a single check simply asks "does this host
          match my tokens at all?" here.
        """
        if not target.includes(self.metadata.levels, self.metadata.profiles):
            return False
        if self.metadata.platforms:
            from ..system.platform import platform_matches
            if not platform_matches(self.metadata.platforms, ctx.platform):
                return False
        return True

    def run(self, ctx: "SystemContext") -> CheckResult:
        """Evaluate the check, never raising. Exceptions become ERROR results.

        A single misbehaving check must not abort a long scan, so everything
        from the author's function is contained here and surfaced as an error
        with a captured traceback for debugging.
        """
        start = time.perf_counter()
        try:
            outcome = self._fn(ctx)
            if outcome is None:  # tolerate a check that forgot to return
                outcome = Outcome(
                    Status.ERROR, "Check returned no outcome", confidence=Confidence.CERTAIN
                )
            if not isinstance(outcome, Outcome):
                outcome = Outcome(Status.ERROR, f"Check returned {type(outcome).__name__}, not Outcome")
            result = CheckResult(
                metadata=self.metadata,
                status=outcome.status,
                summary=outcome.summary,
                evidence=list(outcome.evidence),
                actual=outcome.actual,
                expected=outcome.expected,
                confidence=outcome.confidence,
                host=ctx.host,
            )
        except Exception as exc:  # noqa: BLE001 - intentional catch-all boundary
            result = CheckResult(
                metadata=self.metadata,
                status=Status.ERROR,
                summary=f"Check raised {type(exc).__name__}: {exc}",
                error=traceback.format_exc(limit=6),
                host=ctx.host,
            )
        result.duration_ms = (time.perf_counter() - start) * 1000.0
        return result

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Check {self.metadata.id} {self.metadata.title!r}>"


def check(
    *,
    id: str,
    title: str,
    section: str,
    severity: Severity = Severity.MEDIUM,
    levels: Sequence[Level] = (Level.L1, Level.L2),
    profiles: Sequence[Profile] = (Profile.SERVER, Profile.WORKSTATION),
    description: str = "",
    rationale: str = "",
    remediation: str = "",
    automated: bool = True,
    framework: str = "CIS",
    references: Sequence[str] = (),
    tags: Sequence[str] = (),
    attack: Sequence[str] = (),
    platforms: Sequence[str] = (),
    register: bool = True,
) -> Callable[[CheckFn], Check]:
    """Decorator that turns an evaluation function into a registered Check.

    Normalizes the loosely-typed authoring inputs (a bare ``Level`` instead of
    a tuple, a string severity) so check definitions can stay terse without
    sacrificing the strong types the rest of the framework relies on.
    """

    def decorator(fn: CheckFn) -> Check:
        metadata = CheckMetadata(
            id=id,
            title=title,
            section=section,
            severity=Severity.parse(severity),
            levels=_as_tuple(levels, Level),
            profiles=_as_tuple(profiles, Profile),
            description=_clean(description) or _clean(fn.__doc__ or ""),
            rationale=_clean(rationale),
            remediation=_clean(remediation),
            automated=automated,
            framework=framework,
            references=tuple(references),
            tags=tuple(tags),
            attack=tuple(attack),
            platforms=tuple(platforms),
        )
        instance = Check(metadata, fn)
        if register:
            # Imported lazily to avoid a module-load cycle (registry imports
            # nothing from here, but keeping the edge one-directional is safer).
            from .registry import registry as _registry

            _registry.add(instance)
        return instance

    return decorator


def _as_tuple(value, kind):
    if isinstance(value, kind):
        return (value,)
    return tuple(value)


def _clean(text: Optional[str]) -> str:
    if not text:
        return ""
    # Collapse the leading indentation common in triple-quoted docstrings so
    # auto-derived descriptions render cleanly in reports.
    lines = [ln.strip() for ln in text.strip().splitlines()]
    return "\n".join(lines).strip()
