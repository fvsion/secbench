"""The ScanRunner: turns a selection of checks into a ScanResult.

The runner owns execution policy — ordering, progress reporting, resume, and
applying the risk score — while delegating *what* a check does to the check
and *how* to reach the machine to the SystemContext. That separation is what
lets the same runner drive a local scan, an SSH scan, or a resumed scan with
no changes.
"""

from __future__ import annotations

import datetime as _dt
from typing import Callable, List, Optional, Sequence

from .. import __version__
from .check import Check
from .model import CheckResult, ProfileTarget, ScanResult, Status

# A progress callback receives (index, total, just-finished result).
ProgressCallback = Callable[[int, int, CheckResult], None]
# A scorer maps a finished result to a numeric risk score.
ScoreFn = Callable[[CheckResult], float]


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


class ScanRunner:
    """Executes checks against a context and assembles a ScanResult."""

    def __init__(
        self,
        ctx,
        target: ProfileTarget,
        score_fn: Optional[ScoreFn] = None,
        progress: Optional[ProgressCallback] = None,
    ) -> None:
        self._ctx = ctx
        self._target = target
        self._score_fn = score_fn
        self._progress = progress

    def run(
        self,
        checks: Sequence[Check],
        scan_id: str,
        resume_from: Optional[ScanResult] = None,
        checkpoint: Optional[Callable[[ScanResult], None]] = None,
        checkpoint_every: int = 15,
    ) -> ScanResult:
        """Run ``checks``, optionally resuming a prior partial scan.

        Resume is intentionally simple and safe: any check whose id already has
        a result in ``resume_from`` is carried over untouched and not re-run.
        That makes a resumed scan deterministic w.r.t. what was already done and
        lets an interrupted multi-minute scan pick up exactly where it stopped.
        """
        carried: List[CheckResult] = []
        done_ids = set()
        if resume_from is not None:
            carried = list(resume_from.results)
            done_ids = resume_from.completed_ids()

        scan = ScanResult(
            scan_id=scan_id,
            host=self._ctx.host,
            target=self._target,
            started_at=resume_from.started_at if resume_from else _utc_now_iso(),
            results=carried,
            host_facts=self._host_facts(),
            tool_version=__version__,
        )

        pending = [c for c in checks if c.id not in done_ids]
        total = len(pending)
        for index, chk in enumerate(pending, start=1):
            result = chk.run(self._ctx)
            if self._score_fn is not None:
                result.risk_score = self._score_fn(result)
            scan.results.append(result)
            if self._progress is not None:
                self._progress(index, total, result)
            # Persist-as-you-go: a checkpoint of the (still-incomplete) scan
            # every N checks means a kill -9 mid-scan leaves a resumable partial
            # on disk rather than losing minutes of work.
            if checkpoint is not None and index % max(1, checkpoint_every) == 0:
                checkpoint(scan)

        scan.completed = True
        scan.finished_at = _utc_now_iso()
        return scan

    def _host_facts(self) -> dict:
        """Platform facts plus the resolved CIS benchmark edition for this host.

        The ``benchmark`` descriptor ({os, line, version, exact}) is baked into the
        scan record so reports — including off-box re-renders — can state which
        edition applied (e.g. "CIS Ubuntu 24.04") and whether it was exact or the
        nearest approximation. Resolved from the full catalogue so it reflects the
        host's mapping regardless of any --sections/--ids filter.
        """
        facts = dict(self._ctx.facts())
        try:
            from .registry import registry
            from ..system.platform import available_editions, resolve_benchmark_edition
            edition = resolve_benchmark_edition(
                self._ctx.platform, available_editions(c.metadata for c in registry.all()))
            if edition:
                facts["benchmark"] = edition
        except Exception:
            pass  # facts are best-effort; never fail a scan over the banner
        return facts

    @staticmethod
    def summarize(scan: ScanResult) -> dict:
        """A compact one-line-per-metric summary, handy for logs and tests."""
        counts = scan.counts()
        return {
            "host": scan.host,
            "target": str(scan.target),
            "checks": len(scan.results),
            "pass": counts[Status.PASS.value],
            "fail": counts[Status.FAIL.value],
            "warn": counts[Status.WARN.value],
            "manual": counts[Status.MANUAL.value],
            "error": counts[Status.ERROR.value],
            "skip": counts[Status.SKIP.value],
            "compliance": round(scan.compliance_score(), 1),
            "risk": round(scan.total_risk(), 1),
        }
