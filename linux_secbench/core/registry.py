"""The global check registry and the package auto-discovery mechanism.

Checks register themselves as a side effect of being imported (via the
``@check`` decorator). :meth:`Registry.autodiscover` imports every module
under a checks package so that simply having a file in ``checks/cis/`` or
``checks/extended/`` is enough to enrol its checks — no manual list to keep in
sync, which is the usual source of "I wrote a check but it never ran" bugs.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, Iterable, List, Optional, Sequence

from .check import Check
from .model import Level, Profile, ProfileTarget


class DuplicateCheckError(ValueError):
    """Raised when two checks claim the same id — almost always a copy-paste bug."""


def _is_active_edition(md, active, target: ProfileTarget) -> bool:
    """Nearest-edition fallback: admit a version-pinned check that belongs to the
    host's resolved CIS edition even when the host version isn't an exact match
    (e.g. a release with no published benchmark yet). Still honours level/profile.
    """
    if active is None or not md.platforms:
        return False
    if not target.includes(md.levels, md.profiles):
        return False
    for token in md.platforms:
        if ":" in token:
            line, ver = token.split(":", 1)
            if line == active["line"] and ver == active["version"]:
                return True
    return False


class Registry:
    """An ordered, de-duplicated collection of checks, queryable by scope."""

    def __init__(self) -> None:
        self._checks: Dict[str, Check] = {}

    def add(self, chk: Check) -> None:
        if chk.id in self._checks and self._checks[chk.id] is not chk:
            raise DuplicateCheckError(
                f"Duplicate check id {chk.id!r}: "
                f"{self._checks[chk.id].metadata.title!r} vs {chk.metadata.title!r}"
            )
        self._checks[chk.id] = chk

    def __len__(self) -> int:
        return len(self._checks)

    def __iter__(self):
        return iter(self.all())

    def all(self) -> List[Check]:
        """All registered checks, sorted by natural id order (1.1.2 < 1.10)."""
        return sorted(self._checks.values(), key=lambda c: _id_sort_key(c.id))

    def get(self, check_id: str) -> Optional[Check]:
        return self._checks.get(check_id)

    def frameworks(self) -> List[str]:
        return sorted({c.metadata.framework for c in self._checks.values()})

    def select(
        self,
        target: ProfileTarget,
        ctx,
        frameworks: Optional[Sequence[str]] = None,
        sections: Optional[Sequence[str]] = None,
        ids: Optional[Sequence[str]] = None,
        tags: Optional[Sequence[str]] = None,
        include_extended: bool = True,
        include_kiosk: bool = False,
    ) -> List[Check]:
        """Return the checks that should run, honouring every filter at once.

        Order of precedence is "narrowest wins": an explicit id list overrides
        everything else, otherwise framework/section/tag filters intersect with
        profile applicability. This is the single place scope is decided so the
        runner and the ``list`` CLI command can never disagree.
        """
        if ids:
            wanted = set(ids)
            return [c for c in self.all() if c.id in wanted]

        # Resolve which benchmark *edition* applies to this host (e.g.
        # ubuntu:24.04). On a host whose exact version has no published edition,
        # this picks the nearest one so its checks still run (flagged approximate
        # in the report); adding a future edition is then pure data.
        from ..system.platform import available_editions, resolve_benchmark_edition
        active = resolve_benchmark_edition(
            ctx.platform, available_editions(c.metadata for c in self.all()))

        selected: List[Check] = []
        for chk in self.all():
            md = chk.metadata
            # Kiosk checks are a special opt-in class (enable with --kiosk); they
            # are noise on a normal server/workstation, so stay off by default.
            if md.framework == "Kiosk" and not include_kiosk:
                continue
            if not include_extended and md.framework not in ("CIS", "Kiosk"):
                continue
            if frameworks and md.framework not in frameworks:
                continue
            if sections and not any(md.section.startswith(s) or md.id.startswith(s) for s in sections):
                continue
            if tags and not (set(tags) & set(md.tags)):
                continue
            if not chk.applies_to(target, ctx) and not _is_active_edition(md, active, target):
                continue
            selected.append(chk)
        return selected

    def autodiscover(self, packages: Sequence[str]) -> int:
        """Import every submodule of each package so checks self-register.

        Returns the number of checks known afterwards. Import errors in one
        check module are surfaced loudly (they are author bugs) rather than
        silently swallowed, but we annotate which module failed.
        """
        for package_name in packages:
            package = importlib.import_module(package_name)
            for mod in pkgutil.walk_packages(package.__path__, prefix=package.__name__ + "."):
                if mod.ispkg:
                    continue
                try:
                    importlib.import_module(mod.name)
                except Exception as exc:  # noqa: BLE001
                    raise ImportError(f"Failed to load check module {mod.name!r}: {exc}") from exc
        return len(self)

    def clear(self) -> None:
        """Drop all registered checks (used by tests for isolation)."""
        self._checks.clear()


def _id_sort_key(check_id: str):
    """Sort dotted ids numerically segment-by-segment, strings last.

    So "1.2" < "1.10", and "EXT-ACCT-1" sorts after numeric CIS ids in a stable
    way instead of the lexicographic mess plain string sorting would give.
    """
    parts = []
    for seg in check_id.replace("-", ".").split("."):
        if seg.isdigit():
            parts.append((0, int(seg), ""))
        else:
            parts.append((1, 0, seg))
    return parts


# The process-wide singleton every @check decorator writes into.
registry = Registry()
