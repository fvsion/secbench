"""Suppressions — operator-marked false positives / accepted risks.

A scan record is immutable truth: SecBench never edits a finding to make it go
away. Instead, an operator can *suppress* a finding (mark it a false positive,
an accepted risk, or simply excluded), and that decision is recorded here, in a
separate JSON file. Reports apply suppressions as an **overlay**: a suppressed
finding leaves the score and moves to a "Suppressed / accepted" section, while
the underlying scan data stays exactly as captured.

The file is plain JSON under the store directory — diffable, reviewable, and
trivially version-controlled alongside scan history.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
from typing import Dict, List, Optional

#: Allowed suppression kinds (free-form is tolerated but these are the intent).
KINDS = ("false-positive", "accepted-risk", "excluded")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclasses.dataclass
class Suppression:
    check_id: str
    host: str = "*"                 # '*' = all hosts, else an exact host name
    kind: str = "false-positive"
    reason: str = ""
    added_at: str = ""

    def matches(self, check_id: str, host: str) -> bool:
        return self.check_id == check_id and self.host in ("*", host)

    def to_dict(self) -> Dict[str, str]:
        return {
            "check_id": self.check_id, "host": self.host,
            "kind": self.kind, "reason": self.reason, "added_at": self.added_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, str]) -> "Suppression":
        return cls(
            check_id=d["check_id"], host=d.get("host", "*"),
            kind=d.get("kind", "false-positive"), reason=d.get("reason", ""),
            added_at=d.get("added_at", ""),
        )


class SuppressionStore:
    """Load/modify/persist the suppressions for a store directory."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        self._items: List[Suppression] = []
        self.load()

    def load(self) -> None:
        self._items = []
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._items = [Suppression.from_dict(d) for d in data.get("suppressions", [])]
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            # A corrupt file should not crash a scan; treat as no suppressions.
            self._items = []

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"suppressions": [s.to_dict() for s in self._items]}, fh, indent=2)
        os.replace(tmp, self.path)

    def all(self) -> List[Suppression]:
        return list(self._items)

    def match(self, check_id: str, host: str) -> Optional[Suppression]:
        for s in self._items:
            if s.matches(check_id, host):
                return s
        return None

    def add(self, check_id: str, host: str = "*", kind: str = "false-positive",
            reason: str = "") -> Suppression:
        # Replace any existing entry for the same (check_id, host).
        self._items = [s for s in self._items if not (s.check_id == check_id and s.host == host)]
        sup = Suppression(check_id=check_id, host=host, kind=kind, reason=reason, added_at=_now_iso())
        self._items.append(sup)
        self.save()
        return sup

    def remove(self, check_id: str, host: Optional[str] = None) -> int:
        """Remove suppressions for a check id (any host, or a specific one)."""
        before = len(self._items)
        self._items = [
            s for s in self._items
            if not (s.check_id == check_id and (host is None or s.host == host))
        ]
        removed = before - len(self._items)
        if removed:
            self.save()
        return removed
