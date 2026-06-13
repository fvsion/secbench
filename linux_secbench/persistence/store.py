"""The scan store — JSON-on-disk, organised per host.

A flat directory of timestamped JSON files, one per scan, grouped under a
per-host folder. That layout is deliberately boring: it is trivially
inspectable, diffable, syncable, and needs no database. From it we get three
features for free:

* **Resume** — a partial scan (``completed: false``) can be found and continued.
* **Rescan** — re-running appends a new record without touching old ones.
* **History / trends** — loading a host's records oldest-first feeds the trend
  analyzer directly.

Writes are atomic (write-temp-then-rename) so a crash mid-write never corrupts a
scan or an in-progress checkpoint.
"""

from __future__ import annotations

import json
import os
import re
from typing import List, Optional

from ..core.model import ProfileTarget, ScanResult


def slugify(value: str) -> str:
    """Filesystem-safe slug for host names and ids."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return slug.strip("._-") or "host"


class ScanStore:
    """Reads and writes ScanResult records under a base directory."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = os.path.abspath(os.path.expanduser(base_dir))

    # -- paths ---------------------------------------------------------------

    def _host_dir(self, host: str) -> str:
        return os.path.join(self.base_dir, slugify(host))

    def _path(self, host: str, scan_id: str) -> str:
        return os.path.join(self._host_dir(host), f"{slugify(scan_id)}.json")

    # -- write ---------------------------------------------------------------

    def save(self, scan: ScanResult) -> str:
        """Persist a scan atomically and return the file path."""
        host_dir = self._host_dir(scan.host)
        os.makedirs(host_dir, exist_ok=True)
        path = self._path(scan.host, scan.scan_id)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(scan.to_dict(), fh, indent=2)
        os.replace(tmp, path)  # atomic on POSIX and Windows
        return path

    # -- read ----------------------------------------------------------------

    def load(self, host: str, scan_id: str) -> Optional[ScanResult]:
        path = self._path(host, scan_id)
        return self._load_path(path)

    def load_any(self, scan_id: str) -> Optional[ScanResult]:
        """Find a scan by id across all hosts (when the host is unknown)."""
        for host in self.hosts():
            scan = self.load(host, scan_id)
            if scan is not None:
                return scan
        return None

    def load_path(self, path: str) -> Optional[ScanResult]:
        """Load a scan directly from a JSON file path — no host/id lookup.

        A scan record is fully self-describing (it carries its own host, target
        and findings), so a file copied off the scanned system can be reviewed
        anywhere — this needs no store directory to exist. Accepts **either**
        layout SecBench writes: the raw store record (``scan.to_dict()``) or a
        rendered JSON *report* (the ``-o`` / ``report --format json`` bundle,
        which nests the record under a ``"scan"`` key). Returns None if the file
        is missing or is not a recognisable SecBench scan.
        """
        return self._load_path(path)

    def _load_path(self, path: str) -> Optional[ScanResult]:
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # Accept a raw scan record (store format) or a rendered JSON report
            # bundle, which nests the record under "scan".
            if isinstance(data, dict) and "scan_id" not in data and isinstance(data.get("scan"), dict):
                data = data["scan"]
            return ScanResult.from_dict(data)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            # A corrupt or schema-incompatible file should not crash a scan;
            # callers treat None as "no usable record here".
            return None

    def hosts(self) -> List[str]:
        if not os.path.isdir(self.base_dir):
            return []
        return sorted(
            d for d in os.listdir(self.base_dir)
            if os.path.isdir(os.path.join(self.base_dir, d))
        )

    def history(self, host: str) -> List[ScanResult]:
        """All scans for a host, sorted oldest-first by start time."""
        host_dir = self._host_dir(host)
        if not os.path.isdir(host_dir):
            return []
        scans = []
        for name in os.listdir(host_dir):
            if not name.endswith(".json"):
                continue
            scan = self._load_path(os.path.join(host_dir, name))
            if scan is not None:
                scans.append(scan)
        return sorted(scans, key=lambda s: s.started_at)

    def latest(self, host: str, completed_only: bool = True) -> Optional[ScanResult]:
        scans = self.history(host)
        if completed_only:
            scans = [s for s in scans if s.completed]
        return scans[-1] if scans else None

    def find_resumable(self, host: str, target: ProfileTarget) -> Optional[ScanResult]:
        """The most recent *incomplete* scan for this host+target, if any.

        Resume only makes sense for the same target; resuming an L1-Server
        partial into an L2-Workstation run would mix scopes. Matching on target
        keeps a resume honest.
        """
        candidates = [
            s for s in self.history(host)
            if not s.completed and s.target == target
        ]
        return candidates[-1] if candidates else None

    def prune(self, host: str, keep: int) -> int:
        """Keep only the newest ``keep`` completed scans for a host.

        Returns the number deleted. History grows without bound otherwise;
        this gives the CLI a safe retention knob.
        """
        if keep < 1:
            return 0
        scans = self.history(host)
        completed = [s for s in scans if s.completed]
        to_delete = completed[:-keep] if len(completed) > keep else []
        deleted = 0
        for s in to_delete:
            path = self._path(host, s.scan_id)
            try:
                os.remove(path)
                deleted += 1
            except OSError:
                pass
        return deleted
