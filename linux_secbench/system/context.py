"""SystemContext — the single object every check is handed.

Checks never touch an Executor or parse ``/etc/os-release`` directly; they ask
the context. That buys three things at once:

* **Caching.** A scan does not mutate the host, so every read is cached for the
  scan's lifetime. Dozens of checks read ``sshd -T`` or ``/etc/passwd``; they
  pay for it once. This is the difference between a scan taking seconds and
  taking minutes over SSH.
* **Distro neutrality.** ``package_installed`` asks the right package manager;
  ``service_enabled`` speaks systemd. A portable check stays portable.
* **Uniform failure.** A missing file is ``None``, an absent service is
  ``False`` — never an exception a check has to guard.
"""

from __future__ import annotations

import dataclasses
import shlex
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .executor import CommandResult, Executor
from .platform import PlatformInfo


@dataclasses.dataclass
class StatInfo:
    """Parsed ``stat`` output for a path."""

    path: str
    exists: bool
    mode: int = 0            # numeric permission bits, e.g. 0o644
    uid: int = -1
    gid: int = -1
    owner: str = ""
    group: str = ""
    is_dir: bool = False
    is_symlink: bool = False

    @property
    def mode_str(self) -> str:
        return format(self.mode, "04o")

    def perm_at_most(self, max_mode: int) -> bool:
        """True if no permission bit is set beyond those allowed by max_mode."""
        return (self.mode & ~max_mode) == 0


class SystemContext:
    """A caching, distro-aware facade over an Executor + PlatformInfo."""

    def __init__(self, executor: Executor, platform: PlatformInfo) -> None:
        self._exec = executor
        self.platform = platform
        self._cache: Dict[Tuple, Any] = {}
        # When True, checks may include full plaintext secret values in their
        # evidence; otherwise values are redacted to a short preview. Set by the
        # CLI from --reveal-secrets. Default off so a report never contains live
        # secrets unless the operator explicitly asks.
        self.reveal_secrets: bool = False
        # When True, checks may use *active/intrusive* techniques — currently the
        # in-memory credential recovery (EXT-CRED-16) that reads other processes'
        # heap memory. Set by the CLI from --active-review. Default off so a
        # routine scan never reaches into process memory.
        self.active_review: bool = False

    # ---- identity ----------------------------------------------------------

    @property
    def host(self) -> str:
        return self._exec.host

    @property
    def is_root(self) -> bool:
        return self._exec.is_root

    @property
    def is_local(self) -> bool:
        """True when the target is this machine (not an SSH host).

        Some techniques — notably reading another process's memory — only make
        sense locally; over SSH there is no way to stream raw process memory
        through the command channel, and the scanner's own /proc is the wrong
        host. Such checks degrade to MANUAL when not local.
        """
        from .executor import LocalExecutor
        return isinstance(self._exec, LocalExecutor)

    def facts(self) -> Dict[str, Any]:
        """Host facts embedded in the scan record for reporting and trends."""
        return {**self.platform.to_dict(), "scanned_as_root": self.is_root}

    # ---- raw execution (cached) -------------------------------------------

    def run(
        self,
        command: Sequence[str],
        *,
        timeout: float = 30.0,
        shell: bool = False,
        cache: bool = True,
    ) -> CommandResult:
        """Run a command, caching the result for the scan by default.

        Caching assumes commands are read-only observations of an unchanging
        system, which holds for assessment. A check that genuinely must re-run
        something can pass ``cache=False``.
        """
        key = ("run", tuple(command), shell)
        if cache and key in self._cache:
            return self._cache[key]
        result = self._exec.run(command, timeout=timeout, shell=shell)
        if cache:
            self._cache[key] = result
        return result

    def sh(self, script: str, *, timeout: float = 30.0, cache: bool = True) -> CommandResult:
        """Run a small shell snippet. Use sparingly — prefer argv lists."""
        return self.run(["sh", "-c", script], timeout=timeout, shell=False, cache=cache)

    # ---- filesystem --------------------------------------------------------

    def read_file(self, path: str, *, max_bytes: int = 2_000_000) -> Optional[str]:
        key = ("read", path, max_bytes)
        if key in self._cache:
            return self._cache[key]
        content = self._exec.read_file(path, max_bytes=max_bytes)
        self._cache[key] = content
        return content

    def file_lines(self, path: str) -> List[str]:
        content = self.read_file(path)
        return content.splitlines() if content is not None else []

    def file_exists(self, path: str) -> bool:
        return self.run(["test", "-e", path]).returncode == 0

    def glob(self, pattern: str) -> List[str]:
        """Expand a shell glob on the target, returning matching paths."""
        res = self.sh(f"for f in {pattern}; do [ -e \"$f\" ] && printf '%s\\n' \"$f\"; done")
        return res.lines()

    def stat(self, path: str) -> StatInfo:
        """Stat a path into a structured StatInfo (cached)."""
        key = ("stat", path)
        if key in self._cache:
            return self._cache[key]
        # GNU stat format: octal-perms uid gid owner group type-flags
        res = self.run(["stat", "-L", "-c", "%a %u %g %U %G %F", path])
        if not res.ok:
            # Distinguish "missing" from "exists but stat -L failed on a broken
            # symlink" by retrying without dereference.
            res2 = self.run(["stat", "-c", "%a %u %g %U %G %F", path])
            if not res2.ok:
                info = StatInfo(path=path, exists=False)
                self._cache[key] = info
                return info
            res = res2
        info = self._parse_stat(path, res.out)
        self._cache[key] = info
        return info

    @staticmethod
    def _parse_stat(path: str, out: str) -> StatInfo:
        parts = out.split(None, 5)
        if len(parts) < 6:
            return StatInfo(path=path, exists=False)
        perms, uid, gid, owner, group, ftype = parts
        try:
            mode = int(perms, 8)
        except ValueError:
            mode = 0
        return StatInfo(
            path=path,
            exists=True,
            mode=mode,
            uid=int(uid) if uid.isdigit() else -1,
            gid=int(gid) if gid.isdigit() else -1,
            owner=owner,
            group=group,
            is_dir="directory" in ftype,
            is_symlink="symbolic link" in ftype,
        )

    # ---- kernel / sysctl ---------------------------------------------------

    def sysctl(self, key: str) -> Optional[str]:
        """Return the live value of a sysctl key, or None if unavailable."""
        res = self.run(["sysctl", "-n", key])
        if res.ok:
            return res.out
        # Fall back to reading /proc/sys directly (works without the binary).
        proc_path = "/proc/sys/" + key.replace(".", "/")
        return (self.read_file(proc_path) or "").strip() or None

    def module_loaded(self, name: str) -> bool:
        res = self.run(["sh", "-c", f"lsmod | awk '{{print $1}}'"])
        return name in res.lines()

    def module_loadable(self, name: str) -> bool:
        """Whether a kernel module could be loaded (CIS filesystem checks).

        A module is considered disabled when modprobe is configured to map it
        to /bin/false or blacklist it, or the .ko file is absent.
        """
        res = self.run(["modprobe", "-n", "-v", name])
        loadable_text = res.combined.lower()
        if "install /bin/false" in loadable_text or "install /bin/true" in loadable_text:
            return False
        # No backing module file at all → not loadable.
        find = self.sh(f"find /lib/modules/$(uname -r) -name '{shlex.quote(name)}.ko*' 2>/dev/null | head -1")
        if not find.out and not res.ok:
            return False
        return True

    # ---- packages ----------------------------------------------------------

    def package_installed(self, name: str) -> bool:
        """Distro-aware package presence check."""
        key = ("pkg", name)
        if key in self._cache:
            return self._cache[key]
        pm = self.platform.package_manager
        if pm == "apt":
            res = self.run(["dpkg-query", "-W", "-f=${Status}", name])
            installed = res.ok and "install ok installed" in res.out
        elif pm in ("dnf", "yum", "zypper"):
            installed = self.run(["rpm", "-q", name]).ok
        elif pm == "pacman":
            installed = self.run(["pacman", "-Q", name]).ok
        else:
            # Unknown package manager: fall back to "is the binary present".
            installed = self._exec.which(name) is not None
        self._cache[key] = installed
        return installed

    # ---- services (systemd-first) -----------------------------------------

    def service_enabled(self, unit: str) -> bool:
        return self.run(["systemctl", "is-enabled", unit]).out in (
            "enabled", "enabled-runtime", "static", "alias", "indirect"
        )

    def service_active(self, unit: str) -> bool:
        return self.run(["systemctl", "is-active", unit]).out == "active"

    def service_present(self, unit: str) -> bool:
        res = self.run(["systemctl", "list-unit-files", unit])
        return res.ok and unit in res.combined

    def masked(self, unit: str) -> bool:
        return self.run(["systemctl", "is-enabled", unit]).out == "masked"

    # ---- network -----------------------------------------------------------

    def listening_sockets(self) -> List[Dict[str, str]]:
        """Parse listening TCP/UDP sockets via ``ss`` (cached).

        Returns a list of {proto, local, process} dicts. Best-effort parsing —
        process/PID columns require root and are filled when available.
        """
        key = ("listening",)
        if key in self._cache:
            return self._cache[key]
        res = self.run(["ss", "-tulpnH"])
        sockets: List[Dict[str, str]] = []
        if res.ok:
            for line in res.lines():
                cols = line.split()
                if len(cols) < 5:
                    continue
                proto = cols[0]
                local = cols[4]
                process = " ".join(cols[6:]) if len(cols) > 6 else ""
                sockets.append({"proto": proto, "local": local, "process": process})
        self._cache[key] = sockets
        return sockets

    # ---- accounts ----------------------------------------------------------

    def passwd_entries(self) -> List[Dict[str, str]]:
        return self._parse_colon_db("/etc/passwd", ("name", "passwd", "uid", "gid", "gecos", "home", "shell"))

    def shadow_entries(self) -> List[Dict[str, str]]:
        return self._parse_colon_db(
            "/etc/shadow",
            ("name", "passwd", "lastchg", "min", "max", "warn", "inactive", "expire", "reserved"),
        )

    def group_entries(self) -> List[Dict[str, str]]:
        return self._parse_colon_db("/etc/group", ("name", "passwd", "gid", "members"))

    def _parse_colon_db(self, path: str, columns: Sequence[str]) -> List[Dict[str, str]]:
        key = ("colon", path)
        if key in self._cache:
            return self._cache[key]
        rows: List[Dict[str, str]] = []
        for line in self.file_lines(path):
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            # Pad short rows so callers can index by name without KeyError.
            parts += [""] * (len(columns) - len(parts))
            rows.append(dict(zip(columns, parts)))
        self._cache[key] = rows
        return rows

    # ---- config-file helpers ----------------------------------------------

    def sshd_config(self) -> Dict[str, str]:
        """Effective sshd configuration via ``sshd -T`` (cached, lowercased keys).

        ``sshd -T`` resolves Includes, Match-less defaults and compiled-in
        values — far more reliable than grepping sshd_config, which misses
        drop-ins under sshd_config.d. Falls back to parsing the file if the
        daemon binary refuses to dump (e.g. not root).
        """
        key = ("sshd_-T",)
        if key in self._cache:
            return self._cache[key]
        cfg: Dict[str, str] = {}
        res = self.run(["sshd", "-T"])
        if res.ok:
            for line in res.lines():
                k, _, v = line.partition(" ")
                cfg[k.lower()] = v.strip()
        else:
            cfg = self.parse_keyword_file("/etc/ssh/sshd_config")
        self._cache[key] = cfg
        return cfg

    def parse_keyword_file(self, path: str, *, sep: Optional[str] = None) -> Dict[str, str]:
        """Parse a ``keyword value`` config file into a lowercased dict.

        Last-wins on duplicate keys (matching most daemons' first-wins is left
        to the caller when it matters; for assessment last-value is fine for
        the simple files we use this on). Comments and blanks are skipped.
        """
        out: Dict[str, str] = {}
        for line in self.file_lines(path):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if sep:
                k, _, v = line.partition(sep)
            else:
                parts = line.split(None, 1)
                k, v = parts[0], (parts[1] if len(parts) > 1 else "")
            out[k.strip().lower()] = v.strip()
        return out

    # ---- caching control ---------------------------------------------------

    def invalidate(self) -> None:
        """Drop all cached reads (used when rescanning the same context)."""
        self._cache.clear()
