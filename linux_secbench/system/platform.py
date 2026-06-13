"""Platform detection and the distro-adapter layer.

The CIS content is written for Ubuntu, but most *security* truths (a world
-writable file is bad everywhere; an empty password is bad everywhere) are
distro-agnostic. The split here is deliberate:

* :class:`PlatformInfo` is the detected facts about a host — its family,
  package manager, init system, MAC framework, and inferred role.
* Checks that are portable read those facts and adapt (ask the right package
  manager, look at the right firewall) instead of hard-coding ``apt``.
* Checks that are genuinely Ubuntu/Debian-specific tag themselves and the
  runner skips them elsewhere.

Adding a new distro is therefore mostly a matter of teaching this module how to
classify it — not editing hundreds of checks.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional

from .executor import Executor

# Map the ID / ID_LIKE field of /etc/os-release onto a coarse family that
# determines tooling. Order matters only for readability.
_FAMILY_BY_ID = {
    "ubuntu": "debian",
    "debian": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "raspbian": "debian",
    "rhel": "rhel",
    "centos": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "fedora": "rhel",
    "ol": "rhel",  # Oracle Linux
    "amzn": "rhel",
    "opensuse": "suse",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "sles": "suse",
    "arch": "arch",
}

_PKG_BY_FAMILY = {
    "debian": "apt",
    "rhel": "dnf",
    "suse": "zypper",
    "arch": "pacman",
}

# Packages whose presence strongly implies an interactive desktop (→ workstation).
_DESKTOP_MARKERS = (
    "gdm3", "gdm", "lightdm", "sddm", "gnome-shell", "plasma-desktop",
    "xfce4-session", "cinnamon", "mate-session",
)


@dataclasses.dataclass
class PlatformInfo:
    """Detected, immutable-after-detection facts about the target host."""

    os_id: str = "unknown"
    os_like: str = ""
    name: str = "Unknown Linux"
    version_id: str = ""
    pretty_name: str = ""
    family: str = "unknown"
    package_manager: str = "unknown"
    init_system: str = "unknown"
    mac_framework: str = "none"     # apparmor | selinux | none
    firewall: str = "unknown"       # ufw | firewalld | nftables | iptables | none
    kernel: str = ""
    arch: str = ""
    is_container: bool = False
    inferred_profile: str = "server"  # server | workstation
    hostname: str = "localhost"

    # ---- capability helpers used widely by checks --------------------------

    @property
    def is_ubuntu(self) -> bool:
        return self.os_id == "ubuntu"

    @property
    def is_debian_like(self) -> bool:
        return self.family == "debian"

    @property
    def cis_supported(self) -> bool:
        """Whether the full CIS Ubuntu content is authoritative for this host.

        Outside Ubuntu the CIS-tagged checks still *run* where portable, but we
        flag that the benchmark mapping is approximate so reports don't claim a
        false "CIS Ubuntu 24.04 compliant" verdict on a RHEL box.
        """
        return self.is_ubuntu and self.version_id.startswith("24.04")

    def to_dict(self) -> Dict[str, str]:
        return {
            "os_id": self.os_id,
            "name": self.name,
            "version_id": self.version_id,
            "pretty_name": self.pretty_name,
            "family": self.family,
            "package_manager": self.package_manager,
            "init_system": self.init_system,
            "mac_framework": self.mac_framework,
            "firewall": self.firewall,
            "kernel": self.kernel,
            "arch": self.arch,
            "is_container": self.is_container,
            "inferred_profile": self.inferred_profile,
            "hostname": self.hostname,
            "cis_supported": self.cis_supported,
        }


def detect_platform(executor: Executor) -> PlatformInfo:
    """Probe a host (local or remote) and return its PlatformInfo.

    Every probe is best-effort: a field that can't be determined keeps its
    sensible default rather than aborting detection, because a partial picture
    is still enough to run the portable checks.
    """
    info = PlatformInfo()
    info.hostname = executor.host

    os_release = executor.read_file("/etc/os-release") or ""
    fields = _parse_os_release(os_release)
    info.os_id = fields.get("ID", "unknown").lower()
    info.os_like = fields.get("ID_LIKE", "").lower()
    info.name = fields.get("NAME", info.name)
    info.version_id = fields.get("VERSION_ID", "")
    info.pretty_name = fields.get("PRETTY_NAME", info.name)

    info.family = _classify_family(info.os_id, info.os_like)
    info.package_manager = _PKG_BY_FAMILY.get(info.family, "unknown")

    info.init_system = _detect_init(executor)
    info.mac_framework = _detect_mac(executor)
    info.firewall = _detect_firewall(executor)
    info.kernel = executor.run(["uname", "-r"]).out
    info.arch = executor.run(["uname", "-m"]).out
    info.is_container = _detect_container(executor)
    info.inferred_profile = _infer_profile(executor)
    return info


# --------------------------------------------------------------------------- #
# Detection internals
# --------------------------------------------------------------------------- #

def _parse_os_release(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _classify_family(os_id: str, os_like: str) -> str:
    if os_id in _FAMILY_BY_ID:
        return _FAMILY_BY_ID[os_id]
    for token in os_like.split():
        if token in _FAMILY_BY_ID:
            return _FAMILY_BY_ID[token]
    return "unknown"


def _detect_init(executor: Executor) -> str:
    if executor.read_file("/proc/1/comm", max_bytes=64):
        comm = (executor.read_file("/proc/1/comm", max_bytes=64) or "").strip()
        if comm == "systemd":
            return "systemd"
        if comm:
            return comm
    if executor.run(["sh", "-c", "command -v systemctl"]).ok:
        return "systemd"
    return "unknown"


def _detect_mac(executor: Executor) -> str:
    if executor.run(["sh", "-c", "command -v aa-status || command -v apparmor_status"]).ok:
        return "apparmor"
    if executor.run(["sh", "-c", "command -v getenforce"]).ok:
        return "selinux"
    # Fall back to kernel-exposed state.
    if executor.read_file("/sys/module/apparmor/parameters/enabled"):
        return "apparmor"
    if executor.read_file("/sys/fs/selinux/enforce"):
        return "selinux"
    return "none"


def _detect_firewall(executor: Executor) -> str:
    for tool, name in (("ufw", "ufw"), ("firewall-cmd", "firewalld")):
        if executor.run(["sh", "-c", f"command -v {tool}"]).ok:
            return name
    if executor.run(["sh", "-c", "command -v nft"]).ok:
        return "nftables"
    if executor.run(["sh", "-c", "command -v iptables"]).ok:
        return "iptables"
    return "none"


def _detect_container(executor: Executor) -> bool:
    # systemd exposes this directly; otherwise fall back to cgroup hints.
    if executor.run(["sh", "-c", "command -v systemd-detect-virt"]).ok:
        res = executor.run(["systemd-detect-virt", "--container", "--quiet"])
        return res.returncode == 0
    cgroup = executor.read_file("/proc/1/cgroup") or ""
    return any(token in cgroup for token in ("docker", "lxc", "kubepods", "containerd"))


def _infer_profile(executor: Executor) -> str:
    """Guess whether this is a workstation or a server.

    A display manager or desktop session is the strongest signal of an
    interactive workstation; absent that, default to server, which is both the
    common server-fleet case and the more conservative (stricter) assumption.
    """
    for marker in _DESKTOP_MARKERS:
        if executor.run(["sh", "-c", f"command -v {marker}"]).ok:
            return "workstation"
    # systemd graphical target enabled is another strong hint.
    res = executor.run(["sh", "-c", "systemctl get-default 2>/dev/null"])
    if res.ok and "graphical" in res.out:
        return "workstation"
    if executor.run(["sh", "-c", "ls /usr/share/xsessions 2>/dev/null"]).ok and \
            executor.run(["sh", "-c", "ls -A /usr/share/xsessions 2>/dev/null"]).out:
        return "workstation"
    return "server"


# --------------------------------------------------------------------------- #
# Benchmark applicability — which checks run on which distro / version
# --------------------------------------------------------------------------- #
#
# A check declares ``platforms`` tokens (see CheckMetadata). The grammar:
#   ""  / no tokens   -> portable: runs on every Linux.
#   "<distro>"        -> the host's os_id OR family equals it ("rhel" also
#                        covers Rocky/Alma, whose family is "rhel").
#   "<name>-family"   -> the host's family equals <name> ("debian-family").
#   "<distro>:<ver>"  -> distro-line match AND the host version *starts with*
#                        <ver> ("rhel:9" matches host "9.3"; "ubuntu:24.04"
#                        matches "24.04"/"24.04.1" but not "25.10").
# Version-pinned tokens define benchmark *editions*; on a host whose exact
# version has no edition, ``resolve_benchmark_edition`` picks the nearest one so
# the closest CIS benchmark still applies (flagged approximate).


def parse_version(version_id: str) -> tuple:
    """Best-effort numeric tuple from a VERSION_ID like '24.04', '9.3', '12'."""
    parts = []
    for chunk in str(version_id).split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def _line_matches(left: str, platform: "PlatformInfo") -> bool:
    """Does the distro side of a token match this host (os_id or family)?"""
    return left == platform.os_id or left == platform.family


def _version_prefix_matches(token_ver: str, host_ver: str) -> bool:
    """True when the token version is a leading component of the host version."""
    tv, hv = parse_version(token_ver), parse_version(host_ver)
    if not tv or not hv:
        return token_ver == host_ver
    return hv[: len(tv)] == tv


def platform_matches(tokens, platform: "PlatformInfo") -> bool:
    """OR-match a check's ``platforms`` tokens against a host (see grammar above)."""
    for token in tokens:
        token = (token or "").strip()
        if not token:
            return True  # an explicit empty token means portable
        if ":" in token:
            left, ver = token.split(":", 1)
            if _line_matches(left, platform) and _version_prefix_matches(ver, platform.version_id):
                return True
        elif token.endswith("-family"):
            if platform.family == token[: -len("-family")]:
                return True
        elif _line_matches(token, platform):
            return True
    return False


def available_editions(metadatas) -> Dict[str, List[str]]:
    """Map each distro line to the version-pinned editions present in the catalogue.

    Scans ``platforms`` tokens of the form '<line>:<ver>'. Returns e.g.
    ``{"ubuntu": ["24.04"], "rhel": ["9"], "debian": ["12", "13"]}`` (versions
    ascending). Adding a new edition is therefore pure data — a module of checks
    pinned to "ubuntu:26.04" makes 26.04 selectable automatically.
    """
    out: Dict[str, set] = {}
    for md in metadatas:
        for token in getattr(md, "platforms", ()) or ():
            if ":" in token:
                line, ver = token.split(":", 1)
                out.setdefault(line, set()).add(ver)
    return {line: sorted(vers, key=parse_version) for line, vers in out.items()}


def resolve_benchmark_edition(platform: "PlatformInfo", editions: Dict[str, List[str]]) -> Optional[Dict]:
    """Pick the CIS edition that applies to this host, or None if none does.

    Considers only editions on the host's own distro line (os_id preferred, else
    family). Among those, returns the greatest version <= the host's; if none is
    <=, the lowest available. ``exact`` is True when the host version is actually
    covered by the chosen edition (prefix match), False when it's the nearest
    approximation (e.g. a future release with no published benchmark yet).
    """
    lines = [l for l in editions if l == platform.os_id] or \
            [l for l in editions if l == platform.family]
    hv = parse_version(platform.version_id)
    best = None  # (version_tuple, version_str, line)
    for line in lines:
        for ver in editions[line]:
            tv = parse_version(ver)
            if best is None:
                best = (tv, ver, line)
                continue
            best_tv = best[0]
            le, best_le = tv <= hv, best_tv <= hv
            if le and (not best_le or tv > best_tv):
                best = (tv, ver, line)            # prefer greatest edition <= host
            elif not le and not best_le and tv < best_tv:
                best = (tv, ver, line)            # else the lowest available
    if best is None:
        return None
    _, ver, line = best
    return {"os": platform.os_id, "line": line, "version": ver,
            "exact": _version_prefix_matches(ver, platform.version_id)}
