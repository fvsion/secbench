"""Exploitability knowledge base — the GTFOBins/LOLBin lineage.

A misconfiguration only matters if it is *exploitable*. ``sudo`` to
``/usr/bin/find`` or a setuid ``python3`` is not a "policy nit" — it is a
one-line path to root, the kind of thing a penetration tester finds with
``sudo -l`` and a GTFOBins lookup. This module encodes that operational
knowledge so the privilege checks can say not just "alice can sudo python" but
"alice → root, via python's ``os.system`` breakout."

The data is a curated subset of the well-known GTFOBins project
(https://gtfobins.github.io) plus a few LOLBin-style cases, keyed by binary
basename. Each entry records *which contexts* make the binary dangerous —
``sudo`` (run via sudo), ``suid`` (the setuid bit set), ``cap`` (a privileged
file capability) — and a one-line technique. It is intentionally data, not
logic, so it is trivial to extend.
"""

from __future__ import annotations

import os
from typing import Dict, FrozenSet, NamedTuple, Optional


class Exploit(NamedTuple):
    contexts: FrozenSet[str]   # subset of {"sudo", "suid", "cap"}
    technique: str             # how the breakout works, one line


_ALL = frozenset({"sudo", "suid"})            # shell-breakout: works via sudo or suid
_ALLCAP = frozenset({"sudo", "suid", "cap"})  # also exploitable via cap_setuid (interpreters)

# Curated GTFOBins-style table. Not exhaustive — the high-frequency,
# high-confidence entries a real engagement relies on.
GTFOBINS: Dict[str, Exploit] = {
    # Shells / interpreters — also cap_setuid-exploitable.
    "bash": Exploit(_ALL, "spawns a shell directly"),
    "sh": Exploit(_ALL, "spawns a shell directly"),
    "dash": Exploit(_ALL, "spawns a shell directly"),
    "zsh": Exploit(_ALL, "spawns a shell directly"),
    "python": Exploit(_ALLCAP, "runs any command as root, e.g. python -c 'import os;os.setuid(0);os.system(\"/bin/sh\")' → root shell"),
    "python3": Exploit(_ALLCAP, "runs any command as root, e.g. python3 -c 'import os;os.setuid(0);os.system(\"/bin/sh\")' → root shell"),
    "perl": Exploit(_ALLCAP, "runs any command as root, e.g. perl -e 'exec \"/bin/sh\";' → root shell"),
    "ruby": Exploit(_ALLCAP, "runs any command as root, e.g. ruby -e 'exec \"/bin/sh\"' → root shell"),
    "php": Exploit(_ALLCAP, "runs any command as root, e.g. php -r 'system(\"/bin/sh\");' → root shell"),
    "node": Exploit(_ALLCAP, "runs any command as root via child_process.spawn('/bin/sh') → root shell"),
    "lua": Exploit(_ALL, "os.execute('/bin/sh') breakout"),
    "awk": Exploit(_ALL, "system('/bin/sh') via BEGIN block"),
    "gawk": Exploit(_ALL, "system('/bin/sh') via BEGIN block"),
    "gdb": Exploit(_ALLCAP, "-ex 'call (void)setuid(0)' then shell"),
    "expect": Exploit(_ALL, "spawn /bin/sh"),
    "tclsh": Exploit(_ALL, "exec /bin/sh"),

    # Editors / pagers — shell escape.
    "vim": Exploit(_ALL, "':!/bin/sh' or -c ':py' shell escape"),
    "vi": Exploit(_ALL, "':!/bin/sh' shell escape"),
    "view": Exploit(_ALL, "':!/bin/sh' shell escape"),
    "nano": Exploit(_ALL, "^R^X command execution"),
    "pico": Exploit(_ALL, "^R^X command execution"),
    "less": Exploit(_ALL, "'!/bin/sh' from the pager"),
    "more": Exploit(_ALL, "'!/bin/sh' from the pager"),
    "man": Exploit(_ALL, "'!/bin/sh' via the pager"),
    "ed": Exploit(_ALL, "'!/bin/sh' command"),
    "emacs": Exploit(_ALL, "(term) / shell-command escape"),

    # File / data utilities — read/write/exec as root.
    "find": Exploit(_ALL, "-exec /bin/sh \\; runs a shell"),
    "cp": Exploit(_ALL, "overwrite /etc/passwd or arbitrary root-owned file"),
    "mv": Exploit(_ALL, "replace a root-owned file"),
    "tar": Exploit(_ALL, "--checkpoint-action=exec runs a command"),
    "dd": Exploit(_ALL, "write arbitrary bytes to any file (e.g. /etc/passwd)"),
    "tee": Exploit(_ALL, "write to root-owned files"),
    "sed": Exploit(_ALL, "-e '1e /bin/sh' executes a command"),
    "cpio": Exploit(_ALL, "extract/overwrite files as root"),
    "rsync": Exploit(_ALL, "-e to run a command, or write root files"),
    "zip": Exploit(_ALL, "-T --unzip-command runs a command"),
    "xargs": Exploit(_ALL, "-a /dev/null sh -c"),
    "busybox": Exploit(_ALL, "busybox sh spawns a shell"),
    "flock": Exploit(_ALL, "flock -u / /bin/sh"),

    # Service / package / network tooling.
    "systemctl": Exploit(frozenset({"sudo"}), "edit/run a unit with ExecStart=/bin/sh"),
    "journalctl": Exploit(frozenset({"sudo"}), "pager shell escape '!/bin/sh'"),
    "apt": Exploit(frozenset({"sudo"}), "APT::Update::Pre-Invoke runs a command"),
    "apt-get": Exploit(frozenset({"sudo"}), "APT::Update::Pre-Invoke runs a command"),
    "dpkg": Exploit(frozenset({"sudo"}), "dpkg -i a malicious package / pager escape"),
    "pip": Exploit(frozenset({"sudo"}), "install a package whose setup.py runs code"),
    "pip3": Exploit(frozenset({"sudo"}), "install a package whose setup.py runs code"),
    "make": Exploit(_ALL, "-f a makefile whose recipe runs a shell"),
    "nmap": Exploit(_ALL, "--script or interactive mode runs a shell (older builds)"),
    "tcpdump": Exploit(frozenset({"sudo"}), "-z postrotate-command runs as root"),
    "git": Exploit(_ALL, "-c core.pager / PAGER / hooks run a command"),
    "ftp": Exploit(_ALL, "'!/bin/sh' subshell"),
    "socat": Exploit(_ALL, "exec:/bin/sh"),
    "env": Exploit(_ALL, "env /bin/sh runs a shell directly"),
    "docker": Exploit(frozenset({"sudo"}), "docker run -v /:/host mounts the host filesystem as root"),
    "mount": Exploit(_ALL, "abuses mount (bind-mount over sensitive files / SUID tricks) to read or overwrite root-owned files → root"),
    "crontab": Exploit(frozenset({"sudo"}), "-e to write a root cron job"),
}

# Capabilities that, on the right binary, grant root.
DANGEROUS_CAPS = ("cap_setuid", "cap_dac_override", "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace")

# Binaries that are setuid/setgid-root by design on a stock Ubuntu. Their setuid
# bit is REQUIRED for normal operation (and removing it breaks the system), so
# their presence in the GTFOBins table does NOT make them a default root
# primitive — mount, for example, refuses arbitrary mounts from a non-root user.
# EXT-PRIV-2 excludes these and only flags *unexpected* setuid GTFOBins binaries
# (e.g. a setuid python/find someone added), which genuinely are instant root.
DEFAULT_SETUID = frozenset({
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/fusermount3", "/usr/bin/fusermount",
    "/usr/bin/pkexec", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign", "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/ntfs-3g",
    "/usr/lib/eject/dmcrypt-get-device",
    "/usr/sbin/unix_chkpwd", "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/bin/expiry", "/usr/bin/chage", "/usr/bin/wall", "/usr/bin/write",
    "/usr/bin/ssh-agent", "/usr/bin/bsd-write",
})

# Groups whose membership is effectively root (or trivially escalates to it).
ROOT_EQUIVALENT_GROUPS = {
    "docker": "docker socket → 'docker run -v /:/host' mounts the host fs as root",
    "lxd": "lxd → launch a privileged container mounting the host fs as root",
    "disk": "disk → raw read/write of block devices (debugfs/dd on /dev/sdX) reads/writes any file",
    "shadow": "shadow → read /etc/shadow and crack/forge password hashes",
    "adm": "adm → read system logs, often containing tokens and secrets",
}


def basename(path: str) -> str:
    return os.path.basename(path.strip())


def gtfobins_url(binary: str) -> str:
    """Link to the upstream GTFOBins page for a binary, for full reproduction."""
    return f"https://gtfobins.github.io/gtfobins/{basename(binary)}/"


def lookup(binary: str, context: str) -> Optional[str]:
    """Return the technique string if ``binary`` is exploitable in ``context``.

    ``binary`` may be a full path or a bare name; ``context`` is one of
    ``sudo`` / ``suid`` / ``cap``. Returns None when the binary is not a known
    escalation vector in that context.
    """
    entry = GTFOBINS.get(basename(binary))
    if entry and context in entry.contexts:
        return entry.technique
    return None
