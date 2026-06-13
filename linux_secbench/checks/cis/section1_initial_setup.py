"""CIS Section 1 — Initial Setup (CIS Ubuntu 24.04 Benchmark v2.0.0).

Filesystem kernel modules & partitions (1.1), package management (1.2),
mandatory access control / AppArmor (1.3), bootloader (1.4), additional process
hardening (1.5), command-line warning banners (1.6), and the GNOME Display
Manager (1.7).
"""

from __future__ import annotations

from ...core import Level, Outcome, Profile, Severity
from ._base import cis_check as check

# --------------------------------------------------------------------------- #
# 1.1.1 Configure Filesystem Kernel Modules (CIS Ubuntu 24.04 v2.0.0)
# --------------------------------------------------------------------------- #
# Each is a niche/legacy filesystem driver with a history of vulnerabilities and
# no place on a hardened general-purpose host. v2.0.0 numbering 1.1.1.1–1.1.1.10.
_FS_MODULES = [
    ("1.1.1.1", "cramfs"),
    ("1.1.1.2", "freevxfs"),
    ("1.1.1.3", "hfs"),
    ("1.1.1.4", "hfsplus"),
    ("1.1.1.5", "jffs2"),
    ("1.1.1.6", "overlay"),
    ("1.1.1.7", "squashfs"),
    ("1.1.1.8", "udf"),
    ("1.1.1.9", "firewire-core"),
    ("1.1.1.10", "usb-storage"),
]


def _make_module_check(cis_id: str, module: str):
    @check(
        id=cis_id,
        title=f"Ensure {module} kernel module is not available",
        section="1.1 Filesystem",
        severity=Severity.LOW,
        levels=(Level.L1,),
        profiles=(Profile.SERVER, Profile.WORKSTATION),
        rationale=(
            f"Removing support for the {module} filesystem reduces the kernel's "
            "attack surface; an unused filesystem driver is pure risk."
        ),
        remediation=(
            f"Add 'install {module} /bin/false' and 'blacklist {module}' to a file "
            f"under /etc/modprobe.d/, then 'modprobe -r {module}' if loaded."
        ),
        tags=("filesystem", "kernel-module", "ubuntu"),
        attack=("T1547.006",),
    )
    def _chk(ctx, _module=module):
        loaded = ctx.module_loaded(_module)
        loadable = ctx.module_loadable(_module)
        if not loaded and not loadable:
            return Outcome.passed(f"{_module} is neither loaded nor loadable")
        details = []
        if loaded:
            details.append("currently loaded")
        if loadable:
            details.append("loadable via modprobe")
        return Outcome.failed(
            f"{_module} is {' and '.join(details)}",
            actual={"loaded": loaded, "loadable": loadable},
            expected={"loaded": False, "loadable": False},
        )

    return _chk


for _cid, _mod in _FS_MODULES:
    _make_module_check(_cid, _mod)


@check(
    id="1.1.1.11",
    title="Ensure unused filesystems kernel modules are not available",
    section="1.1 Filesystem",
    severity=Severity.LOW,
    levels=(Level.L2,),
    automated=False,
    rationale="Any filesystem driver the host does not use is attack surface that should be disabled.",
    remediation="Review loadable filesystem modules and blacklist those the system does not require.",
    tags=("filesystem", "kernel-module", "ubuntu"),
)
def unused_fs_modules(ctx):
    return Outcome.manual(
        "Manually review filesystem modules beyond the listed set and disable any the host "
        "does not need (see CIS 1.1.1.11)."
    )


# --------------------------------------------------------------------------- #
# 1.1.2 Configure Filesystem Partitions
# --------------------------------------------------------------------------- #
# A declarative matrix: per mount point, the v2.0.0 "separate partition exists"
# control plus each required mount option. One factory covers all 26.
_SEPARATE = "separate"
_PARTITION_CONTROLS = [
    # /tmp (1.1.2.1.*) — L1
    ("1.1.2.1.1", "/tmp", _SEPARATE, Level.L1),
    ("1.1.2.1.2", "/tmp", "nodev", Level.L1),
    ("1.1.2.1.3", "/tmp", "nosuid", Level.L1),
    ("1.1.2.1.4", "/tmp", "noexec", Level.L1),
    # /dev/shm (1.1.2.2.*) — L1
    ("1.1.2.2.1", "/dev/shm", _SEPARATE, Level.L1),
    ("1.1.2.2.2", "/dev/shm", "nodev", Level.L1),
    ("1.1.2.2.3", "/dev/shm", "nosuid", Level.L1),
    ("1.1.2.2.4", "/dev/shm", "noexec", Level.L1),
    # /home (1.1.2.3.*) — L2 separate, L1 options
    ("1.1.2.3.1", "/home", _SEPARATE, Level.L2),
    ("1.1.2.3.2", "/home", "nodev", Level.L1),
    ("1.1.2.3.3", "/home", "nosuid", Level.L1),
    # /var (1.1.2.4.*)
    ("1.1.2.4.1", "/var", _SEPARATE, Level.L2),
    ("1.1.2.4.2", "/var", "nodev", Level.L1),
    ("1.1.2.4.3", "/var", "nosuid", Level.L1),
    # /var/tmp (1.1.2.5.*)
    ("1.1.2.5.1", "/var/tmp", _SEPARATE, Level.L2),
    ("1.1.2.5.2", "/var/tmp", "nodev", Level.L1),
    ("1.1.2.5.3", "/var/tmp", "nosuid", Level.L1),
    ("1.1.2.5.4", "/var/tmp", "noexec", Level.L1),
    # /var/log (1.1.2.6.*)
    ("1.1.2.6.1", "/var/log", _SEPARATE, Level.L2),
    ("1.1.2.6.2", "/var/log", "nodev", Level.L1),
    ("1.1.2.6.3", "/var/log", "nosuid", Level.L1),
    ("1.1.2.6.4", "/var/log", "noexec", Level.L1),
    # /var/log/audit (1.1.2.7.*)
    ("1.1.2.7.1", "/var/log/audit", _SEPARATE, Level.L2),
    ("1.1.2.7.2", "/var/log/audit", "nodev", Level.L1),
    ("1.1.2.7.3", "/var/log/audit", "nosuid", Level.L1),
    ("1.1.2.7.4", "/var/log/audit", "noexec", Level.L1),
]


def _mount_options(ctx, mountpoint):
    """Effective mount options for a path, or None if it is not a mount point."""
    res = ctx.run(["findmnt", "--kernel", "--noheadings", "--output", "OPTIONS", mountpoint])
    if res.ok and res.out:
        return res.out.split(",")
    return None


def _make_separate_check(cis_id, mountpoint, level):
    @check(
        id=cis_id,
        title=f"Ensure separate partition exists for {mountpoint}",
        section="1.1 Filesystem",
        severity=Severity.MEDIUM,
        levels=(level,),
        rationale=(
            f"A separate {mountpoint} can be mounted nodev/nosuid/noexec and isolates a "
            "fill-up so it cannot exhaust the root filesystem."
        ),
        remediation=f"Provision {mountpoint} on its own partition (or tmpfs where applicable).",
        tags=("filesystem", "partition"),
    )
    def _chk(ctx, _mp=mountpoint):
        res = ctx.run(["findmnt", "--kernel", "--noheadings", "--output", "TARGET", _mp])
        if res.ok and res.out.strip() == _mp:
            return Outcome.passed(f"{_mp} is a separate mount", actual=res.out.strip())
        return Outcome.failed(f"{_mp} is not a separate partition", expected=f"separate mount for {_mp}")

    return _chk


def _make_mount_option_check(cis_id, mountpoint, option, level):
    @check(
        id=cis_id,
        title=f"Ensure {option} option set on {mountpoint} partition",
        section="1.1 Filesystem",
        severity=Severity.MEDIUM,
        levels=(level,),
        rationale=(
            f"Mounting {mountpoint} with {option} prevents a class of escalation: device "
            "nodes, setuid binaries, or executables planted in writable space."
        ),
        remediation=f"Add '{option}' to the {mountpoint} entry in /etc/fstab and remount.",
        tags=("filesystem", "mount-option"),
        attack=("T1222",),
    )
    def _chk(ctx, _mp=mountpoint, _opt=option):
        opts = _mount_options(ctx, _mp)
        if opts is None:
            return Outcome.failed(
                f"{_mp} is not a separate mount, so {_opt} is not enforced",
                expected=f"{_opt} on a separate {_mp}")
        if _opt in opts:
            return Outcome.passed(f"{_opt} is set on {_mp}", actual=",".join(opts))
        return Outcome.failed(f"{_opt} not set on {_mp}", actual=",".join(opts), expected=_opt)

    return _chk


for _cid, _mp, _kind, _lvl in _PARTITION_CONTROLS:
    if _kind == _SEPARATE:
        _make_separate_check(_cid, _mp, _lvl)
    else:
        _make_mount_option_check(_cid, _mp, _kind, _lvl)


# --------------------------------------------------------------------------- #
# Shared permission helpers (used by 1.2, 1.4, 1.6)
# --------------------------------------------------------------------------- #
def _perm_ok(st, max_mode: int):
    """(ok, detail) for a stat against a max mode + root ownership. Absent = ok."""
    if not st.exists:
        return True, "not present"
    if not st.perm_at_most(max_mode):
        return False, f"mode {st.mode_str} (> {format(max_mode, '04o')})"
    if st.uid not in (0, -1) or st.gid not in (0, -1):
        return False, f"owner {st.owner or st.uid}:{st.group or st.gid} (expected root:root)"
    return True, f"mode {st.mode_str}, {st.owner or 'root'}:{st.group or 'root'}"


def _make_path_perm_check(cis_id, path, max_mode, title, section, *,
                          severity=Severity.LOW, level=Level.L1, tags=()):
    @check(id=cis_id, title=title, section=section, severity=severity, levels=(level,),
           rationale="Over-permissive ownership or mode on this path lets an unprivileged user "
                     "tamper with trusted configuration.",
           remediation=f"chmod {format(max_mode, 'o')} and chown root:root {path}.",
           tags=tags or ("permissions",))
    def _chk(ctx, _p=path, _max=max_mode):
        ok, detail = _perm_ok(ctx.stat(_p), _max)
        return Outcome.passed(f"{_p}: {detail}") if ok else \
            Outcome.failed(f"{_p}: {detail}", actual=detail, expected=f"<= {format(_max, '04o')} root:root")
    return _chk


def _make_dir_files_perm_check(cis_id, directory, max_mode, title, section, *,
                               severity=Severity.LOW, level=Level.L1, tags=()):
    """Check that every regular file under a directory is at most ``max_mode``/root."""
    @check(id=cis_id, title=title, section=section, severity=severity, levels=(level,),
           rationale="A world/group-writable or non-root file in this trusted directory can be "
                     "abused to subvert package trust or configuration.",
           remediation=f"chmod {format(max_mode, 'o')} and chown root:root the files under {directory}.",
           tags=tags or ("permissions",))
    def _chk(ctx, _d=directory, _max=max_mode):
        listing = ctx.sh(f"find {_d} -type f 2>/dev/null")
        files = [ln for ln in listing.out.splitlines() if ln.strip()]
        if not files:
            return Outcome.passed(f"No files under {_d} (or directory absent)")
        bad = []
        for f in files[:200]:
            ok, detail = _perm_ok(ctx.stat(f), _max)
            if not ok:
                bad.append(f"{f}: {detail}")
        if bad:
            return Outcome.failed(f"{len(bad)} file(s) under {_d} over-permissive",
                                  evidence=bad[:20], expected=f"<= {format(_max, '04o')} root:root")
        return Outcome.passed(f"All {len(files)} file(s) under {_d} are <= {format(_max, '04o')} root:root")
    return _chk


# --------------------------------------------------------------------------- #
# 1.2 Package Management
# --------------------------------------------------------------------------- #
@check(
    id="1.2.1.1",
    title="Ensure the sources.list and .sources files use the Signed-By option",
    section="1.2 Package Management",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    automated=False,
    rationale="Repositories pinned to a signing key cannot be silently swapped for a malicious mirror.",
    remediation="Add a 'Signed-By:' key reference to each APT source entry.",
    tags=("apt", "package-management", "ubuntu"),
)
def apt_sources_signed_by(ctx):
    return Outcome.manual("Verify each APT source (/etc/apt/sources.list*, *.sources) pins a Signed-By key.")


@check(
    id="1.2.1.2",
    title="Ensure weak dependencies are not automatically installed",
    section="1.2 Package Management",
    severity=Severity.LOW,
    levels=(Level.L2,),
    rationale="Recommended/suggested packages enlarge the attack surface beyond what is required.",
    remediation='Set APT::Install-Recommends "false"; and APT::Install-Suggests "false"; under /etc/apt/apt.conf.d/.',
    tags=("apt", "package-management", "ubuntu"),
)
def apt_weak_dependencies(ctx):
    res = ctx.run(["apt-config", "dump"])
    if not res.ok or not res.out:
        return Outcome.manual("apt-config unavailable; verify APT::Install-Recommends/Suggests are false")
    dump = res.out.lower()
    rec_off = 'apt::install-recommends "false"' in dump or 'apt::install-recommends "0"' in dump
    sug_off = 'apt::install-suggests "false"' in dump or 'apt::install-suggests "0"' in dump
    if rec_off and sug_off:
        return Outcome.passed("Install-Recommends and Install-Suggests are disabled")
    missing = [n for n, v in (("Install-Recommends", rec_off), ("Install-Suggests", sug_off)) if not v]
    return Outcome.failed(f"Weak dependencies still enabled: {', '.join(missing)}",
                          expected='APT::Install-Recommends/Suggests "false"')


# 1.2.1.3–1.2.1.9 — access to the APT trust material. Directories <= 0755, the
# sensitive auth.conf.d <= 0750 (files <= 0600), key/source files <= 0644.
_make_dir_files_perm_check("1.2.1.3", "/etc/apt/trusted.gpg.d", 0o644,
                           "Ensure access to gpg key files is configured", "1.2 Package Management",
                           tags=("apt", "permissions", "ubuntu"))
_make_path_perm_check("1.2.1.4", "/etc/apt/trusted.gpg.d", 0o755,
                      "Ensure access to /etc/apt/trusted.gpg.d directory is configured", "1.2 Package Management",
                      tags=("apt", "permissions", "ubuntu"))
_make_path_perm_check("1.2.1.5", "/etc/apt/auth.conf.d", 0o750,
                      "Ensure access to /etc/apt/auth.conf.d directory is configured", "1.2 Package Management",
                      tags=("apt", "permissions", "ubuntu"))
_make_dir_files_perm_check("1.2.1.6", "/etc/apt/auth.conf.d", 0o600,
                           "Ensure access to files in the /etc/apt/auth.conf.d directory is configured",
                           "1.2 Package Management", severity=Severity.MEDIUM, tags=("apt", "permissions", "ubuntu"))
_make_path_perm_check("1.2.1.7", "/usr/share/keyrings", 0o755,
                      "Ensure access to /usr/share/keyrings directory is configured", "1.2 Package Management",
                      tags=("apt", "permissions", "ubuntu"))
_make_path_perm_check("1.2.1.8", "/etc/apt/sources.list.d", 0o755,
                      "Ensure access to /etc/apt/sources.list.d directory is configured", "1.2 Package Management",
                      tags=("apt", "permissions", "ubuntu"))
_make_dir_files_perm_check("1.2.1.9", "/etc/apt/sources.list.d", 0o644,
                           "Ensure access to files in /etc/apt/sources.list.d is configured",
                           "1.2 Package Management", tags=("apt", "permissions", "ubuntu"))


@check(
    id="1.2.2.1",
    title="Ensure updates, patches, and additional security software are installed",
    section="1.2 Package Management",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    automated=False,
    rationale="Unpatched packages are the most commonly exploited weakness on any host.",
    remediation="apt update && apt -s upgrade, then apply outstanding security updates.",
    tags=("apt", "patching", "ubuntu"),
    attack=("T1190",),
)
def updates_installed(ctx):
    res = ctx.run(["sh", "-c", "apt-get -s upgrade 2>/dev/null | grep -c '^Inst'"])
    if res.ok and res.out.isdigit():
        n = int(res.out)
        if n == 0:
            return Outcome.passed("No pending package upgrades")
        return Outcome.warn(f"{n} package upgrade(s) pending — review and apply security updates", actual=n)
    return Outcome.manual("Verify pending updates with 'apt-get -s upgrade'")


# --------------------------------------------------------------------------- #
# 1.3 Mandatory Access Control (AppArmor)
# --------------------------------------------------------------------------- #
def _aa_status(ctx):
    return ctx.run(["aa-status"])


@check(
    id="1.3.1.1",
    title="Ensure AppArmor is installed",
    section="1.3 Mandatory Access Control",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    rationale="AppArmor confines programs to a limited set of resources, containing compromise.",
    remediation="apt install apparmor apparmor-utils",
    tags=("mac", "apparmor", "ubuntu"),
)
def apparmor_installed(ctx):
    if ctx.platform.mac_framework == "selinux":
        return Outcome.skip("Host uses SELinux, not AppArmor")
    have = ctx.package_installed("apparmor") and ctx.package_installed("apparmor-utils")
    if have:
        return Outcome.passed("apparmor and apparmor-utils are installed")
    if ctx.package_installed("apparmor"):
        return Outcome.warn("apparmor installed but apparmor-utils is missing", expected="both installed")
    return Outcome.failed("AppArmor is not installed", expected="apparmor + apparmor-utils installed")


@check(
    id="1.3.1.2",
    title="Ensure AppArmor is enabled in the bootloader configuration",
    section="1.3 Mandatory Access Control",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    rationale="Without 'apparmor=1 security=apparmor' on the kernel command line, profiles never load.",
    remediation="Add 'apparmor=1 security=apparmor' to GRUB_CMDLINE_LINUX and run update-grub.",
    tags=("mac", "apparmor", "ubuntu"),
)
def apparmor_enabled(ctx):
    if ctx.platform.mac_framework == "selinux":
        return Outcome.skip("Host uses SELinux, not AppArmor")
    res = _aa_status(ctx)
    if res.ok and "module is loaded" in res.combined.lower():
        return Outcome.passed("AppArmor module is loaded and active")
    cmdline = ctx.read_file("/proc/cmdline") or ""
    if "apparmor=1" in cmdline and "security=apparmor" in cmdline:
        return Outcome.passed("AppArmor enabled on the kernel command line", actual=cmdline.strip()[:120])
    if not ctx.is_root and not cmdline:
        return Outcome.manual("Cannot read AppArmor status without root; verify with 'aa-status'")
    return Outcome.failed("AppArmor is not enabled (module not loaded / not on cmdline)",
                          expected="apparmor=1 security=apparmor")


@check(
    id="1.3.1.3",
    title="Ensure all AppArmor profiles are in enforce or complain mode",
    section="1.3 Mandatory Access Control",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    rationale="A loaded profile that is neither enforcing nor complaining is doing nothing; no profile should be unconfined.",
    remediation="aa-enforce (or aa-complain) every profile under /etc/apparmor.d and resolve denials.",
    tags=("mac", "apparmor", "ubuntu"),
    attack=("T1562.001",),
)
def apparmor_profiles_active(ctx):
    if ctx.platform.mac_framework == "selinux":
        return Outcome.skip("Host uses SELinux, not AppArmor")
    if not ctx.is_root:
        return Outcome.manual("Root required to read AppArmor status; verify with 'aa-status'")
    res = _aa_status(ctx)
    if not res.ok:
        return Outcome.failed(f"AppArmor not active or aa-status unavailable ({res.error or 'non-zero exit'})")
    text = res.combined
    unconfined = _extract_int(text, "processes are unconfined")
    loaded = _extract_int(text, "profiles are loaded")
    enforce = _extract_int(text, "profiles are in enforce mode")
    complain = _extract_int(text, "profiles are in complain mode")
    if unconfined == 0 and loaded > 0 and (enforce + complain) >= loaded:
        return Outcome.passed(f"All {loaded} profiles enforce/complain; no unconfined processes")
    return Outcome.failed(
        f"{unconfined} unconfined process(es); {loaded} loaded, {enforce} enforce, {complain} complain",
        actual={"unconfined": unconfined, "loaded": loaded, "enforce": enforce, "complain": complain},
        expected={"unconfined": 0})


@check(
    id="1.3.1.4",
    title="Ensure apparmor_restrict_unprivileged_unconfined is enabled",
    section="1.3 Mandatory Access Control",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    rationale="Restricting unprivileged user namespaces stops an unconfined process from escaping confinement via a new userns.",
    remediation="Set kernel.apparmor_restrict_unprivileged_unconfined = 1 via /etc/sysctl.d and 'sysctl --system'.",
    tags=("mac", "apparmor", "kernel-hardening", "ubuntu"),
)
def apparmor_restrict_unconfined(ctx):
    if ctx.platform.mac_framework == "selinux":
        return Outcome.skip("Host uses SELinux, not AppArmor")
    val = ctx.sysctl("kernel.apparmor_restrict_unprivileged_unconfined")
    if val is None:
        return Outcome.manual("kernel.apparmor_restrict_unprivileged_unconfined not readable on this kernel")
    if val == "1":
        return Outcome.passed("apparmor_restrict_unprivileged_unconfined = 1", actual=val)
    return Outcome.failed(f"apparmor_restrict_unprivileged_unconfined = {val}", actual=val, expected="1")


# --------------------------------------------------------------------------- #
# 1.4 Bootloader
# --------------------------------------------------------------------------- #
@check(
    id="1.4.1",
    title="Ensure bootloader password is set",
    section="1.4 Bootloader",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    profiles=(Profile.SERVER, Profile.WORKSTATION),
    rationale="A GRUB password blocks an attacker with console access from editing boot params (e.g. init=/bin/bash).",
    remediation="Run grub-mkpasswd-pbkdf2 and add a 'password_pbkdf2' entry under /etc/grub.d/.",
    tags=("bootloader", "grub"),
    attack=("T1542",),
)
def bootloader_password(ctx):
    if ctx.platform.is_container:
        return Outcome.skip("No bootloader inside a container")
    for path in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"):
        content = ctx.read_file(path)
        if content and "password_pbkdf2" in content:
            return Outcome.passed("GRUB superuser password is configured", actual=path)
    snippets = ctx.sh("grep -rl password_pbkdf2 /etc/grub.d/ 2>/dev/null")
    if snippets.out:
        return Outcome.passed("GRUB password configured in /etc/grub.d", actual=snippets.out)
    if not ctx.is_root:
        return Outcome.manual("Cannot read grub.cfg without root; verify password_pbkdf2 is set")
    return Outcome.failed("No GRUB bootloader password found", expected="password_pbkdf2 set")


@check(
    id="1.4.2",
    title="Ensure access to bootloader config is configured",
    section="1.4 Bootloader",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    rationale="A world-readable grub.cfg exposes the bootloader password hash; writable lets an attacker alter boot.",
    remediation="chown root:root and chmod u-x,go-rwx /boot/grub/grub.cfg.",
    tags=("bootloader", "grub", "permissions"),
)
def bootloader_config_perms(ctx):
    if ctx.platform.is_container:
        return Outcome.skip("No bootloader inside a container")
    for path in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"):
        st = ctx.stat(path)
        if st.exists:
            ok, detail = _perm_ok(st, 0o600)
            return Outcome.passed(f"{path}: {detail}") if ok else \
                Outcome.failed(f"{path}: {detail}", actual=detail, expected="<= 0600 root:root")
    return Outcome.manual("grub.cfg not found at the standard paths; verify its permissions are <= 0600 root:root")


# --------------------------------------------------------------------------- #
# 1.5 Additional Process Hardening (v2.0.0 numbering)
# --------------------------------------------------------------------------- #
_SYSCTL_CONTROLS = [
    ("1.5.1", "fs.protected_hardlinks", "1", "Ensure fs.protected_hardlinks is configured", Severity.LOW),
    ("1.5.2", "fs.protected_symlinks", "1", "Ensure fs.protected_symlinks is configured", Severity.LOW),
    ("1.5.3", "kernel.yama.ptrace_scope", ("1", "2", "3"), "Ensure kernel.yama.ptrace_scope is configured", Severity.MEDIUM),
    ("1.5.4", "fs.suid_dumpable", "0", "Ensure fs.suid_dumpable is configured", Severity.MEDIUM),
    ("1.5.5", "kernel.dmesg_restrict", "1", "Ensure kernel.dmesg_restrict is configured", Severity.LOW),
    ("1.5.8", "kernel.kptr_restrict", ("1", "2"), "Ensure kernel.kptr_restrict is configured", Severity.LOW),
    ("1.5.9", "kernel.randomize_va_space", "2", "Ensure kernel.randomize_va_space is configured", Severity.MEDIUM),
]


def _make_sysctl_check(cis_id, key, expected, title, severity):
    accepted = (expected,) if isinstance(expected, str) else tuple(expected)

    @check(
        id=cis_id,
        title=title,
        section="1.5 Additional Process Hardening",
        severity=severity,
        levels=(Level.L1,),
        rationale=f"The sysctl {key} hardens the kernel against a known exploitation technique.",
        remediation=f"Set '{key} = {accepted[0]}' in /etc/sysctl.d/ and run 'sysctl --system'.",
        tags=("sysctl", "kernel-hardening"),
    )
    def _chk(ctx, _key=key, _accepted=accepted):
        value = ctx.sysctl(_key)
        if value is None:
            return Outcome.warn(f"{_key} is not available on this kernel", expected=_accepted[0])
        if value in _accepted:
            return Outcome.passed(f"{_key} = {value}", actual=value, expected=_accepted[0])
        return Outcome.failed(f"{_key} = {value}", actual=value, expected=" or ".join(_accepted))

    return _chk


for _row in _SYSCTL_CONTROLS:
    _make_sysctl_check(*_row)


@check(
    id="1.5.6",
    title="Ensure prelink is not installed",
    section="1.5 Additional Process Hardening",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="prelink alters binaries on disk, breaking integrity checks and weakening ASLR.",
    remediation="apt purge prelink (after 'prelink -ua' to restore binaries).",
    tags=("package", "kernel-hardening", "ubuntu"),
)
def prelink_not_installed(ctx):
    if ctx.package_installed("prelink"):
        return Outcome.failed("prelink is installed", expected="not installed")
    return Outcome.passed("prelink is not installed")


@check(
    id="1.5.7",
    title="Ensure Automatic Error Reporting is not enabled",
    section="1.5 Additional Process Hardening",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="Apport collects core dumps and stack traces that can contain sensitive memory contents.",
    remediation="Set 'enabled=0' in /etc/default/apport and 'systemctl stop --now apport.service'.",
    tags=("apport", "ubuntu"),
)
def apport_disabled(ctx):
    if not ctx.package_installed("apport"):
        return Outcome.passed("apport is not installed")
    cfg = ctx.read_file("/etc/default/apport") or ""
    enabled_nonzero = any(
        ln.strip().replace(" ", "").startswith("enabled=") and not ln.strip().replace(" ", "").startswith("enabled=0")
        for ln in cfg.splitlines())
    active = ctx.service_active("apport.service") or ctx.service_active("apport")
    if not enabled_nonzero and not active:
        return Outcome.passed("Apport is disabled (enabled=0) and not active")
    return Outcome.failed(
        f"Apport is { 'active' if active else 'enabled' }",
        actual={"enabled_nonzero": enabled_nonzero, "active": active}, expected="enabled=0 and inactive")


def _coredump_conf_value(ctx, key):
    """Value of <key> from /etc/systemd/coredump.conf (+ .d), or None."""
    text = ctx.read_file("/etc/systemd/coredump.conf") or ""
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        if k.strip().lower() == key.lower():
            return v.strip()
    return None


@check(
    id="1.5.11",
    title="Ensure systemd-coredump ProcessSizeMax is configured",
    section="1.5 Additional Process Hardening",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="ProcessSizeMax=0 stops systemd-coredump from processing core dumps, which may hold secrets.",
    remediation="Set 'ProcessSizeMax=0' in /etc/systemd/coredump.conf and 'systemctl daemon-reload'.",
    tags=("coredump", "ubuntu"),
)
def coredump_processsizemax(ctx):
    val = _coredump_conf_value(ctx, "ProcessSizeMax")
    if val == "0":
        return Outcome.passed("ProcessSizeMax = 0", actual=val)
    if val is None:
        return Outcome.failed("ProcessSizeMax not set in coredump.conf", expected="ProcessSizeMax=0")
    return Outcome.failed(f"ProcessSizeMax = {val}", actual=val, expected="0")


@check(
    id="1.5.12",
    title="Ensure systemd-coredump Storage is configured",
    section="1.5 Additional Process Hardening",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="Storage=none prevents core dumps (which can contain sensitive memory) from being written to disk.",
    remediation="Set 'Storage=none' in /etc/systemd/coredump.conf and 'systemctl daemon-reload'.",
    tags=("coredump", "ubuntu"),
)
def coredump_storage(ctx):
    val = _coredump_conf_value(ctx, "Storage")
    if val == "none":
        return Outcome.passed("Storage = none", actual=val)
    if val is None:
        return Outcome.failed("Storage not set in coredump.conf", expected="Storage=none")
    return Outcome.failed(f"Storage = {val}", actual=val, expected="none")


@check(
    id="1.5.10",
    title="Ensure core file size limit is configured",
    section="1.5 Additional Process Hardening",
    severity=Severity.LOW,
    levels=(Level.L1,),
    automated=False,
    rationale="A hard limit of 0 on the core file size prevents setuid programs leaking memory into core dumps.",
    remediation="Add '* hard core 0' to /etc/security/limits.conf or a file in /etc/security/limits.d.",
    tags=("limits", "coredump"),
)
def core_file_size(ctx):
    blob = (ctx.read_file("/etc/security/limits.conf") or "")
    extra = ctx.sh("grep -rh 'hard *core' /etc/security/limits.d 2>/dev/null")
    haystack = blob + "\n" + (extra.out or "")
    for ln in haystack.splitlines():
        parts = ln.split()
        if len(parts) >= 4 and parts[1] == "hard" and parts[2] == "core" and parts[3] == "0":
            return Outcome.passed("A 'hard core 0' limit is configured", actual=ln.strip())
    return Outcome.manual("No 'hard core 0' limit found; confirm core dumps are restricted")


# --------------------------------------------------------------------------- #
# 1.6 Command Line Warning Banners
# --------------------------------------------------------------------------- #
def _banner_check(path, cis_id, label):
    @check(
        id=cis_id,
        title=f"Ensure {label} is configured",
        section="1.6 Warning Banners",
        severity=Severity.LOW,
        levels=(Level.L1,),
        rationale="A legal warning banner supports prosecution and deters casual misuse; it must not leak OS/version.",
        remediation=f"Set an approved banner in {path} that excludes OS, version and kernel details.",
        tags=("banner",),
    )
    def _chk(ctx, _path=path):
        content = ctx.read_file(_path)
        if content is None or not content.strip():
            return Outcome.failed(f"{_path} is missing or empty", expected="non-empty approved banner")
        lowered = content.lower()
        leaks = [tok for tok in ("\\m", "\\r", "\\s", "\\v", "ubuntu", "linux") if tok in lowered]
        if leaks:
            return Outcome.warn(f"{_path} present but may leak system info ({', '.join(leaks)})",
                                actual=content.strip()[:120])
        return Outcome.passed(f"{_path} contains an approved banner")
    return _chk


_banner_check("/etc/motd", "1.6.1", "/etc/motd")
_banner_check("/etc/issue", "1.6.2", "/etc/issue")
_banner_check("/etc/issue.net", "1.6.3", "/etc/issue.net")


@check(
    id="1.6.4",
    title="Ensure access to /etc/motd is configured",
    section="1.6 Warning Banners",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="The dynamic MOTD must not be writable by non-root or it can run attacker code at login.",
    remediation="Disable motd-news and ensure /etc/update-motd.d scripts are root-owned and not world-writable.",
    tags=("banner", "ubuntu"),
)
def pam_motd_configured(ctx):
    news = ctx.read_file("/etc/default/motd-news") or ""
    if any(ln.strip().replace(" ", "").lower() == "enabled=1" for ln in news.splitlines()):
        return Outcome.warn("motd-news is enabled (fetches remote content at login)", expected="ENABLED=0")
    listing = ctx.sh("find /etc/update-motd.d -type f 2>/dev/null")
    bad = []
    for f in [ln for ln in listing.out.splitlines() if ln.strip()][:50]:
        st = ctx.stat(f)
        if st.exists and (st.mode & 0o022 or st.uid not in (0, -1)):
            bad.append(f"{f}: mode {st.mode_str} {st.owner}:{st.group}")
    if bad:
        return Outcome.failed("Writable/non-root update-motd.d script(s)", evidence=bad[:20])
    return Outcome.passed("MOTD is configured (no remote motd-news, scripts root-owned)")


@check(
    id="1.6.5",
    title="Ensure sshd warning banner is configured",
    section="1.6 Warning Banners",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="A pre-auth SSH banner presents the legal warning before login.",
    remediation="Set 'Banner /etc/issue.net' in /etc/ssh/sshd_config and reload sshd.",
    tags=("banner", "ssh"),
)
def sshd_banner(ctx):
    cfg = ctx.run(["sshd", "-T"])
    if cfg.ok and cfg.out:
        for ln in cfg.out.splitlines():
            if ln.lower().startswith("banner "):
                val = ln.split(None, 1)[1].strip()
                if val.lower() != "none" and val:
                    return Outcome.passed(f"sshd Banner is set to {val}", actual=val)
                return Outcome.failed("sshd Banner is none", expected="a banner path, e.g. /etc/issue.net")
        return Outcome.failed("sshd Banner not configured", expected="Banner /etc/issue.net")
    return Outcome.manual("Could not read 'sshd -T'; verify Banner is set in sshd_config")


# 1.6.6–1.6.10 — access (perms) to the banner files.
_make_path_perm_check("1.6.6", "/etc/motd", 0o644,
                      "Ensure access to /etc/motd is configured", "1.6 Warning Banners", tags=("banner", "permissions"))
_make_path_perm_check("1.6.7", "/etc/issue", 0o644,
                      "Ensure access to /etc/issue is configured", "1.6 Warning Banners", tags=("banner", "permissions"))
_make_path_perm_check("1.6.8", "/etc/issue.net", 0o644,
                      "Ensure access to /etc/issue.net is configured", "1.6 Warning Banners", tags=("banner", "permissions"))
_make_dir_files_perm_check("1.6.9", "/etc/update-motd.d", 0o755,
                           "Ensure access to /etc/update-motd.d files is configured", "1.6 Warning Banners",
                           tags=("banner", "permissions"))


@check(
    id="1.6.10",
    title="Ensure access to the sshd warning banner file is configured",
    section="1.6 Warning Banners",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="A writable banner file lets an attacker alter the legal notice presented at login.",
    remediation="chown root:root and chmod 0644 the file named by the sshd Banner directive.",
    tags=("banner", "permissions", "ssh"),
)
def sshd_banner_perms(ctx):
    cfg = ctx.run(["sshd", "-T"])
    path = "/etc/issue.net"
    if cfg.ok and cfg.out:
        for ln in cfg.out.splitlines():
            if ln.lower().startswith("banner ") and ln.split(None, 1)[1].strip().lower() != "none":
                path = ln.split(None, 1)[1].strip()
    ok, detail = _perm_ok(ctx.stat(path), 0o644)
    return Outcome.passed(f"{path}: {detail}") if ok else \
        Outcome.failed(f"{path}: {detail}", actual=detail, expected="<= 0644 root:root")


# --------------------------------------------------------------------------- #
# 1.7 GNOME Display Manager
# --------------------------------------------------------------------------- #
# All gate on GDM being present: on a server without a display manager these are
# not applicable (PASS). When GDM is installed, settings are verified best-effort.
def _gdm_check(cis_id, title, verify, severity=Severity.LOW):
    @check(id=cis_id, title=title, section="1.7 GNOME Display Manager", severity=severity,
           levels=(Level.L1,), profiles=(Profile.WORKSTATION,),
           rationale="The login screen must not leak the user list, auto-run removable media, or skip the lock.",
           remediation="Apply the corresponding org.gnome dconf setting under /etc/dconf/db/gdm.d and lock it.",
           tags=("gdm", "gnome", "ubuntu"))
    def _chk(ctx, _verify=verify):
        if not (ctx.package_installed("gdm3") or ctx.package_installed("gdm")):
            return Outcome.passed("GDM is not installed (control not applicable)")
        return _verify(ctx)
    return _chk


def _dconf_contains(ctx, needle):
    blob = ctx.sh("grep -rh . /etc/dconf/db/gdm.d 2>/dev/null")
    return needle in (blob.out or "")


_gdm_check("1.7.1", "Ensure GDM login banner is configured",
           lambda ctx: (Outcome.passed("GDM banner-message-enable=true")
                        if _dconf_contains(ctx, "banner-message-enable=true")
                        else Outcome.manual("Verify GDM banner-message-enable=true and banner-message-text")))
_gdm_check("1.7.2", "Ensure GDM disable-user-list option is enabled",
           lambda ctx: (Outcome.passed("GDM disable-user-list=true")
                        if _dconf_contains(ctx, "disable-user-list=true")
                        else Outcome.failed("GDM disable-user-list not enabled", expected="disable-user-list=true")))
_gdm_check("1.7.3", "Ensure GDM screen locks when the user is idle",
           lambda ctx: (Outcome.passed("GDM idle/lock-delay configured")
                        if _dconf_contains(ctx, "lock-delay") or _dconf_contains(ctx, "idle-delay")
                        else Outcome.manual("Verify GDM idle-delay and lock-delay are configured")))
_gdm_check("1.7.4", "Ensure GDM disables automatic mounting of removable media",
           lambda ctx: (Outcome.passed("GDM automount disabled")
                        if _dconf_contains(ctx, "automount=false") or _dconf_contains(ctx, "automount-open=false")
                        else Outcome.manual("Verify GDM automount=false and automount-open=false")))
_gdm_check("1.7.5", "Ensure GDM autorun-never is enabled",
           lambda ctx: (Outcome.passed("GDM autorun-never=true")
                        if _dconf_contains(ctx, "autorun-never=true")
                        else Outcome.manual("Verify GDM autorun-never=true")))


@check(
    id="1.7.6",
    title="Ensure XDMCP is not enabled",
    section="1.7 GNOME Display Manager",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    profiles=(Profile.WORKSTATION,),
    rationale="XDMCP serves unencrypted X sessions over the network and must not be enabled.",
    remediation="Remove any 'Enable=true' under the [xdmcp] section of /etc/gdm3/custom.conf.",
    tags=("gdm", "gnome", "ubuntu"),
    attack=("T1021",),
)
def gdm_xdmcp_disabled(ctx):
    if not (ctx.package_installed("gdm3") or ctx.package_installed("gdm")):
        return Outcome.passed("GDM is not installed (control not applicable)")
    cfg = ctx.read_file("/etc/gdm3/custom.conf") or ""
    in_xdmcp = False
    for ln in cfg.splitlines():
        s = ln.strip().lower()
        if s.startswith("["):
            in_xdmcp = s == "[xdmcp]"
        elif in_xdmcp and s.replace(" ", "") == "enable=true":
            return Outcome.failed("XDMCP is enabled in /etc/gdm3/custom.conf", expected="XDMCP disabled")
    return Outcome.passed("XDMCP is not enabled")


@check(
    id="1.7.7",
    title="Ensure GDM does not allow X11 (Xwayland) where Wayland is available",
    section="1.7 GNOME Display Manager",
    severity=Severity.LOW,
    levels=(Level.L2,),
    profiles=(Profile.WORKSTATION,),
    automated=False,
    rationale="X11/Xwayland exposes a weaker isolation model than Wayland for the login session.",
    remediation="Review WaylandEnable in /etc/gdm3/custom.conf per site policy.",
    tags=("gdm", "gnome", "ubuntu"),
)
def gdm_xwayland(ctx):
    if not (ctx.package_installed("gdm3") or ctx.package_installed("gdm")):
        return Outcome.passed("GDM is not installed (control not applicable)")
    return Outcome.manual("Review GDM WaylandEnable/Xwayland configuration against site policy")


# --------------------------------------------------------------------------- #
def _extract_int(text: str, needle: str) -> int:
    """Pull the integer that precedes ``needle`` in aa-status-style output."""
    for line in text.splitlines():
        if needle in line:
            for token in line.split():
                if token.isdigit():
                    return int(token)
    return 0
