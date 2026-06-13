"""Kernel and runtime hardening — the exploit-mitigation surface.

CIS covers the network sysctls; this module covers the kernel knobs that decide
how *exploitable* the box is once an attacker has a shell: address-space
randomisation, whether one process can read another's memory (ptrace), whether
core dumps can leak secrets, whether kernel addresses and the ring buffer leak,
unprivileged user namespaces and BPF (broad exploit surface), swap encryption,
and whether the runtime mount options on scratch filesystems are actually
applied. Each reads a live value (sysctl / /proc) and degrades to MANUAL when
the value can't be read, never crashing.

These are defence-in-depth: a missing mitigation is rarely a vulnerability by
itself, but it is the difference between an exploit attempt that works and one
that doesn't — so most sit at LOW/MEDIUM and several at L2.
"""

from __future__ import annotations

from typing import List, Optional

from ...core import Confidence, Level, Outcome, Severity, check
from ..extended import EXTENDED_FRAMEWORK


def _intval(ctx, key: str) -> Optional[int]:
    """Read a sysctl as an int, or None if unavailable/non-numeric."""
    raw = ctx.sysctl(key)
    if raw is None:
        return None
    raw = raw.strip().split()[0] if raw.strip() else ""
    try:
        return int(raw)
    except ValueError:
        return None


@check(
    id="EXT-HARD-1",
    title="Ensure full ASLR is enabled (kernel.randomize_va_space=2)",
    section="EXT.Hardening",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Address-space layout randomisation is the baseline mitigation that makes memory-corruption exploits unreliable. Value 2 randomises stack, mmap, and heap; anything less weakens every userspace exploit defence.",
    remediation="Set 'kernel.randomize_va_space = 2' in /etc/sysctl.d and apply with sysctl --system.",
    tags=("hardening", "kernel", "exploit-mitigation"),
    attack=("T1203",),
)
def aslr(ctx):
    v = _intval(ctx, "kernel.randomize_va_space")
    if v is None:
        return Outcome.manual("Could not read kernel.randomize_va_space")
    if v == 2:
        return Outcome.passed("Full ASLR is enabled (randomize_va_space=2)")
    return Outcome.failed(f"ASLR is weakened (randomize_va_space={v}, expected 2)", actual=v, expected=2)


@check(
    id="EXT-HARD-2",
    title="Ensure ptrace is restricted (kernel.yama.ptrace_scope>=1)",
    section="EXT.Hardening",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="ptrace_scope=0 lets any process read another process's memory with the same uid, which is exactly how credential scrapers (mimipenguin, gdb attaches) pull secrets out of running daemons. >=1 confines ptrace to child processes.",
    remediation="Set 'kernel.yama.ptrace_scope = 1' (or higher) in /etc/sysctl.d and apply.",
    tags=("hardening", "kernel", "credential-protection"),
    attack=("T1003",),
)
def ptrace_scope(ctx):
    v = _intval(ctx, "kernel.yama.ptrace_scope")
    if v is None:
        return Outcome.manual("Could not read kernel.yama.ptrace_scope (Yama LSM may be absent)")
    if v >= 1:
        return Outcome.passed(f"ptrace is restricted (ptrace_scope={v})")
    return Outcome.failed("ptrace is unrestricted (ptrace_scope=0) — processes can scrape each other's memory",
                          actual=v, expected=">=1")


@check(
    id="EXT-HARD-3",
    title="Ensure setuid core dumps are disabled",
    section="EXT.Hardening",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A core dump of a setuid process can contain passwords and keys held in memory. fs.suid_dumpable must be 0; a core_pattern that pipes to a world-writable handler can also be abused.",
    remediation="Set 'fs.suid_dumpable = 0' and ensure kernel.core_pattern does not pipe to a user-writable program.",
    tags=("hardening", "kernel", "credential-protection"),
    attack=("T1003",),
)
def core_dumps(ctx):
    v = _intval(ctx, "fs.suid_dumpable")
    problems: List[str] = []
    if v is None:
        return Outcome.manual("Could not read fs.suid_dumpable")
    if v != 0:
        problems.append(f"fs.suid_dumpable={v} (expected 0) — setuid processes can dump core")
    pattern = ctx.sysctl("kernel.core_pattern")
    if pattern and pattern.strip().startswith("|"):
        problems.append(f"kernel.core_pattern pipes cores to a handler: {pattern.strip()[:80]} (verify it is root-owned)")
    if not problems:
        return Outcome.passed("setuid core dumps are disabled")
    return Outcome.failed("; ".join(problems), actual=v, expected=0, confidence=Confidence.LIKELY)


@check(
    id="EXT-HARD-4",
    title="Ensure kernel pointers and dmesg are restricted",
    section="EXT.Hardening",
    severity=Severity.LOW,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="kptr_restrict hides kernel addresses from unprivileged users (defeating KASLR-bypass infoleaks) and dmesg_restrict stops them reading the kernel ring buffer (which leaks addresses and device info exploits rely on).",
    remediation="Set 'kernel.kptr_restrict = 1' (or 2) and 'kernel.dmesg_restrict = 1' in /etc/sysctl.d.",
    tags=("hardening", "kernel", "info-leak"),
    attack=("T1082",),
)
def kernel_info_leaks(ctx):
    kptr = _intval(ctx, "kernel.kptr_restrict")
    dmesg = _intval(ctx, "kernel.dmesg_restrict")
    if kptr is None and dmesg is None:
        return Outcome.manual("Could not read kptr_restrict / dmesg_restrict")
    problems: List[str] = []
    if kptr is not None and kptr < 1:
        problems.append(f"kernel.kptr_restrict={kptr} (expected >=1) — kernel addresses leak to users")
    if dmesg is not None and dmesg < 1:
        problems.append(f"kernel.dmesg_restrict={dmesg} (expected 1) — unprivileged users can read the kernel ring buffer")
    if not problems:
        return Outcome.passed("Kernel pointers and dmesg are restricted")
    return Outcome.failed("; ".join(problems), confidence=Confidence.LIKELY)


@check(
    id="EXT-HARD-5",
    title="Review unprivileged user namespaces",
    section="EXT.Hardening",
    severity=Severity.MEDIUM,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Unprivileged user namespaces are a large kernel attack surface — many local-root exploits (overlayfs, nftables, io_uring) depend on a user being able to create them. Disabling them removes that surface where containers/sandboxes don't need it.",
    remediation="If unprivileged containers are not required, set 'kernel.unprivileged_userns_clone = 0' or 'user.max_user_namespaces = 0'. Weigh against sandbox/browser needs.",
    tags=("hardening", "kernel", "exploit-surface"),
    attack=("T1068",),
)
def unprivileged_userns(ctx):
    clone = _intval(ctx, "kernel.unprivileged_userns_clone")
    maxns = _intval(ctx, "user.max_user_namespaces")
    if clone is None and maxns is None:
        return Outcome.manual("Could not read user-namespace sysctls")
    enabled = (clone == 1) or (maxns is not None and maxns > 0 and clone is None)
    if not enabled:
        return Outcome.passed("Unprivileged user namespaces are disabled")
    return Outcome.warn(
        "Unprivileged user namespaces are enabled — a broad local-exploit surface (disable if not needed)",
        actual={"unprivileged_userns_clone": clone, "max_user_namespaces": maxns},
        confidence=Confidence.POSSIBLE,
    )


@check(
    id="EXT-HARD-6",
    title="Ensure perf_event access is restricted",
    section="EXT.Hardening",
    severity=Severity.LOW,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="The perf subsystem has a long history of local-root CVEs. kernel.perf_event_paranoid >= 2 (or 3, Debian-hardened) blocks unprivileged access to it.",
    remediation="Set 'kernel.perf_event_paranoid = 2' (or 3) in /etc/sysctl.d.",
    tags=("hardening", "kernel", "exploit-surface"),
    attack=("T1068",),
)
def perf_event_paranoid(ctx):
    v = _intval(ctx, "kernel.perf_event_paranoid")
    if v is None:
        return Outcome.manual("Could not read kernel.perf_event_paranoid")
    if v >= 2:
        return Outcome.passed(f"perf_event access is restricted (paranoid={v})")
    return Outcome.failed(f"perf_event is broadly accessible (paranoid={v}, expected >=2)", actual=v, expected=">=2")


@check(
    id="EXT-HARD-7",
    title="Ensure unprivileged BPF is disabled",
    section="EXT.Hardening",
    severity=Severity.LOW,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="The unprivileged bpf() syscall is another recurring local-root surface (verifier bugs). kernel.unprivileged_bpf_disabled = 1 closes it to non-root.",
    remediation="Set 'kernel.unprivileged_bpf_disabled = 1' in /etc/sysctl.d.",
    tags=("hardening", "kernel", "exploit-surface"),
    attack=("T1068",),
)
def unprivileged_bpf(ctx):
    v = _intval(ctx, "kernel.unprivileged_bpf_disabled")
    if v is None:
        return Outcome.manual("Could not read kernel.unprivileged_bpf_disabled")
    if v >= 1:
        return Outcome.passed(f"Unprivileged BPF is disabled (={v})")
    return Outcome.failed("Unprivileged BPF is enabled (=0) — exposes the bpf() local-exploit surface",
                          actual=v, expected=">=1")


@check(
    id="EXT-HARD-8",
    title="Ensure swap is encrypted",
    section="EXT.Hardening",
    severity=Severity.MEDIUM,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Anything in RAM — including passwords and keys — can be paged out to swap. Unencrypted swap on disk is a place those secrets persist where disk encryption or memory protections don't reach.",
    remediation="Use an encrypted swap device (dm-crypt / a /dev/mapper swap, or systemd-cryptsetup), or disable swap where appropriate.",
    tags=("hardening", "encryption", "credential-protection"),
    attack=("T1003",),
)
def swap_encryption(ctx):
    content = ctx.read_file("/proc/swaps")
    if content is None:
        return Outcome.manual("Could not read /proc/swaps")
    lines = [l for l in content.splitlines()[1:] if l.strip()]
    if not lines:
        return Outcome.passed("No active swap (nothing to leak to disk)")
    unencrypted = []
    for line in lines:
        dev = line.split()[0]
        # dm-crypt swap surfaces as /dev/mapper/* or /dev/dm-*; a plain partition does not.
        if not (dev.startswith("/dev/mapper/") or dev.startswith("/dev/dm-")):
            unencrypted.append(dev)
    if not unencrypted:
        return Outcome.passed("All active swap is on encrypted (dm-crypt) devices")
    return Outcome.warn(
        f"{len(unencrypted)} swap device(s) appear unencrypted: {', '.join(unencrypted)}",
        evidence=unencrypted,
        actual=unencrypted,
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-HARD-9",
    title="Ensure scratch filesystems are mounted nodev/nosuid/noexec",
    section="EXT.Hardening",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="/tmp, /var/tmp and /dev/shm are world-writable; without nodev,nosuid,noexec actually applied at runtime, an attacker can drop and run a binary or a setuid payload there. fstab can say one thing while the live mount says another, so this checks /proc/mounts.",
    remediation="Mount /tmp, /var/tmp and /dev/shm with nodev,nosuid,noexec and reload so the runtime options match.",
    tags=("hardening", "mount", "filesystem"),
    attack=("T1204",),
)
def scratch_mount_options(ctx):
    content = ctx.read_file("/proc/mounts")
    if content is None:
        return Outcome.manual("Could not read /proc/mounts")
    want = {"nodev", "nosuid", "noexec"}
    mounts = {}
    for line in content.splitlines():
        cols = line.split()
        if len(cols) >= 4:
            mounts[cols[1]] = set(cols[3].split(","))
    problems: List[str] = []
    for mp in ("/tmp", "/var/tmp", "/dev/shm"):
        if mp not in mounts:
            problems.append(f"{mp} is not a separate mount (cannot enforce nodev/nosuid/noexec)")
            continue
        missing = want - mounts[mp]
        if missing:
            problems.append(f"{mp} is missing {','.join(sorted(missing))}")
    if not problems:
        return Outcome.passed("/tmp, /var/tmp and /dev/shm are mounted nodev,nosuid,noexec")
    return Outcome.warn(
        f"{len(problems)} scratch filesystem(s) lack hardening mount options",
        evidence=problems,
        actual=problems,
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-HARD-10",
    title="Surface the running kernel for privilege-escalation CVE review",
    section="EXT.Hardening",
    severity=Severity.INFO,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    automated=False,
    rationale=(
        "The exact running kernel determines exposure to local-root CVEs (Dirty Pipe, OverlayFS, nf_tables, "
        "io_uring, …). This check reports the running version for review against your patch source — it does "
        "NOT ship a vulnerability database, so it makes no exploitability claim of its own."),
    remediation="Compare the reported kernel against your distro's security advisories (e.g. Ubuntu USN) and apply kernel updates / reboot if behind.",
    tags=("hardening", "kernel", "patching"),
    attack=("T1068",),
)
def kernel_cve_advisory(ctx):
    release = ctx.run(["uname", "-r"]).out.strip()
    if not release:
        return Outcome.manual("Could not read the running kernel version (uname -r)")
    return Outcome.manual(
        f"Running kernel {release} — verify against your distro's local-privilege-escalation advisories",
        evidence=[f"uname -r: {release}",
                  "Review against e.g. Ubuntu USN / 'pro security-status' for the running version."],
        actual=release,
    )
