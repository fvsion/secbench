"""Persistence and backdoor hunting — the "is something already living here?" lens.

The privilege checks ask *can an attacker escalate*; these ask *has an attacker
already established a foothold and arranged to keep it*. They hunt the common
Linux persistence mechanisms a compromise leaves behind: a cron line that pulls
and runs a payload, a planted rc.local stanza, a tampered PAM stack, hidden
files in scratch directories, the immutable bit hiding a dropped file, a
world-writable binary on PATH, drifted/replaced system binaries, and writable
MOTD/profile.d scripts that run on every login.

These are heuristics, not verdicts — each finding is a *lead* to investigate,
marked with a realistic confidence. Sources that need root or aren't present
degrade to MANUAL rather than crashing, matching the rest of the suite.
"""

from __future__ import annotations

import re
from typing import List

from ...core import Confidence, Level, Outcome, Severity, check
from ..extended import EXTENDED_FRAMEWORK

# Command fragments that, inside a scheduled job or login script, are a strong
# "fetch-and-execute payload" signal — the shape of a downloader/backdoor.
_SUSPICIOUS_CMD_RE = re.compile(
    r"(?i)("
    r"curl\s[^|]*\|\s*(ba)?sh|wget\s[^|]*\|\s*(ba)?sh|"      # curl|bash / wget|sh
    r"\bbase64\b\s+-d|\bbase64\b\s+--decode|"                # base64 -d payloads
    r"\bnc\b.*\s-e\b|ncat\b.*\s-e\b|"                        # netcat reverse shell
    r"/dev/tcp/|"                                            # bash /dev/tcp backdoor
    r"\beval\b.*\$\(|python[0-9]?\s+-c\s+.*(socket|os\.system)|"
    r"\bmkfifo\b.*\|\s*(ba)?sh"
    r")"
)


@check(
    id="EXT-PERS-1",
    title="Detect fetch-and-execute payloads in scheduled jobs",
    section="EXT.Persistence",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A cron line that pipes curl/wget into a shell, decodes a base64 blob, or opens /dev/tcp is the classic downloader-and-backdoor pattern — legitimate jobs almost never do this.",
    remediation="Investigate the job and its target URL/payload; remove it and hunt for related artifacts if it is not a known, trusted task.",
    tags=("persistence", "cron", "backdoor"),
    attack=("T1053.003",),
)
def suspicious_cron_content(ctx):
    paths: List[str] = ["/etc/crontab"]
    for pattern in ("/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
                    "/etc/cron.weekly/*", "/etc/cron.monthly/*",
                    "/var/spool/cron/crontabs/*", "/var/spool/cron/*"):
        paths.extend(ctx.glob(pattern))
    findings: List[str] = []
    seen = set()
    for path in paths[:300]:
        if path in seen:
            continue
        seen.add(path)
        content = ctx.read_file(path, max_bytes=128_000)
        if not content:
            continue
        for lineno, line in enumerate(content.splitlines(), start=1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if _SUSPICIOUS_CMD_RE.search(s):
                findings.append(f"{path}:{lineno} — {s[:160]}")
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed("No fetch-and-execute payloads found in scheduled jobs")
    return Outcome.failed(
        f"{len(findings)} scheduled job(s) match a downloader/backdoor pattern",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-PERS-2",
    title="Detect unexpected commands in rc.local and init scripts",
    section="EXT.Persistence",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="/etc/rc.local runs at boot as root and is a favourite persistence hook; on a modern systemd host it should normally be empty or absent. Active commands there warrant review.",
    remediation="Confirm any rc.local / init-script commands are intentional; move legitimate startup work into a reviewed systemd unit.",
    tags=("persistence", "boot"),
    attack=("T1037",),
)
def rc_local_content(ctx):
    findings: List[str] = []
    for path in ["/etc/rc.local", "/etc/rc.d/rc.local"]:
        content = ctx.read_file(path)
        if not content:
            continue
        for lineno, line in enumerate(content.splitlines(), start=1):
            s = line.strip()
            if not s or s.startswith("#") or s in ("exit 0", "#!/bin/sh", "#!/bin/bash"):
                continue
            findings.append(f"{path}:{lineno} — {s[:160]}")
    if not findings:
        return Outcome.passed("No active commands in rc.local / init scripts")
    return Outcome.warn(
        f"{len(findings)} active rc.local/init line(s) to review",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.POSSIBLE,
    )


@check(
    id="EXT-PERS-3",
    title="Detect PAM stack tampering (pam_exec / non-standard modules)",
    section="EXT.Persistence",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Backdoors hook authentication by inserting a pam_exec line (runs a script on every login) or a malicious module loaded by absolute path from a non-standard directory. Both let an attacker capture passwords or grant silent access.",
    remediation="Verify every non-stock PAM line; remove unexpected pam_exec entries and modules loaded from outside the system PAM directory.",
    tags=("persistence", "pam", "authentication"),
    attack=("T1556.003",),
)
def pam_tampering(ctx):
    findings: List[str] = []
    for path in ctx.glob("/etc/pam.d/*"):
        content = ctx.read_file(path, max_bytes=64_000)
        if not content:
            continue
        for lineno, line in enumerate(content.splitlines(), start=1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "pam_exec.so" in s:
                findings.append(f"{path}:{lineno} — pam_exec runs an external program on auth: {s[:140]}")
            # A module referenced by an absolute path outside the standard dirs.
            m = re.search(r"\b(/\S+\.so)\b", s)
            if m and not m.group(1).startswith(("/lib/", "/usr/lib/", "/lib64/", "/usr/lib64/")):
                findings.append(f"{path}:{lineno} — PAM module loaded from non-standard path: {m.group(1)}")
    if not findings:
        return Outcome.passed("No PAM stack tampering indicators found")
    return Outcome.warn(
        f"{len(findings)} PAM line(s) to review for tampering",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.POSSIBLE,
    )


@check(
    id="EXT-PERS-4",
    title="Detect hidden files in scratch directories",
    section="EXT.Persistence",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Attackers stash tools and payloads under names that hide in a directory listing — '...', '. ' (dot-space), or a leading dot — in world-writable scratch dirs like /tmp, /var/tmp and /dev/shm.",
    remediation="Inspect any unexpected hidden entries in scratch directories and remove confirmed artifacts.",
    tags=("persistence", "defense-evasion"),
    attack=("T1564.001",),
)
def hidden_files_in_scratch(ctx):
    listing = ctx.sh(
        r"find /tmp /var/tmp /dev/shm -maxdepth 2 "
        r"\( -name '...*' -o -name '.* *' -o -name ' *' \) "
        r"2>/dev/null | head -100",
        timeout=30,
    )
    hits = [p for p in listing.lines() if p.rstrip("/") not in ("/tmp", "/var/tmp", "/dev/shm")]
    if not hits:
        return Outcome.passed("No suspiciously-named hidden files in scratch directories")
    return Outcome.warn(
        f"{len(hits)} suspiciously-named entry(ies) in scratch directories",
        evidence=hits[:25],
        actual=hits[:25],
        confidence=Confidence.POSSIBLE,
    )


@check(
    id="EXT-PERS-5",
    title="Detect the immutable bit set on unexpected files",
    section="EXT.Persistence",
    severity=Severity.LOW,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Setting chattr +i on a dropped file (or on /etc/passwd after adding a backdoor account) stops admins from editing or deleting it without first clearing the attribute — a persistence-hardening trick worth noticing.",
    remediation="Review immutable files ('lsattr'); clear the bit ('chattr -i') on anything that should not be locked, then remove the artifact.",
    tags=("persistence", "defense-evasion"),
    attack=("T1222",),
)
def immutable_files(ctx):
    if not ctx.run(["sh", "-c", "command -v lsattr"]).ok:
        return Outcome.manual("lsattr not available (e2fsprogs); cannot enumerate immutable files")
    listing = ctx.sh(
        "lsattr -R /etc /root /home /var/spool 2>/dev/null | grep -E '^-{4}i' | head -100",
        timeout=45,
    )
    hits = [l.strip() for l in listing.lines() if l.strip()]
    if not hits:
        return Outcome.passed("No unexpected immutable files found")
    return Outcome.warn(
        f"{len(hits)} immutable file(s) to review",
        evidence=hits[:25],
        actual=len(hits),
        confidence=Confidence.POSSIBLE,
    )


@check(
    id="EXT-PERS-6",
    title="Detect world-writable executables on the system PATH",
    section="EXT.Persistence",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A world-writable binary in a PATH directory (/usr/bin, /usr/local/bin, …) can be overwritten by any user, so the next caller — possibly root — runs attacker code. It is both an escalation and a persistence vector.",
    remediation="Remove world/group write from the binary (chmod o-w,g-w) and restore correct ownership.",
    tags=("persistence", "filesystem", "world-writable"),
    attack=("T1574",),
)
def world_writable_path_binaries(ctx):
    listing = ctx.sh(
        r"find /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin "
        r"-maxdepth 1 -type f -perm -0002 2>/dev/null | head -200",
        timeout=45,
    )
    hits = []
    for path in listing.lines():
        st = ctx.stat(path)
        hits.append(f"{path} (mode {st.mode_str})" if st.exists else path)
    if not hits:
        return Outcome.passed("No world-writable executables on the system PATH")
    return Outcome.failed(
        f"{len(hits)} world-writable executable(s) on the system PATH",
        evidence=hits[:25],
        actual=hits[:25],
        confidence=Confidence.CERTAIN,
    )


@check(
    id="EXT-PERS-7",
    title="Detect package integrity drift in installed files",
    section="EXT.Persistence",
    severity=Severity.MEDIUM,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A package-manager verify ('dpkg --verify' / 'rpm -Va') flags installed files whose content (md5 '5') or mode has changed from what the package shipped — a strong signal of a trojaned or replaced system binary.",
    remediation="Investigate flagged files; reinstall the owning package to restore known-good copies after confirming the cause.",
    tags=("persistence", "integrity"),
    attack=("T1554",),
)
def package_integrity_drift(ctx):
    pm = ctx.platform.package_manager
    if pm == "apt":
        if not ctx.run(["sh", "-c", "command -v dpkg"]).ok:
            return Outcome.manual("dpkg not available; cannot verify package integrity")
        out = ctx.sh("dpkg --verify 2>/dev/null | head -200", timeout=120).lines()
        # dpkg --verify lines look like "??5??????   /usr/bin/foo" — the '5' is content drift.
        drift = [l.strip() for l in out if l.strip() and re.match(r"^\S*5\S*\s", l.strip())]
    elif pm in ("dnf", "yum", "zypper"):
        if not ctx.run(["sh", "-c", "command -v rpm"]).ok:
            return Outcome.manual("rpm not available; cannot verify package integrity")
        out = ctx.sh("rpm -Va 2>/dev/null | head -200", timeout=120).lines()
        drift = [l.strip() for l in out if l.strip() and l.lstrip()[:9].find("5") != -1]
    else:
        return Outcome.manual(f"No supported package verifier for '{pm}'")
    if not drift:
        return Outcome.passed("No package integrity drift detected in installed files")
    return Outcome.warn(
        f"{len(drift)} installed file(s) differ from their package (content/mode drift)",
        evidence=drift[:25],
        actual=len(drift),
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-PERS-8",
    title="Detect system binaries newer than the package database",
    section="EXT.Persistence",
    severity=Severity.LOW,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A binary in /bin or /usr/bin modified more recently than the package database was last updated may have been replaced out-of-band — a weaker, time-based companion to the integrity-verify check.",
    remediation="Cross-check flagged binaries with the integrity verifier and the package history; reinstall if tampering is suspected.",
    tags=("persistence", "integrity"),
    attack=("T1554",),
)
def recently_modified_binaries(ctx):
    ref = "/var/lib/dpkg/status" if ctx.file_exists("/var/lib/dpkg/status") else "/var/lib/rpm"
    if not ctx.file_exists(ref):
        return Outcome.manual("No package database reference available for time comparison")
    listing = ctx.sh(
        f"find /bin /sbin /usr/bin /usr/sbin -maxdepth 1 -type f -newer {ref} 2>/dev/null | head -100",
        timeout=45,
    )
    hits = listing.lines()
    if not hits:
        return Outcome.passed("No system binaries are newer than the package database")
    return Outcome.warn(
        f"{len(hits)} system binary(ies) modified more recently than the package database",
        evidence=hits[:25],
        actual=len(hits),
        confidence=Confidence.POSSIBLE,
    )


@check(
    id="EXT-PERS-9",
    title="Detect writable MOTD / profile.d login scripts",
    section="EXT.Persistence",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Scripts in /etc/update-motd.d run as root on SSH login and /etc/profile.d runs in every login shell; if a non-root user can write them, they get code execution whenever someone (often an admin) logs in.",
    remediation="Set these scripts to root:root without group/other write; review their content for injected commands.",
    tags=("persistence", "login", "escalation-vector"),
    attack=("T1037", "T1546"),
)
def writable_login_scripts(ctx):
    findings: List[str] = []
    for pattern in ("/etc/update-motd.d/*", "/etc/profile.d/*", "/etc/profile"):
        for path in (ctx.glob(pattern) if "*" in pattern else [pattern]):
            st = ctx.stat(path)
            if st.exists and not st.is_dir and (st.mode & 0o022) and st.owner != "root":
                findings.append(f"{path} is writable by non-root (mode {st.mode_str}, owner {st.owner})")
    if not findings:
        return Outcome.passed("No writable MOTD/profile.d login scripts found")
    return Outcome.failed(
        f"{len(findings)} writable login script(s) executed on login",
        evidence=findings[:25],
        actual=findings[:25],
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-PERS-10",
    title="Cross-check backdoor account and setuid persistence indicators",
    section="EXT.Persistence",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "Viewed through a persistence lens, a second UID-0 account, a UID-0 with an unexpected login shell, "
        "or a setuid-root copy of a shell/interpreter dropped outside the OS baseline are all ways an attacker "
        "keeps a way back to root. This consolidates those indicators as a single 'is there a planted door?' lead."),
    remediation="Investigate any flagged account or setuid binary; remove backdoor accounts and strip unexpected setuid bits.",
    tags=("persistence", "accounts", "suid", "backdoor"),
    attack=("T1136", "T1548.001"),
)
def backdoor_persistence_indicators(ctx):
    from . import gtfobins  # local import keeps module load order simple
    findings: List[str] = []
    # Extra UID-0 accounts (a persistent root login).
    uid0 = [e for e in ctx.passwd_entries() if e["uid"] == "0"]
    for e in uid0:
        if e["name"] != "root":
            findings.append(f"account '{e['name']}' has UID 0 (shell {e['shell']}) — a standing root login")
    # Setuid shells/interpreters outside the OS default baseline.
    listing = ctx.sh(
        r"find / -xdev -type f -perm -4000 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -400",
        timeout=90,
    )
    for path in listing.lines():
        if path in gtfobins.DEFAULT_SETUID:
            continue
        if gtfobins.lookup(path, "suid"):
            findings.append(f"setuid-root {path} outside the OS baseline — a re-entry to root")
    if not findings:
        return Outcome.passed("No backdoor-account or setuid persistence indicators found")
    return Outcome.failed(
        f"{len(findings)} persistence indicator(s) for a planted root door",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.LIKELY,
    )
