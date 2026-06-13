"""Defensive posture — is anyone actually watching, and can a foothold be stopped?

The rest of the suite asks "what's exposed." These four ask the complementary
question: if an attacker gets in, will the host *notice or slow them down*? A
mandatory-access-control system left in complain mode, an auditd that's running
but has no rules loaded, no brute-force protection on SSH, and logs that aren't
shipped anywhere an attacker can't also wipe — each is a monitoring gap that
turns a survivable incident into a silent one.

These are posture/MANUAL-leaning checks: where the relevant tool isn't present
they report INFO/MANUAL rather than failing, because "no auditd" is a different
statement than "auditd misconfigured."
"""

from __future__ import annotations

from typing import List

from ...core import Confidence, Level, Outcome, Severity, check
from ..extended import EXTENDED_FRAMEWORK


@check(
    id="EXT-MON-1",
    title="Ensure mandatory access control is enforcing (AppArmor/SELinux)",
    section="EXT.Posture",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="AppArmor/SELinux confine what a compromised service can do. In complain/permissive mode the policy only logs violations instead of blocking them, and disabled means no confinement at all — the containment you think you have isn't there.",
    remediation="Put AppArmor profiles in enforce mode (aa-enforce) or set SELinux to enforcing; investigate any profile deliberately left in complain mode.",
    tags=("posture", "mac", "defense-evasion"),
    attack=("T1562.001",),
)
def mac_enforcing(ctx):
    # SELinux first (RHEL family), then AppArmor (Debian/Ubuntu).
    getenforce = ctx.run(["getenforce"])
    if getenforce.ok and getenforce.out.strip():
        mode = getenforce.out.strip()
        if mode.lower() == "enforcing":
            return Outcome.passed("SELinux is enforcing")
        return Outcome.failed(f"SELinux is {mode} (expected Enforcing)", actual=mode, expected="Enforcing")
    aa = ctx.run(["aa-status"])
    if aa.ok and "apparmor" in aa.combined.lower():
        complain = enforce = 0
        for line in aa.combined.splitlines():
            s = line.strip().lower()
            if "profiles are in complain mode" in s:
                complain = _lead_int(s)
            elif "profiles are in enforce mode" in s:
                enforce = _lead_int(s)
        if complain > 0:
            names = _apparmor_section(aa.combined, "complain")
            evidence = [f"complain-mode profile: {n}" for n in names[:25]]
            if names and len(names) > 25:
                evidence.append(f"… and {len(names) - 25} more")
            if not names:
                evidence.append("Run 'sudo aa-status --complaining' to list the profiles to enforce.")
            return Outcome.warn(
                f"AppArmor has {complain} profile(s) in complain mode (only logging, not enforcing)",
                evidence=evidence,
                actual={"enforce": enforce, "complain": complain, "complaining": names[:50]},
                confidence=Confidence.CERTAIN,
            )
        if enforce > 0:
            return Outcome.passed(f"AppArmor is enforcing ({enforce} profile(s))")
        return Outcome.warn("AppArmor is loaded but no profiles are in enforce mode")
    return Outcome.manual("Neither SELinux nor AppArmor status is available; verify a MAC system is enforcing")


def _lead_int(line: str) -> int:
    tok = line.split()[0] if line.split() else "0"
    return int(tok) if tok.isdigit() else 0


def _apparmor_section(text: str, mode: str):
    """Profile names that aa-status lists (indented) under the given mode header.

    aa-status prints '<N> profiles are in <mode> mode.' followed by one indented
    profile name per line until the next (non-indented) section header. We read
    the first such block (the *profiles* section, before the later *processes*
    sections) so the finding can name exactly which profiles to enforce.
    """
    names = []
    capturing = False
    header = f"profiles are in {mode} mode"
    for raw in text.splitlines():
        low = raw.strip().lower()
        if header in low:
            capturing = True
            continue
        if capturing:
            # An indented, non-numeric line is a profile name; anything else ends
            # the block (the next "N ... mode." / "N processes ..." header).
            if raw[:1].isspace() and raw.strip() and not raw.strip()[0].isdigit():
                names.append(raw.strip())
            else:
                break
    return names


@check(
    id="EXT-MON-2",
    title="Ensure auditd has a non-empty rule set loaded",
    section="EXT.Posture",
    severity=Severity.MEDIUM,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="auditd running with no rules records almost nothing — enabled is not the same as monitoring. Without rules, the tampering, identity changes, and exec events an investigator needs simply aren't captured.",
    remediation="Deploy an audit rule set (e.g. /etc/audit/rules.d/*.rules covering identity, perms, exec) and reload with augenrules --load.",
    tags=("posture", "auditing", "defense-evasion"),
    attack=("T1562.001",),
)
def auditd_rule_depth(ctx):
    if not (ctx.service_active("auditd.service") or ctx.service_active("auditd")
            or ctx.package_installed("auditd")):
        return Outcome.manual("auditd does not appear installed/active; verify auditing is provided some other way")
    # Prefer the live rule list; fall back to the rules.d source files.
    live = ctx.run(["auditctl", "-l"])
    rule_lines: List[str] = []
    if live.ok and live.out.strip() and "No rules" not in live.combined:
        rule_lines = [l for l in live.lines() if l.strip()]
    else:
        src = ctx.sh("cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null")
        rule_lines = [l.strip() for l in src.lines()
                      if l.strip() and not l.strip().startswith("#") and l.strip() not in ("-e 2", "-e 1")]
    if len(rule_lines) >= 1:
        return Outcome.passed(f"auditd has {len(rule_lines)} rule(s) loaded")
    return Outcome.warn(
        "auditd is running but no audit rules are loaded — it is recording almost nothing",
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-MON-3",
    title="Ensure brute-force protection is active (fail2ban/sshguard)",
    section="EXT.Posture",
    severity=Severity.LOW,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="An internet-facing SSH/login service without rate-limiting lets an attacker grind credentials indefinitely. fail2ban or sshguard bans repeat offenders, turning an online brute force from feasible into impractical.",
    remediation="Install and enable fail2ban (or sshguard) with an sshd jail, or enforce rate limits at the firewall.",
    tags=("posture", "brute-force", "ssh"),
    attack=("T1110",),
)
def brute_force_protection(ctx):
    for name, unit in (("fail2ban", "fail2ban.service"), ("sshguard", "sshguard.service")):
        if ctx.service_active(unit) or (ctx.package_installed(name) and ctx.service_active(name)):
            return Outcome.passed(f"{name} is active")
        if ctx.package_installed(name):
            return Outcome.warn(f"{name} is installed but not active", confidence=Confidence.LIKELY)
    return Outcome.warn(
        "No brute-force protection (fail2ban/sshguard) detected",
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-MON-4",
    title="Review log forwarding and rotation (tamper resilience)",
    section="EXT.Posture",
    severity=Severity.LOW,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Logs only on the local disk can be wiped by whoever compromises the host. Forwarding to a remote collector preserves evidence an attacker can't reach, and sane rotation keeps logs available without filling the disk.",
    remediation="Configure remote log forwarding (rsyslog @@host or a journald upload) to a host the local admin can't delete, and verify logrotate is in place.",
    tags=("posture", "logging", "defense-evasion"),
    attack=("T1562", "T1070"),
)
def log_forwarding(ctx):
    sources = ["/etc/rsyslog.conf"] + ctx.glob("/etc/rsyslog.d/*.conf")
    forwards = False
    for path in sources:
        content = ctx.read_file(path)
        if not content:
            continue
        for line in content.splitlines():
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            # rsyslog remote targets: "*.* @host" (UDP) or "@@host" (TCP), or action(... target=...)
            if "@" in s and ("@@" in s or s.split()[-1].startswith("@")) or "target=" in s:
                forwards = True
                break
        if forwards:
            break
    rotation = ctx.file_exists("/etc/logrotate.conf") or bool(ctx.glob("/etc/logrotate.d/*"))
    if forwards:
        return Outcome.passed("Remote log forwarding is configured" + ("" if rotation else " (no logrotate found — verify)"))
    return Outcome.manual(
        "No remote log forwarding detected; logs appear local-only and could be wiped by an attacker on this host"
        + ("" if rotation else " (and no logrotate configuration was found)"),
    )
