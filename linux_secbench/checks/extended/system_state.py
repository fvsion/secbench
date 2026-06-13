"""Extended system-state checks: patch posture and pending reboots."""

from __future__ import annotations

from ...core import Confidence, Level, Outcome, Severity, check
from ..extended import EXTENDED_FRAMEWORK


@check(
    id="EXT-SYS-1",
    title="Ensure no pending security updates",
    section="EXT.SystemState",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Unapplied security updates are the single most common root cause of compromise; the window between patch release and apply is the exposure.",
    remediation="apt-get update && apt-get upgrade (or the distro equivalent); enable unattended-upgrades.",
    tags=("patching", "updates", "vulnerability"),
)
def pending_security_updates(ctx):
    pm = ctx.platform.package_manager
    if pm == "apt":
        # apt prints "<pkg>/<suite> ... [upgradable ...]"; security suites contain '-security'.
        res = ctx.run(["apt-get", "-s", "upgrade"], timeout=60)
        if not res.ok:
            res = ctx.run(["sh", "-c", "apt list --upgradable 2>/dev/null"], timeout=60)
        lines = [l for l in res.lines() if "security" in l.lower()]
        total_upgradable = [l for l in res.lines() if "Inst " in l or "upgradable" in l]
        if not res.ok:
            return Outcome.manual("Could not query apt for updates; run 'apt list --upgradable'")
        if lines:
            return Outcome.failed(
                f"{len(lines)} security update(s) pending",
                evidence=lines[:20],
                actual=len(lines),
                expected=0,
            )
        note = f"{len(total_upgradable)} non-security update(s) available" if total_upgradable else "fully up to date"
        return Outcome.passed(f"No pending security updates ({note})")
    if pm in ("dnf", "yum"):
        res = ctx.run(["sh", "-c", "dnf -q updateinfo list security 2>/dev/null"], timeout=60)
        sec = [l for l in res.lines() if l and not l.lower().startswith("last metadata")]
        if sec:
            return Outcome.failed(f"{len(sec)} security advisory update(s) pending", evidence=sec[:20], actual=len(sec))
        return Outcome.passed("No pending security updates")
    return Outcome.manual(f"Update check not implemented for package manager '{pm}'")


@check(
    id="EXT-SYS-2",
    title="Ensure the system does not require a pending reboot",
    section="EXT.SystemState",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A pending reboot means a patched kernel or library is on disk but the vulnerable version is still running in memory.",
    remediation="Schedule and perform the reboot during a maintenance window.",
    tags=("patching", "reboot"),
)
def reboot_required(ctx):
    if ctx.file_exists("/var/run/reboot-required") or ctx.file_exists("/run/reboot-required"):
        pkgs = ctx.read_file("/var/run/reboot-required.pkgs") or ""
        return Outcome.warn(
            "A reboot is required to complete pending updates",
            evidence=pkgs.splitlines()[:20],
            actual="reboot-required flag present",
        )
    # RHEL family: needs-restarting -r returns 1 when a reboot is needed.
    if ctx.platform.family == "rhel":
        res = ctx.run(["needs-restarting", "-r"])
        if res.returncode == 1:
            return Outcome.warn("needs-restarting reports a reboot is required")
    return Outcome.passed("No pending reboot flagged")
