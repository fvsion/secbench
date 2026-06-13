"""Extended filesystem privilege auditing: SUID/SGID, capabilities, writable dirs."""

from __future__ import annotations

from ...core import Confidence, Level, Outcome, Severity, check
from ..extended import EXTENDED_FRAMEWORK
from . import gtfobins

# SUID/SGID binaries that legitimately ship on a stock Ubuntu and are expected.
# Shared with privesc.py via gtfobins.DEFAULT_SETUID. Anything outside this set
# warrants review — attackers frequently plant a setuid shell to persist root.
_EXPECTED_SETUID = gtfobins.DEFAULT_SETUID


@check(
    id="EXT-FS-1",
    title="Review unexpected SUID/SGID executables",
    section="EXT.Filesystem",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A setuid-root binary runs with full privilege for any caller; an unexpected one is a prime persistence/escalation vector.",
    remediation="For each unexpected binary, confirm it is intended; remove the setuid/setgid bit (chmod -s) if not.",
    tags=("filesystem", "suid", "privilege"),
)
def unexpected_setuid(ctx):
    listing = ctx.sh(
        r"find / -xdev -type f \( -perm -4000 -o -perm -2000 \) "
        r"-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -400",
        timeout=90,
    )
    found = listing.lines()
    unexpected = sorted(set(found) - _EXPECTED_SETUID)
    if not unexpected:
        return Outcome.passed(f"All {len(found)} setuid/setgid binaries match the expected baseline")
    return Outcome.warn(
        f"{len(unexpected)} setuid/setgid binary(ies) outside the expected baseline",
        evidence=unexpected[:30],
        actual=unexpected[:30],
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-FS-2",
    title="Review files granted Linux capabilities",
    section="EXT.Filesystem",
    severity=Severity.MEDIUM,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="File capabilities (e.g. cap_setuid, cap_net_raw) grant slices of root power; an unexpected grant can be a quiet escalation path.",
    remediation="Audit each capability with getcap; remove unneeded grants via 'setcap -r <file>'.",
    tags=("filesystem", "capabilities", "privilege"),
)
def file_capabilities(ctx):
    if not ctx.run(["sh", "-c", "command -v getcap"]).ok:
        return Outcome.skip("getcap not available (libcap2-bin not installed)")
    listing = ctx.sh("getcap -r / 2>/dev/null | head -200", timeout=90)
    caps = listing.lines()
    # cap_setuid / cap_sys_admin / cap_dac_override are the dangerous ones.
    dangerous = [c for c in caps if any(d in c.lower() for d in
                 ("cap_setuid", "cap_sys_admin", "cap_dac_override", "cap_sys_ptrace", "ep"))]
    if not caps:
        return Outcome.passed("No file capabilities are set")
    high = [c for c in caps if any(d in c.lower() for d in ("cap_setuid", "cap_sys_admin", "cap_dac_override"))]
    if high:
        return Outcome.warn(
            f"{len(caps)} file(s) carry capabilities; {len(high)} include high-power caps",
            evidence=caps[:25],
            actual=caps[:25],
            confidence=Confidence.LIKELY,
        )
    return Outcome.info(f"{len(caps)} file(s) carry capabilities (review)", evidence=caps[:25])


@check(
    id="EXT-FS-3",
    title="Ensure world-writable directories have the sticky bit",
    section="EXT.Filesystem",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A world-writable directory without the sticky bit lets any user delete or rename another user's files in it.",
    remediation="chmod +t on legitimate shared dirs; tighten permissions on the rest.",
    tags=("filesystem", "world-writable", "sticky-bit"),
)
def world_writable_dirs_sticky(ctx):
    listing = ctx.sh(
        r"find / -xdev -type d -perm -0002 ! -perm -1000 "
        r"-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -200",
        timeout=90,
    )
    offenders = listing.lines()
    if not offenders:
        return Outcome.passed("All world-writable directories have the sticky bit")
    return Outcome.failed(
        f"{len(offenders)} world-writable director(ies) lack the sticky bit",
        evidence=offenders[:25],
        actual=len(offenders),
        expected=0,
    )
