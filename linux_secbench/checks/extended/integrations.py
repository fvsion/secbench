"""Optional external-tool integrations (mimipenguin, LaZagne, lynis, …).

Per the agreed "optional plugin" policy: these checks *use* a third-party tool
if it is already present on the host, and otherwise report a clean SKIP with a
one-line install hint. Nothing is auto-downloaded — pulling and executing
external code without consent is exactly the kind of supply-chain surprise a
security tool should not create. The native checks in :mod:`credentials` cover
the common cases without any external dependency; these add depth when the
operator has deliberately installed the heavier tooling.
"""

from __future__ import annotations

from ...core import Confidence, Level, Outcome, Severity, check
from ..extended import EXTENDED_FRAMEWORK


def _resolve(ctx, *candidates):
    """Return the first resolvable command path among candidates, or None."""
    for name in candidates:
        if "/" in name:
            if ctx.file_exists(name):
                return name
        else:
            res = ctx.run(["sh", "-c", f"command -v {name}"])
            if res.ok and res.out:
                return res.out
    return None


@check(
    id="EXT-INT-1",
    title="Deep in-memory credential scan via mimipenguin (if installed)",
    section="EXT.Integrations",
    severity=Severity.HIGH,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="mimipenguin extracts cleartext credentials from the memory of display managers, sshd, vsftpd, etc. SecBench now implements this natively in EXT-CRED-16 (under --active-review); the external tool remains a useful independent cross-check.",
    remediation="Investigate any recovered credential; rotate it and remove the exposure vector.",
    references=("https://github.com/huntergregal/mimipenguin",),
    tags=("credentials", "memory", "mimipenguin", "integration"),
)
def mimipenguin_scan(ctx):
    tool = _resolve(ctx, "mimipenguin", "mimipenguin.sh", "mimipenguin.py",
                    "/opt/mimipenguin/mimipenguin.sh", "/usr/local/bin/mimipenguin")
    if not tool:
        return Outcome.skip(
            "mimipenguin not installed — the native in-memory recovery (EXT-CRED-16, under --active-review) "
            "covers this. Optional external cross-check: git clone https://github.com/huntergregal/mimipenguin /opt/mimipenguin"
        )
    if not ctx.is_root:
        return Outcome.manual("mimipenguin requires root to read process memory")
    runner = ["sh", tool] if tool.endswith(".sh") else (["python3", tool] if tool.endswith(".py") else [tool])
    res = ctx.run(runner, timeout=120)
    output = res.combined
    # mimipenguin prints lines like "PROCESS  USERNAME  PASSWORD" on success.
    hits = [l for l in res.lines() if l and not l.lower().startswith(("no ", "[", "error"))]
    if hits and ("password" in output.lower() or any(":" in h for h in hits)):
        return Outcome.failed(
            f"mimipenguin recovered credential material ({len(hits)} line(s))",
            evidence=hits[:20],
            confidence=Confidence.LIKELY,
        )
    return Outcome.passed("mimipenguin ran and recovered no cleartext credentials")


@check(
    id="EXT-INT-2",
    title="Cross-reference with a Lynis audit (if installed)",
    section="EXT.Integrations",
    severity=Severity.LOW,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    automated=False,
    rationale="Lynis is a mature, complementary hardening auditor; its presence and last hardening index provide an independent second opinion.",
    remediation="Run 'lynis audit system' and review its suggestions alongside this report.",
    references=("https://github.com/CISOfy/lynis",),
    tags=("integration", "lynis"),
)
def lynis_presence(ctx):
    tool = _resolve(ctx, "lynis")
    if not tool:
        return Outcome.skip("lynis not installed — optional. Install: apt install lynis")
    report = ctx.read_file("/var/log/lynis-report.dat") or ""
    for line in report.splitlines():
        if line.startswith("hardening_index="):
            index = line.split("=", 1)[1].strip()
            return Outcome.info(f"Lynis is installed; last hardening index = {index}", actual=index)
    return Outcome.info("Lynis is installed; run 'lynis audit system' for a complementary report")
