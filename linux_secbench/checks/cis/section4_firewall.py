"""CIS Section 4 — Host Based Firewall (re-based to CIS Ubuntu 24.04 v2.0.0).

v2.0.0 collapses §4 to a single subsection, **4.1 Configure Uncomplicated
Firewall**, and drops the v1.0.0 nftables / firewalld / iptables alternatives:
Ubuntu standardizes on ufw. These five controls check that ufw is installed,
its service is enabled+active, and its default incoming / outgoing / routed
policies are deliberately configured.
"""

from __future__ import annotations

from ...core import Level, Outcome, Profile, Severity
from ._base import cis_check as check


def _verbose_status(ctx):
    """Return (text, ok). 'ufw status verbose' requires root to read."""
    res = ctx.run(["ufw", "status", "verbose"])
    return res.combined.lower(), res.ok


def _default_line(text: str) -> str:
    for line in text.splitlines():
        if "default:" in line or line.strip().startswith("default"):
            return line.strip()
    return ""


@check(
    id="4.1.1",
    title="Ensure ufw is installed",
    section="4.1 Configure Uncomplicated Firewall",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="A host firewall is the last line of defence when network controls "
              "fail; ufw is the supported Ubuntu front-end for it.",
    remediation="apt install ufw",
    tags=("firewall", "ufw", "ubuntu"),
)
def ufw_installed(ctx):
    if ctx.package_installed("ufw"):
        return Outcome.passed("ufw is installed")
    return Outcome.failed("ufw is not installed", expected="installed")


@check(
    id="4.1.2",
    title="Ensure ufw service is configured",
    section="4.1 Configure Uncomplicated Firewall",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="The ufw service must be enabled and active for ufw to protect the "
              "system across reboots.",
    remediation="systemctl unmask ufw.service; systemctl --now enable ufw.service; ufw enable",
    tags=("firewall", "ufw"),
)
def ufw_service_configured(ctx):
    if not ctx.package_installed("ufw"):
        return Outcome.failed("ufw is not installed", expected="installed + enabled + active")
    enabled = ctx.service_enabled("ufw.service")
    active = ctx.service_active("ufw.service")
    status = ctx.run(["ufw", "status"])
    ufw_active = status.ok and "status: active" in status.combined.lower()
    if enabled and active and ufw_active:
        return Outcome.passed("ufw.service is enabled and active and ufw reports active")
    if not ctx.is_root and not status.ok:
        return Outcome.manual("Root required to read 'ufw status'; verify ufw is enabled and active",
                              actual={"enabled": enabled, "active": active})
    return Outcome.failed(
        "ufw.service is not fully configured",
        actual={"enabled": enabled, "active": active, "ufw_status_active": ufw_active},
        expected="enabled and active and 'Status: active'",
    )


@check(
    id="4.1.3",
    title="Ensure ufw incoming default is configured",
    section="4.1 Configure Uncomplicated Firewall",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="A default deny (or reject) for incoming traffic means only "
              "explicitly allowed connections reach the host.",
    remediation="ufw default deny incoming",
    tags=("firewall", "ufw", "default-deny"),
)
def ufw_incoming_default(ctx):
    if not ctx.package_installed("ufw"):
        return Outcome.skip("ufw not installed")
    text, ok = _verbose_status(ctx)
    if not ok and not ctx.is_root:
        return Outcome.manual("Root required; verify 'ufw status verbose' shows deny/reject (incoming)")
    if not ok:
        return Outcome.failed("Unable to read ufw verbose status")
    if "deny (incoming)" in text or "reject (incoming)" in text:
        return Outcome.passed("ufw default incoming policy is deny/reject",
                              actual=_default_line(text))
    return Outcome.failed("ufw incoming default is not deny/reject",
                          actual=_default_line(text), expected="deny (incoming)")


@check(
    id="4.1.4",
    title="Ensure ufw outgoing default is configured",
    section="4.1 Configure Uncomplicated Firewall",
    severity=Severity.LOW,
    levels=(Level.L2,),
    profiles=(Profile.SERVER,),
    rationale="The outgoing default should be a deliberate choice per site policy "
              "(allow is common; deny/reject is more restrictive).",
    remediation="Set the outgoing default per site policy, e.g. ufw default allow outgoing.",
    tags=("firewall", "ufw"),
)
def ufw_outgoing_default(ctx):
    if not ctx.package_installed("ufw"):
        return Outcome.skip("ufw not installed")
    text, ok = _verbose_status(ctx)
    if not ok and not ctx.is_root:
        return Outcome.manual("Root required; verify the outgoing default in 'ufw status verbose'")
    if not ok:
        return Outcome.failed("Unable to read ufw verbose status")
    if any(p in text for p in ("allow (outgoing)", "deny (outgoing)", "reject (outgoing)")):
        return Outcome.passed("ufw outgoing default is configured", actual=_default_line(text))
    return Outcome.warn("ufw outgoing default is not explicitly set", actual=_default_line(text),
                        expected="an explicit outgoing default")


@check(
    id="4.1.5",
    title="Ensure ufw routed default is configured",
    section="4.1 Configure Uncomplicated Firewall",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="A disabled or deny routed default ensures ufw does not forward "
              "traffic between interfaces unless explicitly allowed.",
    remediation="ufw default deny routed  (or disable routing).",
    tags=("firewall", "ufw"),
)
def ufw_routed_default(ctx):
    if not ctx.package_installed("ufw"):
        return Outcome.skip("ufw not installed")
    text, ok = _verbose_status(ctx)
    if not ok and not ctx.is_root:
        return Outcome.manual("Root required; verify the routed default is disabled/deny")
    if not ok:
        return Outcome.failed("Unable to read ufw verbose status")
    if any(p in text for p in ("disabled (routed)", "deny (routed)", "reject (routed)")):
        return Outcome.passed("ufw routed default is disabled/deny", actual=_default_line(text))
    if "(routed)" not in text:
        # ufw shows no routed line when forwarding isn't configured at all.
        return Outcome.warn("ufw does not report a routed default (routing not configured)")
    return Outcome.failed("ufw routed default is not disabled/deny",
                          actual=_default_line(text), expected="disabled or deny (routed)")
