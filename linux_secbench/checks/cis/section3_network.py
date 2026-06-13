"""CIS Section 3 — Network (re-based to CIS Ubuntu 24.04 Benchmark v2.0.0).

3.1 Network Devices (IPv6 posture, wireless, bluetooth), 3.2 uncommon
network-protocol kernel modules, and 3.3 IPv4/IPv6 hardening sysctls.

v2.0.0 reorganised §3: §3.2 grew to six modules (atm, can, dccp, rds, sctp,
tipc) and §3.3 split every network sysctl into its own recommendation under
3.3.1 (IPv4, 18) and 3.3.2 (IPv6, 8).
"""

from __future__ import annotations

from ...core import Level, Outcome, Profile, Severity
from ._base import cis_check as check

# --------------------------------------------------------------------------- #
# 3.2 — Network kernel modules (CIS 3.2.1–3.2.6). Niche protocols with a poor
# security track record; the benchmark wants them unavailable (not loaded and
# not loadable). (module, cis_id, full-name for the rationale)
# --------------------------------------------------------------------------- #
_DISALLOWED_NET_MODULES = [
    ("atm", "3.2.1", "Asynchronous Transfer Mode"),
    ("can", "3.2.2", "Controller Area Network"),
    ("dccp", "3.2.3", "Datagram Congestion Control Protocol"),
    ("rds", "3.2.4", "Reliable Datagram Sockets"),
    ("sctp", "3.2.5", "Stream Control Transmission Protocol"),
    ("tipc", "3.2.6", "Transparent Inter-Process Communication"),
]


def _make_net_module_check(module: str, cis_id: str, longname: str):
    @check(
        id=cis_id,
        title=f"Ensure {module} kernel module is not available",
        section="3.2 Configure Network Kernel Modules",
        severity=Severity.LOW,
        levels=(Level.L1,),
        rationale=f"The {longname} ({module}) protocol is rarely used and has a "
                  f"history of kernel vulnerabilities; an unused network module is "
                  f"needless attack surface.",
        remediation=f"Add 'install {module} /bin/false' and 'blacklist {module}' "
                    f"under /etc/modprobe.d/, then unload it.",
        tags=("network", "kernel-module"),
    )
    def _chk(ctx, _module=module):
        if not ctx.module_loaded(_module) and not ctx.module_loadable(_module):
            return Outcome.passed(f"{_module} is not loaded or loadable")
        return Outcome.failed(
            f"{_module} is loaded or loadable",
            actual={"loaded": ctx.module_loaded(_module), "loadable": ctx.module_loadable(_module)},
            expected="not available",
        )

    return _chk


for _mod, _cid, _name in _DISALLOWED_NET_MODULES:
    _make_net_module_check(_mod, _cid, _name)


# --------------------------------------------------------------------------- #
# 3.3 — Network kernel parameters. v2.0.0 numbers each key individually.
# Each row: (cis_id, sysctl-key, expected, title, severity). All are Level 1.
# The "all"/"default" scope is encoded directly in the key, exactly as the
# benchmark numbers them.
# --------------------------------------------------------------------------- #
# 3.3.1 — IPv4 parameters (18)
_IPV4_SYSCTLS = [
    ("3.3.1.1", "net.ipv4.ip_forward", "0",
     "Ensure net.ipv4.ip_forward is configured", Severity.MEDIUM),
    ("3.3.1.2", "net.ipv4.conf.all.forwarding", "0",
     "Ensure net.ipv4.conf.all.forwarding is configured", Severity.MEDIUM),
    ("3.3.1.3", "net.ipv4.conf.default.forwarding", "0",
     "Ensure net.ipv4.conf.default.forwarding is configured", Severity.MEDIUM),
    ("3.3.1.4", "net.ipv4.conf.all.send_redirects", "0",
     "Ensure net.ipv4.conf.all.send_redirects is configured", Severity.MEDIUM),
    ("3.3.1.5", "net.ipv4.conf.default.send_redirects", "0",
     "Ensure net.ipv4.conf.default.send_redirects is configured", Severity.MEDIUM),
    ("3.3.1.6", "net.ipv4.icmp_ignore_bogus_error_responses", "1",
     "Ensure net.ipv4.icmp_ignore_bogus_error_responses is configured", Severity.LOW),
    ("3.3.1.7", "net.ipv4.icmp_echo_ignore_broadcasts", "1",
     "Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured", Severity.LOW),
    ("3.3.1.8", "net.ipv4.conf.all.accept_redirects", "0",
     "Ensure net.ipv4.conf.all.accept_redirects is configured", Severity.MEDIUM),
    ("3.3.1.9", "net.ipv4.conf.default.accept_redirects", "0",
     "Ensure net.ipv4.conf.default.accept_redirects is configured", Severity.MEDIUM),
    ("3.3.1.10", "net.ipv4.conf.all.secure_redirects", "0",
     "Ensure net.ipv4.conf.all.secure_redirects is configured", Severity.LOW),
    ("3.3.1.11", "net.ipv4.conf.default.secure_redirects", "0",
     "Ensure net.ipv4.conf.default.secure_redirects is configured", Severity.LOW),
    ("3.3.1.12", "net.ipv4.conf.all.rp_filter", "1",
     "Ensure net.ipv4.conf.all.rp_filter is configured", Severity.MEDIUM),
    ("3.3.1.13", "net.ipv4.conf.default.rp_filter", "1",
     "Ensure net.ipv4.conf.default.rp_filter is configured", Severity.MEDIUM),
    ("3.3.1.14", "net.ipv4.conf.all.accept_source_route", "0",
     "Ensure net.ipv4.conf.all.accept_source_route is configured", Severity.MEDIUM),
    ("3.3.1.15", "net.ipv4.conf.default.accept_source_route", "0",
     "Ensure net.ipv4.conf.default.accept_source_route is configured", Severity.MEDIUM),
    ("3.3.1.16", "net.ipv4.conf.all.log_martians", "1",
     "Ensure net.ipv4.conf.all.log_martians is configured", Severity.LOW),
    ("3.3.1.17", "net.ipv4.conf.default.log_martians", "1",
     "Ensure net.ipv4.conf.default.log_martians is configured", Severity.LOW),
    ("3.3.1.18", "net.ipv4.tcp_syncookies", "1",
     "Ensure net.ipv4.tcp_syncookies is configured", Severity.MEDIUM),
]

# 3.3.2 — IPv6 parameters (8)
_IPV6_SYSCTLS = [
    ("3.3.2.1", "net.ipv6.conf.all.forwarding", "0",
     "Ensure net.ipv6.conf.all.forwarding is configured", Severity.MEDIUM),
    ("3.3.2.2", "net.ipv6.conf.default.forwarding", "0",
     "Ensure net.ipv6.conf.default.forwarding is configured", Severity.MEDIUM),
    ("3.3.2.3", "net.ipv6.conf.all.accept_redirects", "0",
     "Ensure net.ipv6.conf.all.accept_redirects is configured", Severity.MEDIUM),
    ("3.3.2.4", "net.ipv6.conf.default.accept_redirects", "0",
     "Ensure net.ipv6.conf.default.accept_redirects is configured", Severity.MEDIUM),
    ("3.3.2.5", "net.ipv6.conf.all.accept_source_route", "0",
     "Ensure net.ipv6.conf.all.accept_source_route is configured", Severity.MEDIUM),
    ("3.3.2.6", "net.ipv6.conf.default.accept_source_route", "0",
     "Ensure net.ipv6.conf.default.accept_source_route is configured", Severity.MEDIUM),
    ("3.3.2.7", "net.ipv6.conf.all.accept_ra", "0",
     "Ensure net.ipv6.conf.all.accept_ra is configured", Severity.LOW),
    ("3.3.2.8", "net.ipv6.conf.default.accept_ra", "0",
     "Ensure net.ipv6.conf.default.accept_ra is configured", Severity.LOW),
]


def _make_net_sysctl_check(cis_id, key, expected, title, severity, section, family):
    @check(
        id=cis_id,
        title=title,
        section=section,
        severity=severity,
        levels=(Level.L1,),
        rationale=f"Setting {key}={expected} defends against {family} spoofing, "
                  f"redirection, or amplification attacks.",
        remediation=f"Set {key} = {expected} in a file under /etc/sysctl.d/ and "
                    f"run 'sysctl --system'.",
        tags=("network", "sysctl"),
    )
    def _chk(ctx, _key=key, _expected=expected):
        v = ctx.sysctl(_key)
        if v is None:
            # Key absent (e.g. IPv6 disabled, or interface scope unavailable).
            return Outcome.warn(f"{_key} is not present on this kernel")
        if v == _expected:
            return Outcome.passed(f"{_key} = {v}", actual={_key: v})
        return Outcome.failed(
            f"{_key} = {v} (expected {_expected})",
            actual={_key: v},
            expected={_key: _expected},
        )

    return _chk


for _row in _IPV4_SYSCTLS:
    _make_net_sysctl_check(*_row, section="3.3.1 Configure IPv4 Parameters", family="IPv4")
for _row in _IPV6_SYSCTLS:
    _make_net_sysctl_check(*_row, section="3.3.2 Configure IPv6 Parameters", family="IPv6")


# --------------------------------------------------------------------------- #
# 3.1 — Network devices
# --------------------------------------------------------------------------- #
@check(
    id="3.1.1",
    title="Ensure IPv6 status is identified",
    section="3.1 Configure Network Devices",
    severity=Severity.INFO,
    levels=(Level.L1,),
    rationale="The benchmark asks the operator to consciously decide whether IPv6 "
              "is required; the IPv4 vs IPv6 control set applies accordingly.",
    remediation="Confirm whether IPv6 is required. If not, disable it; if it is, "
                "ensure the IPv6 hardening parameters (3.3.2.*) are applied.",
    tags=("network",),
)
def ipv6_status_identified(ctx):
    enabled = ctx.read_file("/sys/module/ipv6/parameters/disable")
    state = "enabled" if (enabled or "").strip() == "0" else (
        "disabled" if enabled is not None else "unknown")
    return Outcome.manual(
        f"IPv6 appears {state}. Confirm this matches site policy and that the "
        f"matching IPv4/IPv6 hardening parameters are applied.",
        actual={"ipv6": state},
    )


@check(
    id="3.1.2",
    title="Ensure wireless interfaces are not available",
    section="3.1 Configure Network Devices",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="A server has no need for Wi-Fi; an active wireless interface is an "
              "unmonitored network path.",
    remediation="Disable the radio (nmcli radio all off) or blacklist the wireless "
                "modules; remove unused wireless hardware support.",
    tags=("network", "wireless"),
)
def wireless_disabled(ctx):
    res = ctx.sh("find /sys/class/net/*/wireless -maxdepth 0 2>/dev/null")
    if not res.out:
        return Outcome.passed("No wireless interfaces present")
    ifaces = [line.split("/")[4] for line in res.lines()]
    rfkill = ctx.run(["sh", "-c", "nmcli radio wifi 2>/dev/null"])
    if rfkill.ok and rfkill.out.lower() == "disabled":
        return Outcome.passed(f"Wireless interfaces present but radio disabled: {ifaces}")
    return Outcome.warn(f"Wireless interface(s) present and possibly enabled: {ifaces}", actual=ifaces)


@check(
    id="3.1.3",
    title="Ensure bluetooth services are not in use",
    section="3.1 Configure Network Devices",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="Bluetooth is a short-range wireless attack surface (e.g. bluesnarfing); "
              "on a server or hardened workstation it is rarely required.",
    remediation="Remove the bluez package, or — if required as a dependency — stop "
                "and mask bluetooth.service.",
    tags=("network", "bluetooth"),
)
def bluetooth_not_in_use(ctx):
    if not ctx.package_installed("bluez"):
        return Outcome.passed("bluez package is not installed")
    enabled = ctx.service_enabled("bluetooth.service")
    active = ctx.service_active("bluetooth.service")
    if not enabled and not active:
        return Outcome.passed("bluez installed but bluetooth.service is masked/stopped",
                              actual={"enabled": enabled, "active": active})
    return Outcome.failed(
        "bluetooth.service is enabled or active",
        actual={"enabled": enabled, "active": active},
        expected="not enabled and not active (or bluez removed)",
    )
