"""Extended network exposure auditing: what is listening, and how widely."""

from __future__ import annotations

from ...core import Confidence, Level, Outcome, Severity, check
from ..extended import EXTENDED_FRAMEWORK

# Service ports that are especially dangerous to expose on all interfaces.
_SENSITIVE_PORTS = {
    "23": "telnet", "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
    "27017": "MongoDB", "9200": "Elasticsearch", "5984": "CouchDB",
    "11211": "memcached", "2375": "Docker API (unencrypted)", "139": "NetBIOS",
    "445": "SMB", "111": "rpcbind", "512": "rexec", "513": "rlogin", "514": "rsh",
    "5900": "VNC", "3389": "RDP",
}


def _port_of(local: str) -> str:
    """Extract the port from an ss 'local address:port' token (IPv4/IPv6)."""
    if local.startswith("["):  # [::]:443
        return local.rsplit(":", 1)[-1]
    return local.rsplit(":", 1)[-1] if ":" in local else ""


def _is_external(local: str) -> bool:
    """True if the socket is bound to a non-loopback address."""
    addr = local.rsplit(":", 1)[0].strip("[]")
    return addr not in ("127.0.0.1", "::1") and not addr.startswith("127.")


@check(
    id="EXT-NET-1",
    title="Inventory network-exposed listening services",
    section="EXT.Network",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Every service listening on a non-loopback address is reachable from the network; the inventory should be minimal and known.",
    remediation="Bind services to localhost where possible, or firewall the ports; stop anything unneeded.",
    tags=("network", "exposure", "attack-surface"),
)
def listening_services_inventory(ctx):
    sockets = ctx.listening_sockets()
    if not sockets:
        return Outcome.info("No listening sockets detected (or 'ss' unavailable)")
    external = [s for s in sockets if _is_external(s["local"])]
    if not external:
        return Outcome.passed(f"All {len(sockets)} listening sockets are loopback-only")
    inventory = [f"{s['proto']} {s['local']} {s['process']}".strip() for s in external]
    return Outcome.warn(
        f"{len(external)} service(s) listening on non-loopback addresses",
        evidence=inventory[:30],
        actual=inventory[:30],
        confidence=Confidence.CERTAIN,
    )


@check(
    id="EXT-NET-2",
    title="Detect sensitive services exposed to all interfaces",
    section="EXT.Network",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Databases, caches, and legacy remote-access services bound to 0.0.0.0 are routinely found unauthenticated and pillaged.",
    remediation="Bind these to localhost or a private interface and require authentication + a firewall allow-list.",
    tags=("network", "exposure", "database"),
)
def sensitive_exposed_services(ctx):
    sockets = ctx.listening_sockets()
    if not sockets:
        return Outcome.info("No listening sockets detected (or 'ss' unavailable)")
    offenders = []
    for s in sockets:
        if not _is_external(s["local"]):
            continue
        port = _port_of(s["local"])
        if port in _SENSITIVE_PORTS:
            offenders.append(f"{_SENSITIVE_PORTS[port]} on {s['local']} {s['process']}".strip())
    if not offenders:
        return Outcome.passed("No sensitive services exposed on external interfaces")
    return Outcome.failed(
        f"{len(offenders)} sensitive service(s) exposed to the network",
        evidence=offenders,
        actual=offenders,
        confidence=Confidence.CERTAIN,
    )
