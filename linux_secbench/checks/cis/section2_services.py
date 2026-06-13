"""CIS Section 2 — Services (CIS Ubuntu 24.04 Benchmark v2.0.0).

Special-purpose server services that should not be in use unless the host's role
requires them (2.1), insecure client packages (2.2), time synchronization (2.3),
and job schedulers cron/at (2.4).
"""

from __future__ import annotations

from ...core import Level, Outcome, Profile, Severity
from ._base import cis_check as check


# --------------------------------------------------------------------------- #
# 2.1 Server Services — "not in use" unless the role requires them.
# --------------------------------------------------------------------------- #
# (cis_id, packages, units, label, severity). A service is "in use" when any of
# its packages is installed AND any unit is enabled/active.
_SERVER_SERVICES = [
    ("2.1.1", ("autofs",), ("autofs.service",), "autofs", Severity.MEDIUM),
    ("2.1.3", ("avahi-daemon",), ("avahi-daemon.service", "avahi-daemon.socket"), "avahi (mDNS)", Severity.MEDIUM),
    ("2.1.5", ("isc-dhcp-server", "dhcpd"), ("isc-dhcp-server.service", "dhcpd.service"), "DHCP server", Severity.MEDIUM),
    ("2.1.6", ("apache2", "nginx"), ("apache2.service", "nginx.service", "httpd.service"), "web server", Severity.LOW),
    ("2.1.7", ("bind9",), ("named.service", "bind9.service"), "DNS server (bind9)", Severity.MEDIUM),
    ("2.1.8", ("vsftpd",), ("vsftpd.service",), "FTP server (vsftpd)", Severity.HIGH),
    ("2.1.9", ("dnsmasq",), ("dnsmasq.service",), "dnsmasq", Severity.MEDIUM),
    ("2.1.10", ("slapd",), ("slapd.service",), "LDAP server (slapd)", Severity.MEDIUM),
    ("2.1.11", ("dovecot-imapd", "dovecot-pop3d", "cyrus-imapd"), ("dovecot.service", "cyrus-imapd.service"),
     "message access (IMAP/POP3)", Severity.MEDIUM),
    ("2.1.12", ("nfs-kernel-server",), ("nfs-server.service",), "NFS server", Severity.MEDIUM),
    ("2.1.13", ("ypserv",), ("ypserv.service",), "NIS server", Severity.HIGH),
    ("2.1.14", ("cups",), ("cups.service", "cups.socket"), "print server (CUPS)", Severity.LOW),
    ("2.1.15", ("rpcbind",), ("rpcbind.service", "rpcbind.socket"), "rpcbind", Severity.MEDIUM),
    ("2.1.16", ("rsync",), ("rsync.service",), "rsync daemon", Severity.MEDIUM),
    ("2.1.17", ("samba",), ("smbd.service", "nmbd.service"), "Samba file server", Severity.MEDIUM),
    ("2.1.18", ("snmpd",), ("snmpd.service",), "SNMP server", Severity.MEDIUM),
    ("2.1.19", ("inetutils-telnetd", "telnetd"), ("inetutils-telnetd.service",), "telnet server", Severity.HIGH),
    ("2.1.20", ("tftpd-hpa",), ("tftpd-hpa.service",), "TFTP server", Severity.HIGH),
    ("2.1.21", ("squid",), ("squid.service",), "web proxy (Squid)", Severity.MEDIUM),
    ("2.1.22", ("xinetd",), ("xinetd.service",), "xinetd", Severity.MEDIUM),
    ("2.1.23", ("xserver-xorg-core",), (), "X window server", Severity.LOW),
]


def _make_service_check(cis_id, packages, units, label, severity):
    @check(
        id=cis_id,
        title=f"Ensure {label} services are not in use",
        section="2.1 Server Services",
        severity=severity,
        levels=(Level.L1,),
        rationale=(
            f"An enabled {label} daemon expands the network attack surface. If the host's "
            "role does not require it, it should be removed or masked."
        ),
        remediation=f"systemctl stop & mask the unit; apt purge the package ({', '.join(packages)}).",
        tags=("services", "attack-surface"),
        attack=("T1046",),
    )
    def _chk(ctx, _pkgs=packages, _units=units, _label=label):
        installed = [p for p in _pkgs if ctx.package_installed(p)]
        present = [u for u in _units if ctx.service_present(u)]
        if not installed and not present:
            return Outcome.passed(f"{_label} is not installed")
        enabled = [u for u in _units if ctx.service_enabled(u)]
        active = [u for u in _units if ctx.service_active(u)]
        if not enabled and not active:
            return Outcome.passed(f"{_label} installed but neither enabled nor active")
        states = []
        if enabled:
            states.append("enabled")
        if active:
            states.append("active")
        return Outcome.warn(
            f"{_label} is {' and '.join(states)} — confirm this host's role requires it",
            actual={"enabled": enabled, "active": active, "installed": installed},
            expected="not in use unless required",
        )

    return _chk


for _row in _SERVER_SERVICES:
    _make_service_check(*_row)


@check(
    id="2.1.2",
    title="Ensure mail transfer agents are configured for local-only mode",
    section="2.1 Server Services",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    rationale="An MTA listening on a non-loopback interface is a remote attack surface; local delivery needs only loopback.",
    remediation="Bind the MTA (postfix 'inet_interfaces = loopback-only', exim, etc.) to 127.0.0.1/::1 and reload.",
    tags=("services", "mail", "attack-surface"),
    attack=("T1046",),
)
def mta_local_only(ctx):
    external = []
    for s in ctx.listening_sockets():
        local = s.get("local", "")
        if local.rsplit(":", 1)[-1] == "25":
            addr = local.rsplit(":", 1)[0].strip("[]")
            if addr not in ("127.0.0.1", "::1") and not addr.startswith("127."):
                external.append(f"{s.get('proto', '')} {local} {s.get('process', '')}".strip())
    if external:
        return Outcome.failed("An MTA is listening on a non-loopback address",
                              evidence=external, expected="port 25 bound to loopback only")
    return Outcome.passed("No MTA is listening on a non-loopback address")


@check(
    id="2.1.4",
    title="Ensure only approved services are listening on a network interface",
    section="2.1 Server Services",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    automated=False,
    rationale="Every externally-listening service should be inventoried and explicitly approved for the host's role.",
    remediation="Review listening sockets ('ss -plntu') and remove/firewall anything not required.",
    tags=("services", "attack-surface"),
)
def approved_listening_services(ctx):
    external = [f"{s.get('proto', '')} {s.get('local', '')} {s.get('process', '')}".strip()
                for s in ctx.listening_sockets()
                if s.get("local", "").rsplit(":", 1)[0].strip("[]") not in ("127.0.0.1", "::1")
                and not s.get("local", "").startswith("127.")]
    if not external:
        return Outcome.passed("No non-loopback listening services detected")
    return Outcome.manual(f"Review the {len(external)} non-loopback listening service(s) and confirm each is approved",
                          evidence=external[:30])


# --------------------------------------------------------------------------- #
# 2.2 Client Services — insecure client packages that should not be installed.
# --------------------------------------------------------------------------- #
_CLIENT_PACKAGES = [
    ("2.2.1", "nis", "NIS client", Severity.HIGH),
    ("2.2.2", "rsh-client", "rsh client", Severity.HIGH),
    ("2.2.3", "talk", "talk client", Severity.LOW),
    ("2.2.4", "telnet", "telnet client", Severity.HIGH),
    ("2.2.5", "ldap-utils", "LDAP client utils", Severity.LOW),
    ("2.2.6", "ftp", "FTP client", Severity.MEDIUM),
]


def _make_client_check(cis_id, package, label, severity):
    @check(
        id=cis_id,
        title=f"Ensure {label} is not installed",
        section="2.2 Client Services",
        severity=severity,
        levels=(Level.L1,),
        rationale=f"{label} transmits credentials/data in cleartext or has insecure defaults; its presence invites misuse.",
        remediation=f"apt purge {package}",
        tags=("services", "client"),
    )
    def _chk(ctx, _pkg=package, _label=label):
        if ctx.package_installed(_pkg):
            return Outcome.failed(f"{_label} ({_pkg}) is installed", expected="not installed")
        return Outcome.passed(f"{_label} is not installed")

    return _chk


for _row in _CLIENT_PACKAGES:
    _make_client_check(*_row)


# --------------------------------------------------------------------------- #
# 2.3 Time Synchronization
# --------------------------------------------------------------------------- #
def _uses_chrony(ctx):
    return ctx.package_installed("chrony") or ctx.service_present("chrony.service") \
        or ctx.service_present("chronyd.service")


def _uses_timesyncd(ctx):
    # systemd-timesyncd is the default; "in use" when chrony isn't taking over.
    return not _uses_chrony(ctx)


@check(
    id="2.3.1.1",
    title="Ensure a single time synchronization daemon is in use",
    section="2.3 Time Synchronization",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    rationale="Accurate, consistent time underpins log correlation and certificate validation; competing daemons cause drift.",
    remediation="Use exactly one of systemd-timesyncd or chrony; disable the other.",
    tags=("time", "ntp"),
)
def time_sync_single(ctx):
    daemons = {
        "systemd-timesyncd": ctx.service_active("systemd-timesyncd.service"),
        "chrony": ctx.service_active("chrony.service") or ctx.service_active("chronyd.service"),
        "ntp": ctx.service_active("ntp.service") or ctx.service_active("ntpd.service"),
    }
    active = [name for name, on in daemons.items() if on]
    if len(active) == 1:
        return Outcome.passed(f"Single time daemon active: {active[0]}", actual=active)
    if not active:
        return Outcome.failed("No time synchronization daemon is active", actual=active, expected="exactly one")
    return Outcome.failed(f"Multiple time daemons active: {', '.join(active)}", actual=active, expected="exactly one")


@check(
    id="2.3.2.1",
    title="Ensure systemd-timesyncd configured with an authorized timeserver",
    section="2.3 Time Synchronization",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="Without an explicit NTP server, time may not synchronise to an authorized source.",
    remediation="Set NTP= (and FallbackNTP=) in /etc/systemd/timesyncd.conf to authorized servers.",
    tags=("time", "ntp"),
)
def timesyncd_timeserver(ctx):
    if not _uses_timesyncd(ctx):
        return Outcome.passed("chrony is in use, not systemd-timesyncd (control not applicable)")
    conf = (ctx.read_file("/etc/systemd/timesyncd.conf") or "") + "\n" + \
        (ctx.sh("grep -rh '^NTP\\|^FallbackNTP' /etc/systemd/timesyncd.conf.d 2>/dev/null").out or "")
    for ln in conf.splitlines():
        s = ln.strip()
        if (s.startswith("NTP=") or s.startswith("FallbackNTP=")) and s.split("=", 1)[1].strip():
            return Outcome.passed("timesyncd has an NTP server configured", actual=s)
    return Outcome.failed("No NTP server configured for systemd-timesyncd", expected="NTP= set in timesyncd.conf")


@check(
    id="2.3.2.2",
    title="Ensure systemd-timesyncd is enabled and running",
    section="2.3 Time Synchronization",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="A configured but stopped time daemon does not keep the clock synchronised.",
    remediation="systemctl enable --now systemd-timesyncd.service",
    tags=("time", "ntp"),
)
def timesyncd_running(ctx):
    if not _uses_timesyncd(ctx):
        return Outcome.passed("chrony is in use, not systemd-timesyncd (control not applicable)")
    enabled = ctx.service_enabled("systemd-timesyncd.service")
    active = ctx.service_active("systemd-timesyncd.service")
    if enabled and active:
        return Outcome.passed("systemd-timesyncd is enabled and active")
    return Outcome.failed(f"systemd-timesyncd enabled={enabled} active={active}",
                          actual={"enabled": enabled, "active": active}, expected="enabled and active")


@check(
    id="2.3.3.1",
    title="Ensure chrony is configured with an authorized timeserver",
    section="2.3 Time Synchronization",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="chrony must point at an authorized server/pool to synchronise from a trusted source.",
    remediation="Add 'server' or 'pool' directives for authorized timeservers to /etc/chrony/chrony.conf.",
    tags=("time", "ntp", "chrony"),
)
def chrony_configured(ctx):
    if not _uses_chrony(ctx):
        return Outcome.passed("chrony is not in use (control not applicable)")
    conf = (ctx.read_file("/etc/chrony/chrony.conf") or "") + "\n" + \
        (ctx.sh("grep -rh '^server\\|^pool' /etc/chrony/conf.d /etc/chrony/sources.d 2>/dev/null").out or "")
    for ln in conf.splitlines():
        s = ln.strip()
        if s.startswith("server ") or s.startswith("pool "):
            return Outcome.passed("chrony has a server/pool configured", actual=s)
    return Outcome.failed("No server/pool configured for chrony", expected="server/pool in chrony.conf")


@check(
    id="2.3.3.2",
    title="Ensure chrony is running as user _chrony",
    section="2.3 Time Synchronization",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="Running chronyd as a dedicated unprivileged user limits the impact of a compromise.",
    remediation="Set 'user _chrony' in the chrony configuration (the Ubuntu default).",
    tags=("time", "ntp", "chrony"),
)
def chrony_user(ctx):
    if not _uses_chrony(ctx):
        return Outcome.passed("chrony is not in use (control not applicable)")
    ps = ctx.sh("ps -o user= -C chronyd 2>/dev/null")
    users = {u.strip() for u in (ps.out or "").splitlines() if u.strip()}
    if users and users <= {"_chrony"}:
        return Outcome.passed("chronyd runs as _chrony", actual=sorted(users))
    conf = ctx.sh("grep -rh '^user' /etc/chrony 2>/dev/null").out or ""
    if "_chrony" in conf:
        return Outcome.passed("chrony configured to run as _chrony", actual=conf.strip()[:80])
    if not users:
        return Outcome.manual("chronyd not running; verify it is configured to run as _chrony")
    return Outcome.failed(f"chronyd runs as {', '.join(sorted(users))}", actual=sorted(users), expected="_chrony")


@check(
    id="2.3.3.3",
    title="Ensure chrony is enabled and running",
    section="2.3 Time Synchronization",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="A configured but stopped chrony does not keep the clock synchronised.",
    remediation="systemctl enable --now chrony.service",
    tags=("time", "ntp", "chrony"),
)
def chrony_running(ctx):
    if not _uses_chrony(ctx):
        return Outcome.passed("chrony is not in use (control not applicable)")
    enabled = ctx.service_enabled("chrony.service") or ctx.service_enabled("chronyd.service")
    active = ctx.service_active("chrony.service") or ctx.service_active("chronyd.service")
    if enabled and active:
        return Outcome.passed("chrony is enabled and active")
    return Outcome.failed(f"chrony enabled={enabled} active={active}",
                          actual={"enabled": enabled, "active": active}, expected="enabled and active")


# --------------------------------------------------------------------------- #
# 2.4 Job Schedulers (cron / at)
# --------------------------------------------------------------------------- #
@check(
    id="2.4.1.1",
    title="Ensure cron daemon is enabled and active",
    section="2.4 Job Schedulers",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="Scheduled maintenance and security jobs (log rotation, updates) rely on a running cron daemon.",
    remediation="systemctl enable --now cron.service",
    tags=("cron",),
)
def cron_enabled(ctx):
    if not (ctx.package_installed("cron") or ctx.service_present("cron.service")):
        return Outcome.manual("cron is not installed; confirm scheduling is handled (e.g. systemd timers)")
    enabled = ctx.service_enabled("cron.service") or ctx.service_enabled("cronie.service")
    active = ctx.service_active("cron.service") or ctx.service_active("cronie.service")
    if enabled and active:
        return Outcome.passed("cron is enabled and active")
    return Outcome.failed(f"cron enabled={enabled} active={active}",
                          actual={"enabled": enabled, "active": active}, expected="enabled and active")


# 2.4.1.2–2.4.1.8 — access (perms) to cron paths. (cis_id, path, max_mode).
_CRON_PATHS = [
    ("2.4.1.2", "/etc/crontab", 0o600),
    ("2.4.1.3", "/etc/cron.hourly", 0o700),
    ("2.4.1.4", "/etc/cron.daily", 0o700),
    ("2.4.1.5", "/etc/cron.weekly", 0o700),
    ("2.4.1.6", "/etc/cron.monthly", 0o700),
    ("2.4.1.7", "/etc/cron.yearly", 0o700),
    ("2.4.1.8", "/etc/cron.d", 0o700),
]


def _make_cron_perm_check(cis_id, path, max_mode):
    @check(
        id=cis_id,
        title=f"Ensure access to {path} is configured",
        section="2.4 Job Schedulers",
        severity=Severity.MEDIUM,
        levels=(Level.L1,),
        rationale="Cron jobs run as root; world/group-writable cron paths allow privilege escalation via job injection.",
        remediation=f"chown root:root {path}; chmod {max_mode:o} {path}",
        tags=("cron", "permissions"),
        attack=("T1053.003",),
    )
    def _chk(ctx, _path=path, _max=max_mode):
        st = ctx.stat(_path)
        if not st.exists:
            return Outcome.skip(f"{_path} does not exist")
        problems = []
        if not st.perm_at_most(_max):
            problems.append(f"mode {st.mode_str} (expected <= {_max:o})")
        if st.uid not in (0, -1):
            problems.append(f"owner {st.owner} (expected root)")
        if problems:
            return Outcome.failed(f"{_path}: " + "; ".join(problems), actual=st.mode_str, expected=format(_max, "04o"))
        return Outcome.passed(f"{_path} mode {st.mode_str}, owned by root")

    return _chk


for _row in _CRON_PATHS:
    _make_cron_perm_check(*_row)


def _allow_deny_check(cis_id, tool, allow, deny, title):
    @check(
        id=cis_id,
        title=title,
        section="2.4 Job Schedulers",
        severity=Severity.LOW,
        levels=(Level.L1,),
        rationale=f"An {allow} that exists (root:root, <=0640) with no {deny} enforces an allow-list — the safer default.",
        remediation=f"Create {allow} (root:root, 0640) and remove {deny}.",
        tags=(tool, "access-control"),
    )
    def _chk(ctx, _allow=allow, _deny=deny):
        a = ctx.stat(_allow)
        d = ctx.stat(_deny)
        if a.exists and a.perm_at_most(0o640) and a.uid in (0, -1):
            if d.exists:
                return Outcome.warn(f"{_allow} present but {_deny} still exists (remove it)")
            return Outcome.passed(f"{_allow} present and secured; no {_deny}")
        return Outcome.failed(f"{_allow} missing or insecure; {tool} not restricted to an allow-list",
                              expected=f"{_allow} exists, root:root, <=0640")
    return _chk


_allow_deny_check("2.4.1.9", "cron", "/etc/cron.allow", "/etc/cron.deny",
                  "Ensure crontab is restricted to authorized users")
_allow_deny_check("2.4.2.1", "at", "/etc/at.allow", "/etc/at.deny",
                  "Ensure access to at is restricted to authorized users")
