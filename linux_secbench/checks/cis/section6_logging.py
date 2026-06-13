"""CIS Section 6 — Logging and Auditing (CIS Ubuntu 24.04 Benchmark v2.0.0).

  6.1 System Logging        (18: journald, rsyslog, logfile access)
  6.2 System Auditing       (48: auditd service, retention, rules, file access)
  6.3 Configure Integrity   (3:  AIDE)

A host that is not logging cannot be investigated after a compromise; auditd in
particular captures the kernel-level events syslog cannot.
"""

from __future__ import annotations

import re

from ...core import Level, Outcome, Severity
from ._base import cis_check as check


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _journald_conf(ctx):
    cfg = ctx.parse_keyword_file("/etc/systemd/journald.conf", sep="=")
    for path in ctx.glob("/etc/systemd/journald.conf.d/*.conf"):
        cfg.update(ctx.parse_keyword_file(path, sep="="))
    return cfg


def _rsyslog_text(ctx):
    parts = [ctx.read_file("/etc/rsyslog.conf") or ""]
    for path in ctx.glob("/etc/rsyslog.d/*.conf"):
        parts.append(ctx.read_file(path) or "")
    return "\n".join(parts)


def _audit_rules_text(ctx):
    """Merged audit rules — on-disk rules.d plus the loaded ruleset — lowercased."""
    disk = ctx.sh("cat /etc/audit/rules.d/*.rules 2>/dev/null")
    text = disk.combined if disk.ok else ""
    loaded = ctx.run(["auditctl", "-l"])
    if loaded.ok:
        text += "\n" + loaded.out
    return text.lower()


def _perm_at_most(st, limit):
    return st.exists and st.perm_at_most(limit)


# --------------------------------------------------------------------------- #
# 6.1.1  journald
# --------------------------------------------------------------------------- #
@check(
    id="6.1.1.1.1", title="Ensure journald service is active",
    section="6.1 System Logging", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="systemd-journald is the base logging service; if inactive the host records nothing.",
    remediation="systemctl --now enable systemd-journald.service", tags=("logging", "journald"),
)
def journald_active(ctx):
    if ctx.service_active("systemd-journald.service"):
        return Outcome.passed("systemd-journald is active")
    return Outcome.failed("systemd-journald is not active", expected="active")


@check(
    id="6.1.1.1.2", title="Ensure systemd-journal-remote service is not in use",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Unless this host is a central log collector, the journal-remote receiver is needless network exposure.",
    remediation="systemctl --now mask systemd-journal-remote.socket systemd-journal-remote.service",
    tags=("logging", "journald", "remote"),
)
def journal_remote_not_used(ctx):
    on = (ctx.service_active("systemd-journal-remote.socket")
          or ctx.service_active("systemd-journal-remote.service")
          or ctx.service_enabled("systemd-journal-remote.socket"))
    if on:
        return Outcome.warn("systemd-journal-remote receiver is in use — confirm this host is a log collector",
                            expected="not in use unless a central collector")
    return Outcome.passed("systemd-journal-remote is not in use")


@check(
    id="6.1.1.1.3", title="Ensure journald is configured to send logs to rsyslog",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Forwarding to rsyslog enables central aggregation and tamper-evident off-host storage.",
    remediation="Set ForwardToSyslog=yes in /etc/systemd/journald.conf (if rsyslog is the chosen aggregator).",
    tags=("logging", "journald", "rsyslog"),
)
def journald_forward(ctx):
    val = _journald_conf(ctx).get("forwardtosyslog", "").lower()
    if val == "yes":
        return Outcome.passed("journald ForwardToSyslog=yes")
    return Outcome.warn("journald ForwardToSyslog is not enabled", actual=val or "unset",
                        expected="yes (when using rsyslog aggregation)")


@check(
    id="6.1.1.1.4", title="Ensure journald log file access is configured",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Journal file permissions are managed by the shipped systemd tmpfiles; CIS asks for an operator review.",
    remediation="Verify /etc/tmpfiles.d journal entries against the shipped defaults.",
    tags=("logging", "journald", "permissions"),
)
def journald_file_access(ctx):
    return Outcome.manual("Confirm journald log-file access matches the shipped systemd tmpfiles defaults.")


@check(
    id="6.1.1.1.5", title="Ensure journald log file rotation is configured",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Rotation/size limits (SystemMaxUse, MaxFileSec) keep the journal bounded per site policy.",
    remediation="Set SystemMaxUse/SystemKeepFree/RuntimeMaxUse/MaxFileSec in journald.conf per site policy.",
    tags=("logging", "journald", "rotation"),
)
def journald_rotation(ctx):
    cfg = _journald_conf(ctx)
    keys = {k: cfg[k] for k in ("systemmaxuse", "systemkeepfree", "runtimemaxuse", "maxfilesec") if k in cfg}
    return Outcome.manual("Confirm journald rotation/size limits meet site policy.",
                          actual=keys or "no explicit limits set")


@check(
    id="6.1.1.1.6", title="Ensure journald Storage is configured",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Storage=persistent keeps logs across reboots; volatile logs vanish, destroying post-incident evidence.",
    remediation="Set Storage=persistent in /etc/systemd/journald.conf and restart systemd-journald.",
    tags=("logging", "journald", "persistence"),
)
def journald_storage(ctx):
    val = _journald_conf(ctx).get("storage", "").lower()
    if val == "persistent" or (not val and ctx.file_exists("/var/log/journal")):
        return Outcome.passed("journald Storage is persistent", actual=val or "auto+/var/log/journal")
    return Outcome.failed(f"journald Storage = {val or 'unset'}", actual=val or "unset", expected="persistent")


@check(
    id="6.1.1.1.7", title="Ensure journald Compress is configured",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Compress=yes lets the journal retain more history within its size budget.",
    remediation="Set Compress=yes in /etc/systemd/journald.conf.", tags=("logging", "journald"),
)
def journald_compress(ctx):
    val = _journald_conf(ctx).get("compress", "").lower()
    if val in ("", "yes"):  # default is yes
        return Outcome.passed("journald Compress is enabled", actual=val or "default (yes)")
    return Outcome.failed(f"journald Compress = {val}", actual=val, expected="yes")


# --------------------------------------------------------------------------- #
# 6.1.2  rsyslog
# --------------------------------------------------------------------------- #
@check(
    id="6.1.2.1", title="Ensure rsyslog is installed",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="rsyslog provides reliable on-disk and remote logging beyond the journal.",
    remediation="apt install rsyslog", tags=("logging", "rsyslog"),
)
def rsyslog_installed(ctx):
    if ctx.package_installed("rsyslog"):
        return Outcome.passed("rsyslog is installed")
    return Outcome.failed("rsyslog is not installed", expected="installed")


@check(
    id="6.1.2.2", title="Ensure rsyslog service is enabled and active",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="rsyslog must be enabled and running to capture and forward logs.",
    remediation="systemctl --now enable rsyslog", tags=("logging", "rsyslog"),
)
def rsyslog_active(ctx):
    if not ctx.package_installed("rsyslog"):
        return Outcome.skip("rsyslog not installed")
    enabled = ctx.service_enabled("rsyslog.service")
    active = ctx.service_active("rsyslog.service")
    if enabled and active:
        return Outcome.passed("rsyslog is enabled and active")
    return Outcome.failed(f"rsyslog enabled={enabled}, active={active}",
                          actual={"enabled": enabled, "active": active}, expected="enabled and active")


@check(
    id="6.1.2.3", title="Ensure rsyslog log file creation mode is configured",
    section="6.1 System Logging", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="$FileCreateMode 0640 keeps rsyslog-created logs out of reach of non-privileged users.",
    remediation="Set '$FileCreateMode 0640' in /etc/rsyslog.conf (or a drop-in).", tags=("logging", "rsyslog", "permissions"),
)
def rsyslog_filecreatemode(ctx):
    text = _rsyslog_text(ctx)
    m = re.search(r"\$FileCreateMode\s+(\d{3,4})", text)
    if not m:
        return Outcome.warn("$FileCreateMode not set; rsyslog defaults to 0644",
                            expected="$FileCreateMode 0640 or more restrictive")
    mode = int(m.group(1), 8)
    if mode & 0o137 == 0:
        return Outcome.passed(f"$FileCreateMode {m.group(1)}", actual=m.group(1))
    return Outcome.failed(f"$FileCreateMode {m.group(1)} is too permissive", actual=m.group(1), expected="<= 0640")


@check(
    id="6.1.2.4", title="Ensure rsyslog logging is configured",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="The set of facility/priority rules is site-specific; CIS marks this Manual.",
    remediation="Review /etc/rsyslog.conf and /etc/rsyslog.d/* against site logging policy.",
    tags=("logging", "rsyslog"),
)
def rsyslog_logging_configured(ctx):
    return Outcome.manual("Confirm rsyslog facility/priority rules match site logging policy.")


@check(
    id="6.1.2.5", title="Ensure rsyslog is configured to send logs to a remote log host",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Off-host log shipping preserves evidence even if the host is compromised; the target is site-specific.",
    remediation="Configure an action forwarding logs to the central log host in rsyslog.",
    tags=("logging", "rsyslog", "remote"),
)
def rsyslog_remote_send(ctx):
    text = _rsyslog_text(ctx)
    if re.search(r"@@?[\w.\-:]+", text) or "target=" in text.lower():
        return Outcome.passed("rsyslog appears to forward to a remote host (confirm the target)")
    return Outcome.manual("Confirm rsyslog forwards logs to the site's central log host.")


@check(
    id="6.1.2.6", title="Ensure rsyslog is not configured to receive logs from a remote client",
    section="6.1 System Logging", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Unless this host is a log server, an open imtcp/imudp receiver is needless network exposure.",
    remediation="Remove/comment imtcp & imudp module loads and inputs in rsyslog config.",
    tags=("logging", "rsyslog", "remote"),
)
def rsyslog_not_receiving(ctx):
    text = _rsyslog_text(ctx).lower()
    active = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#") or not s:
            continue
        if "imtcp" in s or "imudp" in s or "inputtcpserverrun" in s.replace(" ", "") or "inputudpserverrun" in s.replace(" ", ""):
            active.append(s)
    if active:
        return Outcome.warn("rsyslog may be receiving remote logs — confirm this host is a log server",
                            actual=active[:5], expected="no imtcp/imudp inputs unless a log server")
    return Outcome.passed("rsyslog is not configured to receive remote logs")


@check(
    id="6.1.2.7", title="Ensure logrotate is configured",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="logrotate frequency/retention is site-specific; CIS marks this Manual.",
    remediation="Review /etc/logrotate.conf and /etc/logrotate.d/* against site policy.",
    tags=("logging", "logrotate"),
)
def logrotate_configured(ctx):
    present = ctx.file_exists("/etc/logrotate.conf")
    return Outcome.manual("Confirm logrotate retention matches site policy.",
                          actual={"logrotate.conf": present})


@check(
    id="6.1.2.8", title="Ensure rsyslog-gnutls is installed",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="rsyslog-gnutls provides TLS for encrypted log forwarding.",
    remediation="apt install rsyslog-gnutls", tags=("logging", "rsyslog", "tls"),
)
def rsyslog_gnutls_installed(ctx):
    if ctx.package_installed("rsyslog-gnutls"):
        return Outcome.passed("rsyslog-gnutls is installed")
    return Outcome.warn("rsyslog-gnutls is not installed (needed for TLS log forwarding)", expected="installed")


@check(
    id="6.1.2.9", title="Ensure rsyslog forwarding uses gtls",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="The gtls netstream driver encrypts forwarded logs in transit.",
    remediation="Set DefaultNetstreamDriver to gtls and use TLS in the forwarding action.",
    tags=("logging", "rsyslog", "tls"),
)
def rsyslog_gtls(ctx):
    text = _rsyslog_text(ctx).lower()
    if "gtls" in text:
        return Outcome.passed("rsyslog forwarding references the gtls driver")
    return Outcome.manual("If forwarding logs off-host, confirm it uses the gtls (TLS) netstream driver.")


@check(
    id="6.1.2.10", title="Ensure rsyslog CA certificates are configured",
    section="6.1 System Logging", severity=Severity.LOW, levels=(Level.L1,),
    rationale="TLS log forwarding needs a configured CA bundle to authenticate the log server.",
    remediation="Set DefaultNetstreamDriverCAFile to the CA bundle used by the log server.",
    tags=("logging", "rsyslog", "tls"),
)
def rsyslog_ca_certs(ctx):
    return Outcome.manual("If forwarding logs over TLS, confirm the rsyslog CA certificate is configured.")


# 6.1.3  logfiles
@check(
    id="6.1.3.1", title="Ensure access to all logfiles has been configured",
    section="6.1 System Logging", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="World-readable logs leak usernames/IPs/tokens; group/world-writable logs let attackers forge or erase entries.",
    remediation="Tighten ownership and permissions (<=0640) on files under /var/log.",
    tags=("logging", "permissions"),
)
def logfile_permissions(ctx):
    res = ctx.sh(r"find /var/log -type f \( -perm /0137 \) 2>/dev/null | head -50")
    offenders = res.lines()
    if not offenders:
        return Outcome.passed("No overly-permissive files found under /var/log")
    return Outcome.failed(f"{len(offenders)} log file(s) more permissive than 0640",
                          evidence=offenders[:20], actual=offenders[:20], expected="<= 0640, no world access")


# --------------------------------------------------------------------------- #
# 6.2.1  auditd service
# --------------------------------------------------------------------------- #
@check(
    id="6.2.1.1", title="Ensure auditd packages are installed",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="auditd (and the dispatcher plugins) capture security-relevant kernel events for the forensic record.",
    remediation="apt install auditd audispd-plugins", tags=("audit", "auditd"),
)
def auditd_installed(ctx):
    have_auditd = ctx.package_installed("auditd") or ctx.run(["sh", "-c", "command -v auditctl"]).ok
    have_plugins = ctx.package_installed("audispd-plugins")
    if have_auditd and have_plugins:
        return Outcome.passed("auditd and audispd-plugins are installed")
    if have_auditd:
        return Outcome.warn("auditd installed but audispd-plugins is missing", expected="both installed")
    return Outcome.failed("auditd is not installed", expected="auditd + audispd-plugins")


@check(
    id="6.2.1.2", title="Ensure auditd service is enabled and active",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="An installed but stopped auditd records nothing; it must be enabled and running.",
    remediation="systemctl --now enable auditd", tags=("audit", "auditd"),
)
def auditd_active(ctx):
    if not ctx.package_installed("auditd"):
        return Outcome.skip("auditd not installed")
    enabled = ctx.service_enabled("auditd.service")
    active = ctx.service_active("auditd.service")
    if enabled and active:
        return Outcome.passed("auditd is enabled and active")
    return Outcome.failed(f"auditd enabled={enabled}, active={active}",
                          actual={"enabled": enabled, "active": active}, expected="enabled and active")


@check(
    id="6.2.1.3", title="Ensure auditing for processes that start prior to auditd is enabled",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="'audit=1' on the kernel command line audits processes that start before auditd, closing a boot-time gap.",
    remediation="Add 'audit=1' to GRUB_CMDLINE_LINUX and update-grub.", tags=("audit", "boot"),
)
def auditd_boot_param(ctx):
    cmdline = ctx.read_file("/proc/cmdline")
    if cmdline is None:
        return Outcome.manual("Could not read /proc/cmdline; verify 'audit=1' is on the kernel command line")
    if re.search(r"\baudit=1\b", cmdline):
        return Outcome.passed("audit=1 is set on the kernel command line")
    return Outcome.failed("audit=1 not present on the kernel command line", actual=cmdline.strip(), expected="audit=1")


@check(
    id="6.2.1.4", title="Ensure audit_backlog_limit is configured",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="A sufficient audit_backlog_limit (>=8192) avoids dropping early-boot audit events.",
    remediation="Add 'audit_backlog_limit=8192' to GRUB_CMDLINE_LINUX and update-grub.", tags=("audit", "boot"),
)
def auditd_backlog(ctx):
    cmdline = ctx.read_file("/proc/cmdline")
    if cmdline is None:
        return Outcome.manual("Could not read /proc/cmdline; verify audit_backlog_limit>=8192")
    m = re.search(r"audit_backlog_limit=(\d+)", cmdline)
    if m and int(m.group(1)) >= 8192:
        return Outcome.passed(f"audit_backlog_limit={m.group(1)}")
    return Outcome.failed(f"audit_backlog_limit={m.group(1) if m else 'unset'}",
                          actual=cmdline.strip(), expected=">= 8192")


# --------------------------------------------------------------------------- #
# 6.2.2  data retention (auditd.conf)
# --------------------------------------------------------------------------- #
@check(
    id="6.2.2.1", title="Ensure audit log storage size is configured",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="A defined max_log_file bounds each audit log so rotation behaves predictably.",
    remediation="Set max_log_file to a site-appropriate size (MB) in /etc/audit/auditd.conf.",
    tags=("audit", "retention"),
)
def audit_log_size(ctx):
    cfg = ctx.parse_keyword_file("/etc/audit/auditd.conf", sep="=")
    if not cfg:
        return Outcome.skip("auditd.conf not present")
    val = cfg.get("max_log_file")
    if val and val.strip().isdigit():
        return Outcome.passed(f"max_log_file = {val} MB", actual=val)
    return Outcome.failed("max_log_file is not configured", actual=val, expected="a numeric size (MB)")


@check(
    id="6.2.2.2", title="Ensure audit logs are not automatically deleted",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="max_log_file_action=keep_logs stops rotation from discarding the audit trail.",
    remediation="Set 'max_log_file_action = keep_logs' in /etc/audit/auditd.conf.", tags=("audit", "retention"),
)
def audit_keep_logs(ctx):
    cfg = ctx.parse_keyword_file("/etc/audit/auditd.conf", sep="=")
    if not cfg:
        return Outcome.skip("auditd.conf not present")
    action = cfg.get("max_log_file_action", "").lower()
    if action == "keep_logs":
        return Outcome.passed("max_log_file_action = keep_logs")
    return Outcome.failed(f"max_log_file_action = {action or 'unset'}", actual=action, expected="keep_logs")


@check(
    id="6.2.2.3", title="Ensure system is disabled when audit logs are full",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="A halt/single-user admin action when logs fill prevents unaudited operation.",
    remediation="Set disk_full_action / admin_space_left_action to halt or single in auditd.conf.",
    tags=("audit", "retention"),
)
def audit_disk_full(ctx):
    cfg = ctx.parse_keyword_file("/etc/audit/auditd.conf", sep="=")
    if not cfg:
        return Outcome.skip("auditd.conf not present")
    good = {"halt", "single", "syslog"}
    actions = {k: cfg.get(k, "").lower() for k in ("disk_full_action", "admin_space_left_action")}
    if any(v in good for v in actions.values()):
        return Outcome.passed("auditd halts/alerts when logs are full", actual=actions)
    return Outcome.failed("No halt/single action when audit logs are full", actual=actions,
                          expected="disk_full_action/admin_space_left_action in {halt,single}")


@check(
    id="6.2.2.4", title="Ensure system warns when audit logs are low on space",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="A space_left_action of email/exec warns admins before the audit log fills.",
    remediation="Set space_left_action = email (or exec) in /etc/audit/auditd.conf.", tags=("audit", "retention"),
)
def audit_low_space(ctx):
    cfg = ctx.parse_keyword_file("/etc/audit/auditd.conf", sep="=")
    if not cfg:
        return Outcome.skip("auditd.conf not present")
    action = cfg.get("space_left_action", "").lower()
    if action in ("email", "exec", "syslog"):
        return Outcome.passed(f"space_left_action = {action}", actual=action)
    return Outcome.failed(f"space_left_action = {action or 'unset'}", actual=action, expected="email/exec/syslog")


# --------------------------------------------------------------------------- #
# 6.2.3  audit rules — data-table + factory
# (cis_id, title, [match tokens], severity).  PASS if ANY token is present in
# the merged rules text; the tokens are the CIS audit keys + watched paths.
# --------------------------------------------------------------------------- #
_AUDIT_RULES = [
    ("6.2.3.1", "Ensure changes to system administration scope (sudoers) is collected",
     ["-k scope", "key=scope", "/etc/sudoers"]),
    ("6.2.3.2", "Ensure actions as another user are always logged",
     ["-k user_emulation", "key=user_emulation"]),
    ("6.2.3.3", "Ensure events that modify the sudo log file are collected",
     ["-k sudo_log_file", "/var/log/sudo.log"]),
    ("6.2.3.4", "Ensure events that modify date and time information are collected",
     ["-k time-change", "key=time-change", "/etc/localtime", "adjtimex", "settimeofday", "clock_settime"]),
    ("6.2.3.5", "Ensure events that modify sethostname and setdomainname are collected",
     ["-k system-locale", "key=system-locale", "sethostname", "setdomainname"]),
    ("6.2.3.6", "Ensure events that modify /etc/issue and /etc/issue.net are collected",
     ["/etc/issue"]),
    ("6.2.3.7", "Ensure events that modify /etc/hosts and /etc/hostname are collected",
     ["/etc/hosts", "/etc/hostname"]),
    ("6.2.3.8", "Ensure events that modify /etc/network and /etc/networks are collected",
     ["/etc/network", "/etc/networks"]),
    ("6.2.3.9", "Ensure events that modify /etc/netplan are collected",
     ["/etc/netplan"]),
    ("6.2.3.10", "Ensure use of privileged commands are collected",
     ["-k privileged", "key=privileged"]),
    ("6.2.3.11", "Ensure events that modify /etc/group information are collected",
     ["/etc/group"]),
    ("6.2.3.12", "Ensure events that modify /etc/passwd information are collected",
     ["/etc/passwd"]),
    ("6.2.3.13", "Ensure events that modify /etc/shadow and /etc/gshadow are collected",
     ["/etc/shadow", "/etc/gshadow"]),
    ("6.2.3.14", "Ensure events that modify /etc/security/opasswd are collected",
     ["/etc/security/opasswd"]),
    ("6.2.3.15", "Ensure events that modify /etc/nsswitch.conf file are collected",
     ["/etc/nsswitch.conf"]),
    ("6.2.3.16", "Ensure events that modify /etc/pam.conf and /etc/pam.d/ are collected",
     ["/etc/pam.conf", "/etc/pam.d"]),
    ("6.2.3.17", "Ensure unsuccessful file access attempts are collected",
     ["-k access", "key=access"]),
    ("6.2.3.18", "Ensure discretionary access control permission modification events are collected",
     ["-k perm_mod", "key=perm_mod"]),
    ("6.2.3.19", "Ensure successful file system mounts are collected",
     ["-k mounts", "key=mounts"]),
    ("6.2.3.20", "Ensure session initiation information is collected",
     ["-k session", "key=session", "/var/run/utmp"]),
    ("6.2.3.21", "Ensure login and logout events are collected",
     ["-k logins", "key=logins", "/var/log/lastlog", "/var/log/wtmp", "/var/log/btmp", "/var/run/faillock"]),
    ("6.2.3.22", "Ensure file deletion events by users are collected",
     ["-k delete", "key=delete", "unlink"]),
    ("6.2.3.23", "Ensure events that modify the system's Mandatory Access Controls are collected",
     ["-k mac-policy", "key=mac-policy", "/etc/apparmor"]),
    ("6.2.3.24", "Ensure attempts to use the chcon command are collected",
     ["/usr/bin/chcon", "chcon"]),
    ("6.2.3.25", "Ensure attempts to use the setfacl command are collected",
     ["/usr/bin/setfacl", "setfacl"]),
    ("6.2.3.26", "Ensure attempts to use the chacl command are collected",
     ["/usr/bin/chacl", "chacl"]),
    ("6.2.3.27", "Ensure attempts to use the usermod command are collected",
     ["-k usermod", "key=usermod", "/usr/sbin/usermod"]),
    ("6.2.3.28", "Ensure kernel module loading, unloading and modification is collected",
     ["-k kernel_modules", "key=kernel_modules", "init_module", "finit_module", "delete_module", "/usr/bin/kmod"]),
]


def _make_audit_rule_check(cis_id, title, tokens):
    @check(
        id=cis_id, title=title, section="6.2 System Auditing",
        severity=Severity.LOW, levels=(Level.L2,),
        rationale="Audit rules record security-relevant changes so an investigator can reconstruct attacker activity.",
        remediation="Add the corresponding rule to /etc/audit/rules.d/*.rules and run augenrules --load.",
        tags=("audit", "auditd", "rules"),
    )
    def _chk(ctx, _tokens=[t.lower() for t in tokens]):
        text = _audit_rules_text(ctx)
        if not text:
            if not ctx.is_root:
                return Outcome.manual("Root required to read the audit ruleset")
            return Outcome.failed("No audit rules are loaded/configured", expected="the corresponding rule")
        if any(tok in text for tok in _tokens):
            return Outcome.passed("Audit rule present")
        return Outcome.failed("Audit rule not found", expected=" or ".join(_tokens))

    return _chk


for _row in _AUDIT_RULES:
    _make_audit_rule_check(*_row)


@check(
    id="6.2.3.29", title="Ensure the audit configuration is immutable",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="'-e 2' prevents an attacker with root from silently disabling auditing without a reboot.",
    remediation="Add '-e 2' as the final rule in /etc/audit/rules.d/99-finalize.rules.", tags=("audit", "immutable"),
)
def audit_immutable(ctx):
    text = _audit_rules_text(ctx)
    if "-e 2" in text:
        return Outcome.passed("Audit configuration is immutable (-e 2)")
    loaded = ctx.run(["auditctl", "-s"])
    if loaded.ok and "enabled 2" in loaded.combined.lower():
        return Outcome.passed("Audit configuration is immutable (enabled 2)")
    if not text and not ctx.is_root:
        return Outcome.manual("Root required to inspect audit rules")
    return Outcome.failed("Audit configuration is not immutable", expected="-e 2 as the final rule")


@check(
    id="6.2.3.30", title="Ensure the running and on disk configuration is the same",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="A drift between loaded and on-disk rules means a reboot would change auditing; CIS marks this Manual.",
    remediation="Run 'augenrules --check' and reconcile any differences.", tags=("audit", "auditd"),
)
def audit_running_matches_disk(ctx):
    return Outcome.manual("Run 'augenrules --check' to confirm the loaded ruleset matches /etc/audit/rules.d.")


# --------------------------------------------------------------------------- #
# 6.2.4  auditd file access — factory over stat
# --------------------------------------------------------------------------- #
_AUDIT_TOOLS = [
    "/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace",
    "/sbin/auditd", "/sbin/augenrules",
]


def _stat_targets(ctx, paths):
    return [(p, ctx.stat(p)) for p in paths]


@check(
    id="6.2.4.1", title="Ensure the audit log file directory mode is configured",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="A 0750-or-stricter audit log directory keeps non-privileged users from reading the trail.",
    remediation="chmod 0750 /var/log/audit (the directory configured as log_file's parent).", tags=("audit", "permissions"),
)
def audit_logdir_mode(ctx):
    st = ctx.stat("/var/log/audit")
    if not st.exists:
        return Outcome.skip("/var/log/audit not present")
    if st.perm_at_most(0o750):
        return Outcome.passed(f"audit log directory mode {st.mode_str}", actual=st.mode_str)
    return Outcome.failed(f"audit log directory mode {st.mode_str}", actual=st.mode_str, expected="<= 0750")


@check(
    id="6.2.4.2", title="Ensure audit log files mode is configured",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="Audit logs at 0640-or-stricter prevent disclosure/tampering of the forensic record.",
    remediation="chmod 0640 /var/log/audit/*.", tags=("audit", "permissions"),
)
def audit_log_mode(ctx):
    files = ctx.glob("/var/log/audit/*")
    bad = [f"{p} ({st.mode_str})" for p, st in _stat_targets(ctx, files) if st.exists and not st.perm_at_most(0o640)]
    if not files:
        return Outcome.skip("No audit log files found")
    if bad:
        return Outcome.failed("Audit logs too permissive: " + ", ".join(bad), actual=bad, expected="<= 0640")
    return Outcome.passed(f"All {len(files)} audit log file(s) are <= 0640")


@check(
    id="6.2.4.3", title="Ensure audit log files owner is configured",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="root ownership of audit logs prevents non-privileged tampering.",
    remediation="chown root /var/log/audit/*.", tags=("audit", "permissions"),
)
def audit_log_owner(ctx):
    files = ctx.glob("/var/log/audit/*")
    bad = [f"{p} ({st.owner})" for p, st in _stat_targets(ctx, files) if st.exists and st.uid != 0]
    if not files:
        return Outcome.skip("No audit log files found")
    if bad:
        return Outcome.failed("Audit logs not owned by root: " + ", ".join(bad), actual=bad, expected="root")
    return Outcome.passed("All audit log files are owned by root")


@check(
    id="6.2.4.4", title="Ensure audit log files group owner is configured",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="A root/adm group owner keeps audit logs out of reach of other groups.",
    remediation="chgrp root (or adm) /var/log/audit/*.", tags=("audit", "permissions"),
)
def audit_log_group(ctx):
    files = ctx.glob("/var/log/audit/*")
    bad = [f"{p} ({st.group})" for p, st in _stat_targets(ctx, files) if st.exists and st.group not in ("root", "adm")]
    if not files:
        return Outcome.skip("No audit log files found")
    if bad:
        return Outcome.failed("Audit logs with unexpected group: " + ", ".join(bad), actual=bad, expected="root/adm")
    return Outcome.passed("All audit log files are group root/adm")


def _audit_config_files(ctx):
    paths = ["/etc/audit/auditd.conf", "/etc/audit/audit.rules"]
    paths += ctx.glob("/etc/audit/rules.d/*.rules")
    return paths


@check(
    id="6.2.4.5", title="Ensure audit configuration files mode is configured",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="0640-or-stricter audit config prevents tampering with what is (and isn't) audited.",
    remediation="chmod 0640 /etc/audit/auditd.conf and the rules files.", tags=("audit", "permissions"),
)
def audit_conf_mode(ctx):
    files = _audit_config_files(ctx)
    bad = [f"{p} ({st.mode_str})" for p, st in _stat_targets(ctx, files) if st.exists and not st.perm_at_most(0o640)]
    present = [p for p, st in _stat_targets(ctx, files) if st.exists]
    if not present:
        return Outcome.skip("No audit configuration files found")
    if bad:
        return Outcome.failed("Audit config too permissive: " + ", ".join(bad), actual=bad, expected="<= 0640")
    return Outcome.passed(f"All {len(present)} audit config file(s) are <= 0640")


@check(
    id="6.2.4.6", title="Ensure audit configuration files owner is configured",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="root ownership of audit config prevents non-privileged tampering.",
    remediation="chown root /etc/audit/auditd.conf and the rules files.", tags=("audit", "permissions"),
)
def audit_conf_owner(ctx):
    files = _audit_config_files(ctx)
    bad = [f"{p} ({st.owner})" for p, st in _stat_targets(ctx, files) if st.exists and st.uid != 0]
    present = [p for p, st in _stat_targets(ctx, files) if st.exists]
    if not present:
        return Outcome.skip("No audit configuration files found")
    if bad:
        return Outcome.failed("Audit config not owned by root: " + ", ".join(bad), actual=bad, expected="root")
    return Outcome.passed("All audit config files are owned by root")


@check(
    id="6.2.4.7", title="Ensure audit configuration files group owner is configured",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="A root group owner keeps audit config out of reach of other groups.",
    remediation="chgrp root /etc/audit/auditd.conf and the rules files.", tags=("audit", "permissions"),
)
def audit_conf_group(ctx):
    files = _audit_config_files(ctx)
    bad = [f"{p} ({st.group})" for p, st in _stat_targets(ctx, files) if st.exists and st.group != "root"]
    present = [p for p, st in _stat_targets(ctx, files) if st.exists]
    if not present:
        return Outcome.skip("No audit configuration files found")
    if bad:
        return Outcome.failed("Audit config with unexpected group: " + ", ".join(bad), actual=bad, expected="root")
    return Outcome.passed("All audit config files are group root")


@check(
    id="6.2.4.8", title="Ensure audit tools mode is configured",
    section="6.2 System Auditing", severity=Severity.MEDIUM, levels=(Level.L2,),
    rationale="0755-or-stricter audit tools prevent a non-privileged user from replacing them.",
    remediation="chmod 0755 the audit tools under /sbin.", tags=("audit", "permissions", "tools"),
)
def audit_tools_mode(ctx):
    tools = [(p, ctx.stat(p)) for p in _AUDIT_TOOLS]
    present = [(p, st) for p, st in tools if st.exists]
    bad = [f"{p} ({st.mode_str})" for p, st in present if not st.perm_at_most(0o755)]
    if not present:
        return Outcome.skip("No audit tools found")
    if bad:
        return Outcome.failed("Audit tools too permissive: " + ", ".join(bad), actual=bad, expected="<= 0755")
    return Outcome.passed(f"All {len(present)} audit tool(s) are <= 0755")


@check(
    id="6.2.4.9", title="Ensure audit tools owner is configured",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="root-owned audit tools cannot be replaced by a non-privileged user.",
    remediation="chown root the audit tools under /sbin.", tags=("audit", "permissions", "tools"),
)
def audit_tools_owner(ctx):
    present = [(p, ctx.stat(p)) for p in _AUDIT_TOOLS if ctx.stat(p).exists]
    bad = [f"{p} ({st.owner})" for p, st in present if st.uid != 0]
    if not present:
        return Outcome.skip("No audit tools found")
    if bad:
        return Outcome.failed("Audit tools not owned by root: " + ", ".join(bad), actual=bad, expected="root")
    return Outcome.passed("All audit tools are owned by root")


@check(
    id="6.2.4.10", title="Ensure audit tools group owner is configured",
    section="6.2 System Auditing", severity=Severity.LOW, levels=(Level.L2,),
    rationale="A root group owner keeps audit tools out of reach of other groups.",
    remediation="chgrp root the audit tools under /sbin.", tags=("audit", "permissions", "tools"),
)
def audit_tools_group(ctx):
    present = [(p, ctx.stat(p)) for p in _AUDIT_TOOLS if ctx.stat(p).exists]
    bad = [f"{p} ({st.group})" for p, st in present if st.group != "root"]
    if not present:
        return Outcome.skip("No audit tools found")
    if bad:
        return Outcome.failed("Audit tools with unexpected group: " + ", ".join(bad), actual=bad, expected="root")
    return Outcome.passed("All audit tools are group root")


# --------------------------------------------------------------------------- #
# 6.3  Integrity checking (AIDE)
# --------------------------------------------------------------------------- #
@check(
    id="6.3.1", title="Ensure AIDE is installed",
    section="6.3 Configure Integrity Checking", severity=Severity.LOW, levels=(Level.L1,),
    rationale="AIDE detects unauthorised changes to files, a core integrity-monitoring control.",
    remediation="apt install aide aide-common", tags=("integrity", "aide"),
)
def aide_installed(ctx):
    if ctx.package_installed("aide") or ctx.package_installed("aide-common") or \
            ctx.run(["sh", "-c", "command -v aide"]).ok:
        return Outcome.passed("AIDE is installed")
    return Outcome.failed("AIDE is not installed", expected="installed")


@check(
    id="6.3.2", title="Ensure filesystem integrity is regularly checked",
    section="6.3 Configure Integrity Checking", severity=Severity.LOW, levels=(Level.L1,),
    rationale="A scheduled AIDE run (timer or cron) is what actually surfaces tampering between manual checks.",
    remediation="Enable the dailyaidecheck.timer or add an aide --check cron entry.", tags=("integrity", "aide"),
)
def aide_scheduled(ctx):
    if not (ctx.package_installed("aide") or ctx.package_installed("aide-common")):
        return Outcome.skip("AIDE not installed")
    timer = ctx.service_enabled("dailyaidecheck.timer") or ctx.service_active("dailyaidecheck.timer")
    cron = any(ctx.glob(p) for p in ("/etc/cron.*/*aide*", "/etc/cron.d/*aide*")) or \
        bool(ctx.sh("grep -rl aide /etc/cron* /var/spool/cron 2>/dev/null").out)
    if timer or cron:
        return Outcome.passed("A scheduled AIDE integrity check is configured",
                              actual={"timer": timer, "cron": bool(cron)})
    return Outcome.failed("No scheduled AIDE check found", expected="dailyaidecheck.timer or a cron entry")


@check(
    id="6.3.3", title="Ensure cryptographic mechanisms protect the integrity of audit tools",
    section="6.3 Configure Integrity Checking", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Listing the audit tools in AIDE's config detects tampering with the very tools used for forensics.",
    remediation="Add the audit tool paths (with strong rules) to /etc/aide/aide.conf.", tags=("integrity", "aide", "audit"),
)
def aide_protects_audit_tools(ctx):
    conf = ctx.read_file("/etc/aide/aide.conf")
    if conf is None:
        conf = ctx.sh("cat /etc/aide/aide.conf.d/*.conf 2>/dev/null").out or None
    if conf is None:
        return Outcome.manual("Could not read aide.conf; verify the audit tools are integrity-monitored")
    covered = [t for t in _AUDIT_TOOLS if t in conf]
    if covered:
        return Outcome.passed(f"AIDE config references {len(covered)} audit tool(s)", actual=covered)
    return Outcome.failed("Audit tools are not listed in aide.conf", expected="audit tool paths present")
