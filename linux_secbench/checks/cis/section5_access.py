"""CIS Section 5 — Access, Authentication and Authorization (CIS Ubuntu 24.04 v2.0.0).

The densest section of the benchmark. v2.0.0 reorganised it into:
  5.1 Configure SSH Server                 (24)
  5.2 Configure privilege escalation       (7)
  5.3 Pluggable Authentication Modules     (26)
  5.4 User Accounts and Environment        (17)

Note the heavy renumbering vs v1.0.0: e.g. PermitRootLogin is now 5.1.20 (was
5.1.2), PermitEmptyPasswords is 5.1.19, and 5.1.1–5.1.3 are now SSH config /
host-key file-permission controls.
"""

from __future__ import annotations

import re

from ...core import Level, Outcome, Profile, Severity
from ._base import cis_check as check


# --------------------------------------------------------------------------- #
# Predicate helpers (shared by the keyword/login.defs tables)
# --------------------------------------------------------------------------- #
def _eq(expected):
    return (lambda v: v == expected, expected)


def _in(*allowed):
    return (lambda v: v in allowed, " or ".join(allowed))


def _int_at_most(limit):
    return (lambda v: v.isdigit() and int(v) <= limit, f"<= {limit}")


def _int_at_least(limit):
    return (lambda v: v.isdigit() and int(v) >= limit, f">= {limit}")


def _int_between(lo, hi):
    return (lambda v: v.isdigit() and lo <= int(v) <= hi, f"{lo}..{hi}")


# --------------------------------------------------------------------------- #
# 5.1  SSH Server — single-keyword controls (sshd -T)
# (cis_id, key, predicate, title, severity, level)
# --------------------------------------------------------------------------- #
_SSHD_CONTROLS = [
    ("5.1.8", "disableforwarding", _eq("yes"), "Ensure sshd DisableForwarding is enabled", Severity.MEDIUM, Level.L2),
    ("5.1.9", "gssapiauthentication", _eq("no"), "Ensure sshd GSSAPIAuthentication is disabled", Severity.MEDIUM, Level.L1),
    ("5.1.10", "hostbasedauthentication", _eq("no"), "Ensure sshd HostbasedAuthentication is disabled", Severity.MEDIUM, Level.L1),
    ("5.1.11", "ignorerhosts", _eq("yes"), "Ensure sshd IgnoreRhosts is enabled", Severity.MEDIUM, Level.L1),
    ("5.1.13", "logingracetime", _int_between(1, 60), "Ensure sshd LoginGraceTime is configured", Severity.MEDIUM, Level.L1),
    ("5.1.14", "loglevel", _in("verbose", "info"), "Ensure sshd LogLevel is configured", Severity.LOW, Level.L1),
    ("5.1.16", "maxauthtries", _int_at_most(4), "Ensure sshd MaxAuthTries is configured", Severity.MEDIUM, Level.L1),
    ("5.1.18", "maxsessions", _int_at_most(10), "Ensure sshd MaxSessions is configured", Severity.LOW, Level.L1),
    ("5.1.19", "permitemptypasswords", _eq("no"), "Ensure sshd PermitEmptyPasswords is disabled", Severity.CRITICAL, Level.L1),
    ("5.1.20", "permitrootlogin", _eq("no"), "Ensure sshd PermitRootLogin is disabled", Severity.HIGH, Level.L1),
    ("5.1.21", "permituserenvironment", _eq("no"), "Ensure sshd PermitUserEnvironment is disabled", Severity.MEDIUM, Level.L1),
    ("5.1.22", "usepam", _eq("yes"), "Ensure sshd UsePAM is enabled", Severity.MEDIUM, Level.L1),
]


def _make_sshd_check(cis_id, key, predicate, title, severity, level):
    fn, expected_desc = predicate

    @check(
        id=cis_id,
        title=title,
        section="5.1 Configure SSH Server",
        severity=severity,
        levels=(level,),
        profiles=(Profile.SERVER,),
        rationale="SSH is the primary remote-administration channel; weak server "
                  "settings expose it to brute force, hijacking, and info leakage.",
        remediation=f"Set '{key}' appropriately in /etc/ssh/sshd_config(.d) and reload sshd.",
        tags=("ssh", "authentication"),
    )
    def _chk(ctx, _key=key, _fn=fn, _exp=expected_desc):
        cfg = ctx.sshd_config()
        if not cfg:
            return Outcome.manual("Could not read effective sshd config (need sshd binary or root)")
        value = cfg.get(_key)
        if value is None:
            return Outcome.warn(f"{_key} not set; relying on compiled-in default", expected=_exp)
        if _fn(value):
            return Outcome.passed(f"{_key} = {value}", actual=value, expected=_exp)
        return Outcome.failed(f"{_key} = {value}", actual=value, expected=_exp)

    return _chk


for _row in _SSHD_CONTROLS:
    _make_sshd_check(*_row)


# 5.1.1 – 5.1.3  SSH file permissions
@check(
    id="5.1.1",
    title="Ensure access to /etc/ssh/sshd_config is configured",
    section="5.1 Configure SSH Server",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="sshd_config governs remote access; if writable by non-root it can be subverted.",
    remediation="chown root:root /etc/ssh/sshd_config (and sshd_config.d/*); chmod u-x,go-rwx.",
    tags=("ssh", "permissions"),
)
def sshd_config_perms(ctx):
    targets = ["/etc/ssh/sshd_config"] + ctx.glob("/etc/ssh/sshd_config.d/*")
    bad = []
    for path in targets:
        st = ctx.stat(path)
        if not st.exists:
            continue
        if not (st.uid == 0 and st.gid == 0 and st.perm_at_most(0o600)):
            bad.append(f"{path} ({st.mode_str} {st.owner}:{st.group})")
    if bad:
        return Outcome.failed("sshd_config files too permissive: " + ", ".join(bad),
                              actual=bad, expected="root:root, <=600")
    return Outcome.passed("sshd_config (and drop-ins) are root-owned and <=600")


@check(
    id="5.1.2",
    title="Ensure access to SSH private host key files is configured",
    section="5.1 Configure SSH Server",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="A readable private host key lets an attacker impersonate the server (MITM).",
    remediation="chown root:root (or root:ssh_keys) the private host keys; chmod 600 (640 if ssh_keys group).",
    tags=("ssh", "permissions", "host-key"),
)
def sshd_private_key_perms(ctx):
    keys = [k for k in ctx.glob("/etc/ssh/ssh_host_*_key")]
    if not keys:
        return Outcome.passed("No SSH private host keys found")
    bad = []
    for path in keys:
        st = ctx.stat(path)
        if not st.exists:
            continue
        ok_root = st.uid == 0 and st.gid == 0 and st.perm_at_most(0o600)
        ok_sshgrp = st.uid == 0 and st.group == "ssh_keys" and st.perm_at_most(0o640)
        if not (ok_root or ok_sshgrp):
            bad.append(f"{path} ({st.mode_str} {st.owner}:{st.group})")
    if bad:
        return Outcome.failed("Private host keys too permissive: " + ", ".join(bad),
                              actual=bad, expected="root:root <=600 (or root:ssh_keys <=640)")
    return Outcome.passed(f"All {len(keys)} private host key(s) adequately protected")


@check(
    id="5.1.3",
    title="Ensure access to SSH public host key files is configured",
    section="5.1 Configure SSH Server",
    severity=Severity.LOW,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="Public host keys must be readable but not writable by non-root, or they can be swapped.",
    remediation="chown root:root the public host keys; chmod u-x,go-wx (<=644).",
    tags=("ssh", "permissions", "host-key"),
)
def sshd_public_key_perms(ctx):
    keys = [k for k in ctx.glob("/etc/ssh/ssh_host_*_key.pub")]
    if not keys:
        return Outcome.passed("No SSH public host keys found")
    bad = []
    for path in keys:
        st = ctx.stat(path)
        if not st.exists:
            continue
        if not (st.uid == 0 and st.gid == 0 and st.perm_at_most(0o644)):
            bad.append(f"{path} ({st.mode_str} {st.owner}:{st.group})")
    if bad:
        return Outcome.failed("Public host keys too permissive: " + ", ".join(bad),
                              actual=bad, expected="root:root, <=644")
    return Outcome.passed(f"All {len(keys)} public host key(s) adequately protected")


@check(
    id="5.1.4",
    title="Ensure sshd access is configured",
    section="5.1 Configure SSH Server",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="AllowUsers/AllowGroups (or Deny*) restrict who may log in over SSH per site policy.",
    remediation="Set AllowUsers/AllowGroups (or DenyUsers/DenyGroups) in sshd_config per site policy.",
    tags=("ssh", "access-control"),
)
def sshd_access(ctx):
    cfg = ctx.sshd_config()
    if not cfg:
        return Outcome.manual("Could not read effective sshd config")
    configured = {k: cfg.get(k) for k in ("allowusers", "allowgroups", "denyusers", "denygroups")
                  if cfg.get(k)}
    if configured:
        return Outcome.passed("sshd access restriction configured", actual=configured)
    return Outcome.warn("No AllowUsers/AllowGroups/Deny* configured — verify against site policy",
                        expected="an access directive per site policy")


@check(
    id="5.1.5",
    title="Ensure sshd Banner is configured",
    section="5.1 Configure SSH Server",
    severity=Severity.LOW,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="A pre-auth banner presents the required legal/usage notice before login.",
    remediation="Set 'Banner /etc/issue.net' in sshd_config and populate the banner file.",
    tags=("ssh", "banner"),
)
def sshd_banner(ctx):
    cfg = ctx.sshd_config()
    if not cfg:
        return Outcome.manual("Could not read effective sshd config")
    banner = cfg.get("banner", "")
    if banner and banner.lower() != "none":
        return Outcome.passed(f"sshd Banner = {banner}", actual=banner)
    return Outcome.failed("sshd Banner is not configured", actual=banner or "none", expected="a banner path")


# 5.1.6 / 5.1.12 / 5.1.15  Strong crypto (per algorithm field)
_WEAK_CRYPTO = ("cbc", "arcfour", "3des", "md5", "-96", "umac-64",
                "diffie-hellman-group1", "diffie-hellman-group14-sha1", "rsa-sha")
_CRYPTO_CONTROLS = [
    ("5.1.6", "ciphers", "Ensure sshd Ciphers are configured"),
    ("5.1.12", "kexalgorithms", "Ensure sshd KexAlgorithms is configured"),
    ("5.1.15", "macs", "Ensure sshd MACs are configured"),
]


def _make_crypto_check(cis_id, field, title):
    @check(
        id=cis_id,
        title=title,
        section="5.1 Configure SSH Server",
        severity=Severity.MEDIUM,
        levels=(Level.L1,),
        profiles=(Profile.SERVER,),
        rationale="Weak ciphers (CBC, arcfour, 3des), MD5/96-bit MACs, and SHA1 KEX are broken or weak.",
        remediation=f"Restrict {field} in sshd_config to modern AEAD/ETM algorithms.",
        tags=("ssh", "crypto"),
    )
    def _chk(ctx, _field=field):
        cfg = ctx.sshd_config()
        if not cfg:
            return Outcome.manual("Could not read effective sshd config")
        value = cfg.get(_field, "")
        offenders = [m for m in _WEAK_CRYPTO if m in value.lower()]
        if offenders:
            return Outcome.failed(f"Weak algorithms in {_field}: {', '.join(offenders)}",
                                  actual=value, expected="modern algorithms only")
        return Outcome.passed(f"No weak algorithms in {_field}", actual=value or "compiled-in default")

    return _chk


for _row in _CRYPTO_CONTROLS:
    _make_crypto_check(*_row)


@check(
    id="5.1.7",
    title="Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured",
    section="5.1 Configure SSH Server",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="Idle-session timeouts end abandoned SSH sessions, limiting hijack windows.",
    remediation="Set ClientAliveInterval (nonzero, e.g. 15) and ClientAliveCountMax (1..3) in sshd_config.",
    tags=("ssh", "timeout"),
)
def sshd_client_alive(ctx):
    cfg = ctx.sshd_config()
    if not cfg:
        return Outcome.manual("Could not read effective sshd config")
    interval = cfg.get("clientaliveinterval", "")
    countmax = cfg.get("clientalivecountmax", "")
    ok_int = interval.isdigit() and 0 < int(interval) <= 900
    ok_cnt = countmax.isdigit() and 0 < int(countmax) <= 3
    if ok_int and ok_cnt:
        return Outcome.passed(f"ClientAliveInterval={interval}, ClientAliveCountMax={countmax}",
                              actual={"interval": interval, "countmax": countmax})
    return Outcome.failed("ClientAlive timeout not properly configured",
                          actual={"interval": interval, "countmax": countmax},
                          expected="interval nonzero (<=900), countmax 1..3")


@check(
    id="5.1.17",
    title="Ensure sshd MaxStartups is configured",
    section="5.1 Configure SSH Server",
    severity=Severity.LOW,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="Rate-limiting unauthenticated connections (10:30:60 or stricter) blunts SSH connection floods.",
    remediation="Set 'MaxStartups 10:30:60' (or more restrictive) in sshd_config.",
    tags=("ssh", "dos"),
)
def sshd_maxstartups(ctx):
    cfg = ctx.sshd_config()
    if not cfg:
        return Outcome.manual("Could not read effective sshd config")
    value = cfg.get("maxstartups", "")
    parts = value.split(":")
    limits = (10, 30, 60)
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return Outcome.failed(f"MaxStartups unparseable: {value!r}", expected="10:30:60 or stricter")
    if nums and all(n <= lim for n, lim in zip(nums, limits)):
        return Outcome.passed(f"MaxStartups = {value}", actual=value, expected="<= 10:30:60")
    return Outcome.failed(f"MaxStartups = {value}", actual=value, expected="<= 10:30:60")


@check(
    id="5.1.23",
    title="Ensure sshd post-quantum cryptography key exchange algorithms are configured",
    section="5.1 Configure SSH Server",
    severity=Severity.LOW,
    levels=(Level.L2,),
    profiles=(Profile.SERVER,),
    rationale="PQC-hybrid KEX (e.g. sntrup761x25519, mlkem768x25519) resists 'harvest-now, decrypt-later' attacks.",
    remediation="Prefer a PQC-hybrid KexAlgorithms list (e.g. sntrup761x25519-sha512@openssh.com) in sshd_config.",
    tags=("ssh", "crypto", "post-quantum"),
)
def sshd_pqc_kex(ctx):
    cfg = ctx.sshd_config()
    if not cfg:
        return Outcome.manual("Could not read effective sshd config")
    kex = cfg.get("kexalgorithms", "").lower()
    if any(m in kex for m in ("sntrup761", "mlkem768", "mlkem1024")):
        return Outcome.passed("PQC-hybrid key exchange is configured", actual=kex)
    return Outcome.warn("No post-quantum KEX algorithm configured", actual=kex or "compiled-in default",
                        expected="a PQC-hybrid KEX (sntrup761x25519 / mlkem768x25519)")


@check(
    id="5.1.24",
    title="Ensure sshd ListenAddress is configured",
    section="5.1 Configure SSH Server",
    severity=Severity.INFO,
    levels=(Level.L1,),
    profiles=(Profile.SERVER,),
    rationale="Binding sshd to specific addresses (per site policy) avoids exposing it on unintended interfaces.",
    remediation="Set ListenAddress to the required management interface(s) in sshd_config.",
    tags=("ssh", "network"),
)
def sshd_listen_address(ctx):
    cfg = ctx.sshd_config()
    addrs = cfg.get("listenaddress", "") if cfg else ""
    return Outcome.manual(
        f"sshd ListenAddress = {addrs or 'default (all interfaces)'} — confirm this matches site policy.",
        actual=addrs or "0.0.0.0/::",
    )


# --------------------------------------------------------------------------- #
# 5.2  Privilege escalation (sudo / su)
# --------------------------------------------------------------------------- #
@check(
    id="5.2.1", title="Ensure sudo is installed", section="5.2 Configure privilege escalation",
    severity=Severity.LOW, levels=(Level.L1,),
    rationale="sudo provides accountable, logged privilege escalation; its absence implies shared root or su.",
    remediation="apt install sudo", tags=("sudo",),
)
def sudo_installed(ctx):
    if ctx.package_installed("sudo") or ctx.run(["sh", "-c", "command -v sudo"]).ok:
        return Outcome.passed("sudo is installed")
    return Outcome.failed("sudo is not installed", expected="installed")


@check(
    id="5.2.2", title="Ensure sudo commands use a pty", section="5.2 Configure privilege escalation",
    severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Defaults use_pty stops a sudo-run program from hijacking the user's terminal after the session ends.",
    remediation="Add 'Defaults use_pty' to /etc/sudoers (via visudo).", tags=("sudo",),
)
def sudo_use_pty(ctx):
    text = _sudoers_text(ctx)
    if text is None:
        return Outcome.manual("Root required to read sudoers; verify 'Defaults use_pty'")
    if _has_default(text, "use_pty"):
        return Outcome.passed("'Defaults use_pty' is configured")
    return Outcome.failed("'Defaults use_pty' is not configured", expected="Defaults use_pty")


@check(
    id="5.2.3", title="Ensure sudo log file exists", section="5.2 Configure privilege escalation",
    severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="A dedicated sudo logfile creates an audit trail of privilege use independent of syslog.",
    remediation='Add \'Defaults logfile="/var/log/sudo.log"\' to /etc/sudoers.', tags=("sudo", "logging"),
)
def sudo_logfile(ctx):
    text = _sudoers_text(ctx)
    if text is None:
        return Outcome.manual("Root required to read sudoers; verify 'Defaults logfile'")
    if "logfile" in text:
        return Outcome.passed("sudo logfile is configured")
    return Outcome.warn("No 'Defaults logfile' in sudoers (syslog may still capture sudo)",
                        expected="Defaults logfile=...")


@check(
    id="5.2.4", title="Ensure users must provide password for privilege escalation",
    section="5.2 Configure privilege escalation",
    severity=Severity.HIGH, levels=(Level.L1,),
    rationale="NOPASSWD rules let a hijacked session escalate to root with no further authentication.",
    remediation="Remove NOPASSWD from sudoers rules (scope to specific commands only if truly required).",
    tags=("sudo", "nopasswd"),
)
def sudo_requires_password(ctx):
    text = _sudoers_text(ctx)
    if text is None:
        return Outcome.manual("Root required to read sudoers; verify no NOPASSWD rules")
    offenders = [s.strip() for s in text.splitlines()
                 if s.strip() and not s.strip().startswith("#") and "NOPASSWD" in s]
    if offenders:
        return Outcome.failed("NOPASSWD rules present in sudoers", evidence=offenders, actual=offenders,
                              expected="no NOPASSWD")
    return Outcome.passed("No NOPASSWD rules in sudoers")


@check(
    id="5.2.5", title="Ensure re-authentication for privilege escalation is not disabled globally",
    section="5.2 Configure privilege escalation",
    severity=Severity.HIGH, levels=(Level.L1,),
    rationale="A global '!authenticate' lets any compromised sudo user escalate without a password.",
    remediation="Remove '!authenticate' from sudoers; require authentication for escalation.",
    tags=("sudo", "authenticate"),
)
def sudo_reauth(ctx):
    text = _sudoers_text(ctx)
    if text is None:
        return Outcome.manual("Root required to read sudoers; verify no global '!authenticate'")
    offenders = [s.strip() for s in text.splitlines()
                 if s.strip() and not s.strip().startswith("#") and "!authenticate" in s]
    if offenders:
        return Outcome.failed("Global '!authenticate' weakens re-auth", evidence=offenders, actual=offenders)
    return Outcome.passed("No global '!authenticate' found")


@check(
    id="5.2.6", title="Ensure sudo timestamp_timeout is configured",
    section="5.2 Configure privilege escalation",
    severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="A bounded timestamp_timeout limits how long a cached sudo credential stays valid.",
    remediation="Set 'Defaults timestamp_timeout=15' (or less, >=0) in /etc/sudoers.",
    tags=("sudo", "timeout"),
)
def sudo_timestamp_timeout(ctx):
    text = _sudoers_text(ctx)
    if text is None:
        return Outcome.manual("Root required to read sudoers; verify timestamp_timeout<=15")
    m = re.search(r"timestamp_timeout\s*=\s*(-?\d+)", text)
    if not m:
        return Outcome.warn("timestamp_timeout not set; relying on the 15-minute default",
                            expected="<= 15 (and >= 0)")
    val = int(m.group(1))
    if 0 <= val <= 15:
        return Outcome.passed(f"timestamp_timeout = {val}", actual=val)
    return Outcome.failed(f"timestamp_timeout = {val}", actual=val, expected="<= 15 and >= 0")


@check(
    id="5.2.7", title="Ensure access to the su command is restricted",
    section="5.2 Configure privilege escalation",
    severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Restricting su to an (empty) wheel-style group prevents users sharing the root password via su.",
    remediation="Add 'auth required pam_wheel.so use_uid group=<grp>' to /etc/pam.d/su; keep <grp> empty.",
    tags=("su", "pam"),
)
def su_restricted(ctx):
    text = ctx.read_file("/etc/pam.d/su")
    if text is None:
        return Outcome.manual("Could not read /etc/pam.d/su; verify pam_wheel restricts su")
    line = next((s for s in text.splitlines()
                 if "pam_wheel.so" in s and s.strip() and not s.strip().startswith("#")), None)
    if not line or "use_uid" not in line:
        return Outcome.failed("pam_wheel use_uid is not configured for su", actual=line or "absent",
                              expected="auth required pam_wheel.so use_uid group=<grp>")
    gm = re.search(r"group=(\S+)", line)
    if not gm:
        return Outcome.failed("pam_wheel configured without an explicit group=", actual=line,
                              expected="group=<grp>")
    grp = gm.group(1)
    members = next((g.get("members", "") for g in ctx.group_entries() if g.get("name") == grp), "")
    if members.strip():
        return Outcome.warn(f"su group '{grp}' is not empty: {members}", actual={grp: members})
    return Outcome.passed(f"su restricted via pam_wheel group '{grp}' (empty)", actual=line)


# --------------------------------------------------------------------------- #
# 5.3  PAM
# --------------------------------------------------------------------------- #
_COMMON_FILES = (
    "/etc/pam.d/common-auth", "/etc/pam.d/common-account",
    "/etc/pam.d/common-password", "/etc/pam.d/common-session",
)


def _pam_lines(ctx, module):
    """Non-comment lines mentioning `module` across the common-* PAM files."""
    hits = []
    for f in _COMMON_FILES:
        for line in ctx.file_lines(f):
            s = line.strip()
            if s and not s.startswith("#") and module in s:
                hits.append(s)
    return hits


def _arg_value(lines, arg):
    for s in lines:
        m = re.search(rf"\b{re.escape(arg)}\s*=\s*(\S+)", s)
        if m:
            return m.group(1)
    return None


def _has_arg(lines, arg):
    return any(re.search(rf"\b{re.escape(arg)}\b", s) for s in lines)


def _pwquality_value(ctx, key):
    """A pwquality setting from pwquality.conf(.d) or pam_pwquality.so args."""
    cfg = ctx.parse_keyword_file("/etc/security/pwquality.conf", sep="=")
    for path in ctx.glob("/etc/security/pwquality.conf.d/*.conf"):
        cfg.update(ctx.parse_keyword_file(path, sep="="))
    if key in cfg:
        return cfg[key]
    return _arg_value(_pam_lines(ctx, "pam_pwquality.so"), key)


# 5.3.1  PAM packages installed
_PAM_PACKAGES = [
    ("5.3.1.1", "libpam-runtime", "Ensure latest version of pam is installed"),
    ("5.3.1.2", "libpam-modules", "Ensure latest version of libpam-modules is installed"),
    ("5.3.1.3", "libpam-pwquality", "Ensure latest version of libpam-pwquality is installed"),
    ("5.3.1.4", "cracklib-runtime", "Ensure latest version of cracklib-runtime is installed"),
]


def _make_pam_pkg_check(cis_id, pkg, title):
    @check(
        id=cis_id, title=title, section="5.3 Pluggable Authentication Modules",
        severity=Severity.LOW, levels=(Level.L1,),
        rationale="PAM and its quality/lockout modules must be present (and patched) to enforce auth policy.",
        remediation=f"apt install {pkg}; keep it updated.", tags=("pam", "package"),
    )
    def _chk(ctx, _pkg=pkg):
        if ctx.package_installed(_pkg):
            return Outcome.passed(f"{_pkg} is installed (verify it is the latest version)")
        return Outcome.failed(f"{_pkg} is not installed", expected="installed")

    return _chk


for _row in _PAM_PACKAGES:
    _make_pam_pkg_check(*_row)


# 5.3.2  PAM modules enabled (present in the common-* stack)
_PAM_MODULES = [
    ("5.3.2.1", "pam_unix.so", "Ensure pam_unix module is enabled"),
    ("5.3.2.2", "pam_faillock.so", "Ensure pam_faillock module is enabled"),
    ("5.3.2.3", "pam_pwquality.so", "Ensure pam_pwquality module is enabled"),
    ("5.3.2.4", "pam_pwhistory.so", "Ensure pam_pwhistory module is enabled"),
]


def _make_pam_module_check(cis_id, module, title):
    @check(
        id=cis_id, title=title, section="5.3 Pluggable Authentication Modules",
        severity=Severity.MEDIUM, levels=(Level.L1,),
        rationale="The PAM stack must reference each module for its policy (hashing, lockout, quality, history) to apply.",
        remediation=f"Enable {module} via pam-auth-update / the relevant /etc/pam.d/common-* file.",
        tags=("pam", "module"),
    )
    def _chk(ctx, _module=module):
        if _pam_lines(ctx, _module):
            return Outcome.passed(f"{_module} is enabled in the PAM stack")
        return Outcome.failed(f"{_module} is not enabled", expected="present in /etc/pam.d/common-*")

    return _chk


for _row in _PAM_MODULES:
    _make_pam_module_check(*_row)


# 5.3.3.1  pam_faillock arguments
@check(
    id="5.3.3.1.1", title="Ensure password failed attempts lockout is configured",
    section="5.3 Pluggable Authentication Modules", severity=Severity.HIGH, levels=(Level.L1,),
    rationale="Locking accounts after a few failures defeats online password brute force.",
    remediation="Set deny<=5 in /etc/security/faillock.conf (or the pam_faillock.so line).",
    tags=("pam", "faillock", "brute-force"),
)
def faillock_deny(ctx):
    cfg = ctx.parse_keyword_file("/etc/security/faillock.conf", sep="=")
    val = cfg.get("deny") or _arg_value(_pam_lines(ctx, "pam_faillock.so"), "deny")
    if val is None:
        return Outcome.failed("faillock deny threshold not configured", expected="deny <= 5")
    if val.isdigit() and int(val) <= 5:
        return Outcome.passed(f"faillock deny = {val}", actual=val)
    return Outcome.failed(f"faillock deny = {val}", actual=val, expected="deny <= 5")


@check(
    id="5.3.3.1.2", title="Ensure password unlock time is configured",
    section="5.3 Pluggable Authentication Modules", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="A sufficient unlock_time (or 0 = admin-only unlock) keeps brute-force lockouts effective.",
    remediation="Set unlock_time=0 or >=900 in /etc/security/faillock.conf.",
    tags=("pam", "faillock"),
)
def faillock_unlock(ctx):
    cfg = ctx.parse_keyword_file("/etc/security/faillock.conf", sep="=")
    val = cfg.get("unlock_time") or _arg_value(_pam_lines(ctx, "pam_faillock.so"), "unlock_time")
    if val is None:
        return Outcome.failed("faillock unlock_time not configured", expected="0 or >= 900")
    if val.isdigit() and (int(val) == 0 or int(val) >= 900):
        return Outcome.passed(f"faillock unlock_time = {val}", actual=val)
    return Outcome.failed(f"faillock unlock_time = {val}", actual=val, expected="0 or >= 900")


@check(
    id="5.3.3.1.3", title="Ensure password failed attempts lockout includes root account",
    section="5.3 Pluggable Authentication Modules", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="root must also be subject to lockout (or a defined root_unlock_time) to resist brute force.",
    remediation="Set even_deny_root and root_unlock_time>=60 in /etc/security/faillock.conf.",
    tags=("pam", "faillock", "root"),
)
def faillock_root(ctx):
    cfg = ctx.parse_keyword_file("/etc/security/faillock.conf", sep="=")
    lines = _pam_lines(ctx, "pam_faillock.so")
    even_deny = "even_deny_root" in cfg or _has_arg(lines, "even_deny_root")
    rut = cfg.get("root_unlock_time") or _arg_value(lines, "root_unlock_time")
    if even_deny or (rut and rut.isdigit() and int(rut) >= 60):
        return Outcome.passed("root is included in faillock lockout",
                              actual={"even_deny_root": even_deny, "root_unlock_time": rut})
    return Outcome.failed("root is not included in faillock lockout",
                          expected="even_deny_root or root_unlock_time>=60")


# 5.3.3.2  pam_pwquality arguments
@check(
    id="5.3.3.2.1", title="Ensure password number of changed characters is configured",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="difok forces a minimum number of characters to differ from the previous password.",
    remediation="Set difok>=2 in /etc/security/pwquality.conf(.d).", tags=("pam", "pwquality"),
)
def pwquality_difok(ctx):
    val = _pwquality_value(ctx, "difok")
    if val is None:
        return Outcome.failed("difok not configured", expected="difok >= 2")
    if val.isdigit() and int(val) >= 2:
        return Outcome.passed(f"difok = {val}", actual=val)
    return Outcome.failed(f"difok = {val}", actual=val, expected="difok >= 2")


@check(
    id="5.3.3.2.2", title="Ensure password length is configured",
    section="5.3 Pluggable Authentication Modules", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="A minimum length (>=14) is the single most effective password-strength control.",
    remediation="Set minlen>=14 in /etc/security/pwquality.conf(.d).", tags=("pam", "pwquality"),
)
def pwquality_minlen(ctx):
    val = _pwquality_value(ctx, "minlen")
    if val is None:
        return Outcome.failed("minlen not configured", expected="minlen >= 14")
    if val.isdigit() and int(val) >= 14:
        return Outcome.passed(f"minlen = {val}", actual=val)
    return Outcome.failed(f"minlen = {val}", actual=val, expected="minlen >= 14")


@check(
    id="5.3.3.2.3", title="Ensure password complexity is configured",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Credit/complexity rules (minclass or *credit) raise guessing cost; CIS treats this as Manual.",
    remediation="Configure minclass or the *credit options in /etc/security/pwquality.conf per site policy.",
    tags=("pam", "pwquality"),
)
def pwquality_complexity(ctx):
    found = {k: _pwquality_value(ctx, k)
             for k in ("minclass", "dcredit", "ucredit", "ocredit", "lcredit")
             if _pwquality_value(ctx, k) is not None}
    return Outcome.manual(
        "Confirm password complexity meets site policy (CIS marks this Manual).",
        actual=found or "no complexity options set",
    )


@check(
    id="5.3.3.2.4", title="Ensure password same consecutive characters is configured",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="maxrepeat limits runs of the same character (e.g. 'aaaa'), which weaken passwords.",
    remediation="Set maxrepeat<=3 (and >0) in /etc/security/pwquality.conf(.d).", tags=("pam", "pwquality"),
)
def pwquality_maxrepeat(ctx):
    val = _pwquality_value(ctx, "maxrepeat")
    if val is None:
        return Outcome.failed("maxrepeat not configured", expected="1..3")
    if val.isdigit() and 0 < int(val) <= 3:
        return Outcome.passed(f"maxrepeat = {val}", actual=val)
    return Outcome.failed(f"maxrepeat = {val}", actual=val, expected="1..3")


@check(
    id="5.3.3.2.5", title="Ensure password maximum sequential characters is configured",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="maxsequence limits monotonic runs (e.g. '1234', 'abcd').",
    remediation="Set maxsequence<=3 (and >0) in /etc/security/pwquality.conf(.d).", tags=("pam", "pwquality"),
)
def pwquality_maxsequence(ctx):
    val = _pwquality_value(ctx, "maxsequence")
    if val is None:
        return Outcome.failed("maxsequence not configured", expected="1..3")
    if val.isdigit() and 0 < int(val) <= 3:
        return Outcome.passed(f"maxsequence = {val}", actual=val)
    return Outcome.failed(f"maxsequence = {val}", actual=val, expected="1..3")


@check(
    id="5.3.3.2.6", title="Ensure password dictionary check is enabled",
    section="5.3 Pluggable Authentication Modules", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="dictcheck rejects dictionary words, the easiest passwords to guess.",
    remediation="Ensure dictcheck is not set to 0 in /etc/security/pwquality.conf(.d).", tags=("pam", "pwquality"),
)
def pwquality_dictcheck(ctx):
    val = _pwquality_value(ctx, "dictcheck")
    if val is None or val == "1":
        return Outcome.passed("dictionary check is enabled (dictcheck not disabled)", actual=val or "default")
    if val == "0":
        return Outcome.failed("dictcheck = 0 disables the dictionary check", actual=val, expected="dictcheck != 0")
    return Outcome.passed(f"dictcheck = {val}", actual=val)


@check(
    id="5.3.3.2.7", title="Ensure password quality checking is enforced",
    section="5.3 Pluggable Authentication Modules", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="enforcing=0 makes pwquality advisory only — weak passwords would still be accepted.",
    remediation="Remove enforcing=0 from pwquality config / the pam_pwquality.so line.", tags=("pam", "pwquality"),
)
def pwquality_enforced(ctx):
    val = _pwquality_value(ctx, "enforcing")
    if val == "0":
        return Outcome.failed("enforcing=0 — pwquality is advisory only", actual=val, expected="enforcing != 0")
    return Outcome.passed("password quality checking is enforced", actual=val or "default (enforced)")


@check(
    id="5.3.3.2.8", title="Ensure password quality is enforced for the root user",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="enforce_for_root applies the quality rules when root sets a password too.",
    remediation="Add enforce_for_root to the pam_pwquality.so line / pwquality config.", tags=("pam", "pwquality", "root"),
)
def pwquality_root(ctx):
    if _has_arg(_pam_lines(ctx, "pam_pwquality.so"), "enforce_for_root") or \
            _pwquality_value(ctx, "enforce_for_root") is not None:
        return Outcome.passed("pwquality is enforced for root (enforce_for_root)")
    return Outcome.failed("enforce_for_root is not set", expected="enforce_for_root present")


# 5.3.3.3  pam_pwhistory arguments
@check(
    id="5.3.3.3.1", title="Ensure password history remember is configured",
    section="5.3 Pluggable Authentication Modules", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Remembering past passwords (>=24) stops users cycling back to a reused password.",
    remediation="Set remember=24 (or more) on the pam_pwhistory.so line in common-password.",
    tags=("pam", "pwhistory"),
)
def pwhistory_remember(ctx):
    val = _arg_value(_pam_lines(ctx, "pam_pwhistory.so"), "remember")
    if val is None:
        return Outcome.failed("pwhistory remember not configured", expected="remember >= 24")
    if val.isdigit() and int(val) >= 24:
        return Outcome.passed(f"pwhistory remember = {val}", actual=val)
    return Outcome.failed(f"pwhistory remember = {val}", actual=val, expected="remember >= 24")


@check(
    id="5.3.3.3.2", title="Ensure password history is enforced for the root user",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="enforce_for_root applies password-history reuse rules to root as well.",
    remediation="Add enforce_for_root to the pam_pwhistory.so line.", tags=("pam", "pwhistory", "root"),
)
def pwhistory_root(ctx):
    if _has_arg(_pam_lines(ctx, "pam_pwhistory.so"), "enforce_for_root"):
        return Outcome.passed("pwhistory is enforced for root")
    return Outcome.failed("enforce_for_root not set on pam_pwhistory", expected="enforce_for_root present")


@check(
    id="5.3.3.3.3", title="Ensure pam_pwhistory includes use_authtok",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="use_authtok makes pwhistory use the password already vetted by earlier modules in the stack.",
    remediation="Add use_authtok to the pam_pwhistory.so line.", tags=("pam", "pwhistory"),
)
def pwhistory_authtok(ctx):
    lines = _pam_lines(ctx, "pam_pwhistory.so")
    if not lines:
        return Outcome.failed("pam_pwhistory is not configured", expected="pam_pwhistory.so use_authtok")
    if _has_arg(lines, "use_authtok"):
        return Outcome.passed("pam_pwhistory includes use_authtok")
    return Outcome.failed("pam_pwhistory missing use_authtok", expected="use_authtok present")


# 5.3.3.4  pam_unix arguments
@check(
    id="5.3.3.4.1", title="Ensure pam_unix does not include nullok",
    section="5.3 Pluggable Authentication Modules", severity=Severity.HIGH, levels=(Level.L1,),
    rationale="nullok lets accounts with an empty password authenticate — a trivial bypass.",
    remediation="Remove nullok from the pam_unix.so lines in /etc/pam.d/common-*.", tags=("pam", "pam_unix"),
)
def pam_unix_nullok(ctx):
    lines = _pam_lines(ctx, "pam_unix.so")
    if _has_arg(lines, "nullok"):
        return Outcome.failed("pam_unix permits empty passwords (nullok)", actual=lines, expected="no nullok")
    return Outcome.passed("pam_unix does not include nullok")


@check(
    id="5.3.3.4.2", title="Ensure pam_unix does not include remember",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Password history should be handled by pam_pwhistory, not pam_unix's weaker remember.",
    remediation="Remove remember= from the pam_unix.so line; use pam_pwhistory instead.", tags=("pam", "pam_unix"),
)
def pam_unix_remember(ctx):
    lines = _pam_lines(ctx, "pam_unix.so")
    if _arg_value(lines, "remember") is not None:
        return Outcome.failed("pam_unix includes remember=", actual=lines, expected="no remember on pam_unix")
    return Outcome.passed("pam_unix does not include remember")


@check(
    id="5.3.3.4.3", title="Ensure pam_unix includes a strong password hashing algorithm",
    section="5.3 Pluggable Authentication Modules", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="yescrypt or sha512 resist offline cracking far better than md5/des.",
    remediation="Add yescrypt (or sha512) to the pam_unix.so line in common-password.", tags=("pam", "pam_unix", "hashing"),
)
def pam_unix_hashing(ctx):
    lines = _pam_lines(ctx, "pam_unix.so")
    if any(algo in s.lower() for s in lines for algo in ("yescrypt", "sha512")):
        return Outcome.passed("pam_unix uses a strong hashing algorithm", actual=lines)
    return Outcome.failed("pam_unix strong hashing not confirmed", actual=lines, expected="yescrypt or sha512")


@check(
    id="5.3.3.4.4", title="Ensure pam_unix includes use_authtok",
    section="5.3 Pluggable Authentication Modules", severity=Severity.LOW, levels=(Level.L1,),
    rationale="use_authtok makes pam_unix use the password already vetted by pwquality earlier in the stack.",
    remediation="Add use_authtok to the pam_unix.so password line.", tags=("pam", "pam_unix"),
)
def pam_unix_authtok(ctx):
    lines = [s for s in _pam_lines(ctx, "pam_unix.so") if "password" in s]
    if not lines:
        return Outcome.warn("No pam_unix password line found to check use_authtok", actual="absent")
    if _has_arg(lines, "use_authtok"):
        return Outcome.passed("pam_unix (password) includes use_authtok")
    return Outcome.failed("pam_unix password line missing use_authtok", actual=lines, expected="use_authtok present")


# --------------------------------------------------------------------------- #
# 5.4  User accounts and environment
# --------------------------------------------------------------------------- #
# 5.4.1  shadow password suite (login.defs)
_LOGIN_DEFS_CONTROLS = [
    ("5.4.1.1", "pass_max_days", _int_at_most(365), "Ensure password expiration is configured", Severity.MEDIUM),
    ("5.4.1.3", "pass_warn_age", _int_at_least(7), "Ensure password expiration warning days is configured", Severity.LOW),
]


def _make_login_defs_check(cis_id, key, predicate, title, severity):
    fn, expected_desc = predicate

    @check(
        id=cis_id, title=title, section="5.4 User Accounts and Environment",
        severity=severity, levels=(Level.L1,),
        rationale="login.defs governs the default password-aging lifecycle for new accounts.",
        remediation=f"Set {key.upper()} to a compliant value in /etc/login.defs.",
        tags=("accounts", "password-aging"),
    )
    def _chk(ctx, _key=key, _fn=fn, _exp=expected_desc):
        cfg = ctx.parse_keyword_file("/etc/login.defs")
        value = cfg.get(_key)
        if value is None:
            return Outcome.failed(f"{_key.upper()} not set in login.defs", expected=_exp)
        if _fn(value):
            return Outcome.passed(f"{_key.upper()} = {value}", actual=value, expected=_exp)
        return Outcome.failed(f"{_key.upper()} = {value}", actual=value, expected=_exp)

    return _chk


for _row in _LOGIN_DEFS_CONTROLS:
    _make_login_defs_check(*_row)


@check(
    id="5.4.1.2", title="Ensure minimum password days is configured",
    section="5.4 User Accounts and Environment", severity=Severity.LOW, levels=(Level.L1,),
    rationale="A minimum age stops users defeating history by changing a password repeatedly in one sitting.",
    remediation="Set PASS_MIN_DAYS>=1 in /etc/login.defs per site policy.", tags=("accounts", "password-aging"),
)
def pass_min_days(ctx):
    cfg = ctx.parse_keyword_file("/etc/login.defs")
    val = cfg.get("pass_min_days")
    if val is None:
        return Outcome.manual("PASS_MIN_DAYS not set; confirm against site policy", expected=">= 1")
    if val.isdigit() and int(val) >= 1:
        return Outcome.passed(f"PASS_MIN_DAYS = {val} (confirm against site policy)", actual=val)
    return Outcome.warn(f"PASS_MIN_DAYS = {val}", actual=val, expected=">= 1 per site policy")


@check(
    id="5.4.1.4", title="Ensure strong password hashing algorithm is configured",
    section="5.4 User Accounts and Environment", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="ENCRYPT_METHOD must be yescrypt or sha512 so new passwords hash with a strong algorithm.",
    remediation="Set ENCRYPT_METHOD YESCRYPT (or SHA512) in /etc/login.defs.", tags=("accounts", "hashing"),
)
def login_defs_hashing(ctx):
    cfg = ctx.parse_keyword_file("/etc/login.defs")
    method = cfg.get("encrypt_method", "").lower()
    if method in ("yescrypt", "sha512"):
        return Outcome.passed(f"ENCRYPT_METHOD = {method}", actual=method)
    return Outcome.failed(f"ENCRYPT_METHOD = {method or 'unset'}", actual=method, expected="YESCRYPT or SHA512")


@check(
    id="5.4.1.5", title="Ensure inactive password lock is configured",
    section="5.4 User Accounts and Environment", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Locking accounts soon after password expiry (<=30 days inactive) shrinks the dormant-account window.",
    remediation="Set INACTIVE=30 (or less) via 'useradd -D -f 30' (/etc/default/useradd).", tags=("accounts", "inactive"),
)
def inactive_lock(ctx):
    cfg = ctx.parse_keyword_file("/etc/default/useradd", sep="=")
    val = cfg.get("inactive")
    if val is None:
        res = ctx.run(["sh", "-c", "useradd -D | grep INACTIVE"])
        m = re.search(r"INACTIVE\s*=\s*(-?\d+)", res.out or "")
        val = m.group(1) if m else None
    if val is None:
        return Outcome.failed("INACTIVE is not configured", expected="0 <= INACTIVE <= 30")
    if val.lstrip("-").isdigit() and 0 <= int(val) <= 30:
        return Outcome.passed(f"INACTIVE = {val}", actual=val)
    return Outcome.failed(f"INACTIVE = {val}", actual=val, expected="0 <= INACTIVE <= 30")


@check(
    id="5.4.1.6", title="Ensure all users last password change date is in the past",
    section="5.4 User Accounts and Environment", severity=Severity.LOW, levels=(Level.L1,),
    rationale="A future last-change date indicates clock tampering or a malformed shadow entry.",
    remediation="Investigate and correct any account whose last password change is in the future.",
    tags=("accounts", "shadow"),
)
def last_change_in_past(ctx):
    now = ctx.run(["date", "+%s"])
    try:
        today_days = int(now.out) // 86400
    except (ValueError, TypeError):
        return Outcome.manual("Could not determine current date to compare shadow last-change")
    future = []
    for e in ctx.shadow_entries():
        lc = e.get("lastchg", "")
        if lc.isdigit() and int(lc) > today_days:
            future.append(e.get("name"))
    if future:
        return Outcome.failed("Accounts with a future last-change date: " + ", ".join(future),
                              actual=future, expected="all in the past")
    return Outcome.passed("All last password change dates are in the past")


# 5.4.2  root and system accounts
@check(
    id="5.4.2.1", title="Ensure root is the only UID 0 account",
    section="5.4 User Accounts and Environment", severity=Severity.CRITICAL, levels=(Level.L1,),
    rationale="Any second UID 0 account is a hidden, fully-privileged backdoor.",
    remediation="Remove or re-UID any non-root account with UID 0.", tags=("accounts", "root", "uid0"),
)
def only_root_uid0(ctx):
    uid0 = [e["name"] for e in ctx.passwd_entries() if e.get("uid") == "0"]
    if uid0 == ["root"]:
        return Outcome.passed("root is the only UID 0 account")
    return Outcome.failed("Multiple UID 0 accounts: " + ", ".join(uid0), actual=uid0, expected="['root']")


@check(
    id="5.4.2.2", title="Ensure root is the only GID 0 account",
    section="5.4 User Accounts and Environment", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="root's primary group should be GID 0; other GID-0 users inherit group-root file access.",
    remediation="Set non-root users' primary group to a non-zero GID.", tags=("accounts", "root", "gid0"),
)
def only_root_gid0(ctx):
    gid0 = [e["name"] for e in ctx.passwd_entries() if e.get("gid") == "0"]
    non_root = [n for n in gid0 if n != "root"]
    if not non_root:
        return Outcome.passed("root is the only account with primary GID 0")
    return Outcome.failed("Accounts with primary GID 0: " + ", ".join(non_root), actual=gid0, expected="root only")


@check(
    id="5.4.2.3", title="Ensure group root is the only GID 0 group",
    section="5.4 User Accounts and Environment", severity=Severity.LOW, levels=(Level.L1,),
    rationale="A second GID 0 group muddies group-root ownership semantics.",
    remediation="Ensure only the 'root' group has GID 0 in /etc/group.", tags=("accounts", "root", "gid0"),
)
def only_root_group_gid0(ctx):
    g0 = [g["name"] for g in ctx.group_entries() if g.get("gid") == "0"]
    if g0 == ["root"]:
        return Outcome.passed("group 'root' is the only GID 0 group")
    return Outcome.failed("Multiple GID 0 groups: " + ", ".join(g0), actual=g0, expected="['root']")


@check(
    id="5.4.2.4", title="Ensure root account access is controlled",
    section="5.4 User Accounts and Environment", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="root must have a valid (locked-or-hashed) password entry, not an empty or '!'-only one that breaks single-user recovery policy.",
    remediation="Set a strong root password or lock it per site policy (passwd -l root / set a hash).",
    tags=("accounts", "root"),
)
def root_access_controlled(ctx):
    root = next((e for e in ctx.shadow_entries() if e.get("name") == "root"), None)
    if root is None:
        return Outcome.manual("Could not read root's shadow entry (need root)")
    pw = root.get("passwd", "")
    if pw == "":
        return Outcome.failed("root has an EMPTY password", actual="(empty)", expected="locked or strong hash")
    return Outcome.passed("root has a password hash / locked entry", actual=pw[:3] + "…")


@check(
    id="5.4.2.5", title="Ensure root path integrity",
    section="5.4 User Accounts and Environment", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="A '.' or world-writable directory in root's PATH lets a planted binary run as root.",
    remediation="Remove empty/'.'/world-writable entries from root's PATH.", tags=("accounts", "root", "path"),
)
def root_path_integrity(ctx):
    res = ctx.run(["sh", "-c", "echo $PATH"]) if ctx.is_root else None
    path = (res.out if res and res.ok else "") or ""
    if not path:
        return Outcome.manual("Could not read root's PATH; verify it has no '.', empty, or world-writable entries")
    entries = path.split(":")
    problems = [e for e in entries if e in ("", ".")]
    for e in entries:
        if e and e not in ("", "."):
            st = ctx.stat(e)
            if st.exists and st.is_dir and (st.mode & 0o002):
                problems.append(f"{e} (world-writable)")
    if problems:
        return Outcome.failed("root PATH integrity issues: " + ", ".join(problems), actual=problems)
    return Outcome.passed("root PATH has no '.', empty, or world-writable entries")


@check(
    id="5.4.2.6", title="Ensure root user umask is configured",
    section="5.4 User Accounts and Environment", severity=Severity.LOW, levels=(Level.L1,),
    rationale="A restrictive root umask (>=027) keeps root-created files from being group/world accessible.",
    remediation="Set 'umask 027' (or stricter) in root's shell init / /etc/profile.d.", tags=("accounts", "root", "umask"),
)
def root_umask(ctx):
    candidates = []
    for path in ("/root/.bash_profile", "/root/.bashrc", "/root/.profile", "/etc/profile", "/etc/bash.bashrc"):
        for line in ctx.file_lines(path):
            s = line.strip()
            if s.startswith("umask"):
                candidates.append(s.split()[-1])
    if not candidates:
        return Outcome.warn("No explicit root umask found; relying on the system default", expected="027 or stricter")
    if all(_umask_at_least_027(c) for c in candidates):
        return Outcome.passed(f"root umask is restrictive: {candidates}", actual=candidates)
    return Outcome.failed(f"root umask not restrictive enough: {candidates}", actual=candidates, expected="027")


@check(
    id="5.4.2.7", title="Ensure system accounts do not have a valid login shell",
    section="5.4 User Accounts and Environment", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Service/system accounts (UID < 1000, non-root) with a real shell broaden the attack surface for lateral movement.",
    remediation="Set the shell of system accounts to nologin/false.", tags=("accounts", "system", "shell"),
)
def system_accounts_no_shell(ctx):
    valid_shell = lambda s: s and not s.endswith(("nologin", "false", "/sync", "/shutdown", "/halt"))
    offenders = []
    for e in ctx.passwd_entries():
        name, uid, shell = e.get("name"), e.get("uid", ""), e.get("shell", "")
        if name == "root" or not uid.isdigit():
            continue
        if int(uid) < 1000 and valid_shell(shell):
            offenders.append(f"{name}:{shell}")
    if offenders:
        return Outcome.failed("System accounts with a valid shell: " + ", ".join(offenders),
                              actual=offenders, expected="nologin/false")
    return Outcome.passed("No system account has a valid login shell")


@check(
    id="5.4.2.8", title="Ensure accounts without a valid login shell are locked",
    section="5.4 User Accounts and Environment", severity=Severity.LOW, levels=(Level.L1,),
    rationale="A no-shell account with an unlocked password can still authenticate to services using PAM.",
    remediation="Lock (passwd -l) accounts that have a nologin/false shell.", tags=("accounts", "locked"),
)
def no_shell_accounts_locked(ctx):
    no_shell = {e["name"] for e in ctx.passwd_entries()
                if e.get("shell", "").endswith(("nologin", "false"))}
    unlocked = []
    for e in ctx.shadow_entries():
        if e.get("name") in no_shell:
            pw = e.get("passwd", "")
            if pw and not pw.startswith(("!", "*")):
                unlocked.append(e.get("name"))
    if unlocked:
        return Outcome.failed("No-shell accounts that are not locked: " + ", ".join(unlocked),
                              actual=unlocked, expected="locked (! or *)")
    return Outcome.passed("All no-shell accounts are locked")


# 5.4.3  default user environment
@check(
    id="5.4.3.1", title="Ensure nologin is not listed in /etc/shells",
    section="5.4 User Accounts and Environment", severity=Severity.LOW, levels=(Level.L1,),
    rationale="If nologin appears in /etc/shells it counts as a 'valid' shell, defeating no-shell account checks.",
    remediation="Remove any nologin path from /etc/shells.", tags=("accounts", "shells"),
)
def nologin_not_in_shells(ctx):
    shells = [s.strip() for s in ctx.file_lines("/etc/shells") if s.strip() and not s.startswith("#")]
    offenders = [s for s in shells if s.endswith("nologin")]
    if offenders:
        return Outcome.failed("nologin present in /etc/shells: " + ", ".join(offenders), actual=offenders)
    return Outcome.passed("nologin is not listed in /etc/shells")


@check(
    id="5.4.3.2", title="Ensure default user shell timeout is configured",
    section="5.4 User Accounts and Environment", severity=Severity.LOW, levels=(Level.L1,),
    rationale="A default TMOUT (<=900s) ends idle interactive shells, limiting unattended-session risk.",
    remediation="Set 'readonly TMOUT=900; export TMOUT' in /etc/profile.d/ and /etc/profile.", tags=("accounts", "timeout"),
)
def shell_timeout(ctx):
    candidates = []
    paths = ["/etc/profile", "/etc/bash.bashrc"] + ctx.glob("/etc/profile.d/*.sh")
    for path in paths:
        for line in ctx.file_lines(path):
            m = re.search(r"\bTMOUT\s*=\s*(\d+)", line)
            if m:
                candidates.append(int(m.group(1)))
    if not candidates:
        return Outcome.failed("No default TMOUT configured", expected="TMOUT <= 900 (and > 0)")
    if all(0 < c <= 900 for c in candidates):
        return Outcome.passed(f"TMOUT configured: {candidates}", actual=candidates)
    return Outcome.failed(f"TMOUT not within 1..900: {candidates}", actual=candidates, expected="<= 900 and > 0")


@check(
    id="5.4.3.3", title="Ensure default user umask is configured",
    section="5.4 User Accounts and Environment", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="A 027 default umask keeps new files non-world-readable and new dirs non-world-accessible.",
    remediation="Set 'UMASK 027' in /etc/login.defs and 'umask 027' in /etc/profile.d/.", tags=("accounts", "umask"),
)
def default_umask(ctx):
    login_defs = ctx.parse_keyword_file("/etc/login.defs")
    umask = login_defs.get("umask")
    candidates = [umask] if umask else []
    for path in ("/etc/profile", "/etc/bash.bashrc"):
        for line in ctx.file_lines(path):
            if line.strip().startswith("umask"):
                candidates.append(line.split()[-1])
    present = [c for c in candidates if c]
    restrictive = [c for c in present if _umask_at_least_027(c)]
    if present and len(restrictive) == len(present):
        return Outcome.passed(f"Default umask is restrictive: {present}", actual=present)
    if not present:
        return Outcome.failed("No default umask configured", expected="027 or stricter")
    return Outcome.failed(f"Default umask not restrictive enough: {present}", actual=present, expected="027")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _sudoers_text(ctx):
    """Concatenated /etc/sudoers + sudoers.d content, or None if unreadable."""
    text = ctx.read_file("/etc/sudoers")
    if text is None:
        return None
    parts = [text]
    for path in ctx.glob("/etc/sudoers.d/*"):
        extra = ctx.read_file(path)
        if extra:
            parts.append(extra)
    return "\n".join(parts)


def _has_default(text: str, token: str) -> bool:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Defaults") and token in s:
            return True
    return False


def _umask_at_least_027(value: str) -> bool:
    """True if the umask masks at least the bits 027 masks (i.e. >= 027)."""
    try:
        mask = int(value, 8)
    except (ValueError, TypeError):
        return False
    return (mask & 0o027) == 0o027
