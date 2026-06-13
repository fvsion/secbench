"""Extended account, privilege, and authorization auditing.

Goes beyond the CIS account controls to answer the assessment questions:
who effectively has root, which accounts can escalate, which system accounts
have unexpected login shells, and whether any account's credentials look
statistically anomalous (a hint at a planted or forgotten backdoor).
"""

from __future__ import annotations

import re

from ...core import Confidence, Level, Outcome, Profile, Severity, check
from ..extended import EXTENDED_FRAMEWORK
from ...analysis.statistics import modified_z_scores

# Shells that mean "this account cannot log in interactively".
_NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "", "/dev/null"}

# System accounts shipped by Ubuntu that legitimately own a login shell.
_SYSTEM_SHELL_ALLOWLIST = {"root", "sync", "halt", "shutdown"}


@check(
    id="EXT-ACCT-1",
    title="Ensure no UID 0 account other than root exists",
    section="EXT.Accounts",
    severity=Severity.CRITICAL,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Any account with UID 0 *is* root. A second UID-0 account is a classic, easily-overlooked backdoor.",
    remediation="Change the account's UID to a unique non-zero value or remove it entirely after investigation.",
    tags=("accounts", "privilege", "backdoor"),
)
def single_uid_zero(ctx):
    uid0 = [e["name"] for e in ctx.passwd_entries() if e["uid"] == "0"]
    extra = [n for n in uid0 if n != "root"]
    if not extra:
        return Outcome.passed("root is the only UID 0 account")
    return Outcome.failed(
        f"Additional UID 0 account(s): {', '.join(extra)}",
        evidence=extra,
        actual=uid0,
        expected="['root']",
    )


@check(
    id="EXT-ACCT-2",
    title="Inventory accounts with administrative (sudo) access",
    section="EXT.Accounts",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Every member of sudo/admin can become root. The set should be small, known, and reviewed.",
    remediation="Remove unexpected members from the sudo/admin groups; prefer per-command sudoers rules.",
    tags=("accounts", "sudo", "privilege"),
)
def sudo_membership(ctx):
    admins = set()
    for group in ctx.group_entries():
        if group["name"] in ("sudo", "admin", "wheel"):
            admins.update(m for m in group["members"].split(",") if m)
    # Also count users whose primary group is an admin group.
    if not admins:
        return Outcome.passed("No members in sudo/admin/wheel groups")
    listing = ", ".join(sorted(admins))
    status = Outcome.warn if len(admins) > 5 else Outcome.info
    return status(
        f"{len(admins)} account(s) have sudo/admin group access: {listing}",
        evidence=sorted(admins),
        actual=sorted(admins),
    )


@check(
    id="EXT-ACCT-3",
    title="Ensure system accounts do not have an interactive login shell",
    section="EXT.Accounts",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A service account (UID < 1000) with a real shell is a login vector that should not exist; nologin is correct.",
    remediation="Set the shell of non-human system accounts to /usr/sbin/nologin.",
    tags=("accounts", "shell", "attack-surface"),
)
def system_accounts_nologin(ctx):
    offenders = []
    for e in ctx.passwd_entries():
        name, uid, shell = e["name"], e["uid"], e["shell"]
        if not uid.isdigit():
            continue
        if int(uid) < 1000 and name not in _SYSTEM_SHELL_ALLOWLIST and shell not in _NOLOGIN_SHELLS:
            offenders.append(f"{name} (uid {uid}) -> {shell}")
    if not offenders:
        return Outcome.passed("All system accounts use a non-login shell")
    return Outcome.failed(
        f"{len(offenders)} system account(s) with a login shell",
        evidence=offenders,
        actual=offenders,
        expected="nologin/false for system accounts",
    )


@check(
    id="EXT-ACCT-4",
    title="Ensure no enabled account has a non-expiring password policy gap",
    section="EXT.Accounts",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A human, login-capable account whose password never expires sidesteps the aging policy indefinitely.",
    remediation="Apply 'chage -M 365 <user>' to human accounts so passwords rotate.",
    tags=("accounts", "password-aging"),
)
def non_expiring_passwords(ctx):
    if not ctx.is_root:
        return Outcome.manual("Root required to read /etc/shadow aging fields")
    passwd = {e["name"]: e for e in ctx.passwd_entries()}
    offenders = []
    for s in ctx.shadow_entries():
        name = s["name"]
        pw = s["passwd"]
        # Only care about accounts that can actually authenticate.
        if pw in ("*", "!", "!!", "") or pw.startswith("!"):
            continue
        entry = passwd.get(name)
        if entry and entry["shell"] in _NOLOGIN_SHELLS:
            continue
        maxd = s["max"]
        if maxd in ("", "99999") or (maxd.isdigit() and int(maxd) > 365):
            offenders.append(f"{name} (max days={maxd or 'unset'})")
    if not offenders:
        return Outcome.passed("All login-capable accounts have a password-expiry policy")
    return Outcome.warn(
        f"{len(offenders)} login account(s) with no/long password expiry",
        evidence=offenders,
        actual=offenders,
        expected="PASS_MAX_DAYS <= 365",
    )


@check(
    id="EXT-ACCT-5",
    title="Detect statistically anomalous account password ages",
    section="EXT.Accounts",
    severity=Severity.LOW,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    automated=True,
    rationale=(
        "Robust outlier detection (modified z-score over the MAD) flags an account whose last "
        "password change is wildly out of line with its peers — e.g. an account never touched since "
        "imaging, a hallmark of a forgotten or planted credential. This is a heuristic lead, not proof."
    ),
    remediation="Review flagged accounts: confirm they are expected and rotate stale credentials.",
    tags=("accounts", "anomaly-detection", "statistics"),
)
def anomalous_password_age(ctx):
    if not ctx.is_root:
        return Outcome.manual("Root required to read /etc/shadow last-change field")
    passwd = {e["name"]: e for e in ctx.passwd_entries()}
    samples = []  # (name, lastchg_days)
    for s in ctx.shadow_entries():
        name = s["name"]
        entry = passwd.get(name)
        if not entry or entry["shell"] in _NOLOGIN_SHELLS:
            continue
        lastchg = s["lastchg"]
        if lastchg.isdigit():
            samples.append((name, int(lastchg)))
    if len(samples) < 4:
        return Outcome.info(f"Too few interactive accounts ({len(samples)}) for meaningful outlier analysis")
    scores = modified_z_scores([v for _, v in samples])
    outliers = [
        f"{name} (last change day {val}, z={score:.1f})"
        for (name, val), score in zip(samples, scores)
        if abs(score) > 3.5
    ]
    if not outliers:
        return Outcome.passed(f"No anomalous password ages across {len(samples)} accounts")
    return Outcome.warn(
        f"{len(outliers)} account(s) have anomalous password-change dates",
        evidence=outliers,
        actual=outliers,
    )


# --------------------------------------------------------------------------- #
# 6. stale / never-logged-in accounts
# --------------------------------------------------------------------------- #

@check(
    id="EXT-ACCT-6",
    title="Detect enabled accounts that have never logged in",
    section="EXT.Accounts",
    severity=Severity.LOW,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A login-capable account that has never been used is an unmonitored credential — exactly the kind of forgotten or pre-provisioned account that gets abused. lastlog shows whether each user has ever authenticated.",
    remediation="Disable or remove accounts that are not in active use (usermod -L / deluser) after confirming they are unneeded.",
    tags=("accounts", "stale", "attack-surface"),
    attack=("T1078",),
)
def never_logged_in(ctx):
    res = ctx.run(["lastlog"])
    if not res.ok or not res.out.strip():
        return Outcome.manual("lastlog output unavailable; manually review for unused login-capable accounts")
    interactive = {e["name"] for e in ctx.passwd_entries()
                   if e["shell"] not in _NOLOGIN_SHELLS and e["uid"].isdigit() and int(e["uid"]) >= 1000}
    never = []
    for line in res.lines()[1:]:  # skip header
        cols = line.split()
        if not cols:
            continue
        name = cols[0]
        if name in interactive and "**Never logged in**" in line:
            never.append(name)
    if not never:
        return Outcome.passed("No never-logged-in interactive accounts")
    return Outcome.warn(
        f"{len(never)} interactive account(s) have never logged in: {', '.join(never)}",
        evidence=never,
        actual=never,
        confidence=Confidence.LIKELY,
    )


# --------------------------------------------------------------------------- #
# 7. expired-but-enabled accounts
# --------------------------------------------------------------------------- #

@check(
    id="EXT-ACCT-7",
    title="Detect accounts past their expiry date that still have a shell",
    section="EXT.Accounts",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="An account whose shadow expiry date has passed but still has an interactive shell and an active password is a policy gap — the account was meant to be retired but can still authenticate.",
    remediation="Lock or remove expired accounts (usermod -L / -e), and confirm the expiry was intended.",
    tags=("accounts", "lifecycle"),
    attack=("T1078",),
)
def expired_but_enabled(ctx):
    if not ctx.is_root:
        return Outcome.manual("Root required to read /etc/shadow expiry fields")
    now_raw = ctx.run(["date", "-u", "+%s"]).out.strip()
    if not now_raw.isdigit():
        return Outcome.manual("Could not determine the current date to compare expiry against")
    today = int(now_raw) // 86400  # days since the epoch
    passwd = {e["name"]: e for e in ctx.passwd_entries()}
    offenders = []
    for s in ctx.shadow_entries():
        expire = s["expire"]
        if not expire.isdigit():
            continue
        if int(expire) >= today:
            continue  # not yet expired
        entry = passwd.get(s["name"])
        if not entry or entry["shell"] in _NOLOGIN_SHELLS:
            continue
        pw = s["passwd"]
        if pw in ("*", "!", "!!", "") or pw.startswith("!"):
            continue  # already locked
        offenders.append(f"{s['name']} (expired day {expire}, today {today}, shell {entry['shell']})")
    if not offenders:
        return Outcome.passed("No expired accounts retain an interactive login")
    return Outcome.failed(
        f"{len(offenders)} expired account(s) can still log in",
        evidence=offenders,
        actual=offenders,
        confidence=Confidence.CERTAIN,
    )


# --------------------------------------------------------------------------- #
# 8. duplicate UIDs / GIDs
# --------------------------------------------------------------------------- #

@check(
    id="EXT-ACCT-8",
    title="Detect duplicate UIDs and GIDs",
    section="EXT.Accounts",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Two accounts sharing a UID are the same identity to the kernel — file ownership and privileges are indistinguishable, and a shared UID 0 is a backdoor. Duplicate GIDs similarly blur group-based access control.",
    remediation="Assign every account a unique UID and every group a unique GID; investigate any shared UID 0.",
    tags=("accounts", "uid", "backdoor"),
    attack=("T1136",),
)
def duplicate_ids(ctx):
    findings = []
    uid_map = {}
    for e in ctx.passwd_entries():
        uid_map.setdefault(e["uid"], []).append(e["name"])
    for uid, names in uid_map.items():
        if len(names) > 1:
            sev = "UID 0 (root-equivalent) " if uid == "0" else ""
            findings.append(f"{sev}UID {uid} shared by: {', '.join(names)}")
    gid_map = {}
    for g in ctx.group_entries():
        gid_map.setdefault(g["gid"], []).append(g["name"])
    for gid, names in gid_map.items():
        if len(names) > 1:
            findings.append(f"GID {gid} shared by groups: {', '.join(names)}")
    if not findings:
        return Outcome.passed("All UIDs and GIDs are unique")
    return Outcome.failed(
        f"{len(findings)} duplicate UID/GID(s)",
        evidence=findings,
        actual=findings,
        confidence=Confidence.CERTAIN,
    )


# --------------------------------------------------------------------------- #
# 9. empty-password accounts in shadow
# --------------------------------------------------------------------------- #

@check(
    id="EXT-ACCT-9",
    title="Ensure no account has an empty password",
    section="EXT.Accounts",
    severity=Severity.CRITICAL,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="An empty password field in /etc/shadow means the account authenticates with no password at all — anyone who reaches a login prompt for it is in. This is one of the most direct footholds there is.",
    remediation="Set a strong password or lock the account (passwd -l); never leave the shadow password field empty for a login-capable account.",
    tags=("accounts", "password", "credentials"),
    attack=("T1078",),
)
def empty_passwords(ctx):
    if not ctx.is_root:
        return Outcome.manual("Root required to read /etc/shadow password fields")
    passwd = {e["name"]: e for e in ctx.passwd_entries()}
    offenders = []
    for s in ctx.shadow_entries():
        if s["passwd"] == "":
            entry = passwd.get(s["name"])
            shell = entry["shell"] if entry else "?"
            offenders.append(f"{s['name']} (shell {shell})")
    if not offenders:
        return Outcome.passed("No accounts have an empty password")
    return Outcome.failed(
        f"{len(offenders)} account(s) have an empty password",
        evidence=offenders,
        actual=offenders,
        confidence=Confidence.CERTAIN,
    )


# --------------------------------------------------------------------------- #
# 10. root tty / securetty / root SSH posture
# --------------------------------------------------------------------------- #

@check(
    id="EXT-ACCT-10",
    title="Review direct root login exposure (tty/securetty/SSH)",
    section="EXT.Accounts",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Direct root login defeats accountability (no record of who became root) and exposes the highest-value account to brute force. Root should log in via su/sudo from a named account, and remote root SSH should be off.",
    remediation="Set 'PermitRootLogin no' in sshd, and restrict console root login; require named accounts + sudo.",
    tags=("accounts", "root", "ssh"),
    attack=("T1078.003",),
)
def root_login_exposure(ctx):
    problems = []
    prl = ctx.sshd_config().get("permitrootlogin", "")
    if prl and prl not in ("no", "forced-commands-only", "prohibit-password"):
        problems.append(f"sshd PermitRootLogin={prl} — remote root login is allowed")
    securetty = ctx.read_file("/etc/securetty")
    if securetty is not None:
        ttys = [l.strip() for l in securetty.splitlines() if l.strip() and not l.startswith("#")]
        risky = [t for t in ttys if t.startswith(("pts", "ttyp", "ttyS"))]
        if risky:
            problems.append(f"/etc/securetty permits root on remote/serial ttys: {', '.join(risky[:5])}")
    if not problems:
        return Outcome.passed("Direct root login is appropriately restricted")
    return Outcome.warn(
        f"{len(problems)} direct-root-login exposure(s)",
        evidence=problems,
        actual=problems,
        confidence=Confidence.LIKELY,
    )


# --------------------------------------------------------------------------- #
# 11. weak default umask
# --------------------------------------------------------------------------- #

@check(
    id="EXT-ACCT-11",
    title="Ensure the default umask is 027 or stricter",
    section="EXT.Accounts",
    severity=Severity.LOW,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="The default umask decides the permissions of every new file. A loose umask (022 or 000) makes users' new files group/world-readable by default, leaking data and the occasional secret. 027 keeps new files private to the owner and group.",
    remediation="Set 'UMASK 027' in /etc/login.defs and 'umask 027' in /etc/profile (and /etc/bash.bashrc).",
    tags=("accounts", "umask", "permissions"),
    attack=("T1552",),
)
def default_umask(ctx):
    found = []
    weak = []
    # /etc/login.defs UMASK
    defs = ctx.parse_keyword_file("/etc/login.defs")
    if "umask" in defs:
        found.append(("login.defs", defs["umask"]))
    # umask lines in profile-type files
    for path in ["/etc/profile", "/etc/bash.bashrc"] + ctx.glob("/etc/profile.d/*.sh"):
        content = ctx.read_file(path)
        if not content:
            continue
        for line in content.splitlines():
            m = re.match(r"\s*umask\s+([0-7]{3,4})", line)
            if m:
                found.append((path, m.group(1)))
    for source, value in found:
        try:
            mask = int(value, 8)
        except ValueError:
            continue
        if (mask & 0o027) != 0o027:
            weak.append(f"{source}: umask {value} is weaker than 027")
    if not found:
        return Outcome.manual("No default umask declaration found; verify /etc/login.defs and /etc/profile")
    if not weak:
        return Outcome.passed("Default umask is 027 or stricter")
    return Outcome.failed(
        f"{len(weak)} weak default umask setting(s)",
        evidence=weak,
        actual=weak,
    )
