"""CIS Section 7 — System Maintenance (CIS Ubuntu 24.04 Benchmark v2.0.0).

  7.1 Configure system file and directory access  (13)
  7.2 Local User and Group Settings                (10)

Permissions/ownership on the critical account databases, the absence of
world-writable / unowned files, and integrity of the passwd/group/shadow
databases. These are the controls auditors check first: unambiguous, high-signal.
"""

from __future__ import annotations

from ...core import Level, Outcome, Severity
from ._base import cis_check as check


# --------------------------------------------------------------------------- #
# 7.1.1 – 7.1.10  critical file/directory access
# (cis_id, path, max_mode, owner, group)
# --------------------------------------------------------------------------- #
_SYSTEM_FILES = [
    ("7.1.1", "/etc/passwd", 0o644, "root", "root"),
    ("7.1.2", "/etc/passwd-", 0o644, "root", "root"),
    ("7.1.3", "/etc/group", 0o644, "root", "root"),
    ("7.1.4", "/etc/group-", 0o644, "root", "root"),
    ("7.1.5", "/etc/shadow", 0o640, "root", "shadow"),
    ("7.1.6", "/etc/shadow-", 0o640, "root", "shadow"),
    ("7.1.7", "/etc/gshadow", 0o640, "root", "shadow"),
    ("7.1.8", "/etc/gshadow-", 0o640, "root", "shadow"),
    ("7.1.9", "/etc/shells", 0o644, "root", "root"),
    ("7.1.10", "/etc/security/opasswd", 0o600, "root", "root"),
]


def _make_system_file_check(cis_id, path, max_mode, owner, group):
    @check(
        id=cis_id,
        title=f"Ensure access to {path} is configured",
        section="7.1 Configure system file and directory access",
        severity=Severity.HIGH if "shadow" in path else Severity.MEDIUM,
        levels=(Level.L1,),
        rationale=f"{path} underpins authentication/accounting; loose permissions enable "
                  f"credential theft or account tampering.",
        remediation=f"chown {owner}:{group} {path}; chmod {max_mode:o} {path}",
        tags=("permissions", "accounts"),
    )
    def _chk(ctx, _path=path, _max=max_mode, _owner=owner, _group=group):
        st = ctx.stat(_path)
        if not st.exists:
            return Outcome.skip(f"{_path} does not exist")
        problems = []
        if not st.perm_at_most(_max):
            problems.append(f"mode {st.mode_str} (expected <= {_max:o})")
        if st.owner not in ("", _owner):
            problems.append(f"owner {st.owner} (expected {_owner})")
        # shadow/gshadow group is root on some installs; tolerate root, else expect group.
        if st.group not in ("", _group) and st.group != "root":
            problems.append(f"group {st.group} (expected {_group})")
        if problems:
            return Outcome.failed(f"{_path}: " + "; ".join(problems),
                                  actual=st.mode_str, expected=format(_max, "04o"))
        return Outcome.passed(f"{_path}: mode {st.mode_str}, {st.owner}:{st.group}")

    return _chk


for _row in _SYSTEM_FILES:
    _make_system_file_check(*_row)


# Also cover /etc/security/opasswd.old under the 7.1.10 control's spirit by folding
# it into the same check above? CIS lists only opasswd by id; .old is part of its
# audit. Keep the single id; the audit text covers both files identically.


@check(
    id="7.1.11",
    title="Ensure world writable files and directories are secured",
    section="7.1 Configure system file and directory access",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    rationale="A world-writable file can be altered by any user; a world-writable directory without "
              "the sticky bit lets any user delete/replace others' files.",
    remediation="Remove the world-write bit (chmod o-w) from files; add the sticky bit (chmod +t) to shared dirs.",
    tags=("permissions", "world-writable"),
)
def world_writable_secured(ctx):
    files = ctx.sh(
        r"find / -xdev -type f -perm -0002 "
        r"-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -200"
    ).lines()
    # Directories that are world-writable AND lack the sticky bit (perm bit 01000).
    dirs = ctx.sh(
        r"find / -xdev -type d -perm -0002 ! -perm -1000 "
        r"-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -200"
    ).lines()
    offenders = [f"file: {f}" for f in files] + [f"dir(no-sticky): {d}" for d in dirs]
    if not offenders:
        return Outcome.passed("No insecure world-writable files or directories found")
    return Outcome.failed(
        f"{len(offenders)} world-writable issue(s) found",
        evidence=offenders[:25], actual=len(offenders), expected=0,
    )


@check(
    id="7.1.12",
    title="Ensure no files or directories without an owner and a group exist",
    section="7.1 Configure system file and directory access",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    rationale="Files owned by a non-existent UID/GID are often residue of a deleted account and can be silently re-claimed.",
    remediation="chown a valid owner/group, or remove the orphaned files after review.",
    tags=("permissions", "orphaned"),
)
def no_unowned_files(ctx):
    offenders = ctx.sh(
        r"find / -xdev \( -nouser -o -nogroup \) "
        r"-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -200"
    ).lines()
    if not offenders:
        return Outcome.passed("No unowned or ungrouped files/directories found")
    return Outcome.failed(
        f"{len(offenders)} unowned/ungrouped path(s) found",
        evidence=offenders[:25], actual=len(offenders), expected=0,
    )


@check(
    id="7.1.13",
    title="Ensure SUID and SGID files are reviewed",
    section="7.1 Configure system file and directory access",
    severity=Severity.INFO,
    levels=(Level.L1,),
    rationale="Each SUID/SGID binary runs with elevated privilege; the full set must be reviewed against a known-good baseline.",
    remediation="Review every SUID/SGID file; remove the bits from any that don't require them.",
    tags=("permissions", "suid", "sgid"),
)
def suid_sgid_reviewed(ctx):
    found = ctx.sh(
        r"find / -xdev -type f \( -perm -4000 -o -perm -2000 \) "
        r"-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -200"
    ).lines()
    return Outcome.manual(
        f"Review the {len(found)} SUID/SGID file(s) against a known-good baseline.",
        actual=found[:30] if found else "none found",
    )


# --------------------------------------------------------------------------- #
# 7.2  Local user and group settings
# --------------------------------------------------------------------------- #
@check(
    id="7.2.1",
    title="Ensure accounts in /etc/passwd use shadowed passwords",
    section="7.2 Local User and Group Settings",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    rationale="A password hash stored in /etc/passwd (field not 'x') is world-readable — it must live in /etc/shadow.",
    remediation="Run pwconv to migrate any inline password hashes into /etc/shadow.",
    tags=("accounts", "shadow"),
)
def accounts_use_shadow(ctx):
    offenders = [e["name"] for e in ctx.passwd_entries() if e.get("passwd", "") not in ("x",)]
    if not offenders:
        return Outcome.passed("All /etc/passwd accounts defer to /etc/shadow (field = x)")
    return Outcome.failed(
        f"{len(offenders)} account(s) not using shadowed passwords: {', '.join(offenders)}",
        evidence=offenders, actual=offenders, expected="passwd field = x",
    )


@check(
    id="7.2.2",
    title="Ensure /etc/shadow password fields are not empty",
    section="7.2 Local User and Group Settings",
    severity=Severity.CRITICAL,
    levels=(Level.L1,),
    rationale="An empty shadow password field allows login with no password — a complete authentication bypass.",
    remediation="Lock the account ('passwd -l <user>') or set a password immediately.",
    tags=("accounts", "password", "critical"),
)
def no_empty_shadow_passwords(ctx):
    if not ctx.is_root:
        return Outcome.manual("Root required to read /etc/shadow")
    offenders = [e["name"] for e in ctx.shadow_entries() if e.get("passwd", "") == ""]
    if not offenders:
        return Outcome.passed("No accounts have empty password fields")
    return Outcome.failed(
        f"{len(offenders)} account(s) with empty password: {', '.join(offenders)}",
        evidence=offenders, actual=offenders, expected="no empty passwords",
    )


@check(
    id="7.2.3",
    title="Ensure all groups in /etc/passwd exist in /etc/group",
    section="7.2 Local User and Group Settings",
    severity=Severity.LOW,
    levels=(Level.L1,),
    rationale="A primary GID with no /etc/group entry leaves files effectively ungrouped and confuses access decisions.",
    remediation="Create the missing groups or reassign affected users to valid groups.",
    tags=("accounts", "group"),
)
def passwd_groups_exist(ctx):
    group_gids = {g.get("gid") for g in ctx.group_entries()}
    missing = sorted({e.get("gid") for e in ctx.passwd_entries()
                      if e.get("gid") and e.get("gid") not in group_gids})
    if not missing:
        return Outcome.passed("All primary GIDs in /etc/passwd exist in /etc/group")
    return Outcome.failed(f"Primary GID(s) missing from /etc/group: {', '.join(missing)}",
                          actual=missing, expected="all present")


@check(
    id="7.2.4",
    title="Ensure shadow group is empty",
    section="7.2 Local User and Group Settings",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    rationale="Members of the shadow group can read /etc/shadow; no user should be granted that standing access.",
    remediation="Remove all members from the shadow group and reassign any user whose primary group is shadow.",
    tags=("accounts", "shadow", "group"),
)
def shadow_group_empty(ctx):
    shadow = next((g for g in ctx.group_entries() if g.get("name") == "shadow"), None)
    if shadow is None:
        return Outcome.skip("No shadow group present")
    members = [m for m in shadow.get("members", "").split(",") if m]
    shadow_gid = shadow.get("gid")
    primaries = [e["name"] for e in ctx.passwd_entries() if e.get("gid") == shadow_gid]
    offenders = members + primaries
    if not offenders:
        return Outcome.passed("shadow group is empty")
    return Outcome.failed(f"shadow group has members: {', '.join(offenders)}",
                          actual=offenders, expected="empty")


def _dupes(pairs):
    """pairs: list of (key, label); return {key: [labels]} for keys seen >1 time."""
    seen = {}
    for key, label in pairs:
        seen.setdefault(key, []).append(label)
    return {k: v for k, v in seen.items() if len(v) > 1}


@check(
    id="7.2.5", title="Ensure no duplicate UIDs exist",
    section="7.2 Local User and Group Settings", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Two usernames sharing a UID share all file ownership and privileges, defeating accountability.",
    remediation="Assign each account a unique UID and reconcile file ownership.", tags=("accounts", "uid"),
)
def no_duplicate_uids(ctx):
    dupes = _dupes([(e.get("uid"), e.get("name")) for e in ctx.passwd_entries()])
    if not dupes:
        return Outcome.passed("All UIDs are unique")
    detail = "; ".join(f"UID {u}: {', '.join(n)}" for u, n in dupes.items())
    return Outcome.failed(f"Duplicate UIDs found — {detail}", actual=dupes, expected="unique UIDs")


@check(
    id="7.2.6", title="Ensure no duplicate GIDs exist",
    section="7.2 Local User and Group Settings", severity=Severity.LOW, levels=(Level.L1,),
    rationale="Two group names sharing a GID share all group-based file access, blurring accountability.",
    remediation="Assign each group a unique GID.", tags=("accounts", "gid"),
)
def no_duplicate_gids(ctx):
    dupes = _dupes([(g.get("gid"), g.get("name")) for g in ctx.group_entries()])
    if not dupes:
        return Outcome.passed("All GIDs are unique")
    detail = "; ".join(f"GID {g}: {', '.join(n)}" for g, n in dupes.items())
    return Outcome.failed(f"Duplicate GIDs found — {detail}", actual=dupes, expected="unique GIDs")


@check(
    id="7.2.7", title="Ensure no duplicate user names exist",
    section="7.2 Local User and Group Settings", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="A duplicate user name makes file ownership and authorization ambiguous.",
    remediation="Ensure each account has a unique user name.", tags=("accounts", "username"),
)
def no_duplicate_usernames(ctx):
    dupes = _dupes([(e.get("name"), e.get("uid")) for e in ctx.passwd_entries()])
    if not dupes:
        return Outcome.passed("All user names are unique")
    return Outcome.failed(f"Duplicate user names: {', '.join(dupes)}", actual=dupes, expected="unique names")


@check(
    id="7.2.8", title="Ensure no duplicate group names exist",
    section="7.2 Local User and Group Settings", severity=Severity.LOW, levels=(Level.L1,),
    rationale="A duplicate group name makes group-based authorization ambiguous.",
    remediation="Ensure each group has a unique name.", tags=("accounts", "group"),
)
def no_duplicate_groupnames(ctx):
    dupes = _dupes([(g.get("name"), g.get("gid")) for g in ctx.group_entries()])
    if not dupes:
        return Outcome.passed("All group names are unique")
    return Outcome.failed(f"Duplicate group names: {', '.join(dupes)}", actual=dupes, expected="unique names")


def _interactive_users(ctx):
    """Local interactive users: UID>=1000 (and != nobody 65534), with a real shell."""
    out = []
    for e in ctx.passwd_entries():
        uid, shell = e.get("uid", ""), e.get("shell", "")
        if not uid.isdigit():
            continue
        if 1000 <= int(uid) < 65534 and shell and not shell.endswith(("nologin", "false")):
            out.append(e)
    return out


@check(
    id="7.2.9", title="Ensure local interactive user home directories are configured",
    section="7.2 Local User and Group Settings", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Each interactive user must own an existing home directory at <=750 so others can't read or tamper with it.",
    remediation="Create missing home dirs, chown them to the user, and chmod <=750.",
    tags=("accounts", "home"),
)
def home_dirs_configured(ctx):
    problems = []
    for e in _interactive_users(ctx):
        name, home = e.get("name"), e.get("home", "")
        if not home:
            problems.append(f"{name}: no home directory defined")
            continue
        st = ctx.stat(home)
        if not st.exists or not st.is_dir:
            problems.append(f"{name}: {home} missing")
            continue
        if st.owner not in ("", name):
            problems.append(f"{name}: {home} owned by {st.owner}")
        if not st.perm_at_most(0o750):
            problems.append(f"{name}: {home} mode {st.mode_str} (> 750)")
    if not _interactive_users(ctx):
        return Outcome.passed("No local interactive users to evaluate")
    if problems:
        return Outcome.failed("Home directory issues: " + "; ".join(problems),
                              actual=problems, expected="owned by user, <= 750")
    return Outcome.passed("All interactive-user home directories are configured")


@check(
    id="7.2.10", title="Ensure local interactive user dot files access is configured",
    section="7.2 Local User and Group Settings", severity=Severity.MEDIUM, levels=(Level.L1,),
    rationale="Group/world-writable dot files let others alter a user's shell environment; .netrc/.rhosts/.forward enable trust abuse.",
    remediation="Remove group/world-write from dot files; remove .netrc/.rhosts/.forward (or restrict .netrc to <=600).",
    tags=("accounts", "home", "dotfiles"),
)
def dot_files_access(ctx):
    if not _interactive_users(ctx):
        return Outcome.passed("No local interactive users to evaluate")
    problems = []
    forbidden = (".rhosts", ".forward")
    for e in _interactive_users(ctx):
        home = e.get("home", "")
        if not home:
            continue
        for path in ctx.glob(f"{home}/.[!.]*"):
            base = path.rsplit("/", 1)[-1]
            st = ctx.stat(path)
            if not st.exists:
                continue
            if base in forbidden:
                problems.append(f"{path} present")
            elif base == ".netrc" and not st.perm_at_most(0o600):
                problems.append(f"{path} mode {st.mode_str} (> 600)")
            elif st.mode & 0o022:
                problems.append(f"{path} group/world-writable ({st.mode_str})")
    if problems:
        return Outcome.failed("Dot file issues: " + "; ".join(problems[:20]),
                              actual=problems[:20], expected="no writable/forbidden dot files")
    return Outcome.passed("Interactive-user dot files are adequately restricted")
