"""Exploitable privilege-escalation vectors — the attacker's actual path to root.

Where the CIS sudo control asks "is re-auth globally disabled," these checks ask
the question a penetration tester asks: *given a shell as an unprivileged user,
can I become root, and how?* Each finding here is a concrete escalation
technique, not a policy nit — sudo to a GTFOBins binary, a setuid interpreter, a
file capability, membership in a root-equivalent group, or a writable unit a
root process executes.

Crucially, every finding also emits a **structured escalation edge** in its
``actual`` payload (``{"vectors": [...]}``) tagged ``escalation-vector``. The
:mod:`linux_secbench.analysis.attackgraph` layer stitches those edges into a
graph and derives the end-to-end attack paths, the chokepoints that sever them,
and which weaknesses the most paths route through. The exploitability data comes
from :mod:`gtfobins`.
"""

from __future__ import annotations

import re
from typing import Dict, List

from ...core import Confidence, Level, Outcome, Severity, Status, check
from ..extended import EXTENDED_FRAMEWORK
from . import gtfobins

# A reasonable root PATH when /etc/environment doesn't pin one. Used by the
# writable-PATH check to know which directories root would resolve binaries in.
_DEFAULT_ROOT_PATH = (
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
)

# Node names shared with the attack-graph builder. Keeping them here (rather
# than importing from analysis) preserves the one-directional layering: checks
# never import analysis.
NODE_LOCAL = "local"     # an unprivileged local shell (the assumed foothold)
NODE_ROOT = "root"


def _vector(src: str, dst: str, technique: str) -> Dict[str, str]:
    return {"src": src, "dst": dst, "technique": technique}


# --------------------------------------------------------------------------- #
# 1. sudo — per-binary exploitability, SETENV, NOPASSWD, writable target
# --------------------------------------------------------------------------- #

def _read_sudoers(ctx) -> str:
    text = ctx.read_file("/etc/sudoers")
    if text is None:
        return ""
    parts = [text]
    for path in ctx.glob("/etc/sudoers.d/*"):
        extra = ctx.read_file(path)
        if extra:
            parts.append(extra)
    return "\n".join(parts)


_TAG_RE = re.compile(r"\b(NOPASSWD|SETENV|NOEXEC)\b")
_SKIP_PREFIX = ("Defaults", "User_Alias", "Cmnd_Alias", "Host_Alias",
                "Runas_Alias", "@include", "#include")


def _parse_sudoers(text: str):
    """Yield (principal, tags, commands) for each user/group spec line.

    A pragmatic parser: it handles the common single-line specs seen in the
    wild. Tags (NOPASSWD/SETENV) are detected across the whole line, which errs
    toward flagging when tags are interleaved — the safe direction for a
    security check.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(_SKIP_PREFIX):
            continue
        if "=" not in line:
            continue
        who, rhs = line.split("=", 1)
        principal = who.split()[0]
        tags = set(_TAG_RE.findall(line))
        # Drop the runas spec "(...)" and any TAG: tokens, leaving the commands.
        rhs = re.sub(r"\([^)]*\)", "", rhs)
        rhs = re.sub(r"\b(?:NOPASSWD|PASSWD|SETENV|NOSETENV|NOEXEC|EXEC|LOG_INPUT|"
                     r"NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW)\s*:", " ", rhs)
        commands = [c.strip() for c in rhs.split(",") if c.strip()]
        yield principal, tags, commands


@check(
    id="EXT-PRIV-1",
    title="Detect exploitable sudo grants (GTFOBins / SETENV / writable target)",
    section="EXT.PrivEsc",
    severity=Severity.CRITICAL,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "Sudo to a single shell-capable binary is full root. A user allowed 'sudo python', 'sudo find', "
        "'sudo vim' — or any command with the SETENV tag — can break out to a root shell. NOPASSWD removes "
        "even the password barrier. This is the most common real-world local privilege escalation."),
    remediation=(
        "Scope sudo to exact, non-interactive commands; never grant interpreters/editors/pagers or SETENV. "
        "Prefer 'NOEXEC:' and avoid NOPASSWD."),
    references=("https://gtfobins.github.io",),
    tags=("sudo", "privilege", "nopasswd", "escalation-vector", "gtfobins"),
)
def exploitable_sudo(ctx):
    text = _read_sudoers(ctx)
    if not text:
        return Outcome.manual("Root required to read sudoers; manually cross-reference 'sudo -l' with GTFOBins")
    vectors: List[Dict[str, str]] = []
    evidence: List[str] = []
    worst = Severity.LOW
    for principal, tags, commands in _parse_sudoers(text):
        nopasswd = "NOPASSWD" in tags
        setenv = "SETENV" in tags
        for cmd in commands:
            binary = cmd.split()[0] if cmd.split() else cmd
            base = gtfobins.basename(binary)
            reasons = []
            gtfo_tech = gtfobins.lookup(binary, "sudo")  # set only for a real GTFOBins binary
            if cmd == "ALL" or base == "ALL":
                reasons.append("unrestricted sudo (ALL) — run any command as root")
            if gtfo_tech:
                reasons.append(f"GTFOBins: {gtfo_tech}")
            if setenv:
                reasons.append("SETENV allows env injection (PYTHONPATH/BASH_ENV/PERL5LIB/LD_*)")
            if "*" in cmd:
                reasons.append("wildcard in command spec → argument/path injection")
            writable = False
            if binary.startswith("/"):
                st = ctx.stat(binary)
                if st.exists and (st.mode & 0o022) and st.owner != "root":
                    reasons.append("command target is writable by non-root")
                    writable = True
            if not reasons:
                continue
            pw = "NOPASSWD" if nopasswd else "password required"
            note = f"{principal}: sudo {cmd} [{pw}] — " + "; ".join(reasons)
            # Link to the GTFOBins page only for an actual catalogued binary.
            if gtfo_tech:
                note += f"  [how: {gtfobins.gtfobins_url(binary)}]"
            evidence.append(note)
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"as {principal}: sudo {base} ({pw})"))
            sev = Severity.CRITICAL if (gtfo_tech and nopasswd) or writable else Severity.HIGH
            worst = max(worst, sev)
    if not vectors:
        return Outcome.passed("No exploitable sudo grants detected")
    return Outcome(
        status=Status.FAIL,
        summary=f"{len(vectors)} exploitable sudo grant(s) → root",
        evidence=evidence[:30],
        actual={"vectors": vectors},
        confidence=Confidence.LIKELY,
    )


# --------------------------------------------------------------------------- #
# 2. setuid/setgid binaries that are GTFOBins escalations
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-2",
    title="Detect exploitable SUID/SGID binaries (GTFOBins)",
    section="EXT.PrivEsc",
    severity=Severity.CRITICAL,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "An UNEXPECTED setuid-root binary that can run commands, write files, or spawn a shell (find, vim, "
        "python, cp, tar, …) is instant root for ANY local user — no password, no sudo entry. Binaries that "
        "are setuid by design (mount, su, passwd, pkexec, …) are excluded: their bit is required and their "
        "GTFOBins technique is conditional, not a default escalation."),
    remediation="Remove the setuid bit (chmod -s) from the unexpected binary; it should not run as root for every user.",
    references=("https://gtfobins.github.io",),
    tags=("suid", "privilege", "escalation-vector", "gtfobins"),
)
def exploitable_suid(ctx):
    listing = ctx.sh(
        r"find / -xdev -type f \( -perm -4000 -o -perm -2000 \) "
        r"-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -400",
        timeout=90,
    )
    vectors, evidence = [], []
    for path in listing.lines():
        # Skip binaries that are setuid-root by design (mount, su, passwd,
        # pkexec, …): their setuid bit is required and their GTFOBins technique
        # is conditional, not a default non-root→root primitive. Only an
        # *unexpected* setuid GTFOBins binary (e.g. a setuid python/find someone
        # added) is the real instant-root finding.
        if path in gtfobins.DEFAULT_SETUID:
            continue
        technique = gtfobins.lookup(path, "suid")
        if technique:
            evidence.append(f"{path} — {technique}  [how: {gtfobins.gtfobins_url(path)}]")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"setuid {gtfobins.basename(path)}: {technique}"))
    if not vectors:
        return Outcome.passed("No unexpected GTFOBins-exploitable setuid/setgid binaries found")
    return Outcome(Status.FAIL, f"{len(vectors)} exploitable setuid/setgid binary(ies) → root",
                   evidence=evidence[:30], actual={"vectors": vectors}, confidence=Confidence.CERTAIN)


# --------------------------------------------------------------------------- #
# 3. file capabilities that grant root
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-3",
    title="Detect root-granting file capabilities (GTFOBins)",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="cap_setuid on an interpreter (python/perl/ruby) or cap_dac_override on a file tool is a one-liner to root.",
    remediation="Remove the capability with 'setcap -r <file>'; grant the narrowest capability actually required.",
    references=("https://gtfobins.github.io",),
    tags=("capabilities", "privilege", "escalation-vector", "gtfobins"),
)
def exploitable_capabilities(ctx):
    if not ctx.run(["sh", "-c", "command -v getcap"]).ok:
        return Outcome.skip("getcap not available (libcap2-bin not installed)")
    listing = ctx.sh("getcap -r / 2>/dev/null | head -200", timeout=90)
    vectors, evidence = [], []
    for line in listing.lines():
        low = line.lower()
        if not any(cap in low for cap in gtfobins.DANGEROUS_CAPS):
            continue
        path = line.split()[0]
        technique = gtfobins.lookup(path, "cap")
        cap = next((c for c in gtfobins.DANGEROUS_CAPS if c in low), "capability")
        if technique:
            evidence.append(f"{line.strip()} — {technique}")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"{cap} on {gtfobins.basename(path)}: {technique}"))
        elif "cap_setuid" in low or "cap_dac_override" in low:
            evidence.append(f"{line.strip()} — dangerous capability on a non-catalogued binary (review)")
    if not vectors:
        if evidence:
            return Outcome.warn(f"{len(evidence)} dangerous file capability(ies) to review",
                                evidence=evidence[:20], confidence=Confidence.LIKELY)
        return Outcome.passed("No root-granting file capabilities found")
    return Outcome(Status.FAIL, f"{len(vectors)} capability-based escalation(s) → root",
                   evidence=evidence[:20], actual={"vectors": vectors}, confidence=Confidence.LIKELY)


# --------------------------------------------------------------------------- #
# 4. root-equivalent group membership (docker, lxd, disk, shadow, adm)
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-4",
    title="Detect membership in root-equivalent groups (docker, lxd, disk, …)",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "Some groups are root by another name. A 'docker' or 'lxd' member can mount the host filesystem as "
        "root; 'disk' can read/write raw block devices; 'shadow' can read password hashes. These are escalation "
        "shortcuts that bypass sudo entirely."),
    remediation="Remove users from these groups unless strictly required; treat membership as equivalent to root.",
    tags=("privilege", "accounts", "escalation-vector", "groups"),
)
def root_equivalent_groups(ctx):
    # Map gid → group name and collect explicit members.
    members_by_group: Dict[str, set] = {}
    gid_to_group: Dict[str, str] = {}
    for g in ctx.group_entries():
        gid_to_group[g["gid"]] = g["name"]
        if g["name"] in gtfobins.ROOT_EQUIVALENT_GROUPS:
            members_by_group.setdefault(g["name"], set()).update(
                m for m in g["members"].split(",") if m)
    # Add users whose *primary* group is one of these.
    for u in ctx.passwd_entries():
        grp = gid_to_group.get(u["gid"])
        if grp in gtfobins.ROOT_EQUIVALENT_GROUPS:
            members_by_group.setdefault(grp, set()).add(u["name"])

    vectors, evidence = [], []
    for group, members in members_by_group.items():
        members = {m for m in members if m and m != "root"}
        if not members:
            continue
        capability = gtfobins.ROOT_EQUIVALENT_GROUPS[group]
        node = f"group:{group}"
        # One capability edge (the chokepoint) ...
        vectors.append(_vector(node, NODE_ROOT, capability))
        # ... and a membership edge per user routing through it.
        for m in sorted(members):
            vectors.append(_vector(NODE_LOCAL, node, f"{m} is a member of '{group}'"))
            evidence.append(f"{m} ∈ {group} — {capability}")
    if not vectors:
        return Outcome.passed("No users in root-equivalent groups")
    return Outcome(Status.FAIL, f"{len(evidence)} membership(s) in root-equivalent group(s)",
                   evidence=evidence[:30], actual={"vectors": vectors}, confidence=Confidence.CERTAIN)


# --------------------------------------------------------------------------- #
# 5. writable units / cron a root process executes
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-5",
    title="Detect writable systemd units / cron jobs executed as root",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "If a non-root user can edit a systemd unit or a cron script that root runs, they control code "
        "execution as root at the next start or tick — a reliable persistence-and-escalation path."),
    remediation="Set these files to root:root ownership and remove group/other write (chmod o-w,g-w).",
    tags=("privilege", "cron", "escalation-vector", "world-writable"),
)
def writable_root_execution(ctx):
    listing = ctx.sh(
        r"find /etc/systemd /lib/systemd /run/systemd /etc/cron* /var/spool/cron "
        r"-type f -perm /022 2>/dev/null | head -200",
        timeout=60,
    )
    vectors, evidence = [], []
    for path in listing.lines():
        st = ctx.stat(path)
        if st.exists and st.owner != "root" or (st.exists and st.mode & 0o022):
            kind = "unit" if "systemd" in path else "cron job"
            evidence.append(f"{path} (mode {st.mode_str}, owner {st.owner})")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"writable {kind} executed by root: {path}"))
    if not vectors:
        return Outcome.passed("No writable root-executed units or cron jobs found")
    return Outcome(Status.FAIL, f"{len(vectors)} writable root-executed file(s)",
                   evidence=evidence[:25], actual={"vectors": vectors}, confidence=Confidence.LIKELY)


# --------------------------------------------------------------------------- #
# 6. writable directory on root's PATH (and "." / empty entries)
# --------------------------------------------------------------------------- #

def _root_path_dirs(ctx) -> List[str]:
    """Root's PATH entries, from /etc/environment if pinned, else a sane default."""
    env = ctx.parse_keyword_file("/etc/environment", sep="=")
    raw = env.get("path", "")
    if raw:
        return [p.strip().strip('"') for p in raw.split(":")]
    return list(_DEFAULT_ROOT_PATH)


@check(
    id="EXT-PRIV-6",
    title="Detect writable directories or '.' on root's PATH",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "If a directory on root's PATH is writable by a non-root user — or PATH contains '.' or an empty "
        "entry (the current directory) — that user can drop a binary that root runs by name (e.g. 'ls', "
        "'service') and execute code as root at the next invocation."),
    remediation="Remove non-root-writable directories and '.'/empty entries from root's PATH; chown PATH dirs to root and drop group/other write.",
    tags=("privilege", "path", "escalation-vector"),
    attack=("T1574.007",),
)
def writable_path_dirs(ctx):
    vectors, evidence = [], []
    for entry in _root_path_dirs(ctx):
        if entry in ("", "."):
            evidence.append(f"PATH contains '{entry or 'empty'}' (current directory) — code-execution by filename")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, "writable '.' on root's PATH"))
            continue
        st = ctx.stat(entry)
        if st.exists and (st.mode & 0o022) and st.owner != "root":
            evidence.append(f"{entry} on root's PATH is writable by non-root (mode {st.mode_str}, owner {st.owner})")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"writable PATH dir {entry}"))
    if not vectors:
        return Outcome.passed("No writable directories or '.' on root's PATH")
    return Outcome(Status.FAIL, f"{len(vectors)} writable/'.' entry(ies) on root's PATH → root",
                   evidence=evidence[:25], actual={"vectors": vectors}, confidence=Confidence.LIKELY)


# --------------------------------------------------------------------------- #
# 7. ld.so.preload / ld.so.conf.d — library-injection escalation
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-7",
    title="Detect ld.so.preload injection or writable loader config",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "/etc/ld.so.preload force-loads a library into every dynamically-linked process, including "
        "setuid-root ones — a classic rootkit and escalation hook. A populated preload file, or a "
        "writable ld.so.preload / ld.so.conf.d, lets an attacker inject code into root processes."),
    remediation="Empty/remove unexpected /etc/ld.so.preload entries; ensure ld.so.preload and ld.so.conf.d are root-owned and not writable by others.",
    tags=("privilege", "library-injection", "escalation-vector", "persistence"),
    attack=("T1574.006",),
)
def loader_preload_injection(ctx):
    vectors, evidence = [], []
    preload = ctx.read_file("/etc/ld.so.preload")
    if preload and preload.strip():
        libs = [l.strip() for l in preload.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        if libs:
            evidence.append(f"/etc/ld.so.preload force-loads {len(libs)} library(ies) into every process: {', '.join(libs[:5])}")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, "ld.so.preload library injection into setuid-root processes"))
    for path in ["/etc/ld.so.preload", "/etc/ld.so.conf"] + ctx.glob("/etc/ld.so.conf.d/*"):
        st = ctx.stat(path)
        if st.exists and (st.mode & 0o022) and st.owner != "root":
            evidence.append(f"{path} is writable by non-root (mode {st.mode_str}, owner {st.owner}) — can inject a library into root")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"writable loader config {path}"))
    if not vectors:
        return Outcome.passed("No ld.so.preload injection or writable loader config found")
    return Outcome(Status.FAIL, f"{len(vectors)} loader-injection vector(s) → root",
                   evidence=evidence[:25], actual={"vectors": vectors}, confidence=Confidence.LIKELY)


# --------------------------------------------------------------------------- #
# 8. pwnkit — pkexec / polkit CVE-2021-4034 advisory
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-8",
    title="Check pkexec/polkit for the PwnKit vulnerability (CVE-2021-4034)",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="PwnKit (CVE-2021-4034) is a memory-corruption bug in setuid-root pkexec that gives any local user instant root, with reliable public exploits. Unpatched polkit < 0.120 (Ubuntu pkexec before the 2022 security update) is affected.",
    remediation="Update the 'policykit-1'/'polkit' package to the patched version; if pkexec is not needed, remove its setuid bit.",
    references=("https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt",),
    tags=("privilege", "cve", "escalation-vector"),
    attack=("T1548",),
)
def pwnkit_pkexec(ctx):
    pkexec = "/usr/bin/pkexec"
    st = ctx.stat(pkexec)
    if not st.exists:
        return Outcome.passed("pkexec is not installed")
    setuid = bool(st.mode & 0o4000)
    ver = ctx.run(["pkexec", "--version"]).out.strip()
    m = re.search(r"(\d+)\.(\d+)", ver)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if (major, minor) < (0, 120):
            return Outcome.failed(
                f"pkexec reports polkit {m.group(0)} (< 0.120) — vulnerable to PwnKit (CVE-2021-4034)"
                + (", and is setuid-root" if setuid else ""),
                evidence=[f"{pkexec} version: {ver}", f"setuid bit: {'set' if setuid else 'absent'}"],
                actual=m.group(0),
                confidence=Confidence.LIKELY,
            )
        return Outcome.passed(f"pkexec reports polkit {m.group(0)} (>= 0.120, PwnKit-patched)")
    # Version not reported — fall back to a manual, honest pointer rather than guessing.
    return Outcome.manual(
        "Could not read the polkit version; verify the 'policykit-1'/'polkit' package is patched for CVE-2021-4034",
        evidence=[f"{pkexec} setuid bit: {'set' if setuid else 'absent'}"],
    )


# --------------------------------------------------------------------------- #
# 9. polkit rules granting unprivileged escalation
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-9",
    title="Detect polkit rules that grant unprivileged privilege escalation",
    section="EXT.PrivEsc",
    severity=Severity.MEDIUM,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A polkit rule (.rules) or .pkla that returns YES / auth_admin_keep for any active or any user broadens who can run privileged actions (mount, package install, systemctl) without re-authenticating — a quiet escalation path.",
    remediation="Scope polkit rules to specific actions and groups; avoid returning polkit.Result.YES for subject.active/any.",
    tags=("privilege", "polkit", "escalation-vector"),
    attack=("T1548",),
)
def polkit_rules(ctx):
    findings: List[str] = []
    for path in ctx.glob("/etc/polkit-1/rules.d/*.rules") + ctx.glob("/usr/share/polkit-1/rules.d/*.rules"):
        content = ctx.read_file(path, max_bytes=128_000) or ""
        low = content.lower()
        if "polkit.result.yes" in low and ("subject.active" in low or "subject.local" in low or "true" in low):
            findings.append(f"{path}: returns polkit.Result.YES (review which actions/subjects it covers)")
    for path in (ctx.glob("/etc/polkit-1/localauthority/*/*.pkla")
                 + ctx.glob("/var/lib/polkit-1/localauthority/*/*.pkla")):
        content = ctx.read_file(path, max_bytes=128_000) or ""
        if re.search(r"(?i)Result\w*\s*=\s*yes", content):
            findings.append(f"{path}: .pkla grants an action with Result=yes (review scope)")
    if not findings:
        return Outcome.passed("No over-broad polkit rules detected")
    return Outcome.warn(
        f"{len(findings)} polkit rule(s) to review for over-broad escalation",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.POSSIBLE,
    )


# --------------------------------------------------------------------------- #
# 10. NFS exports with no_root_squash
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-10",
    title="Detect NFS exports with no_root_squash",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="An NFS export with no_root_squash lets a client's root write files as root on the share — including setuid-root binaries — so any client admin (or attacker who reaches the export) can plant a root shell on the server.",
    remediation="Replace no_root_squash with root_squash on every export, and restrict exports to specific trusted hosts.",
    tags=("privilege", "nfs", "escalation-vector"),
    attack=("T1210",),
)
def nfs_no_root_squash(ctx):
    findings: List[str] = []
    for path in ["/etc/exports"] + ctx.glob("/etc/exports.d/*.exports"):
        content = ctx.read_file(path)
        if not content:
            continue
        for lineno, line in enumerate(content.splitlines(), start=1):
            s = line.strip()
            if s and not s.startswith("#") and "no_root_squash" in s:
                findings.append(f"{path}:{lineno} — {s[:160]}")
    if not findings:
        return Outcome.passed("No NFS exports use no_root_squash")
    return Outcome.failed(
        f"{len(findings)} NFS export(s) use no_root_squash",
        evidence=findings[:25],
        actual=findings[:25],
        confidence=Confidence.CERTAIN,
    )


# --------------------------------------------------------------------------- #
# 11. writable ExecStart targets in systemd units
# --------------------------------------------------------------------------- #

_EXECKEY_RE = re.compile(r"(?im)^\s*ExecStart(?:Pre|Post)?\s*=\s*(.+)$")


@check(
    id="EXT-PRIV-11",
    title="Detect writable program targets in root systemd units",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A systemd unit's ExecStart= may point at a script or binary that a non-root user can write, even when the unit file itself is locked down. Editing that target is code execution as the unit's (usually root) user at the next start.",
    remediation="chown the ExecStart target to root and remove group/other write; keep service binaries out of user-writable locations.",
    tags=("privilege", "systemd", "escalation-vector"),
    attack=("T1543.002",),
)
def writable_execstart_targets(ctx):
    vectors, evidence = [], []
    units = (ctx.glob("/etc/systemd/system/*.service")
             + ctx.glob("/lib/systemd/system/*.service")
             + ctx.glob("/usr/lib/systemd/system/*.service"))
    seen_targets = set()
    for unit in units[:400]:
        content = ctx.read_file(unit, max_bytes=64_000)
        if not content:
            continue
        for m in _EXECKEY_RE.finditer(content):
            spec = m.group(1).strip()
            # Strip systemd exec prefixes (-, @, +, !, !!) and take the program.
            spec = spec.lstrip("-@+!:")
            prog = spec.split()[0] if spec.split() else ""
            if not prog.startswith("/") or prog in seen_targets:
                continue
            seen_targets.add(prog)
            st = ctx.stat(prog)
            if st.exists and (st.mode & 0o022) and st.owner != "root":
                evidence.append(f"{unit}: ExecStart target {prog} is writable by non-root (mode {st.mode_str}, owner {st.owner})")
                vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"writable service binary {prog}"))
    if not vectors:
        return Outcome.passed("No writable ExecStart targets in systemd units")
    return Outcome(Status.FAIL, f"{len(vectors)} writable service program(s) executed by root → root",
                   evidence=evidence[:25], actual={"vectors": vectors}, confidence=Confidence.LIKELY)


# --------------------------------------------------------------------------- #
# 12. sudoers risk flags (secure_path, env_keep, !authenticate)
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-12",
    title="Detect risky sudoers Defaults (missing secure_path, env_keep, !authenticate)",
    section="EXT.PrivEsc",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "sudo's safety rests on its Defaults. No secure_path lets a poisoned PATH reach the sudo'd command; "
        "an over-broad env_keep (LD_PRELOAD, PYTHONPATH, BASH_ENV) lets a user inject code into the elevated "
        "process; '!authenticate' drops the password check entirely."),
    remediation="Set 'Defaults secure_path=...', remove dangerous env_keep entries, and do not use !authenticate.",
    tags=("privilege", "sudo", "escalation-vector"),
    attack=("T1548.003",),
)
def sudoers_risk_flags(ctx):
    text = _read_sudoers(ctx)
    if not text:
        return Outcome.manual("Root required to read sudoers; manually review Defaults for secure_path/env_keep/!authenticate")
    findings: List[str] = []
    has_secure_path = bool(re.search(r"(?im)^\s*Defaults\b.*\bsecure_path\s*=", text))
    if not has_secure_path:
        findings.append("No 'Defaults secure_path=' — a user-controlled PATH can reach sudo'd commands")
    dangerous_env = ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB", "BASH_ENV", "RUBYLIB", "PATH")
    for m in re.finditer(r"(?im)^\s*Defaults\b.*\benv_keep\b[+]?=\s*\"?([^\"\n]+)\"?", text):
        kept = m.group(1)
        bad = [e for e in dangerous_env if e in kept]
        if bad:
            findings.append(f"env_keep retains dangerous variable(s): {', '.join(bad)}")
    if re.search(r"(?im)^\s*Defaults\b.*!authenticate", text) or "NOPASSWD: ALL" in text:
        if re.search(r"(?im)^\s*Defaults\b.*!authenticate", text):
            findings.append("'Defaults !authenticate' disables the sudo password check globally")
    if not findings:
        return Outcome.passed("sudoers Defaults look safe (secure_path set, no dangerous env_keep/!authenticate)")
    return Outcome.warn(
        f"{len(findings)} risky sudoers Default(s)",
        evidence=findings,
        actual=findings,
        confidence=Confidence.LIKELY,
    )


# --------------------------------------------------------------------------- #
# 13. writable critical system files
# --------------------------------------------------------------------------- #

_CRITICAL_FILES = (
    "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
    "/etc/sudoers", "/etc/crontab", "/etc/hosts", "/etc/fstab",
)


@check(
    id="EXT-PRIV-13",
    title="Detect critical system files writable by non-root",
    section="EXT.PrivEsc",
    severity=Severity.CRITICAL,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="If a non-root user can write /etc/passwd, /etc/shadow, /etc/sudoers, or /etc/crontab, they can add a UID-0 account, blank root's password, grant themselves sudo, or schedule a root job — instant, total escalation.",
    remediation="Restore root:root ownership and remove group/other write (e.g. chmod 644 /etc/passwd, 600 /etc/sudoers).",
    tags=("privilege", "filesystem", "escalation-vector"),
    attack=("T1222", "T1098"),
)
def writable_critical_files(ctx):
    vectors, evidence = [], []
    for path in _CRITICAL_FILES:
        st = ctx.stat(path)
        if st.exists and (st.mode & 0o022):
            evidence.append(f"{path} is writable beyond owner (mode {st.mode_str}, owner {st.owner})")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"writable {path}"))
    if not vectors:
        return Outcome.passed("No critical system files are writable by non-root")
    return Outcome(Status.FAIL, f"{len(vectors)} critical system file(s) writable by non-root → root",
                   evidence=evidence, actual={"vectors": vectors}, confidence=Confidence.CERTAIN)


# --------------------------------------------------------------------------- #
# 14. docker / container runtime socket permissions
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-14",
    title="Detect over-permissive container runtime sockets",
    section="EXT.PrivEsc",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Write access to the docker/containerd socket is root: 'docker run -v /:/host' mounts the host as root. A world-accessible socket (or one whose owning group is broad) hands that out to local users beyond the intended docker group.",
    remediation="Restrict the socket to mode 660 root:docker, keep the docker group tiny, and prefer rootless/socket-activated access.",
    tags=("privilege", "docker", "escalation-vector"),
    attack=("T1610",),
)
def container_socket_perms(ctx):
    vectors, evidence = [], []
    for sock in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
                 "/run/podman/podman.sock"):
        st = ctx.stat(sock)
        if not st.exists:
            continue
        if st.mode & 0o006:  # any world read/write
            evidence.append(f"{sock} is world-accessible (mode {st.mode_str}) — local users can control the daemon as root")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"world-accessible container socket {sock}"))
        elif st.mode & 0o060 and st.group not in ("root", "docker"):
            evidence.append(f"{sock} is group-writable by '{st.group}' (mode {st.mode_str}) — broad group grants root-equivalent access")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"broad-group container socket {sock}"))
    if not vectors:
        return Outcome.passed("Container runtime sockets are not over-permissive")
    return Outcome(Status.FAIL, f"{len(vectors)} over-permissive container socket(s) → root",
                   evidence=evidence, actual={"vectors": vectors}, confidence=Confidence.LIKELY)


# --------------------------------------------------------------------------- #
# 15. at jobs & writable systemd timers
# --------------------------------------------------------------------------- #

@check(
    id="EXT-PRIV-15",
    title="Detect writable systemd timers and queued at jobs",
    section="EXT.PrivEsc",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="systemd timers are the modern cron; a writable .timer (or the .service it triggers) is scheduled root code execution. Queued 'at' jobs run later as the submitting user and are worth inventorying for unexpected root tasks.",
    remediation="Lock timer/unit files to root:root without group/other write; review the at queue ('atq') for unexpected jobs.",
    tags=("privilege", "cron", "systemd", "escalation-vector"),
    attack=("T1053",),
)
def writable_timers_and_at(ctx):
    vectors, evidence = [], []
    for path in ctx.glob("/etc/systemd/system/*.timer") + ctx.glob("/lib/systemd/system/*.timer"):
        st = ctx.stat(path)
        if st.exists and (st.mode & 0o022) and st.owner != "root":
            evidence.append(f"{path} timer is writable by non-root (mode {st.mode_str}, owner {st.owner})")
            vectors.append(_vector(NODE_LOCAL, NODE_ROOT, f"writable systemd timer {path}"))
    at_jobs = ctx.glob("/var/spool/cron/atjobs/*") + ctx.glob("/var/spool/at/*")
    queued = [j for j in at_jobs if not j.endswith("/.SEQ")]
    if queued:
        evidence.append(f"{len(queued)} queued 'at' job(s) present — review with atq for unexpected root tasks")
    if not vectors and not queued:
        return Outcome.passed("No writable timers or queued at jobs found")
    if not vectors:
        return Outcome.warn(
            f"{len(queued)} queued at job(s) to review",
            evidence=evidence[:25], actual=len(queued), confidence=Confidence.POSSIBLE)
    return Outcome(Status.FAIL, f"{len(vectors)} writable timer(s) executed by root → root",
                   evidence=evidence[:25], actual={"vectors": vectors}, confidence=Confidence.LIKELY)
