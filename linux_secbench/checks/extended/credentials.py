"""Native credential and secret hunting (mimipenguin-inspired).

This is the "go a step beyond CIS" core of the assessment. It looks for the
ways credentials actually leak on a real host, implemented natively in Python
so there are no third-party dependencies:

* secrets sitting in world/group-readable config files,
* unencrypted or loosely-permissioned private keys,
* passwords pasted into shell history,
* credentials exposed in live process *environments* and *command lines*
  (``/proc/<pid>/environ`` and ``/proc/<pid>/cmdline`` — the kernel-exposed
  argv/env, NOT heap memory; the actual mimipenguin heap-scraping technique
  lives separately in :mod:`memscan` (EXT-CRED-16), gated by ``--active-review``),
* exposed credential stores (.netrc, .pgpass, cloud credentials).

Detection blends **known-pattern matching** with **Shannon-entropy scoring** so
a random API token is caught while a config comment is not. Every heuristic
finding is marked with a realistic confidence so risk scoring does not treat a
guess like a certainty. External deep-memory tools (mimipenguin, LaZagne) are
handled separately in :mod:`integrations` as optional plugins.
"""

from __future__ import annotations

import re
import shlex
from typing import List, Optional, Sequence, Tuple

from ...core import Confidence, Level, Outcome, Severity, check
from ..extended import EXTENDED_FRAMEWORK
from ...analysis.statistics import normalized_entropy
from ...analysis.evidence import fuse_secret_signals

# Assignment-style secrets: key = value where the key name screams "secret".
# An optional WORD_/word- prefix is allowed so prefixed names like DB_PASSWORD,
# MYSQL_PASSWORD or app-secret are caught too — a plain \b before the keyword
# would miss them (the underscore is a word char, so \bpassword\b never matches
# inside DB_PASSWORD).
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9])((?:[A-Za-z0-9]+[_-])?"
    r"(?:passwd|password|passphrase|secret|api[_-]?key|apikey|token|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|"
    r"db[_-]?pass|aws_secret_access_key))\s*[:=]\s*(\S+)"
)

# Unambiguous command-line secret markers. The bare `-p<pw>` form is handled
# separately and only for mysql-family commands (see _find_cmd_secret), because
# `-p` matches inside ordinary tokens (run-parts, --pidfile, pipewire-pulse).
# Each alternative captures just the secret token so redaction masks the value
# while leaving the surrounding command for context.
_CMD_SECRET_RE = re.compile(
    r"(?i)("
    r"\b(?:[A-Z0-9]+_)*PASS[A-Z0-9_]*\s*=\s*\S+|"          # *PASS*=value env/assignment (PASS at segment start)
    r"--pass(?:word|wd)?[=\s]\S+|--token[=\s]\S+|--secret[=\s]\S+|"
    r"--api[_-]?key[=\s]\S+|--access[_-]?key[=\s]\S+|"
    r"PGPASSWORD=\S+|MYSQL_PWD=\S+|"
    r"sshpass\s+-p\s*\S+|"
    r"://[^:@\s/]+:[^@\s/]+@|"                              # creds embedded in a URL
    r"\bcurl\b[^\n]*?\s-u\s+\S+:\S+"                        # curl -u user:pass
    r")"
)

# mysql-family invocations where a no-space `-p<password>` is a real credential.
_MYSQL_CMD_RE = re.compile(r"(?i)\b(?:mysql|mysqldump|mysqladmin|mysqlshow|mysqlimport|mariadb)\b")
# `-p<password>` anchored to a token boundary (not preceded by a word char or '-'),
# so it never matches mid-token (run-parts, --pidfile, pipewire-pulse, (sd-pam)).
_MYSQL_PW_RE = re.compile(r"(?<![\w-])-p\S{3,}")


def _find_cmd_secret(text: str) -> Optional[str]:
    """Return the sensitive substring on a command line, or None.

    Precise by design: only the unambiguous markers in ``_CMD_SECRET_RE`` fire
    everywhere; a bare ``-p<pw>`` is honoured only when the line is actually a
    mysql-family invocation. Returns the matched token (for redaction).
    """
    m = _CMD_SECRET_RE.search(text)
    if m:
        return m.group(0)
    if _MYSQL_CMD_RE.search(text):
        pm = _MYSQL_PW_RE.search(text)
        if pm:
            return pm.group(0)
    return None


def _cmd_evidence(line: str, match: str, reveal: bool) -> str:
    """Format a command-line secret hit for evidence.

    Leads with the matched token so it's obvious what fired, then the command
    for context — with the same value masked (unless --reveal-secrets) so the
    secret is never echoed in clear in the context tail.
    """
    token = match if reveal else _redact(match, False)
    context = line.strip()
    if not reveal:
        context = context.replace(match, token)
    return f"{token}  ⟵ {context[:100]}"

# High-signal literal markers worth flagging regardless of entropy.
_HARD_MARKERS = (
    ("-----BEGIN RSA PRIVATE KEY-----", "unencrypted RSA private key material"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key material"),
    ("-----BEGIN PRIVATE KEY-----", "PKCS#8 private key material"),
    ("AKIA", "possible AWS access key id"),
    ("xoxb-", "possible Slack bot token"),
    ("ghp_", "possible GitHub personal access token"),
)

# Values that look like a secret key but are obviously placeholders.
_PLACEHOLDERS = {
    "", "x", "changeme", "password", "none", "null", "true", "false",
    "yourpassword", "example", "<password>", "redacted", "********",
}

# Directories worth scanning for at-rest secrets. Bounded on purpose.
_CONFIG_DIRS = ("/etc", "/opt", "/srv", "/var/www")

_ENTROPY_THRESHOLD = 0.72   # normalized; tuned to separate tokens from prose
_MIN_SECRET_LEN = 12

# Home-directory values that are not real, browsable homes. Critically, "/" must
# never be used as a search root — a malformed passwd entry with home=/ would
# otherwise turn a targeted scan into a full-filesystem walk.
_NON_HOME_DIRS = frozenset({
    "/", "/nonexistent", "/dev/null", "/run", "/var/run",
    "/bin", "/sbin", "/usr/sbin", "/usr/bin", "/proc",
})


def _home_dirs(ctx) -> List[str]:
    """Every real home directory on the host, from /etc/passwd, plus /root.

    Hardcoding /home misses accounts whose home lives elsewhere (service
    accounts under /var/lib, /opt, custom paths) — and those can still hold
    shell history, keys, and credential files. We read the actual homes from
    passwd so coverage matches every account, while excluding junk/sentinel
    paths (and never "/") so the scan stays bounded.
    """
    homes = {"/root"}
    for entry in ctx.passwd_entries():
        home = (entry.get("home") or "").rstrip("/") or "/"
        if home.startswith("/") and home not in _NON_HOME_DIRS:
            homes.add(home)
    # Keep only directories that actually exist, to keep the find args tight.
    return sorted(h for h in homes if ctx.file_exists(h))


def _quoted_roots(dirs: Sequence[str]) -> str:
    """Shell-quote a list of search roots; fall back to /root if empty."""
    import shlex
    return " ".join(shlex.quote(d) for d in dirs) or "/root"


def _redact(value: str, reveal: bool) -> str:
    """Render a secret value for the report.

    With ``reveal`` the full value is shown (the operator opted in with
    --reveal-secrets and accepts that the report now holds live secrets).
    Otherwise we show just enough to *identify and locate* the secret for
    rotation — the first and last two characters and its length — never enough
    to use it: e.g. ``aZ…y6 (24 chars)``. Short values are fully masked.
    """
    value = value.strip()
    if reveal:
        return value
    n = len(value)
    if n <= 6:
        return f"(hidden, {n} chars)"
    return f"{value[:2]}…{value[-2:]} ({n} chars)"


def _scan_text_for_secrets(text: str, source: str,
                           sensitive_location: bool = True,
                           reveal: bool = False) -> List[Tuple[str, str, Confidence]]:
    """Return (location, reason, confidence) tuples for secrets found in text.

    Rather than trusting any single clue, each candidate's clues — a known
    secret marker, a random-looking value, a secret-y key name, a sensitive
    location, an obvious placeholder — are fused into one belief with
    Dempster–Shafer (see analysis.evidence). The fused belief decides both
    whether to report and how confident to be, so corroborating weak hints
    raise confidence and placeholders pull it back down.
    """
    findings: List[Tuple[str, str, Confidence]] = []

    # Literal key material is near-conclusive on its own.
    for marker, reason in _HARD_MARKERS:
        if marker in text:
            belief = fuse_secret_signals(known_marker=True, sensitive_location=sensitive_location)
            findings.append((source, reason, belief.confidence()))

    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        m = _SECRET_KEY_RE.search(line)
        if not m:
            continue
        value = m.group(2).strip().strip("'\"")
        # Known placeholders and trivially short values are definitively not
        # secrets — a hard veto, not a soft vote that entropy could outweigh.
        if value.lower() in _PLACEHOLDERS or len(value) < _MIN_SECRET_LEN:
            continue
        belief = fuse_secret_signals(
            secret_keyword=True,
            high_entropy=normalized_entropy(value) >= _ENTROPY_THRESHOLD,
            sensitive_location=sensitive_location,
        )
        if not belief.is_secret():
            continue
        kind = ("high-entropy value" if normalized_entropy(value) >= _ENTROPY_THRESHOLD
                else "credential-like assignment")
        # Include a preview so the secret can be identified and rotated; redacted
        # unless --reveal-secrets was passed.
        reason = f"{kind} for '{m.group(1)}' = {_redact(value, reveal)}"
        findings.append((f"{source}:{lineno}", reason, belief.confidence()))
    return findings


@check(
    id="EXT-CRED-1",
    title="Scan group/world-readable files for embedded secrets",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A password or API key in a file any user can read is a credential available to every account on the host.",
    remediation="Move secrets to a vault or env-injection, restrict file permissions, and rotate exposed credentials.",
    tags=("credentials", "secrets", "entropy"),
)
def readable_secrets(ctx):
    # Only files readable by group or other are interesting here (perm bits 0o044).
    dirs = " ".join(d for d in _CONFIG_DIRS if ctx.file_exists(d))
    if not dirs:
        return Outcome.skip("No standard config directories present to scan")
    listing = ctx.sh(
        f"find {dirs} -type f -perm /0044 "
        r"\( -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.yml' "
        r"-o -name '*.yaml' -o -name '*.env' -o -name '*.properties' -o -name '*.json' \) "
        "2>/dev/null | head -400",
        timeout=60,
    )
    files = listing.lines()
    findings: List[str] = []
    confidence = Confidence.POSSIBLE
    for path in files:
        content = ctx.read_file(path, max_bytes=256_000)
        if not content:
            continue
        for loc, reason, conf in _scan_text_for_secrets(content, path, reveal=ctx.reveal_secrets):
            findings.append(f"{loc} — {reason}")
            confidence = max(confidence, conf)
        if len(findings) >= 50:
            break
    if not findings:
        return Outcome.passed(f"No embedded secrets detected in {len(files)} readable config file(s)")
    return Outcome.failed(
        f"Potential secrets in {len(findings)} location(s) within readable files",
        evidence=findings[:30],
        actual=len(findings),
        confidence=confidence,
    )


@check(
    id="EXT-CRED-2",
    title="Ensure private keys are encrypted and not world/group readable",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="An unencrypted private key readable beyond its owner is a directly usable identity for any local user.",
    remediation="chmod 600 private keys; passphrase-protect them; store under the owner's ~/.ssh only.",
    tags=("credentials", "ssh", "keys"),
)
def private_key_exposure(ctx):
    roots = _quoted_roots(_home_dirs(ctx) + ["/etc/ssl/private", "/etc/ssh"])
    listing = ctx.sh(
        f"find {roots} -type f "
        r"\( -name 'id_*' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null | head -200",
        timeout=45,
    )
    offenders: List[str] = []
    for path in listing.lines():
        if path.endswith(".pub"):
            continue
        st = ctx.stat(path)
        if not st.exists:
            continue
        problems = []
        if st.mode & 0o077:  # any group/other access
            problems.append(f"mode {st.mode_str}")
        head = ctx.read_file(path, max_bytes=200) or ""
        # An unencrypted PEM key lacks the "ENCRYPTED"/Proc-Type markers.
        if "PRIVATE KEY" in head and "ENCRYPTED" not in head and "Proc-Type" not in head:
            problems.append("unencrypted")
        if problems:
            offenders.append(f"{path} ({', '.join(problems)})")
    if not offenders:
        return Outcome.passed("No exposed or unencrypted private keys found")
    return Outcome.failed(
        f"{len(offenders)} private key(s) exposed or unencrypted",
        evidence=offenders[:25],
        actual=offenders[:25],
        confidence=Confidence.CERTAIN,
    )


@check(
    id="EXT-CRED-3",
    title="Scan shell history for leaked credentials",
    section="EXT.Credentials",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Passwords typed on the command line (mysql -p<pass>, curl -u user:pass) persist in history files readable by the account.",
    remediation="Remove the offending lines, rotate the credentials, and prefer interactive prompts or secret files.",
    tags=("credentials", "history"),
)
def history_credentials(ctx):
    roots = _quoted_roots(_home_dirs(ctx))
    listing = ctx.sh(f"find {roots} -maxdepth 3 -name '.*_history' 2>/dev/null | head -200")
    offenders: List[str] = []
    for path in listing.lines():
        content = ctx.read_file(path, max_bytes=512_000)
        if not content:
            continue
        for lineno, line in enumerate(content.splitlines(), start=1):
            match = _find_cmd_secret(line)
            if match:
                # Lead with the matched secret (redacted unless --reveal-secrets)
                # so it's obvious what fired, then a little command context (with
                # the same value masked so the secret isn't echoed twice in clear).
                offenders.append(f"{path}:{lineno}: {_cmd_evidence(line, match, ctx.reveal_secrets)}")
                if len(offenders) >= 50:
                    break
    if not offenders:
        return Outcome.passed("No credentials detected in shell history files")
    return Outcome.failed(
        f"Possible credentials in {len(offenders)} shell-history location(s)",
        evidence=offenders[:25],
        actual=len(offenders),
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-CRED-4",
    title="Scan live process environments for exposed credentials",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "Reading /proc/<pid>/environ exposes secrets passed to running processes as environment variables — "
        "the same in-memory credential exposure mimipenguin targets, captured from the kernel-exposed "
        "environment region. Requires root."
    ),
    remediation="Inject secrets via files or a secrets manager, never via environment variables on long-lived processes.",
    tags=("credentials", "memory", "proc", "mimipenguin"),
)
def process_environment_secrets(ctx):
    if ctx.platform.family == "unknown" and not ctx.file_exists("/proc"):
        return Outcome.skip("No /proc filesystem; live environment scan not applicable")
    if not ctx.is_root:
        return Outcome.manual("Root required to read other processes' /proc/<pid>/environ")
    # Walk PIDs; environ entries are NUL-separated. We translate them to lines
    # and reuse the same secret detector used for files.
    pids = ctx.sh("ls /proc | grep -E '^[0-9]+$' | head -800").lines()
    findings: List[str] = []
    for pid in pids:
        raw = ctx.sh(f"tr '\\0' '\\n' < /proc/{pid}/environ 2>/dev/null", timeout=10).stdout
        if not raw:
            continue
        comm = (ctx.read_file(f"/proc/{pid}/comm", max_bytes=64) or "").strip()
        for loc, reason, _conf in _scan_text_for_secrets(raw, f"pid {pid} ({comm})", reveal=ctx.reveal_secrets):
            findings.append(f"{loc} — {reason}")
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed(f"No exposed credentials found in {len(pids)} process environment(s)")
    return Outcome.failed(
        f"Credentials exposed in {len(findings)} process-environment location(s)",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.LIKELY,
    )


@check(
    id="EXT-CRED-5",
    title="Ensure credential stores (.netrc, .pgpass, cloud creds) are protected",
    section="EXT.Credentials",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=".netrc/.pgpass and cloud credential files hold plaintext logins; group/world access turns them into shared secrets.",
    remediation="chmod 600 these files; better, migrate to short-lived credentials.",
    tags=("credentials", "files"),
)
def credential_store_exposure(ctx):
    roots = _quoted_roots(_home_dirs(ctx))
    listing = ctx.sh(
        f"find {roots} -maxdepth 4 \\( -name '.netrc' -o -name '.pgpass' "
        r"-o -path '*/.aws/credentials' -o -path '*/.docker/config.json' "
        r"-o -path '*/.kube/config' \) 2>/dev/null | head -100"
    )
    offenders: List[str] = []
    for path in listing.lines():
        st = ctx.stat(path)
        if st.exists and (st.mode & 0o077):
            offenders.append(f"{path} (mode {st.mode_str})")
    if not offenders:
        return Outcome.passed("No exposed credential-store files found")
    return Outcome.failed(
        f"{len(offenders)} credential-store file(s) accessible beyond owner",
        evidence=offenders,
        actual=offenders,
    )


# --------------------------------------------------------------------------- #
# 6. Filename-heuristic secret sweep — catch credential files by NAME, not an
#    extension allowlist. This is what EXT-CRED-1/5 structurally miss: a file
#    literally called `.rdp_pass`, `creds.txt`, or `vpn.ovpn` has no recognised
#    extension and is not on the credential-store allowlist, so its content is
#    never read. Here we match by secret-y name AND scan content.
# --------------------------------------------------------------------------- #

# Glob names that, by themselves, strongly suggest a credential lives in the
# file. Bounded and ordered toward precision so the sweep stays cheap.
_SECRET_FILE_NAMES = (
    "*pass*", "*secret*", "*cred*", "*token*", "*.key", "*.pem", "*.ppk",
    "*.ovpn", "*.kdbx", "*.keytab", ".env", ".env.*", "*.env",
    ".rdp_pass", ".my.cnf", ".git-credentials", ".npmrc", ".s3cfg",
)


def _name_predicate(names: Sequence[str]) -> str:
    """Build a ``find`` ``\\( -name a -o -name b ... \\)`` predicate."""
    return " -o ".join(f"-name {shlex.quote(n)}" for n in names)


@check(
    id="EXT-CRED-6",
    title="Hunt for secret-bearing files by name (vpn/rdp/key/token/.env)",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "Credential files are named for what they hold — .rdp_pass, vpn.ovpn, prod.kdbx, .env, "
        "service.keytab — not for a tidy extension. An allowlist of known names/extensions silently "
        "misses these. Matching on the name and then scanning the content catches the password file "
        "an attacker would grep for in seconds."),
    remediation="Move the secret into a vault or env-injection, restrict the file to its owner (chmod 600), and rotate it.",
    tags=("credentials", "secrets", "files"),
    attack=("T1552.001",),
)
def secret_files_by_name(ctx):
    roots = _quoted_roots([d for d in _CONFIG_DIRS if ctx.file_exists(d)] + _home_dirs(ctx))
    listing = ctx.sh(
        f"find {roots} -maxdepth 6 -type f \\( {_name_predicate(_SECRET_FILE_NAMES)} \\) "
        "2>/dev/null | head -300",
        timeout=60,
    )
    findings: List[str] = []
    confidence = Confidence.POSSIBLE
    for path in listing.lines():
        if path.endswith(".pub"):
            continue
        st = ctx.stat(path)
        readable_by_others = st.exists and bool(st.mode & 0o044)
        content = ctx.read_file(path, max_bytes=256_000) or ""
        secret_hits = _scan_text_for_secrets(content, path, reveal=ctx.reveal_secrets) if content else []
        if secret_hits:
            for loc, reason, conf in secret_hits:
                findings.append(f"{loc} — {reason}")
                confidence = max(confidence, conf)
        elif readable_by_others:
            # No parsed secret, but a file *named* like a credential that any
            # account can read is itself worth surfacing for review.
            findings.append(f"{path} — credential-named file readable beyond owner (mode {st.mode_str})")
            confidence = max(confidence, Confidence.POSSIBLE)
        if len(findings) >= 50:
            break
    if not findings:
        return Outcome.passed(f"No secret-bearing files found among {len(listing.lines())} credential-named file(s)")
    return Outcome.failed(
        f"Potential secrets in {len(findings)} credential-named file(s)",
        evidence=findings[:30],
        actual=len(findings),
        confidence=confidence,
    )


# --------------------------------------------------------------------------- #
# 7. Live process command lines — the `ps aux` half of process secret exposure
#    (EXT-CRED-4 already covers the environment / `ps auxe` half).
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-7",
    title="Scan live process command lines for exposed credentials",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "A daemon started as 'mysql -psecret', 'curl -u user:pass', or '--token=…' exposes that "
        "credential in /proc/<pid>/cmdline, which on most systems is world-readable. EXT-CRED-4 reads "
        "the process *environment*; this reads the *command line* — together they cover everything "
        "'ps auxe' would reveal, without the truncation."),
    remediation="Pass secrets via a file, stdin, or a secrets manager — never as a command-line argument on a long-lived process.",
    tags=("credentials", "proc", "memory"),
    attack=("T1552.001", "T1057"),
)
def process_cmdline_secrets(ctx):
    if not ctx.file_exists("/proc"):
        return Outcome.skip("No /proc filesystem; live command-line scan not applicable")
    pids = ctx.sh("ls /proc | grep -E '^[0-9]+$' | head -800").lines()
    findings: List[str] = []
    for pid in pids:
        raw = ctx.sh(f"tr '\\0' ' ' < /proc/{pid}/cmdline 2>/dev/null", timeout=10).stdout
        if not raw or not raw.strip():
            continue
        match = _find_cmd_secret(raw)
        if not match:
            continue
        comm = (ctx.read_file(f"/proc/{pid}/comm", max_bytes=64) or "").strip()
        findings.append(f"pid {pid} ({comm}): {_cmd_evidence(raw, match, ctx.reveal_secrets)}")
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed(f"No credentials found on the command line of {len(pids)} process(es)")
    return Outcome.failed(
        f"Credentials on the command line of {len(findings)} process(es)",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.LIKELY,
    )


# --------------------------------------------------------------------------- #
# 8. dotenv files — the single most common application secret leak.
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-8",
    title="Detect readable .env / dotenv application secrets",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=".env files hold database URLs, API keys, and signing secrets in plaintext; deployed under a web root or readable by other accounts they are a direct credential leak.",
    remediation="Restrict .env to the app user (chmod 600), keep it out of the web root, and rotate anything exposed.",
    tags=("credentials", "secrets", "files"),
    attack=("T1552.001",),
)
def dotenv_secrets(ctx):
    roots = _quoted_roots(["/opt", "/srv", "/var/www"] + [h for h in _home_dirs(ctx) if h != "/root"])
    listing = ctx.sh(
        f"find {roots} -maxdepth 6 -type f \\( -name '.env' -o -name '.env.*' -o -name '*.env' \\) "
        "2>/dev/null | head -200",
        timeout=45,
    )
    findings: List[str] = []
    confidence = Confidence.POSSIBLE
    for path in listing.lines():
        st = ctx.stat(path)
        content = ctx.read_file(path, max_bytes=128_000) or ""
        hits = _scan_text_for_secrets(content, path, reveal=ctx.reveal_secrets) if content else []
        if hits:
            for loc, reason, conf in hits:
                findings.append(f"{loc} — {reason}")
                confidence = max(confidence, conf)
        elif st.exists and (st.mode & 0o044):
            findings.append(f"{path} — dotenv readable beyond owner (mode {st.mode_str})")
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed("No exposed dotenv secrets found")
    return Outcome.failed(
        f"Potential secrets in {len(findings)} dotenv location(s)",
        evidence=findings[:25],
        actual=len(findings),
        confidence=confidence,
    )


# --------------------------------------------------------------------------- #
# 9. Secrets baked into cron jobs and systemd units.
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-9",
    title="Detect credentials embedded in cron jobs and systemd units",
    section="EXT.Credentials",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Cron lines and unit Environment=/ExecStart= directives that carry a password or token expose it to anyone who can read the (often world-readable) job or unit file, and it persists across reboots.",
    remediation="Move secrets to a root-only EnvironmentFile= or a secrets manager; never inline them in a unit or crontab.",
    tags=("credentials", "secrets", "cron"),
    attack=("T1552.001",),
)
def scheduled_job_secrets(ctx):
    paths: List[str] = []
    for f in ("/etc/crontab",):
        if ctx.file_exists(f):
            paths.append(f)
    for pattern in ("/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
                    "/var/spool/cron/crontabs/*", "/etc/systemd/system/*.service",
                    "/lib/systemd/system/*.service"):
        paths.extend(ctx.glob(pattern))
    findings: List[str] = []
    confidence = Confidence.POSSIBLE
    seen = set()
    for path in paths[:400]:
        if path in seen:
            continue
        seen.add(path)
        content = ctx.read_file(path, max_bytes=128_000)
        if not content:
            continue
        for loc, reason, conf in _scan_text_for_secrets(content, path, reveal=ctx.reveal_secrets):
            findings.append(f"{loc} — {reason}")
            confidence = max(confidence, conf)
        for lineno, line in enumerate(content.splitlines(), start=1):
            match = _find_cmd_secret(line)
            if match:
                findings.append(f"{path}:{lineno}: {_cmd_evidence(line, match, ctx.reveal_secrets)}")
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed("No credentials embedded in cron jobs or systemd units")
    return Outcome.failed(
        f"Credentials in {len(findings)} cron/unit location(s)",
        evidence=findings[:25],
        actual=len(findings),
        confidence=confidence,
    )


# --------------------------------------------------------------------------- #
# 10. Web-application config secrets (wp-config.php, settings.py, …).
# --------------------------------------------------------------------------- #

_WEBAPP_CONFIG_NAMES = (
    "wp-config.php", "config.php", "configuration.php", "settings.php",
    "application.properties", "application.yml", "appsettings.json",
    "settings.py", "local_settings.py", "database.yml", "secrets.yml",
)


@check(
    id="EXT-CRED-10",
    title="Detect secrets in web-application configuration files",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Framework config files (wp-config.php, Django settings.py, Spring application.properties) hold DB passwords and signing keys; under a web root a path-traversal or source-disclosure bug turns them into a credential leak.",
    remediation="Keep config out of the served directory, restrict permissions, and load secrets from the environment or a vault.",
    tags=("credentials", "secrets", "files"),
    attack=("T1552.001",),
)
def webapp_config_secrets(ctx):
    roots = _quoted_roots([d for d in ("/var/www", "/srv", "/opt") if ctx.file_exists(d)])
    if roots == "/root":
        return Outcome.skip("No web/application roots present to scan")
    listing = ctx.sh(
        f"find {roots} -maxdepth 8 -type f \\( {_name_predicate(_WEBAPP_CONFIG_NAMES)} \\) "
        "2>/dev/null | head -200",
        timeout=45,
    )
    findings: List[str] = []
    confidence = Confidence.POSSIBLE
    for path in listing.lines():
        content = ctx.read_file(path, max_bytes=256_000)
        if not content:
            continue
        for loc, reason, conf in _scan_text_for_secrets(content, path, reveal=ctx.reveal_secrets):
            findings.append(f"{loc} — {reason}")
            confidence = max(confidence, conf)
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed("No secrets detected in web-application config files")
    return Outcome.failed(
        f"Potential secrets in {len(findings)} web-app config location(s)",
        evidence=findings[:25],
        actual=len(findings),
        confidence=confidence,
    )


# --------------------------------------------------------------------------- #
# 11. Git credential leaks (.git-credentials, tokens in .git/config).
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-11",
    title="Detect git credential leaks (.git-credentials, tokens in config)",
    section="EXT.Credentials",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="git's store helper writes plaintext 'https://user:token@host' lines to ~/.git-credentials, and remote URLs in .git/config can embed tokens — both are reusable credentials sitting on disk.",
    remediation="Use a credential helper that does not persist plaintext (libsecret/osxkeychain), purge ~/.git-credentials, and rotate the token.",
    tags=("credentials", "secrets", "files"),
    attack=("T1552.001",),
)
def git_credential_leaks(ctx):
    roots = _quoted_roots(_home_dirs(ctx) + [d for d in ("/var/www", "/srv", "/opt") if ctx.file_exists(d)])
    listing = ctx.sh(
        f"find {roots} -maxdepth 8 \\( -name '.git-credentials' -o -path '*/.git/config' \\) "
        "2>/dev/null | head -200",
        timeout=45,
    )
    findings: List[str] = []
    cred_url_re = re.compile(r"://[^:@/\s]+:[^@/\s]+@")
    for path in listing.lines():
        content = ctx.read_file(path, max_bytes=128_000)
        if not content:
            continue
        for lineno, line in enumerate(content.splitlines(), start=1):
            if cred_url_re.search(line):
                snippet = line.strip()
                if not ctx.reveal_secrets:
                    snippet = cred_url_re.sub("://…:…@", snippet)
                findings.append(f"{path}:{lineno} — embedded credential in URL: {snippet[:160]}")
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed("No git credential leaks found")
    return Outcome.failed(
        f"Git credentials exposed in {len(findings)} location(s)",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.LIKELY,
    )


# --------------------------------------------------------------------------- #
# 12. Config backup/swap files left behind with secrets.
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-12",
    title="Detect secret-bearing backup/swap files (*.bak, *~, .*.swp)",
    section="EXT.Credentials",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="An editor backup or .swp of a sensitive config (config.php.bak, .env~, .htpasswd.swp) keeps the secret around under a name no server protects, and is a classic source-disclosure target.",
    remediation="Delete stray backup/swap files, and configure editors not to write them under served or shared directories.",
    tags=("credentials", "secrets", "files"),
    attack=("T1552",),
)
def backup_file_secrets(ctx):
    roots = _quoted_roots([d for d in _CONFIG_DIRS if ctx.file_exists(d)])
    listing = ctx.sh(
        f"find {roots} -maxdepth 8 -type f \\( -name '*.bak' -o -name '*~' -o -name '*.old' "
        "-o -name '*.orig' -o -name '*.save' -o -name '.*.swp' \\) 2>/dev/null | head -300",
        timeout=45,
    )
    findings: List[str] = []
    confidence = Confidence.POSSIBLE
    for path in listing.lines():
        content = ctx.read_file(path, max_bytes=128_000)
        if not content:
            continue
        for loc, reason, conf in _scan_text_for_secrets(content, path, reveal=ctx.reveal_secrets):
            findings.append(f"{loc} — {reason}")
            confidence = max(confidence, conf)
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed("No secrets found in backup/swap files")
    return Outcome.failed(
        f"Potential secrets in {len(findings)} backup/swap file(s)",
        evidence=findings[:25],
        actual=len(findings),
        confidence=confidence,
    )


# --------------------------------------------------------------------------- #
# 13. Kerberos keytabs / credential caches exposed beyond owner.
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-13",
    title="Ensure Kerberos keytabs and credential caches are protected",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="A keytab is a long-lived service credential and a ccache (/tmp/krb5cc_*) is a live ticket; readable beyond its owner, either lets another local user impersonate the principal.",
    remediation="Restrict keytabs and ccaches to mode 600 owned by the service principal; rotate any that were exposed.",
    tags=("credentials", "keys", "files"),
    attack=("T1558", "T1552"),
)
def kerberos_credential_exposure(ctx):
    roots = _quoted_roots([d for d in ("/etc", "/var/lib", "/opt", "/tmp") if ctx.file_exists(d)] + _home_dirs(ctx))
    listing = ctx.sh(
        f"find {roots} -maxdepth 6 -type f \\( -name '*.keytab' -o -name 'krb5cc_*' \\) "
        "2>/dev/null | head -200",
        timeout=45,
    )
    offenders: List[str] = []
    for path in listing.lines():
        st = ctx.stat(path)
        if st.exists and (st.mode & 0o077):
            offenders.append(f"{path} (mode {st.mode_str})")
    if not offenders:
        return Outcome.passed("No exposed Kerberos keytabs or credential caches found")
    return Outcome.failed(
        f"{len(offenders)} Kerberos credential file(s) accessible beyond owner",
        evidence=offenders[:25],
        actual=offenders[:25],
        confidence=Confidence.CERTAIN,
    )


# --------------------------------------------------------------------------- #
# 14. authorized_keys anomalies — unexpected/unrestricted SSH trust.
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-14",
    title="Review SSH authorized_keys for risky or writable trust",
    section="EXT.Credentials",
    severity=Severity.MEDIUM,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "authorized_keys is standing remote access. A key on root, a service account trusting an "
        "unrestricted key (no from=/command=), or a group/world-writable authorized_keys (anyone can "
        "append their own key) are all persistence and lateral-movement footholds."),
    remediation="Remove unexpected keys, scope service-account keys with from=/command= restrictions, and chmod 600 the file.",
    tags=("credentials", "ssh", "keys", "persistence"),
    attack=("T1098.004",),
)
def authorized_keys_anomalies(ctx):
    homes = _home_dirs(ctx)
    findings: List[str] = []
    for home in homes:
        for name in ("authorized_keys", "authorized_keys2"):
            path = f"{home}/.ssh/{name}"
            content = ctx.read_file(path, max_bytes=128_000)
            if content is None:
                continue
            st = ctx.stat(path)
            if st.exists and (st.mode & 0o022):
                findings.append(f"{path} is writable beyond owner (mode {st.mode_str}) — anyone can add a trusted key")
            keys = [l for l in content.splitlines() if l.strip() and not l.lstrip().startswith("#")]
            if home == "/root" and keys:
                findings.append(f"{path}: {len(keys)} key(s) grant direct root SSH access")
            for line in keys:
                # A bare key line (starts with a key type) has no from=/command= restriction.
                if re.match(r"^(ssh-(rsa|ed25519|dss)|ecdsa-)", line.strip()):
                    findings.append(f"{path}: unrestricted key (no from=/command=): {line.strip()[:60]}…")
                    break
    if not findings:
        return Outcome.passed("No risky authorized_keys entries found")
    return Outcome.warn(
        f"{len(findings)} authorized_keys finding(s) to review",
        evidence=findings[:25],
        actual=len(findings),
        confidence=Confidence.LIKELY,
    )


# --------------------------------------------------------------------------- #
# 15. Cloud / IaC credential files (gcloud, azure, terraform state, s3cfg).
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-15",
    title="Detect exposed cloud / IaC credentials (gcloud, azure, tfstate)",
    section="EXT.Credentials",
    severity=Severity.HIGH,
    levels=(Level.L1,),
    framework=EXTENDED_FRAMEWORK,
    rationale="Cloud SDK token caches, .s3cfg, and especially terraform state files routinely contain long-lived access keys and even resource secrets in plaintext; readable beyond owner they hand over the cloud account.",
    remediation="Restrict these files to their owner, store terraform state in an encrypted remote backend, and rotate exposed keys.",
    tags=("credentials", "secrets", "files"),
    attack=("T1552.001",),
)
def cloud_credential_exposure(ctx):
    roots = _quoted_roots(_home_dirs(ctx) + [d for d in ("/opt", "/srv") if ctx.file_exists(d)])
    listing = ctx.sh(
        f"find {roots} -maxdepth 7 -type f \\( "
        "-path '*/.config/gcloud/*credentials*' -o -path '*/.config/gcloud/access_tokens.db' "
        "-o -path '*/.azure/*' -o -name '*.tfstate' -o -name '*.tfstate.backup' -o -name '.s3cfg' \\) "
        "2>/dev/null | head -200",
        timeout=45,
    )
    findings: List[str] = []
    confidence = Confidence.POSSIBLE
    for path in listing.lines():
        st = ctx.stat(path)
        exposed = st.exists and (st.mode & 0o044)
        content = ctx.read_file(path, max_bytes=256_000) or ""
        hits = _scan_text_for_secrets(content, path, reveal=ctx.reveal_secrets) if content else []
        if hits:
            for loc, reason, conf in hits:
                findings.append(f"{loc} — {reason}")
                confidence = max(confidence, conf)
        elif exposed:
            findings.append(f"{path} — cloud credential file readable beyond owner (mode {st.mode_str})")
        if len(findings) >= 40:
            break
    if not findings:
        return Outcome.passed("No exposed cloud/IaC credential files found")
    return Outcome.failed(
        f"Potential cloud credentials in {len(findings)} location(s)",
        evidence=findings[:25],
        actual=len(findings),
        confidence=confidence,
    )
