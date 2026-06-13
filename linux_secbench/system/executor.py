"""Command execution backends.

Every check reaches the system through an :class:`Executor`. There are two
concrete backends — local subprocess and SSH — behind one interface, which is
the whole reason a scan can target the machine it runs on or a remote server
without any check knowing the difference.

Design choices that matter:

* Commands are passed as **argument lists**, never shell strings, and run with
  ``shell=False`` locally. Where a pipeline is genuinely needed a check can opt
  into ``shell=True``, but the default closes off the most common command
  -injection footgun.
* Every call is bounded by a timeout. A hung ``find /`` on a huge filesystem
  must not wedge an entire scan, so a timeout returns a distinct, inspectable
  result rather than blocking forever.
* Nothing here raises on a non-zero exit. Checks routinely run commands that
  *expect* to fail (``systemctl is-enabled`` on an absent unit); the result
  object carries the returncode and the check decides what it means.
"""

from __future__ import annotations

import abc
import dataclasses
import os
import shlex
import subprocess
from typing import List, Optional, Sequence, Union

CommandSpec = Union[str, Sequence[str]]

DEFAULT_TIMEOUT = 30.0


@dataclasses.dataclass
class CommandResult:
    """The captured result of one command invocation."""

    argv: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: Optional[str] = None  # transport-level failure (e.g. ssh unreachable)

    @property
    def ok(self) -> bool:
        """Exit code 0 and no transport/timeout failure."""
        return self.returncode == 0 and not self.timed_out and self.error is None

    @property
    def out(self) -> str:
        """stdout with trailing whitespace stripped — the common case."""
        return self.stdout.strip()

    def lines(self) -> List[str]:
        """Non-empty stdout lines, stripped."""
        return [ln.strip() for ln in self.stdout.splitlines() if ln.strip()]

    @property
    def combined(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


def _normalize(command: CommandSpec, shell: bool) -> List[str]:
    if isinstance(command, str):
        return [command] if shell else shlex.split(command)
    return list(command)


class Executor(abc.ABC):
    """Abstract command runner. Subclasses implement the transport only."""

    #: Human-readable host identity used to label results.
    host: str = "localhost"
    #: Whether commands run with effective root on the target.
    is_root: bool = False

    @abc.abstractmethod
    def run(
        self,
        command: CommandSpec,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        shell: bool = False,
        input_text: Optional[str] = None,
    ) -> CommandResult:
        ...

    def which(self, program: str) -> Optional[str]:
        """Resolve a program on the target's PATH, or None if absent."""
        res = self.run(["sh", "-c", f"command -v {shlex.quote(program)} 2>/dev/null"], timeout=10)
        return res.out or None

    def read_file(self, path: str, *, max_bytes: int = 2_000_000) -> Optional[str]:
        """Read a text file from the target, or None if it cannot be read.

        Bounded so a check that names a pathologically large file (a runaway
        log) cannot blow up memory. Implemented via the same transport as
        commands so it works identically over SSH.
        """
        res = self.run(["head", "-c", str(max_bytes), path], timeout=20)
        if not res.ok:
            return None
        return res.stdout


class LocalExecutor(Executor):
    """Runs commands on the machine the tool is executing on."""

    def __init__(self) -> None:
        self.host = _local_hostname()
        self.is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def run(
        self,
        command: CommandSpec,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        shell: bool = False,
        input_text: Optional[str] = None,
    ) -> CommandResult:
        argv = _normalize(command, shell)
        try:
            proc = subprocess.run(
                " ".join(argv) if shell else argv,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_text,
                errors="replace",
            )
            return CommandResult(
                argv=argv,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                argv=argv,
                returncode=124,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr),
                timed_out=True,
                error=f"timed out after {timeout}s",
            )
        except FileNotFoundError as exc:
            return CommandResult(argv=argv, returncode=127, error=str(exc))
        except OSError as exc:  # pragma: no cover - defensive
            return CommandResult(argv=argv, returncode=126, error=str(exc))


class SSHExecutor(Executor):
    """Runs commands on a remote host over SSH.

    Intentionally thin: it shells out to the system ``ssh`` client rather than
    pulling in a dependency like paramiko, so it inherits the operator's
    existing SSH config, agent, jump hosts and known_hosts. Authentication is
    expected to be non-interactive (keys/agent); ``BatchMode=yes`` makes a
    missing key fail fast with a clear transport error instead of hanging on a
    password prompt.
    """

    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        identity: Optional[str] = None,
        use_sudo: bool = False,
        connect_timeout: int = 10,
        extra_opts: Optional[Sequence[str]] = None,
    ) -> None:
        self.target_host = host
        self.user = user
        self.port = port
        self.identity = identity
        self.use_sudo = use_sudo
        self.connect_timeout = connect_timeout
        self.extra_opts = list(extra_opts or [])
        self.host = f"{user}@{host}" if user else host
        # Determined lazily on first probe so construction never blocks.
        self.is_root = False

    def _ssh_prefix(self) -> List[str]:
        argv = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-p", str(self.port),
        ]
        if self.identity:
            argv += ["-i", self.identity]
        argv += self.extra_opts
        argv.append(self.host)
        return argv

    def run(
        self,
        command: CommandSpec,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        shell: bool = False,
        input_text: Optional[str] = None,
    ) -> CommandResult:
        argv = _normalize(command, shell)
        # Build the remote command line, quoting each argument so it survives
        # the trip through the remote shell exactly as intended.
        remote = " ".join(shlex.quote(a) for a in argv) if not shell else " ".join(argv)
        if self.use_sudo:
            remote = f"sudo -n sh -c {shlex.quote(remote)}"
        full = self._ssh_prefix() + [remote]
        try:
            proc = subprocess.run(
                full,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_text,
                errors="replace",
            )
            # ssh returns 255 specifically for its own connection failures.
            if proc.returncode == 255 and "Permission denied" not in proc.stderr:
                return CommandResult(
                    argv=argv,
                    returncode=255,
                    stderr=proc.stderr or "",
                    error="ssh transport failure (unreachable, auth, or host key)",
                )
            return CommandResult(
                argv=argv,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                argv=argv,
                returncode=124,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr),
                timed_out=True,
                error=f"timed out after {timeout}s",
            )
        except OSError as exc:  # ssh binary missing, etc.
            return CommandResult(argv=argv, returncode=126, error=str(exc))

    def probe(self) -> CommandResult:
        """Verify connectivity and detect effective root on the remote host."""
        res = self.run(["id", "-u"], timeout=self.connect_timeout + 5)
        if res.ok:
            self.is_root = res.out == "0"
        return res


def build_executor(
    host: Optional[str] = None,
    *,
    user: Optional[str] = None,
    port: int = 22,
    identity: Optional[str] = None,
    use_sudo: bool = False,
) -> Executor:
    """Factory: a local executor when no host is given, else an SSH one.

    The single entry point the CLI uses so the local/remote decision lives in
    exactly one place.
    """
    if host is None or host in ("localhost", "127.0.0.1", "::1"):
        return LocalExecutor()
    return SSHExecutor(host, user=user, port=port, identity=identity, use_sudo=use_sudo)


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _local_hostname() -> str:
    try:
        import socket

        return socket.gethostname()
    except Exception:  # pragma: no cover - defensive
        return "localhost"
