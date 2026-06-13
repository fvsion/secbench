"""The system-access layer: execution, platform detection, and context."""

from __future__ import annotations

from .executor import CommandResult, Executor, LocalExecutor, SSHExecutor, build_executor
from .platform import PlatformInfo, detect_platform
from .context import SystemContext, StatInfo

__all__ = [
    "CommandResult",
    "Executor",
    "LocalExecutor",
    "SSHExecutor",
    "build_executor",
    "PlatformInfo",
    "detect_platform",
    "SystemContext",
    "StatInfo",
]
