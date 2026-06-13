"""Check content packages.

``cis/`` mirrors the CIS Ubuntu 24.04 benchmark's seven-section layout;
``extended/`` holds the beyond-CIS security audits. Both are auto-discovered by
the registry at startup, so adding a check is just adding a function to the
right module — there is no registration list to maintain.

The two package paths the runner discovers are exported here for convenience.
"""

from __future__ import annotations

CHECK_PACKAGES = (
    "linux_secbench.checks.cis",
    "linux_secbench.checks.extended",
)

__all__ = ["CHECK_PACKAGES"]
