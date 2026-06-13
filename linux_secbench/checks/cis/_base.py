"""Shared decorator for the CIS benchmark check modules.

Every check under ``checks/cis/`` is part of the **CIS Ubuntu 24.04** benchmark,
so its platform applicability defaults to the ``ubuntu:24.04`` edition — it then
auto-skips on a RHEL or Debian host (which get their own benchmark modules) via
the distro/version gate in :func:`core.check.Check.applies_to`.

Use ``cis_check`` exactly like the core ``@check``; pass ``platforms=...`` to
override (e.g. a control that also applies to an older Ubuntu edition).
"""

from __future__ import annotations

import functools

from ...core import check as _core_check

#: The benchmark edition these modules implement. Bump/extend when a new Ubuntu
#: CIS edition is added (e.g. a future ``ubuntu:26.04`` module).
UBUNTU_EDITION = ("ubuntu:24.04",)

cis_check = functools.partial(_core_check, platforms=UBUNTU_EDITION)
