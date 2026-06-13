"""Extended, beyond-CIS security audits.

These checks carry ``framework="Security"`` so the runner and reports can show
them separately from formal CIS compliance. They cover the questions a real
security assessment asks that the benchmark does not fully address: who can
become root, where credentials are leaking, what is unexpectedly setuid or
listening, and which accounts look anomalous.

Like the CIS modules they self-register on import via ``@check`` and are picked
up by the registry's auto-discovery.
"""

from __future__ import annotations

#: Framework label all extended checks use, so reporting can group them.
EXTENDED_FRAMEWORK = "Security"
