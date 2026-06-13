"""Linux SecBench — a modular Linux security & CIS-Benchmark assessment engine.

Primary target: Ubuntu 24.04 LTS (CIS Benchmark v1.0.0, Levels 1 & 2,
Server & Workstation profiles). Designed to extend cleanly to other Linux
families via the distro-adapter layer in :mod:`linux_secbench.system.platform`.

The package is deliberately layered:

    core/         Framework primitives: the data model, the Check abstraction,
                  the registry, and the orchestrating runner. Knows nothing
                  about any specific check or OS.
    system/       Everything that touches a real machine: command execution
                  (local or over SSH), platform detection, and a caching
                  SystemContext that checks query instead of shelling out
                  themselves.
    checks/       The check content. `cis/` mirrors the benchmark's section
                  layout; `extended/` holds the beyond-CIS security audits.
    analysis/     Risk scoring and cross-domain statistics (entropy, robust
                  outlier detection, EWMA trend tracking, Pareto priorit
                  -ization).
    reporting/    Renderers: rich terminal, self-contained HTML, JSON, CSV,
                  and Markdown.
    persistence/  The scan store that makes scans resumable and rescannable
                  and feeds the trend analysis.

Nothing in this top-level module imports the heavy submodules, so
`import linux_secbench` stays cheap.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
