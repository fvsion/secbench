"""CIS Ubuntu Linux 24.04 LTS Benchmark checks, organized by section.

Modules map one-to-one onto the benchmark's top-level sections so an auditor
reading the official PDF can find the implementing code by number:

    section1_initial_setup    1  Initial Setup
    section2_services         2  Services
    section3_network          3  Network
    section4_firewall         4  Host Based Firewall
    section5_access           5  Access, Authentication and Authorization
    section6_logging          6  Logging and Auditing
    section7_maintenance      7  System Maintenance

Coverage is a curated, high-signal subset of the ~250 controls rather than a
1:1 transcription — the controls that most move the security needle and that
can be assessed deterministically. The framework imposes no cap; new controls
drop into the matching module and register automatically.
"""

from __future__ import annotations
