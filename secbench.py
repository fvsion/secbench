#!/usr/bin/env python3
"""Standalone launcher for Linux SecBench.

Lets the tool be copied to a target host and run as a single ``./secbench.py``
without installation, as long as the ``linux_secbench`` package sits beside it.
For development, ``python3 -m linux_secbench`` works identically.
"""

from __future__ import annotations

import os
import sys

# Ensure the package directory is importable even when invoked by absolute path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from linux_secbench.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
