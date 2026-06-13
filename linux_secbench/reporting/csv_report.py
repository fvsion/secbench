"""Flat per-control CSV — one row per check, for spreadsheets and auditors."""

from __future__ import annotations

import csv
import io

from .base import ReportBundle, Reporter


class CsvReporter(Reporter):
    extension = "csv"

    _COLUMNS = [
        "id", "title", "framework", "section", "status", "severity",
        "confidence", "risk_score", "summary", "remediation", "host",
    ]

    def render(self, bundle: ReportBundle) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=self._COLUMNS, extrasaction="ignore")
        writer.writeheader()
        # Emit in ranked order so the most important findings sit at the top,
        # followed by the remaining (non-finding) controls for completeness.
        ranked = list(bundle.ranked)
        ranked_ids = {id(r) for r in ranked}
        rest = [r for r in bundle.scan.results if id(r) not in ranked_ids]
        for r in ranked + rest:
            writer.writerow({
                "id": r.id,
                "title": r.metadata.title,
                "framework": r.metadata.framework,
                "section": r.metadata.section,
                "status": r.status.value,
                "severity": r.severity.name,
                "confidence": r.confidence.name,
                "risk_score": f"{r.risk_score:.2f}",
                "summary": r.summary,
                "remediation": r.metadata.remediation,
                "host": r.host,
            })
        return buf.getvalue()
