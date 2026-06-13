"""Markdown report — good for tickets, wikis, and pull-request bodies."""

from __future__ import annotations

from typing import List

from ..core.model import Status
from .base import ReportBundle, Reporter

_SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


class MarkdownReporter(Reporter):
    extension = "md"

    def __init__(self, top_n: int = 30) -> None:
        self.top_n = top_n

    def _target_table(self, targets, empty: str) -> List[str]:
        if not targets:
            return [f"_{empty}_", ""]
        rows = ["| Tactic | ID | Title | Value | Severity |",
                "|--------|----|-------|------:|----------|"]
        for t in targets:
            rows.append(f"| {_esc(t.tactic)} | `{t.check_id}` | {_esc(t.title)} | "
                        f"{t.attacker_value:.1f} | {t.severity} |")
        rows.append("")
        return rows

    def render(self, bundle: ReportBundle) -> str:
        p = bundle.posture
        facts = bundle.scan.host_facts
        out: List[str] = []
        out.append(f"# Linux SecBench Report — {bundle.host}")
        out.append("")
        out.append(f"**Grade {p['grade']}** · Posture {p['posture_score']}/100 · "
                   f"Compliance {p['compliance']}% · Residual risk {p['total_risk']}")
        out.append("")
        out.append(f"- **Target:** {bundle.scan.target}")
        out.append(f"- **OS:** {facts.get('pretty_name', '?')} (kernel {facts.get('kernel', '?')})")
        out.append(f"- **Scanned as root:** {'yes' if facts.get('scanned_as_root') else 'no'}")
        out.append(f"- **Generated:** {bundle.generated_at}")
        from .base import benchmark_note
        _bn = benchmark_note(facts)
        if _bn:
            out.append(f"- ⚠️ _{_bn}_")
        out.append("")

        counts = bundle.scan.counts()
        out.append("## Results at a glance")
        out.append("")
        out.append("| Pass | Fail | Warn | Manual | Skip | Error |")
        out.append("|-----:|-----:|-----:|-------:|-----:|------:|")
        out.append(f"| {counts[Status.PASS.value]} | {counts[Status.FAIL.value]} | "
                   f"{counts[Status.WARN.value]} | {counts[Status.MANUAL.value]} | "
                   f"{counts[Status.SKIP.value]} | {counts[Status.ERROR.value]} |")
        out.append("")

        if bundle.regression:
            r = bundle.regression
            out.append(f"> ⚠️ **Compliance regression detected:** {r['latest']}% is below the control "
                       f"limit of {r['lower_control_limit']}% (baseline {r['baseline_median']}%).")
            out.append("")
        if bundle.changepoints:
            cp = bundle.changepoints[-1]
            how = "+".join(cp.get("detectors", []))
            out.append(f"> ⚠️ **Compliance drop detected** at scan `{cp['scan_id']}` "
                       f"({cp['compliance']}%) — flagged by {how}.")
            out.append("")

        vital = [pi for pi in bundle.pareto_sections if pi.is_vital_few]
        if vital:
            out.append("## Where the risk is (Pareto)")
            out.append("")
            out.append("| Section | Risk | Share | Findings |")
            out.append("|---------|-----:|------:|---------:|")
            for item in vital[:8]:
                out.append(f"| {item.label} | {item.risk:.1f} | {item.share*100:.1f}% | {item.findings} |")
            out.append("")

        c = bundle.compromise
        ag = bundle.attack_graph
        pct = c.pct if c else (lambda p: f"{round(100*p)}%")

        # --- Lens 1: prevent foothold ---
        out.append("## Prevent foothold")
        out.append("")
        out.append("_Stop an attacker from getting onto the box in the first place._")
        out.append("")
        if c:
            if c.foothold_assumed:
                out.append("_No externally-reachable entry weakness was found — this scan "
                           "can't demonstrate initial access (it may come via phishing, a "
                           "vulnerable app, or stolen credentials); the analysis below assumes "
                           "a shell is obtained._")
            else:
                out.append(f"**Estimated chance an attacker can get in:** {pct(c.foothold)} "
                           f"(from {c.foothold_drivers} network entry weakness(es)).")
            out.append("")
        out.extend(self._target_table(bundle.foothold_targets, "No entry weaknesses were found."))

        # --- Lens 2: assume foothold, prevent escalation ---
        out.append("## Assume foothold → prevent escalation")
        out.append("")
        out.append("_Assume the attacker already has a shell; stop them from reaching root._")
        out.append("")
        if c:
            note = " (assuming a foothold is obtained)" if c.foothold_assumed else ""
            out.append(f"**Estimated chance they reach root from a shell:** {pct(c.escalation)}{note}.")
            out.append("")
        if ag is not None and ag.root_reachable:
            out.append("**Attack paths to root:**")
            out.append("")
            for i, p in enumerate(ag.paths[:8], start=1):
                chain = " → ".join([p.nodes[0]] + [f"`{_esc(e.technique)}` → {e.dst}" for e in p.edges])
                out.append(f"{i}. **[{p.max_severity}]** {chain}")
            if ag.chokepoints:
                out.append("")
                out.append("**Chokepoints** — fixing these severs every path to root:")
                out.append("")
                id_title = {r.id: r.metadata.title for r in bundle.scan.results}
                for e in ag.chokepoints:
                    title = id_title.get(e.finding_id, e.technique)
                    out.append(f"- `{e.finding_id or '—'}` — {_esc(title)}"
                               + (f" — _fix:_ {_esc(e.remediation)}" if e.remediation else ""))
            out.append("")
        elif ag is not None:
            out.append("_No local privilege-escalation path to root was found._")
            out.append("")
        out.extend(self._target_table(bundle.escalation_targets, "No escalation vectors were found."))

        out.append("## Findings (by risk)")
        out.append("")
        ranked = bundle.ranked[: self.top_n]
        if not ranked:
            out.append("_No findings — all evaluated controls passed._")
        else:
            out.append("| | ID | Severity | Status | Title | Risk |")
            out.append("|-|----|----------|--------|-------|-----:|")
            for r in ranked:
                emoji = _SEV_EMOJI.get(r.severity.name, "")
                out.append(f"| {emoji} | `{r.id}` | {r.severity.name} | {r.status.value} | "
                           f"{_esc(r.metadata.title)} | {r.risk_score:.1f} |")
            out.append("")
            out.append("### Remediation detail")
            out.append("")
            for r in ranked:
                out.append(f"#### `{r.id}` {_esc(r.metadata.title)}")
                out.append(f"- **Status:** {r.status.value} ({r.severity.name}, {r.confidence.name})")
                out.append(f"- **Finding:** {_esc(r.summary)}")
                if r.metadata.remediation:
                    out.append(f"- **Fix:** {_esc(r.metadata.remediation)}")
                if r.evidence:
                    out.append("- **Evidence:**")
                    for ev in r.evidence[:8]:
                        out.append(f"  - `{_esc(ev)}`")
                out.append("")

        if bundle.suppressed:
            out.append("## Suppressed / accepted")
            out.append("")
            out.append("_Excluded from scoring by operator decision._")
            out.append("")
            out.append("| ID | Kind | Title | Reason |")
            out.append("|----|------|-------|--------|")
            for r in bundle.suppressed:
                out.append(f"| `{r.id}` | {r.suppression_kind} | {_esc(r.metadata.title)} | "
                           f"{_esc(r.suppression_reason)} |")
            out.append("")

        out.append("---")
        out.append(f"_Generated by Linux SecBench v{bundle.scan.tool_version} · "
                   f"scan `{bundle.scan.scan_id}` · {len(bundle.scan.results)} controls evaluated._")
        return "\n".join(out) + "\n"


def _esc(text: str) -> str:
    """Escape the pipe character so table cells do not break."""
    return (text or "").replace("|", "\\|").replace("\n", " ")
