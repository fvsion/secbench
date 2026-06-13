"""Rich, colour-coded terminal report.

Designed to be read top-down by someone who just ran a scan: the verdict and
grade first, then the at-a-glance counts, then where the risk is concentrated,
then the specific findings to fix in priority order. Colour is informative, not
decorative — green/yellow/red map to pass/warn/fail consistently.
"""

from __future__ import annotations

from typing import List

from ..core.model import CheckResult, Severity, Status
from ..analysis.attack import attack_ids
from .ansi import Style, should_colorize, visible_len
from .base import ReportBundle, Reporter

_STATUS_STYLE = {
    Status.PASS: ("green", "PASS"),
    Status.FAIL: ("red", "FAIL"),
    Status.WARN: ("yellow", "WARN"),
    Status.MANUAL: ("cyan", "MANUAL"),
    Status.SKIP: ("gray", "SKIP"),
    Status.ERROR: ("bright_magenta", "ERROR"),
    Status.INFO: ("blue", "INFO"),
}

_SEVERITY_STYLE = {
    Severity.CRITICAL: ("bright_red", "CRIT"),
    Severity.HIGH: ("red", "HIGH"),
    Severity.MEDIUM: ("yellow", "MED"),
    Severity.LOW: ("cyan", "LOW"),
    Severity.INFO: ("gray", "INFO"),
}

_GRADE_STYLE = {"A": "bright_green", "B": "green", "C": "yellow", "D": "bright_yellow", "F": "bright_red"}

_TACTIC_COLOR = {
    "credential_access": "bright_red",
    "privilege_escalation": "red",
    "exploitation": "bright_magenta",
    "initial_access": "yellow",
    "persistence": "magenta",
    "defense_evasion": "blue",
    "hardening": "gray",
}

_WIDTH = 78


class TerminalReporter(Reporter):
    extension = "txt"
    interactive = True

    def __init__(self, color=None, top_n: int = 20, verbose: bool = False) -> None:
        self._color_override = color
        self.top_n = top_n
        self.verbose = verbose

    def render(self, bundle: ReportBundle) -> str:
        s = Style(should_colorize(override=self._color_override))
        out: List[str] = []
        out += self._header(bundle, s)
        out += self._posture(bundle, s)
        out += self._counts(bundle, s)
        out += self._sections(bundle, s)
        out += self._pareto(bundle, s)
        out += self._two_lens(bundle, s)
        out += self._trend(bundle, s)
        out += self._findings(bundle, s)
        out += self._suppressed(bundle, s)
        out += self._footer(bundle, s)
        return "\n".join(out) + "\n"

    def _suppressed(self, b: ReportBundle, s: Style) -> List[str]:
        if not b.suppressed:
            return []
        lines = [s.bold("SUPPRESSED / ACCEPTED")
                 + s.dim(f"  ({len(b.suppressed)} excluded from scoring)")]
        for r in b.suppressed:
            kind = r.suppression_kind or "suppressed"
            reason = f" — {r.suppression_reason}" if r.suppression_reason else ""
            lines.append(s.gray(f"  {r.id:<14} [{kind}] {r.metadata.title}{reason}"))
        lines.append("")
        return lines

    # -- sections ------------------------------------------------------------

    def _rule(self, s: Style, ch: str = "─") -> str:
        return s.gray(ch * _WIDTH)

    def _header(self, b: ReportBundle, s: Style) -> List[str]:
        facts = b.scan.host_facts
        title = "Linux SecBench — Security & CIS Compliance Report"
        sub = f"{facts.get('pretty_name', 'Unknown OS')}  •  kernel {facts.get('kernel', '?')}  •  {facts.get('arch', '?')}"
        from .base import benchmark_note
        _bn = benchmark_note(facts)
        cis_note = s.yellow(f"  [{_bn}]") if _bn else ""
        return [
            s.paint("═" * _WIDTH, "cyan"),
            s.bold(s.cyan(title)),
            self._rule(s),
            f"{s.bold('Host')}: {b.host}   {s.bold('Target')}: {b.scan.target}   "
            f"{s.bold('Root')}: {'yes' if facts.get('scanned_as_root') else 'no'}",
            f"{s.dim(sub)}{cis_note}",
            f"{s.dim('Scanned')}: {b.scan.started_at}   {s.dim('Tool')}: v{b.scan.tool_version}",
            "",
        ]

    def _posture(self, b: ReportBundle, s: Style) -> List[str]:
        p = b.posture
        grade = p["grade"]
        grade_painted = s.paint(f" {grade} ", _GRADE_STYLE.get(grade, "white"), "bold")
        bar = self._meter(p["compliance"], s)
        lines = [
            s.bold("SECURITY POSTURE"),
            f"  Grade {grade_painted}   Posture score {s.bold(str(p['posture_score']))}/100",
            f"  Compliance {bar} {p['compliance']}%",
            f"  Residual risk {s.bold(str(p['total_risk']))}   "
            f"({s.paint(str(p['critical']) + ' critical', 'bright_red')}, "
            f"{s.red(str(p['high']) + ' high')}, {p['findings']} findings total)",
            "",
        ]
        if p["critical"]:
            lines.insert(1, "  " + s.paint(" ACTION REQUIRED: critical findings present ", "bg_red", "white", "bold"))
        return lines

    def _meter(self, pct: float, s: Style, width: int = 24) -> str:
        filled = int(round(width * pct / 100.0))
        color = "green" if pct >= 85 else ("yellow" if pct >= 60 else "red")
        return s.paint("█" * filled, color) + s.gray("░" * (width - filled))

    def _counts(self, b: ReportBundle, s: Style) -> List[str]:
        counts = b.scan.counts()
        cells = []
        for status in (Status.PASS, Status.FAIL, Status.WARN, Status.MANUAL, Status.SKIP, Status.ERROR, Status.INFO):
            n = counts.get(status.value, 0)
            color, label = _STATUS_STYLE[status]
            cells.append(s.paint(f"{label} {n}", color))
        return [s.bold("RESULTS"), "  " + "   ".join(cells), self._rule(s), ""]

    def _sections(self, b: ReportBundle, s: Style) -> List[str]:
        lines = [s.bold("BY SECTION")]
        by_section = b.scan.by_section()
        for section in sorted(by_section, key=_section_key):
            results = by_section[section]
            scored = [r for r in results if r.status.is_scored]
            passed = sum(1 for r in scored if r.status is Status.PASS)
            pct = (100.0 * passed / len(scored)) if scored else 0.0
            fails = sum(1 for r in results if r.status is Status.FAIL)
            mini = self._meter(pct, s, width=14)
            label = section if len(section) <= 40 else section[:37] + "..."
            fail_note = s.red(f"  {fails} fail") if fails else ""
            lines.append(f"  {label:<42} {mini} {pct:5.1f}%{fail_note}")
        lines.append("")
        return lines

    def _pareto(self, b: ReportBundle, s: Style) -> List[str]:
        vital = [p for p in b.pareto_sections if p.is_vital_few]
        if not vital:
            return []
        lines = [
            s.bold("RISK CONCENTRATION") + s.dim("  (Pareto — the vital few driving ~80% of risk)"),
        ]
        for item in vital[:6]:
            lines.append(
                f"  {item.label:<42} {s.red(format(item.risk, '6.1f'))}  "
                f"{s.dim(f'{item.share*100:4.1f}% of risk, {item.findings} findings')}"
            )
        lines.append("")
        return lines

    def _two_lens(self, b: ReportBundle, s: Style) -> List[str]:
        """The two ways to defend a host, shown side by side: keep the attacker
        out, and (assuming they get in anyway) keep them from reaching root."""
        c = b.compromise
        lines: List[str] = []
        ev_by_id = {r.id: r.evidence for r in b.scan.results}

        # --- Lens 1: prevent foothold ---
        lines.append(s.paint("══ PREVENT FOOTHOLD ", "cyan", "bold")
                     + s.dim("stop an attacker from getting onto the box"))
        if c.foothold_assumed:
            lines.append(s.dim("  No externally-reachable entry weakness was found — this scan "
                               "can't demonstrate initial access"))
            lines.append(s.dim("  (it may come via phishing, a vulnerable app, or stolen "
                               "credentials); the analysis below assumes a shell is obtained."))
        else:
            lines.append(f"  Estimated chance an attacker can get in: {self._prob(c.foothold, s)}"
                         + s.dim(f"  (from {c.foothold_drivers} network entry weakness(es))"))
        lines += self._target_lines(b.foothold_targets, s, empty="  No entry weaknesses found. ",
                                     evidence_by_id=ev_by_id)
        lines.append("")

        # --- Lens 2: assume foothold, prevent escalation ---
        lines.append(s.paint("══ ASSUME FOOTHOLD → PREVENT ESCALATION ", "magenta", "bold")
                     + s.dim("assume they have a shell; stop them reaching root"))
        esc_label = self._prob(c.escalation, s)
        assume_note = s.dim("  (assuming a foothold is obtained)") if c.foothold_assumed else ""
        lines.append(f"  Estimated chance they reach root from a shell: {esc_label}{assume_note}")
        lines += self._attack_paths(b, s)
        lines += self._target_lines(b.escalation_targets, s, empty="  No escalation vectors found. ",
                                     evidence_by_id=ev_by_id)
        lines.append("")
        return lines

    def _prob(self, p: float, s: Style) -> str:
        pct = round(100 * p)
        color = "red" if pct >= 66 else ("yellow" if pct >= 33 else "green")
        return s.paint(f"{pct}%", color, "bold")

    def _target_lines(self, targets, s: Style, empty: str, evidence_by_id=None) -> List[str]:
        if not targets:
            return [s.green(empty)]
        evidence_by_id = evidence_by_id or {}
        out = []
        for t in targets[:8]:
            color = _TACTIC_COLOR.get(t.tactic_key, "white")
            tag = s.paint(f"{t.tactic:<20}", color, "bold")
            out.append(f"  {tag} {s.bold(t.check_id):<14} {t.title}  {s.dim(f'value {t.attacker_value:.1f}')}")
            # Show a couple of evidence lines so the detail is visible inline,
            # not buried in the findings list below.
            for ev in evidence_by_id.get(t.check_id, [])[:2]:
                out.append(s.gray(f"        - {ev}"))
        return out

    def _attack_paths(self, b: ReportBundle, s: Style) -> List[str]:
        ag = b.attack_graph
        if ag is None:
            return []
        if not ag.root_reachable:
            return [s.bold("ATTACK PATHS TO ROOT"),
                    "  " + s.green("No local privilege-escalation path to root was found. "),
                    ""]
        sev_color = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "gray"}
        lines = [s.bold("ATTACK PATHS TO ROOT")
                 + s.dim(f"  ({len(ag.paths)} path(s) — how an attacker chains findings to root)")]
        if ag.assumed_foothold:
            lines.append(s.dim("  (assuming the standard premise: the attacker can obtain a local shell)"))
        for i, path in enumerate(ag.paths[:6], start=1):
            chain = self._format_chain(path, s)
            sev = s.paint(f"[{path.max_severity[:4]}]", sev_color.get(path.max_severity, "white"), "bold")
            lines.append(f"  {s.bold(f'{i}.')} {sev} {chain}")
        lines.append("")

        # Chokepoints — the min-cut.
        if ag.chokepoints:
            id_title = {r.id: r.metadata.title for r in b.scan.results}
            lines.append(s.bold("CHOKEPOINTS")
                         + s.dim("  (min-cut — fixing these severs every path to root)"))
            for e in ag.chokepoints:
                title = id_title.get(e.finding_id, e.technique)
                fid = s.bold(e.finding_id or "—")
                lines.append(f"  ✖ {fid:<14} {title}")
                if e.remediation:
                    lines.append(s.dim(f"      ↳ fix: {e.remediation}"))
            lines.append("")
        return lines

    def _format_chain(self, path, s: Style) -> str:
        out = []
        nodes = path.nodes
        out.append(s.cyan(nodes[0]))
        for e in path.edges:
            tech = e.technique if not e.assumed else s.dim(e.technique)
            out.append(s.gray("─(") + tech + s.gray(")▶ ") + s.cyan(e.dst))
        return " ".join(out)

    def _trend(self, b: ReportBundle, s: Style) -> List[str]:
        if len(b.trend_points) < 2:
            return []
        spark = self._sparkline([p.compliance for p in b.trend_points], s)
        first = b.trend_points[0].compliance
        last = b.trend_points[-1].compliance
        delta = last - first
        arrow = s.green("▲ +" + format(delta, ".1f")) if delta > 0 else (
            s.red("▼ " + format(delta, ".1f")) if delta < 0 else s.dim("● flat"))
        lines = [s.bold("TREND") + s.dim(f"  (last {len(b.trend_points)} scans)"),
                 f"  Compliance {spark}  {arrow}"]
        if b.regression:
            r = b.regression
            lines.append("  " + s.paint(
                f" REGRESSION: compliance {r['latest']}% is below control limit {r['lower_control_limit']}% "
                f"(baseline {r['baseline_median']}%) ", "bg_yellow", "black", "bold"))
        if b.changepoints:
            cp = b.changepoints[-1]
            how = "+".join(cp.get("detectors", []))
            lines.append("  " + s.yellow(
                f"⚠ Compliance drop detected at scan {cp['scan_id']} ({cp['compliance']}%) [{how}]"))
        lines.append("")
        return lines

    def _sparkline(self, values, s: Style) -> str:
        if not values:
            return ""
        blocks = "▁▂▃▄▅▆▇█"
        lo, hi = min(values), max(values)
        span = (hi - lo) or 1.0
        chars = "".join(blocks[min(len(blocks) - 1, int((v - lo) / span * (len(blocks) - 1)))] for v in values)
        return s.cyan(chars)

    def _findings(self, b: ReportBundle, s: Style) -> List[str]:
        ranked = b.ranked[: self.top_n]
        if not ranked:
            return [s.green("No findings — all evaluated controls passed. "), ""]
        lines = [s.bold(f"TOP FINDINGS") + s.dim(f"  (by risk; showing {len(ranked)} of {len(b.ranked)})"), ""]
        for r in ranked:
            lines += self._finding_block(r, s)
        return lines

    def _finding_block(self, r: CheckResult, s: Style) -> List[str]:
        sev_color, sev_label = _SEVERITY_STYLE.get(r.severity, ("white", "?"))
        st_color, st_label = _STATUS_STYLE.get(r.status, ("white", "?"))
        tag = s.paint(f"[{sev_label}]", sev_color, "bold")
        st = s.paint(st_label, st_color)
        risk = s.dim(f"risk {r.risk_score:.1f}")
        head = f"  {tag} {st} {s.bold(r.id)} {r.metadata.title}  {risk}"
        block = [head, f"      {r.summary}"]
        if self.verbose:
            for ev in r.evidence[:5]:
                block.append(s.gray(f"        - {ev}"))
            if r.metadata.remediation:
                block.append(s.dim(f"        ↳ fix: {r.metadata.remediation}"))
            ids = attack_ids(r)
            if ids:
                block.append(s.dim(f"        ATT&CK: {', '.join(ids)}"))
        return block

    def _footer(self, b: ReportBundle, s: Style) -> List[str]:
        return [self._rule(s),
                s.dim(f"Generated {b.generated_at}  •  scan {b.scan.scan_id}  •  "
                      f"{len(b.scan.results)} controls evaluated"),
                s.paint("═" * _WIDTH, "cyan")]


def _section_key(section: str):
    head = section.split()[0] if section else ""
    parts = []
    for seg in head.replace("-", ".").split("."):
        parts.append((0, int(seg), "") if seg.isdigit() else (1, 0, seg))
    return parts
