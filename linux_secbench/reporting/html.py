"""Self-contained HTML report.

Everything — CSS, the charts (hand-built inline SVG), the data — is embedded in
a single file with no external requests, so it renders identically whether
opened from disk, emailed, or served. The charts are SVG rather than a JS
charting library precisely to keep it dependency-free and printable.
"""

from __future__ import annotations

import html
import json
import math
from typing import List

from ..core.model import CheckResult, Status
from ..analysis.attack import attack_ids
from .base import ReportBundle, Reporter

# Colour palette shared between CSS and SVG so the report is internally consistent.
_C = {
    "pass": "#3fb950", "fail": "#f85149", "warn": "#d29922", "manual": "#58a6ff",
    "skip": "#6e7681", "error": "#bc8cff", "info": "#79c0ff",
    "crit": "#ff5c5c", "high": "#f85149", "med": "#d29922", "low": "#58a6ff",
    "bg": "#0d1117", "panel": "#161b22", "border": "#30363d", "text": "#e6edf3",
    "muted": "#8b949e", "accent": "#58a6ff",
}
_GRADE_COLOR = {"A": "#3fb950", "B": "#56d364", "C": "#d29922", "D": "#db6d28", "F": "#f85149"}
_TACTIC_COLOR = {
    "credential_access": "#ff5c5c", "privilege_escalation": "#f85149",
    "exploitation": "#bc8cff", "initial_access": "#d29922",
    "persistence": "#db61a2", "defense_evasion": "#58a6ff", "hardening": "#6e7681",
}
_SEV_COLOR = {"CRITICAL": _C["crit"], "HIGH": _C["high"], "MEDIUM": _C["med"], "LOW": _C["low"], "INFO": _C["skip"]}


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _prob_color(pct: int) -> str:
    return _C["fail"] if pct >= 66 else (_C["warn"] if pct >= 33 else _C["pass"])


def _attack_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _attack_html(result) -> str:
    """Render ' · ATT&CK: T1046, T1548.001' with links, or '' if none."""
    ids = attack_ids(result)
    if not ids:
        return ""
    links = ", ".join(
        f"<a class='jump' href='{_attack_url(t)}' target='_blank' rel='noopener'>{_e(t)}</a>"
        for t in ids)
    return f" · ATT&CK: {links}"


class HtmlReporter(Reporter):
    extension = "html"

    def render(self, bundle: ReportBundle) -> str:
        body = "\n".join([
            self._header(bundle),
            "<main class='wrap'>",
            self._summary_cards(bundle),
            self._two_lens(bundle),
            "<div class='grid'>",
            self._status_donut(bundle),
            self._section_bars(bundle),
            "</div>",
            self._pareto(bundle),
            self._trend(bundle),
            self._findings_table(bundle),
            "</main>",
            self._footer(bundle),
        ])
        return f"<!DOCTYPE html>\n<html lang='en'><head><meta charset='utf-8'>" \
               f"<meta name='viewport' content='width=device-width, initial-scale=1'>" \
               f"<title>SecBench — {_e(bundle.host)}</title><style>{_CSS}</style></head>" \
               f"<body>{body}</body></html>\n"

    # -- pieces --------------------------------------------------------------

    def _header(self, b: ReportBundle) -> str:
        p = b.posture
        facts = b.scan.host_facts
        grade = p["grade"]
        gcolor = _GRADE_COLOR.get(grade, "#888")
        from .base import benchmark_note
        _bn = benchmark_note(facts)
        cis_warn = f"<span class='chip warn'>{_bn}</span>" if _bn else ""
        return f"""
<header class='hero'>
  <div class='hero-main'>
    <h1>Linux SecBench</h1>
    <p class='sub'>Security &amp; CIS Compliance Assessment</p>
    <div class='meta'>
      <span class='chip'>{_e(b.host)}</span>
      <span class='chip'>{_e(str(b.scan.target))}</span>
      <span class='chip'>{_e(facts.get('pretty_name', 'Unknown OS'))}</span>
      <span class='chip'>{'root' if facts.get('scanned_as_root') else 'non-root'} scan</span>
      {cis_warn}
    </div>
  </div>
  <div class='grade-badge' id='hero-badge' style='--g:{gcolor}'>
    <div class='grade' id='hero-grade'>{_e(grade)}</div>
    <div class='grade-score' id='hero-score'>{p['posture_score']}/100</div>
  </div>
</header>
<div class='scopebar wrap'>
  <span class='scope-label'>Scope:</span>
  <button class='scope active' data-scope='All' onclick='secbenchScope(this)'>All</button>
  <button class='scope' data-scope='CIS' onclick='secbenchScope(this)'>CIS</button>
  <button class='scope' data-scope='Security' onclick='secbenchScope(this)'>Security</button>
  <button class='scope' data-scope='Kiosk' onclick='secbenchScope(this)'>Kiosk</button>
  <span class='scope-note' id='scope-note'></span>
</div>"""

    def _summary_cards(self, b: ReportBundle) -> str:
        p = b.posture
        counts = b.scan.counts()
        cards = [
            ("Compliance", f"{p['compliance']}%", _C["accent"], "compliance"),
            ("Residual risk", f"{p['total_risk']}", _C["warn"], "risk"),
            ("Critical", str(p["critical"]), _C["crit"], "critical"),
            ("High", str(p["high"]), _C["high"], "high"),
            ("Findings", str(p["findings"]), _C["fail"], "findings"),
            ("Controls", str(len(b.scan.results)), _C["muted"], "controls"),
            ("Passed", str(counts[Status.PASS.value]), _C["pass"], "pass"),
            ("Manual", str(counts[Status.MANUAL.value]), _C["manual"], "manual"),
        ]
        cells = "".join(
            f"<div class='card'><div class='card-val' id='card-{key}' style='color:{c}'>{_e(v)}</div>"
            f"<div class='card-label'>{_e(label)}</div></div>"
            for label, v, c, key in cards
        )
        return f"<section class='cards'>{cells}</section>"

    def _two_lens(self, b: ReportBundle) -> str:
        """The two-lens attacker view with a toggle: keep them out vs. assume
        they're in and keep them off root."""
        c = b.compromise
        foot_pct = round(100 * c.foothold) if c else 0
        esc_pct = round(100 * c.escalation) if c else 0
        assume = " (assuming a foothold)" if c and c.foothold_assumed else ""

        if c and c.foothold_assumed:
            foothold_stat = (
                "<p class='lens-stat muted'>No externally-reachable entry weakness was found — "
                "this scan can't demonstrate initial access (it may come via phishing, a "
                "vulnerable app, or stolen credentials); the analysis below assumes a shell "
                "is obtained.</p>")
        else:
            foothold_stat = (
                f"<p class='lens-stat'>Estimated chance an attacker can get onto this host: "
                f"<b style='color:{_prob_color(foot_pct)}'>{foot_pct}%</b>"
                f"<span class='muted'> &nbsp;(from {c.foothold_drivers if c else 0} network entry weakness(es))</span></p>")
        foothold_body = (
            foothold_stat
            + self._targets_html(b, b.foothold_targets, "No entry weaknesses were found."))

        escalation_body = (
            f"<p class='lens-stat'>Estimated chance they reach root from a shell: "
            f"<b style='color:{_prob_color(esc_pct)}'>{esc_pct}%</b>"
            f"<span class='muted'>{_e(assume)}</span></p>"
            + self._paths_html(b)
            + self._targets_html(b, b.escalation_targets, "No escalation vectors were found."))

        return f"""
<section class='panel'>
  <h2>Attacker's-eye view <small>two ways to defend — pick a tab</small></h2>
  <div class='tabs'>
    <button class='tab active' data-lens='foothold' onclick='secbenchLens(this)'>🚪 Prevent foothold</button>
    <button class='tab' data-lens='escalation' onclick='secbenchLens(this)'>🧗 Assume foothold → prevent escalation</button>
  </div>
  <div class='lens' id='lens-foothold'>
    <p class='lens-intro'>Stop an attacker from getting onto the box in the first place.</p>
    {foothold_body}
  </div>
  <div class='lens' id='lens-escalation' hidden>
    <p class='lens-intro'>Assume the attacker already has a shell — now stop them from reaching root.</p>
    {escalation_body}
  </div>
</section>
<script>
function secbenchLens(btn){{
  var lens = btn.getAttribute('data-lens');
  document.querySelectorAll('.tab').forEach(function(t){{ t.classList.toggle('active', t===btn); }});
  document.getElementById('lens-foothold').hidden = (lens!=='foothold');
  document.getElementById('lens-escalation').hidden = (lens!=='escalation');
}}
</script>"""

    def _paths_html(self, b: ReportBundle) -> str:
        ag = b.attack_graph
        if ag is None:
            return ""
        if not ag.root_reachable:
            return "<p class='ok'>No local privilege-escalation path to root was found.</p>"
        id_title = {r.id: r.metadata.title for r in b.scan.results}
        id_result = {r.id: r for r in b.scan.results}
        path_rows = []
        for p in ag.paths[:8]:
            sev = p.max_severity
            color = _SEV_COLOR.get(sev, "#888")
            chain = ["<span class='node'>" + _e(p.nodes[0]) + "</span>"]
            for e in p.edges:
                cls = "step assumed" if e.assumed else "step"
                chain.append(f"<span class='{cls}'>{_e(e.technique)}</span>"
                             f"<span class='node'>{_e(e.dst)}</span>")
            path_rows.append(
                f"<li><span class='sev' style='background:{color}'>{_e(sev)}</span>"
                f"<div class='chain'>{''.join(chain)}</div></li>")
        choke = ""
        if ag.chokepoints:
            items = []
            for e in ag.chokepoints:
                title = id_title.get(e.finding_id, e.technique)
                fr = id_result.get(e.finding_id)
                ev = "".join(f"<li>{_e(x)}</li>" for x in (fr.evidence[:8] if fr else []))
                ev_block = f"<ul class='evidence'>{ev}</ul>" if ev else ""
                fix = f"<div class='fix'>fix: {_e(e.remediation)}</div>" if e.remediation else ""
                link = (f" <a class='jump' href='#finding-{_e(e.finding_id)}'>↓</a>"
                        if e.finding_id else "")
                items.append(f"<li><span class='mono'>{_e(e.finding_id or '—')}</span> "
                             f"{_e(title)}{link}{ev_block}{fix}</li>")
            choke = (f"<h3 class='choke-h'>Chokepoints — fixing these severs every path to root</h3>"
                     f"<ul class='chokepoints'>{''.join(items)}</ul>")
        return (f"<h3 class='choke-h'>Attack paths to root</h3>"
                f"<ol class='paths'>{''.join(path_rows)}</ol>{choke}")

    def _targets_html(self, b: ReportBundle, targets, empty: str) -> str:
        if not targets:
            return f"<p class='ok'>{_e(empty)}</p>"
        id_result = {r.id: r for r in b.scan.results}
        rows = []
        for t in targets:
            color = _TACTIC_COLOR.get(t.tactic_key, "#888")
            r = id_result.get(t.check_id)
            ev = "".join(f"<li>{_e(e)}</li>" for e in (r.evidence[:10] if r else []))
            ev_block = f"<ul class='evidence'>{ev}</ul>" if ev else ""
            fix = f"<div class='fix'><b>Fix:</b> {_e(t.remediation)}</div>" if t.remediation else ""
            meta = (f"<div class='detail-meta'>{_e(r.metadata.section)} · {_e(t.tactic)} "
                    f"· severity {_e(t.severity)}{_attack_html(r)}</div>" if r else "")
            jump = (f"<a class='jump' href='#finding-{_e(t.check_id)}' "
                    f"onclick='event.stopPropagation()'>see full finding below ↓</a>")
            rows.append(f"""
<li class='atk' onclick='this.classList.toggle("open")' title='click to expand'>
  <span class='atk-tactic' style='--tc:{color}'>{_e(t.tactic)}</span>
  <div class='atk-body'>
    <div class='atk-title'><span class='mono'>{_e(t.check_id)}</span> {_e(t.title)} <span class='chev'>▸</span></div>
    <div class='atk-sum'>{_e(t.summary)}</div>
    <div class='atk-detail'>{ev_block}{fix}{meta}{jump}</div>
  </div>
  <span class='atk-val' title='offensive value'>{t.attacker_value:.1f}</span>
</li>""")
        return f"<ol class='attack'>{''.join(rows)}</ol>"

    def _status_donut(self, b: ReportBundle) -> str:
        counts = b.scan.counts()
        segments = [(s, counts.get(s.value, 0)) for s in
                    (Status.PASS, Status.FAIL, Status.WARN, Status.MANUAL, Status.SKIP, Status.ERROR, Status.INFO)]
        total = sum(n for _, n in segments) or 1
        svg = _donut([(_C[s.value], n) for s, n in segments if n], total)
        legend = "".join(
            f"<li><span class='dot' style='background:{_C[s.value]}'></span>{_e(s.value)} <b>{n}</b></li>"
            for s, n in segments if n
        )
        return f"""
<section class='panel'>
  <h2>Result distribution</h2>
  <div class='donut-row'>{svg}<ul class='legend'>{legend}</ul></div>
</section>"""

    def _section_bars(self, b: ReportBundle) -> str:
        by_section = b.scan.by_section()
        rows = []
        for section in sorted(by_section, key=lambda s: s):
            results = by_section[section]
            scored = [r for r in results if r.status.is_scored]
            if not scored:
                continue
            passed = sum(1 for r in scored if r.status is Status.PASS)
            pct = 100.0 * passed / len(scored)
            color = _C["pass"] if pct >= 85 else (_C["warn"] if pct >= 60 else _C["fail"])
            rows.append(
                f"<div class='bar-row'><span class='bar-label' title='{_e(section)}'>{_e(section)}</span>"
                f"<span class='bar-track'><span class='bar-fill' style='width:{pct:.0f}%;background:{color}'></span></span>"
                f"<span class='bar-pct'>{pct:.0f}%</span></div>"
            )
        return f"<section class='panel'><h2>Compliance by section</h2><div class='bars'>{''.join(rows)}</div></section>"

    def _pareto(self, b: ReportBundle) -> str:
        items = b.pareto_sections[:10]
        if not items:
            return ""
        maxrisk = max((i.risk for i in items), default=1.0) or 1.0
        rows = []
        for i in items:
            w = 100.0 * i.risk / maxrisk
            cls = "vital" if i.is_vital_few else ""
            rows.append(
                f"<div class='bar-row {cls}'><span class='bar-label' title='{_e(i.label)}'>{_e(i.label)}</span>"
                f"<span class='bar-track'><span class='bar-fill' style='width:{w:.0f}%'></span></span>"
                f"<span class='bar-pct'>{i.risk:.0f} <small>({i.cumulative*100:.0f}%)</small></span></div>"
            )
        return f"""
<section class='panel'>
  <h2>Risk concentration <small>Pareto — highlighted bars are the vital few (~80% of risk)</small></h2>
  <div class='bars pareto'>{''.join(rows)}</div>
</section>"""

    def _trend(self, b: ReportBundle) -> str:
        if len(b.trend_points) < 2:
            return ""
        svg = _line_chart(
            [p.compliance for p in b.trend_points],
            [p.ewma_compliance for p in b.trend_points],
        )
        reg = ""
        if b.regression:
            r = b.regression
            reg = (f"<p class='regression'>⚠ Regression: latest {r['latest']}% is below the "
                   f"control limit of {r['lower_control_limit']}% (baseline {r['baseline_median']}%).</p>")
        if b.changepoints:
            cp = b.changepoints[-1]
            reg += (f"<p class='regression'>⚠ CUSUM change-point: sustained compliance drop at scan "
                    f"{_e(cp['scan_id'])} ({cp['compliance']}%).</p>")
        return f"""
<section class='panel'>
  <h2>Compliance trend <small>raw vs EWMA-smoothed, last {len(b.trend_points)} scans</small></h2>
  {svg}{reg}
</section>"""

    def _findings_table(self, b: ReportBundle) -> str:
        if not b.ranked:
            return "<section class='panel'><h2>Findings</h2><p class='ok'>No findings — all evaluated controls passed.</p></section>"
        rows = []
        for r in b.ranked:
            sev = r.severity.name
            color = _SEV_COLOR.get(sev, "#888")
            ev = "".join(f"<li>{_e(e)}</li>" for e in r.evidence[:8])
            ev_block = f"<ul class='evidence'>{ev}</ul>" if ev else ""
            fix = f"<div class='fix'><b>Fix:</b> {_e(r.metadata.remediation)}</div>" if r.metadata.remediation else ""
            # data-* attributes give the sort script a clean key per column,
            # and sev-rank lets Severity sort by danger, not alphabetically.
            sev_rank = r.severity.value
            rows.append(f"""
<tr class='f-row' id='finding-{_e(r.id)}'
    data-sev='{sev_rank}' data-id='{_e(r.id)}' data-title='{_e(r.metadata.title)}'
    data-status='{_e(r.status.value)}' data-risk='{r.risk_score:.4f}' data-fw='{_e(r.metadata.framework)}'>
  <td><input type='checkbox' class='fpbox' title='mark false-positive'
       onclick='event.stopPropagation();secbenchFP(this)'></td>
  <td onclick='secbenchToggle(this)'><span class='sev' style='background:{color}'>{_e(sev)}</span></td>
  <td class='mono' onclick='secbenchToggle(this)'>{_e(r.id)}</td>
  <td onclick='secbenchToggle(this)'>{_e(r.metadata.title)}</td>
  <td class='st st-{r.status.value}' onclick='secbenchToggle(this)'>{_e(r.status.value)}</td>
  <td class='num' onclick='secbenchToggle(this)'>{r.risk_score:.1f}</td>
  <td class='mono small' onclick='secbenchToggle(this)'>{_e(r.metadata.framework)}</td>
</tr>
<tr class='detail'><td colspan='7'>
  <div class='detail-body'>
    <p>{_e(r.summary)}</p>{ev_block}{fix}
    <div class='detail-meta'>{_e(r.metadata.section)} · confidence {_e(r.confidence.name)}{_attack_html(r)}</div>
  </div>
</td></tr>""")
        scopes_json = json.dumps(b.scope_summaries)
        grade_json = json.dumps(_GRADE_COLOR)
        host_json = json.dumps(b.host)
        return f"""
<section class='panel'>
  <h2>Findings <small>{len(b.ranked)} total · click a row for detail · click a header to sort · tick FP to exclude</small></h2>
  <div class='findings-toolbar'>
    <span id='live-compliance'></span>
    <span>
      <label class='allhosts' title="By default a suppression applies only to this host ({_e(b.host)}); tick to apply to every host (a check that is a false positive everywhere).">
        <input type='checkbox' id='sb-allhosts'> apply to all hosts</label>
      <button class='tab' onclick='secbenchSave()'>💾 Save to server</button>
      <button class='tab' onclick='secbenchRegenerate()'>⤓ Regenerate report files</button>
      <button class='tab' onclick='secbenchExport()'>⬇ Export suppressions</button>
    </span>
  </div>
  <table class='findings' id='findings-table'>
    <thead><tr>
      <th>FP</th>
      <th data-key='sev' data-type='num'>Severity</th>
      <th data-key='id' data-type='text'>ID</th>
      <th data-key='title' data-type='text'>Title</th>
      <th data-key='status' data-type='text'>Status</th>
      <th data-key='risk' data-type='num' class='sorted-desc'>Risk</th>
      <th data-key='fw' data-type='text'>Framework</th>
    </tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>
<script>
window.SECBENCH = {{scopes: {scopes_json}, gradeColors: {grade_json}}};
(function(){{
  var table = document.getElementById('findings-table');
  if(!table) return;
  var tbody = table.tBodies[0], headers = table.tHead.rows[0].cells;
  var curScope = 'All';
  var SECBENCH_HOST = {host_json};
  // The scope a suppression is recorded against: this host by default, or every
  // host when the operator ticks "apply to all hosts".
  function sbHost(){{ var b=document.getElementById('sb-allhosts'); return (b&&b.checked)?'*':SECBENCH_HOST; }}

  window.secbenchToggle = function(td){{
    var d = td.parentElement.nextElementSibling;
    if(d && d.classList.contains('detail')) d.classList.toggle('open');
  }};

  function fRows(){{ return Array.prototype.filter.call(tbody.rows, function(r){{return r.classList.contains('f-row');}}); }}
  function pairs(){{
    var out = [], rows = Array.prototype.slice.call(tbody.rows);
    for(var i=0;i<rows.length;i++) if(rows[i].classList.contains('f-row'))
      out.push([rows[i], rows[i+1] && rows[i+1].classList.contains('detail') ? rows[i+1] : null]);
    return out;
  }}
  function sortBy(idx){{
    var th = headers[idx], key = th.getAttribute('data-key'), type = th.getAttribute('data-type');
    if(!key) return;
    var asc = !th.classList.contains('sorted-asc');
    for(var h=0;h<headers.length;h++) headers[h].classList.remove('sorted-asc','sorted-desc');
    th.classList.add(asc ? 'sorted-asc' : 'sorted-desc');
    var ps = pairs();
    ps.sort(function(a,b){{
      var x=a[0].getAttribute('data-'+key), y=b[0].getAttribute('data-'+key);
      if(type==='num'){{ x=parseFloat(x)||0; y=parseFloat(y)||0; return asc?x-y:y-x; }}
      return asc ? String(x).localeCompare(y) : String(y).localeCompare(x);
    }});
    ps.forEach(function(p){{ tbody.appendChild(p[0]); if(p[1]) tbody.appendChild(p[1]); }});
  }}
  for(var i=0;i<headers.length;i++) (function(i){{ headers[i].onclick=function(){{sortBy(i);}}; }})(i);

  function visible(r){{ return curScope==='All' || r.getAttribute('data-fw')===curScope; }}
  function recompute(){{
    var pass=0, scored=0;
    fRows().forEach(function(r){{
      if(!visible(r) || r.classList.contains('fp')) return;
      var st=r.getAttribute('data-status');
      if(st==='pass'||st==='fail'||st==='warn'){{ scored++; if(st==='pass') pass++; }}
    }});
    var pct = scored ? Math.round(1000*pass/scored)/10 : 0;
    document.getElementById('live-compliance').textContent =
      'Live compliance (visible, minus FP): ' + pct + '%  ·  ' + scored + ' scored';
  }}

  window.secbenchFP = function(box){{
    var row = box.closest('tr'); row.classList.toggle('fp', box.checked);
    var d = row.nextElementSibling; if(d&&d.classList.contains('detail')) d.classList.toggle('fp', box.checked);
    recompute();
  }};

  window.secbenchScope = function(btn){{
    curScope = btn.getAttribute('data-scope');
    Array.prototype.forEach.call(document.querySelectorAll('.scope'), function(b){{ b.classList.toggle('active', b===btn); }});
    // Filter findings rows + their detail rows by framework.
    pairs().forEach(function(p){{
      var show = visible(p[0]);
      p[0].style.display = show ? '' : 'none';
      if(p[1]) p[1].style.display = show ? '' : 'none';
    }});
    // Swap the headline grade + summary cards to the scope's precomputed numbers.
    var s = SECBENCH.scopes[curScope] || SECBENCH.scopes['All']; if(!s) {{ recompute(); return; }}
    function set(id,v){{ var el=document.getElementById(id); if(el) el.textContent=v; }}
    set('hero-grade', s.grade); set('hero-score', s.posture_score+'/100');
    var badge=document.getElementById('hero-badge');
    if(badge) badge.style.setProperty('--g', SECBENCH.gradeColors[s.grade]||'#888');
    set('card-compliance', s.compliance+'%'); set('card-critical', s.critical);
    set('card-high', s.high); set('card-findings', s.findings);
    set('card-risk', s.total_risk); set('card-controls', s.total);
    if(s.counts){{ set('card-pass', s.counts.pass); set('card-manual', s.counts.manual); }}
    set('scope-note', curScope==='All' ? '' : '(showing '+curScope+'-only score)');
    recompute();
  }};

  window.secbenchSave = function(){{
    if(location.protocol === 'file:'){{
      alert('Open this report via "secbench serve" to save suppressions to the server. Use Export instead when viewing a file.');
      return;
    }}
    var ids = fRows().filter(function(r){{return r.classList.contains('fp');}})
      .map(function(r){{return r.getAttribute('data-id');}});
    if(!ids.length){{ alert('Tick at least one FP box first.'); return; }}
    var host = sbHost();
    Promise.all(ids.map(function(id){{
      return fetch('/suppress', {{method:'POST', headers:{{'Content-Type':'application/json'}},
        body: JSON.stringify({{check_id:id, kind:'false-positive', reason:'via report', host:host}})}});
    }})).then(function(){{ location.reload(); }});
  }};

  window.secbenchExport = function(){{
    var host = sbHost();
    var sup = fRows().filter(function(r){{return r.classList.contains('fp');}})
      .map(function(r){{ return {{check_id:r.getAttribute('data-id'), host:host, kind:'false-positive', reason:''}}; }});
    var blob = new Blob([JSON.stringify({{suppressions:sup}}, null, 2)], {{type:'application/json'}});
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob);
    a.download='suppressions.json'; a.click();
  }};

  window.secbenchRegenerate = function(){{
    if(location.protocol === 'file:'){{
      alert('Regenerating the on-disk HTML/CSV/MD/JSON needs the live server — open this report via "secbench serve".');
      return;
    }}
    fetch('/export', {{method:'POST'}}).then(function(r){{ return r.json(); }}).then(function(d){{
      if(d && d.ok){{ alert('Wrote ' + d.files.length + ' report file(s) (current suppressions applied) to:\\n' + d.dir); }}
      else {{ alert('Regeneration failed: ' + ((d && d.error) || 'unknown error')); }}
    }}).catch(function(e){{ alert('Regeneration failed: ' + e); }});
  }};

  recompute();
}})();
</script>"""

    def _footer(self, b: ReportBundle) -> str:
        return (f"<footer>Generated {_e(b.generated_at)} · scan {_e(b.scan.scan_id)} · "
                f"Linux SecBench v{_e(b.scan.tool_version)}</footer>")


# --------------------------------------------------------------------------- #
# Inline SVG chart builders
# --------------------------------------------------------------------------- #

def _donut(slices, total, size=180, thickness=34) -> str:
    """Build an SVG donut from (color, value) slices."""
    r = (size - thickness) / 2
    cx = cy = size / 2
    circ = 2 * math.pi * r
    offset = 0.0
    arcs = []
    for color, value in slices:
        frac = value / total
        dash = frac * circ
        arcs.append(
            f"<circle cx='{cx}' cy='{cy}' r='{r}' fill='none' stroke='{color}' "
            f"stroke-width='{thickness}' stroke-dasharray='{dash:.2f} {circ - dash:.2f}' "
            f"stroke-dashoffset='{-offset:.2f}' transform='rotate(-90 {cx} {cy})'/>"
        )
        offset += dash
    pct = next((f"{100*value/total:.0f}%" for color, value in slices), "0%")
    center = (f"<text x='{cx}' y='{cy-2}' text-anchor='middle' class='donut-num'>{pct}</text>"
              f"<text x='{cx}' y='{cy+16}' text-anchor='middle' class='donut-sub'>pass</text>")
    return (f"<svg width='{size}' height='{size}' viewBox='0 0 {size} {size}' class='donut'>"
            f"{''.join(arcs)}{center}</svg>")


def _line_chart(raw, smoothed, w=720, h=200, pad=28) -> str:
    """Build an SVG line chart for the compliance trend (raw + EWMA overlay)."""
    n = len(raw)
    if n < 2:
        return ""
    lo = min(min(raw), min(smoothed), 0)
    hi = max(max(raw), max(smoothed), 100)
    span = (hi - lo) or 1.0

    def pts(series):
        step = (w - 2 * pad) / (n - 1)
        coords = []
        for i, v in enumerate(series):
            x = pad + i * step
            y = h - pad - (v - lo) / span * (h - 2 * pad)
            coords.append(f"{x:.1f},{y:.1f}")
        return " ".join(coords)

    grid = "".join(
        f"<line x1='{pad}' y1='{h-pad-frac*(h-2*pad):.1f}' x2='{w-pad}' "
        f"y2='{h-pad-frac*(h-2*pad):.1f}' class='grid'/>"
        f"<text x='4' y='{h-pad-frac*(h-2*pad)+4:.1f}' class='axis'>{int(lo+frac*span)}</text>"
        for frac in (0, 0.5, 1.0)
    )
    raw_pts = pts(raw)
    sm_pts = pts(smoothed)
    dots = "".join(
        f"<circle cx='{c.split(',')[0]}' cy='{c.split(',')[1]}' r='2.5' fill='{_C['accent']}'/>"
        for c in raw_pts.split()
    )
    return (f"<svg width='100%' viewBox='0 0 {w} {h}' class='trend'>{grid}"
            f"<polyline points='{sm_pts}' fill='none' stroke='{_C['warn']}' stroke-width='2.5' stroke-dasharray='5 4'/>"
            f"<polyline points='{raw_pts}' fill='none' stroke='{_C['accent']}' stroke-width='2'/>{dots}"
            f"<text x='{w-pad}' y='14' text-anchor='end' class='axis'>— raw  - - EWMA</text></svg>")


_CSS = """
* { box-sizing: border-box; }
body { margin:0; background:#0d1117; color:#e6edf3; font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width:1080px; margin:0 auto; padding:0 20px 60px; }
.hero { display:flex; justify-content:space-between; align-items:center; gap:24px;
  max-width:1080px; margin:0 auto; padding:32px 20px 24px; flex-wrap:wrap; }
.hero h1 { margin:0; font-size:30px; letter-spacing:-.5px; }
.sub { margin:2px 0 14px; color:#8b949e; }
.meta { display:flex; gap:8px; flex-wrap:wrap; }
.chip { background:#161b22; border:1px solid #30363d; border-radius:20px; padding:4px 12px; font-size:12px; color:#c9d1d9; }
.chip.warn { background:#3d2e00; border-color:#9e7700; color:#f0c674; }
.grade-badge { width:120px; height:120px; border-radius:50%; border:5px solid var(--g);
  display:flex; flex-direction:column; align-items:center; justify-content:center; box-shadow:0 0 24px -6px var(--g); }
.grade { font-size:52px; font-weight:800; color:var(--g); line-height:1; }
.grade-score { font-size:12px; color:#8b949e; margin-top:4px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin:8px 0 24px; }
.card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px; text-align:center; }
.card-val { font-size:26px; font-weight:700; }
.card-label { font-size:12px; color:#8b949e; margin-top:4px; text-transform:uppercase; letter-spacing:.4px; }
.grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
@media (max-width:760px){ .grid{ grid-template-columns:1fr; } .hero{ justify-content:center; text-align:center;} }
.panel { background:#161b22; border:1px solid #30363d; border-radius:12px; padding:20px; margin-bottom:16px; }
.panel h2 { margin:0 0 16px; font-size:16px; }
.panel h2 small { color:#8b949e; font-weight:400; font-size:12px; margin-left:6px; }
.donut-row { display:flex; align-items:center; gap:20px; flex-wrap:wrap; }
.donut-num { fill:#e6edf3; font-size:30px; font-weight:700; }
.donut-sub { fill:#8b949e; font-size:12px; }
.legend { list-style:none; padding:0; margin:0; display:grid; grid-template-columns:1fr 1fr; gap:6px 18px; }
.legend li { font-size:13px; color:#c9d1d9; }
.dot { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:7px; }
.bars { display:flex; flex-direction:column; gap:8px; }
.bar-row { display:flex; align-items:center; gap:10px; font-size:13px; }
.bar-label { flex:0 0 200px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; color:#c9d1d9; }
.bar-track { flex:1; height:14px; background:#0d1117; border-radius:7px; overflow:hidden; border:1px solid #30363d; }
.bar-fill { display:block; height:100%; background:#58a6ff; border-radius:7px; }
.bar-pct { flex:0 0 78px; text-align:right; color:#8b949e; font-variant-numeric:tabular-nums; }
.pareto .bar-fill { background:#6e7681; }
.pareto .vital .bar-fill { background:#f85149; }
.pareto .vital .bar-label { color:#fff; font-weight:600; }
.trend { background:#0d1117; border-radius:8px; }
.grid line, .trend .grid { stroke:#30363d; stroke-width:1; }
.axis { fill:#8b949e; font-size:10px; }
.regression { color:#f0c674; background:#3d2e00; border:1px solid #9e7700; border-radius:8px; padding:8px 12px; margin:12px 0 0; }
table.findings { width:100%; border-collapse:collapse; font-size:13px; }
table.findings th { text-align:left; color:#8b949e; font-weight:500; padding:8px; border-bottom:1px solid #30363d; font-size:12px; }
.f-row { cursor:pointer; border-bottom:1px solid #21262d; }
.f-row:hover { background:#1c2230; }
.f-row td { padding:9px 8px; vertical-align:middle; }
.sev { color:#0d1117; font-weight:700; font-size:11px; padding:2px 8px; border-radius:10px; }
.mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:#c9d1d9; }
.small { font-size:11px; color:#8b949e; }
.num { text-align:right; font-variant-numeric:tabular-nums; color:#f0c674; }
.st { text-transform:uppercase; font-size:11px; font-weight:600; }
.st-fail { color:#f85149; } .st-warn { color:#d29922; } .st-manual { color:#58a6ff; }
.detail { display:none; } .detail.open { display:table-row; }
.detail-body { background:#0d1117; padding:14px 16px; border-radius:8px; margin:0 0 6px; }
.detail-body p { margin:0 0 8px; }
.evidence { margin:8px 0; padding-left:18px; color:#c9d1d9; font-family:ui-monospace,monospace; font-size:12px; }
.fix { color:#3fb950; margin-top:8px; }
.detail-meta { color:#8b949e; font-size:11px; margin-top:10px; }
.ok { color:#3fb950; }
.tabs { display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
.tab { background:#0d1117; border:1px solid #30363d; color:#8b949e; border-radius:8px;
  padding:8px 14px; font-size:13px; font-weight:600; cursor:pointer; }
.tab:hover { color:#e6edf3; }
.tab.active { background:#1f6feb22; border-color:#58a6ff; color:#58a6ff; }
.lens-intro { color:#8b949e; margin:0 0 12px; }
.lens-stat { font-size:15px; margin:0 0 14px; }
.muted { color:#8b949e; font-weight:400; font-size:13px; }
ol.attack { list-style:none; counter-reset:none; margin:0; padding:0; }
.atk { display:flex; align-items:flex-start; gap:12px; padding:12px 6px; border-bottom:1px solid #21262d; }
.atk:last-child { border-bottom:none; }
.atk-rank { flex:0 0 26px; height:26px; line-height:26px; text-align:center; border-radius:50%;
  background:#0d1117; border:1px solid #30363d; color:#8b949e; font-weight:700; font-size:13px; }
.atk-tactic { flex:0 0 150px; align-self:center; color:var(--tc); font-weight:700; font-size:12px;
  text-transform:uppercase; letter-spacing:.3px; border-left:3px solid var(--tc); padding-left:8px; }
.atk-body { flex:1; min-width:0; }
.atk-title { font-size:14px; }
.atk-sum { color:#c9d1d9; font-size:13px; margin-top:2px; }
.atk-frame { color:#8b949e; font-size:12px; font-style:italic; margin-top:4px; }
.atk-val { flex:0 0 48px; align-self:center; text-align:right; font-weight:700; font-size:18px; color:#f0c674;
  font-variant-numeric:tabular-nums; }
ol.paths { list-style:none; margin:0; padding:0; }
ol.paths li { display:flex; gap:10px; align-items:flex-start; padding:8px 0; border-bottom:1px solid #21262d; }
ol.paths li:last-child { border-bottom:none; }
.chain { display:flex; flex-wrap:wrap; align-items:center; gap:6px; font-size:13px; }
.node { background:#0d1117; border:1px solid #30363d; border-radius:6px; padding:2px 8px; color:#e6edf3; font-weight:600; }
.step { color:#8b949e; font-size:12px; }
.step::before { content:"──▶ "; color:#444c56; }
.step::after { content:" ▶"; color:#444c56; }
.step.assumed { font-style:italic; opacity:.7; }
.choke-h { font-size:14px; margin:16px 0 8px; color:#f0c674; }
ul.chokepoints { list-style:none; margin:0; padding:0; }
ul.chokepoints li { padding:7px 10px; border-left:3px solid #f85149; background:#0d1117; margin-bottom:6px; border-radius:0 6px 6px 0; font-size:13px; }
ul.chokepoints .fix { color:#3fb950; font-size:12px; margin-top:3px; }
ul.chokepoints .evidence { margin:6px 0; padding-left:18px; color:#c9d1d9; font-family:ui-monospace,monospace; font-size:12px; }
.atk { cursor:pointer; }
.atk .chev { color:#8b949e; display:inline-block; font-size:11px; transition:transform .15s; }
.atk.open .chev { transform:rotate(90deg); }
.atk-detail { display:none; margin-top:8px; }
.atk.open .atk-detail { display:block; }
.atk-detail .evidence { margin:6px 0; padding-left:18px; color:#c9d1d9; font-family:ui-monospace,monospace; font-size:12px; }
a.jump { color:#58a6ff; font-size:12px; text-decoration:none; }
a.jump:hover { text-decoration:underline; }
table.findings th { cursor:pointer; user-select:none; }
table.findings th.sorted-asc::after { content:' ▲'; color:#58a6ff; }
table.findings th.sorted-desc::after { content:' ▼'; color:#58a6ff; }
.f-row:target { background:#1f6feb33 !important; box-shadow:inset 3px 0 0 #58a6ff; }
.scopebar { display:flex; align-items:center; gap:8px; padding:14px 20px 0; flex-wrap:wrap; }
.scope-label { color:#8b949e; font-size:13px; }
.scope { background:#0d1117; border:1px solid #30363d; color:#8b949e; border-radius:8px;
  padding:5px 12px; font-size:13px; font-weight:600; cursor:pointer; }
.scope:hover { color:#e6edf3; }
.scope.active { background:#1f6feb22; border-color:#58a6ff; color:#58a6ff; }
.scope-note { color:#8b949e; font-size:12px; }
.findings-toolbar { display:flex; justify-content:space-between; align-items:center; gap:12px;
  margin-bottom:10px; flex-wrap:wrap; }
#live-compliance { color:#8b949e; font-size:13px; }
tr.f-row.fp td:not(:first-child) { opacity:.45; text-decoration:line-through; }
.fpbox { cursor:pointer; }
footer { text-align:center; color:#8b949e; font-size:12px; padding:24px; border-top:1px solid #21262d; }
"""
