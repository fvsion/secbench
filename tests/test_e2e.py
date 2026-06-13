"""End-to-end tests driving the real CLI ``main()`` across a fleet of hosts.

These are black-box-ish: they invoke ``linux_secbench.cli.main(argv)`` exactly
as the shell would, with the only seam being ``build_executor`` patched to
return a fake host from :mod:`tests.fleet` (the CLI has no other host-injection
point, and a subprocess run would scan the macOS test machine — useless for the
Ubuntu content). Everything else is the genuine pipeline: arg parsing →
platform detection → registry selection → runner → risk scoring → persistence →
every report format → diff / suppress / serve → ``--fail-on`` exit codes.

The fleet exercises three Ubuntu postures (neglected, hardened, kiosk) plus RHEL
and Debian hosts that prove the version-aware edition routing (Ubuntu CIS content
gates out; the portable extended checks still run).
"""

from __future__ import annotations

import glob
import json
import os
import time

import pytest

from linux_secbench import cli
from tests import fleet


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _inject(monkeypatch, host):
    """Make the CLI scan `host` instead of building a real local/SSH executor."""
    monkeypatch.setattr(cli, "build_executor", lambda *a, **k: host)


def _only_json(report_dir):
    paths = glob.glob(os.path.join(report_dir, "*.json"))
    assert paths, f"no JSON report written to {report_dir}"
    with open(paths[0]) as fh:
        return json.load(fh)


def _results(bundle_json):
    return bundle_json["scan"]["results"]


def _status_by_id(bundle_json):
    return {r["metadata"]["id"]: r["status"] for r in _results(bundle_json)}


def _no_errors(bundle_json):
    return [r["metadata"]["id"] for r in _results(bundle_json) if r["status"] == "error"]


def _scan(monkeypatch, host, store, out, extra=None, quiet=True):
    _inject(monkeypatch, host)
    argv = ["--store", store, "scan", "--level", "2", "-o", out]
    if quiet:
        argv.append("--quiet")
    argv += extra or []
    return cli.main(argv)


# --------------------------------------------------------------------------- #
# 1. Full pipeline on the neglected host: every format, valid JSON, no ERRORs
# --------------------------------------------------------------------------- #
def test_e2e_neglected_full_pipeline_all_formats(tmp_path, monkeypatch, capsys):
    store, out = str(tmp_path / "store"), str(tmp_path / "reports")
    _inject(monkeypatch, fleet.neglected_ubuntu(host="srv01"))
    # No --quiet: also exercises the live TerminalReporter.
    rc = cli.main(["--store", store, "scan", "--profile", "server", "--level", "2", "-o", out])
    assert rc == 0  # --fail-on defaults to none → success exit

    # All four file formats landed, plus the terminal report on stdout.
    exts = {os.path.splitext(p)[1] for p in os.listdir(out)}
    assert {".html", ".json", ".csv", ".md"} <= exts
    assert "srv01" in capsys.readouterr().out

    bundle = _only_json(out)
    assert len(_results(bundle)) > 300                      # full catalogue ran
    assert not _no_errors(bundle), "no check may end in ERROR end-to-end"

    st = _status_by_id(bundle)
    assert st["7.2.2"] == "fail"                            # empty shadow password
    assert st["5.4.2.1"] == "fail"                          # UID-0 backdoor
    assert st["EXT-ACCT-1"] == "fail"                       # an extended finding too
    # The Ubuntu benchmark edition is stamped on the scan.
    assert bundle["scan"]["host_facts"]["benchmark"]["os"] == "ubuntu"


def test_e2e_fail_on_severity_exit_codes(tmp_path, monkeypatch):
    store, out = str(tmp_path / "store"), str(tmp_path / "reports")
    # The neglected host has critical findings → --fail-on critical exits non-zero.
    assert _scan(monkeypatch, fleet.neglected_ubuntu(host="srv01"), store, out,
                 extra=["--fail-on", "critical"]) == 1
    # …and the default (none) still exits 0 on the same host.
    assert _scan(monkeypatch, fleet.neglected_ubuntu(host="srv01"), store, out) == 0


# --------------------------------------------------------------------------- #
# 2. Hardened host is measurably more compliant than the neglected one
# --------------------------------------------------------------------------- #
def test_e2e_hardened_is_more_compliant(tmp_path, monkeypatch):
    store = str(tmp_path / "store")
    out_n, out_h = str(tmp_path / "neg"), str(tmp_path / "hard")
    _scan(monkeypatch, fleet.neglected_ubuntu(host="n"), store, out_n)
    _scan(monkeypatch, fleet.hardened_ubuntu(host="h"), store, out_h)

    neg, hard = _status_by_id(_only_json(out_n)), _status_by_id(_only_json(out_h))
    passes = lambda d: sum(1 for v in d.values() if v == "pass")
    assert passes(hard) > passes(neg)                       # remediation shows up
    # The planted flaws are fixed on the hardened host.
    for cid in ("5.4.2.1", "7.2.2", "5.2.4", "3.3.1.1"):
        assert neg[cid] == "fail" and hard[cid] == "pass", cid
    assert not _no_errors(_only_json(out_h))


# --------------------------------------------------------------------------- #
# 3. diff between two snapshots of the same host shows the remediation
# --------------------------------------------------------------------------- #
def test_e2e_diff_shows_resolved_findings(tmp_path, monkeypatch, capsys):
    store = str(tmp_path / "store")
    _scan(monkeypatch, fleet.neglected_ubuntu(host="srv01"), store, str(tmp_path / "a"))
    time.sleep(1.1)  # distinct second-resolution scan id so both snapshots persist
    _scan(monkeypatch, fleet.hardened_ubuntu(host="srv01"), store, str(tmp_path / "b"))

    ids = [f[:-5] for f in sorted(os.listdir(os.path.join(store, "srv01")))]
    assert len(ids) == 2, "expected two stored snapshots for srv01"
    capsys.readouterr()  # clear scan output

    rc = cli.main(["--store", store, "diff", "--host", "srv01", ids[0], ids[1]])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Resolved" in out
    assert "5.4.2.1" in out                                 # backdoor removal shows as resolved


# --------------------------------------------------------------------------- #
# 4. report from a copied-off JSON bundle re-renders every format
# --------------------------------------------------------------------------- #
def test_e2e_report_from_offbox_json(tmp_path, monkeypatch):
    store, out = str(tmp_path / "store"), str(tmp_path / "reports")
    _scan(monkeypatch, fleet.neglected_ubuntu(host="srv01"), store, out)
    src_json = glob.glob(os.path.join(out, "*.json"))[0]

    out2 = str(tmp_path / "rerender")
    rc = cli.main(["--store", str(tmp_path / "absent"), "report", "-f", src_json, "-o", out2])
    assert rc == 0
    exts = {os.path.splitext(p)[1] for p in os.listdir(out2)}
    assert {".html", ".json", ".csv", ".md"} <= exts


# --------------------------------------------------------------------------- #
# 5. host-scoped suppression flows through to the rendered report
# --------------------------------------------------------------------------- #
def test_e2e_suppress_then_report_marks_finding(tmp_path, monkeypatch):
    store, out = str(tmp_path / "store"), str(tmp_path / "reports")
    _scan(monkeypatch, fleet.neglected_ubuntu(host="srv01"), store, out)

    rc = cli.main(["--store", store, "suppress", "7.2.2", "--host", "srv01",
                   "--kind", "false-positive", "--reason", "accepted for this host"])
    assert rc == 0
    assert cli.main(["--store", store, "suppressions"]) == 0

    # Re-render the scan's JSON with the store's suppressions overlaid.
    src_json = glob.glob(os.path.join(out, "*.json"))[0]
    sup = os.path.join(store, "suppressions.json")
    out2 = str(tmp_path / "rerender")
    rc = cli.main(["--store", store, "report", "-f", src_json,
                   "--suppressions", sup, "-o", out2, "--format", "json"])
    assert rc == 0
    suppressed = {s["id"] for s in _only_json(out2).get("suppressed", [])}
    assert "7.2.2" in suppressed


# --------------------------------------------------------------------------- #
# 6. serve: the real CLI wiring renders, suppresses, and exports (run() stubbed
#    so the blocking server loop is replaced by one pass over the callbacks)
# --------------------------------------------------------------------------- #
def test_e2e_serve_callbacks_via_main(tmp_path, monkeypatch):
    from linux_secbench.reporting import serve as serve_mod
    store, out = str(tmp_path / "store"), str(tmp_path / "reports")
    _scan(monkeypatch, fleet.neglected_ubuntu(host="srv01"), store, out)
    src_json = glob.glob(os.path.join(out, "*.json"))[0]
    captured = {}

    def fake_run(render_html, suppress, unsuppress, bind, port, export=None):
        captured["html"] = render_html()                    # HTML renders
        suppress("EXT-CRED-1", "false-positive", "test", None)   # live suppress
        captured["export"] = export()                       # regenerate files

    monkeypatch.setattr(serve_mod, "run", fake_run)
    report_dir = str(tmp_path / "served")
    rc = cli.main(["--store", store, "serve", "-f", src_json, "--report-dir", report_dir])
    assert rc == 0
    assert "<html" in captured["html"].lower()
    assert len(captured["export"]["files"]) == 4
    assert {os.path.splitext(p)[1] for p in os.listdir(report_dir)} >= {".html", ".json", ".csv", ".md"}


# --------------------------------------------------------------------------- #
# 7. kiosk workstation: --kiosk pulls in the Kiosk catalogue, no ERRORs
# --------------------------------------------------------------------------- #
def test_e2e_kiosk_workstation(tmp_path, monkeypatch):
    store, out = str(tmp_path / "store"), str(tmp_path / "reports")
    rc = _scan(monkeypatch, fleet.kiosk_workstation(host="kiosk01"), store, out,
               extra=["--profile", "workstation", "--kiosk"])
    assert rc == 0
    bundle = _only_json(out)
    assert not _no_errors(bundle)
    kiosk_ids = [r["metadata"]["id"] for r in _results(bundle)
                 if r["metadata"]["id"].startswith("KIOSK-")]
    assert len(kiosk_ids) >= 10, "kiosk-breakout checks should run with --kiosk"


# --------------------------------------------------------------------------- #
# 8. multi-distro: edition routing gates Ubuntu CIS out on RHEL / Debian
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("builder,os_id", [
    (fleet.rhel9_host, "rhel"),
    (fleet.debian12_host, "debian"),
])
def test_e2e_multidistro_edition_routing(tmp_path, monkeypatch, builder, os_id):
    store, out = str(tmp_path / "store"), str(tmp_path / "reports")
    rc = _scan(monkeypatch, builder(host=os_id), store, out)
    assert rc == 0
    bundle = _only_json(out)
    assert not _no_errors(bundle)

    ids = [r["metadata"]["id"] for r in _results(bundle)]
    # Ubuntu CIS controls (numeric ids like "5.4.2.1") must NOT run here.
    assert not [i for i in ids if i[:1].isdigit()], "Ubuntu CIS must gate out off-Ubuntu"
    # …but the portable extended checks still run.
    assert any(i.startswith("EXT-") for i in ids)
    # No Ubuntu benchmark edition is stamped for a non-Ubuntu host.
    assert bundle["scan"]["host_facts"].get("benchmark") is None
