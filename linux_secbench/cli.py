"""Command-line interface.

One entry point, several subcommands, and a lot of attention to user error —
because a security tool that crashes on a typo or silently scans the wrong
profile is worse than no tool. Every externally-supplied value (host, level,
profile, format, paths) is validated before any work starts, failures explain
themselves, and the process exit code is meaningful for CI use.

Subcommands:
    scan          run an assessment (local or over SSH) and report
    list-checks   show the catalogue of available checks
    history       show a host's scan history and compliance trend
    report        re-render a stored scan in any format
    hosts         list hosts with stored scans
    diff          compare two scans (what got fixed, what regressed)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import shutil
import sys
from typing import List, Optional, Sequence

from . import __version__
from .checks import CHECK_PACKAGES
from .core.model import Level, Profile, ProfileTarget, Severity, Status
from .core.registry import registry
from .core.runner import ScanRunner
from .analysis.risk import RiskScorer
from .persistence import ScanStore, SuppressionStore, KINDS, slugify
from .reporting import REPORTERS, get_reporter
from .reporting.ansi import Style, should_colorize
from .reporting.base import build_bundle
from .reporting.terminal import TerminalReporter
from .system.executor import LocalExecutor, SSHExecutor, build_executor
from .system.platform import detect_platform
from .system.context import SystemContext

DEFAULT_STORE = os.path.join(os.path.expanduser("~"), ".linux_secbench", "scans")

# The shareable report formats written to an output directory. "all formats"
# means every reporter except `terminal`, which is the stdout view (and is only
# written as a .txt when explicitly named in --format).
FILE_FORMATS = [f for f in sorted(REPORTERS) if f != "terminal"]


# --------------------------------------------------------------------------- #
# Coloured help
# --------------------------------------------------------------------------- #

def _help_should_color() -> bool:
    """Decide colour for help text, which argparse prints during parsing.

    Help can be emitted before the --no-color/--color flags are resolved, so we
    consult argv directly here in addition to the usual NO_COLOR/tty rules. This
    keeps `secbench -h | less` clean and honours an explicit --no-color.
    """
    argv = sys.argv
    if "--no-color" in argv:
        return False
    if "--color" in argv:
        return True
    return should_colorize(sys.stdout)


class ColorHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Help formatter that adds ANSI colour as a line-scoped post-processing pass.

    Colour is applied to the fully-laid-out help text, never to individual
    actions — argparse measures string length to align the help columns, and
    injecting escape codes earlier would throw that alignment off. Working
    line-by-line on the finished output also avoids nesting colour spans (e.g. a
    section heading that contains an option name), which would otherwise reset
    mid-heading.

    Sections become bold cyan, option flags (here and in the examples) green,
    and the 'usage:' prefix bold.
    """

    _OPTION = re.compile(r"(?<![\w-])(-{1,2}[A-Za-z][\w-]*)")

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._style = Style(_help_should_color())

    def format_help(self) -> str:
        text = super().format_help()
        if not self._style.enabled:
            return text
        trailing_nl = text.endswith("\n")
        rendered = "\n".join(self._colorize_line(line) for line in text.splitlines())
        return rendered + ("\n" if trailing_nl else "")

    def _colorize_line(self, line: str) -> str:
        s = self._style
        if line.startswith("usage:"):
            return s.bold("usage:") + self._color_options(line[6:])
        # A section/group heading sits at column 0 and ends with a colon.
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            return s.paint(line, "cyan", "bold")
        return self._color_options(line)

    def _color_options(self, text: str) -> str:
        return self._OPTION.sub(lambda m: self._style.green(m.group(1)), text)


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secbench",
        description="Linux SecBench — Security & CIS-Benchmark assessment for Ubuntu and beyond.",
        formatter_class=ColorHelpFormatter,
        epilog="Examples:\n"
               "  secbench scan                         # assess this machine, auto-detect profile\n"
               "  secbench scan --level 2 --profile server\n"
               "  secbench scan --host db01 --user ops --sudo --format html json\n"
               "  secbench list-checks --section 5\n"
               "  secbench history --host db01\n",
    )
    parser.add_argument("--version", action="version", version=f"Linux SecBench {__version__}")
    parser.add_argument("--store", default=DEFAULT_STORE, metavar="DIR",
                        help=("resume/history store — saved scans used by --resume, the 'history' "
                              f"command, and trends (default: {DEFAULT_STORE}; under /root when run with sudo). "
                              "This is separate from report files (--output); remove it with 'secbench clean'."))
    sub = parser.add_subparsers(dest="command")

    # Subparsers do not inherit the parent's formatter_class, so every command
    # is created through this helper to keep coloured help consistent.
    def addcmd(name, **kw):
        return sub.add_parser(name, formatter_class=ColorHelpFormatter, **kw)

    # -- scan ----
    sc = addcmd("scan", help="run a security assessment")
    _add_target_args(sc)
    sc.add_argument("--profile", choices=["auto", "server", "workstation"], default="auto",
                    help="benchmark profile to assess against (default: auto-detect)")
    sc.add_argument("--level", type=int, choices=[1, 2], default=2,
                    help="CIS hardening level; level 2 includes level 1 (default: 2)")
    sc.add_argument("--sections", nargs="+", metavar="N", help="only run these section prefixes, e.g. 5 6.1")
    sc.add_argument("--ids", nargs="+", metavar="ID", help="only run these exact check ids")
    sc.add_argument("--tags", nargs="+", metavar="TAG", help="only run checks carrying any of these tags")
    sc.add_argument("--no-extended", action="store_true", help="run only formal CIS checks, skip extended audits")
    sc.add_argument("--kiosk", action="store_true",
                    help="also run kiosk-breakout checks (off by default; for locked-down single-app machines)")
    sc.add_argument("--reveal-secrets", action="store_true",
                    help="include full plaintext secret values in evidence (default: redacted preview). "
                         "WARNING: the report file will then contain live secrets.")
    sc.add_argument("--active-review", action="store_true",
                    help="enable active/intrusive checks — in-memory credential recovery (EXT-CRED-16) "
                         "that reads other processes' heap memory. Root-only; off by default.")
    sc.add_argument("--format", nargs="+", default=["terminal"], metavar="FMT",
                    choices=sorted(REPORTERS),
                    help=("report format(s) (default: terminal → stdout). With -o and no --format, "
                          "all file formats (" + ", ".join(FILE_FORMATS) + ") are written; "
                          "--format narrows that set."))
    sc.add_argument("--output", "-o", metavar="DIR", default=None,
                    help="write report files to this directory (all formats by default; narrow with --format)")
    sc.add_argument("--resume", action="store_true", help="resume the most recent interrupted scan for this target")
    sc.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none",
                    help="exit non-zero if any finding at/above this severity exists (for CI)")
    sc.add_argument("--quiet", "-q", action="store_true", help="suppress the live terminal report (files still written)")
    sc.add_argument("--verbose", "-v", action="store_true", help="include evidence and remediation in the terminal report")
    _add_color_args(sc)

    # -- list-checks ----
    lc = addcmd("list-checks", help="list the available checks")
    lc.add_argument("--section", nargs="+", metavar="N", help="filter by section prefix")
    lc.add_argument("--framework", nargs="+", metavar="FW", help="filter by framework (CIS, Security)")
    lc.add_argument("--tags", nargs="+", metavar="TAG", help="filter by tag")
    _add_color_args(lc)

    # -- history ----
    hi = addcmd("history", help="show a host's scan history and trend")
    hi.add_argument("--host", default=None, help="host name (default: this machine)")
    _add_color_args(hi)

    # -- report ----
    rp = addcmd("report", help="re-render a stored scan, or a scan JSON file from another host")
    rp.add_argument("scan_id", nargs="?", default=None, help="scan id to render (see 'history')")
    rp.add_argument("--file", "-f", metavar="PATH", default=None,
                    help="render this scan JSON directly — no store needed (for reviewing a scan "
                         "copied off another machine)")
    rp.add_argument("--host", default=None, help="host the scan belongs to (searched if omitted)")
    rp.add_argument("--format", nargs="+", default=["terminal"], metavar="FMT",
                    choices=sorted(REPORTERS),
                    help=("format(s) to render. With -o and no --format, all file formats ("
                          + ", ".join(FILE_FORMATS) + ") are written; without -o, a single format "
                          "goes to stdout (default: terminal)."))
    rp.add_argument("--output", "-o", metavar="DIR", default=None,
                    help="write report files to this directory (all formats by default; narrow with --format)")
    rp.add_argument("--suppressions", metavar="PATH", default=None,
                    help="suppressions JSON to overlay (default: the store's, or a sibling of --file)")
    _add_color_args(rp)

    # -- hosts ----
    addcmd("hosts", help="list hosts with stored scans")

    # -- suppress / unsuppress / suppressions ----
    sp = addcmd("suppress", help="mark a finding as a false positive / accepted risk")
    sp.add_argument("check_id", help="the check id to suppress (e.g. EXT-PRIV-2)")
    sp.add_argument("--reason", default="", help="why it's suppressed (recorded for audit)")
    sp.add_argument("--kind", choices=list(KINDS), default="false-positive", help="suppression kind")
    sp.add_argument("--host", default=None,
                    help="host this suppression applies to (default: this machine)")
    sp.add_argument("--all-hosts", action="store_true",
                    help="suppress on every host — for a check that is a false positive everywhere "
                         "(default: just this host, since an FP on one host may be real on another)")

    us = addcmd("unsuppress", help="remove a suppression")
    us.add_argument("check_id", help="the check id to un-suppress")
    us.add_argument("--host", default=None, help="limit removal to one host (default: all)")

    addcmd("suppressions", help="list active suppressions")

    # -- serve ----
    sv = addcmd("serve", help="serve an interactive report with live suppress/unsuppress (local-only)")
    sv.add_argument("--scan-id", default=None, help="scan to serve (default: latest for the host)")
    sv.add_argument("--file", "-f", metavar="PATH", default=None,
                    help="serve this scan JSON directly — no store needed (for reviewing a scan "
                         "copied off another machine)")
    sv.add_argument("--host", default=None, help="host whose scan to serve (default: this machine)")
    sv.add_argument("--port", type=int, default=8765, help="port (default: 8765)")
    sv.add_argument("--bind", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    sv.add_argument("--suppressions", metavar="PATH", default=None,
                    help="suppressions JSON to read/write (default: the store's, or a sibling of --file)")
    sv.add_argument("--report-dir", metavar="DIR", default=None,
                    help="where the in-browser 'Regenerate report files' button writes all formats "
                         "(default: the --file's folder, else the current directory)")
    sv.add_argument("--i-understand-exposure", action="store_true",
                    help="required to bind a non-loopback address (exposes the report on the network)")

    # -- clean ----
    cl = addcmd("clean", help="remove the saved scan store (resume/history)")
    cl.add_argument("--host", default=None, help="only clean this host's history (default: the whole store)")
    cl.add_argument("--dry-run", action="store_true", help="show what would be removed; delete nothing")
    cl.add_argument("--yes", "-y", action="store_true", help="skip the confirmation prompt")
    _add_color_args(cl)

    # -- diff ----
    df = addcmd("diff", help="compare two scans (stored ids or scan JSON files)")
    df.add_argument("old", help="older scan id, or a path to a scan JSON file")
    df.add_argument("new", help="newer scan id, or a path to a scan JSON file")
    df.add_argument("--host", default=None, help="host the scans belong to (searched if omitted)")
    _add_color_args(df)

    return parser


def _add_target_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("target host (omit --host to scan this machine)")
    g.add_argument("--host", default=None, help="remote host to assess over SSH")
    g.add_argument("--user", default=None, help="SSH user")
    g.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    g.add_argument("--identity", "-i", default=None, metavar="KEY", help="SSH private key file")
    g.add_argument("--sudo", action="store_true", help="run remote checks via 'sudo -n' (passwordless sudo required)")


def _add_color_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--color", action="store_true", help="force coloured output even when not a TTY")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # No subcommand → show help rather than silently doing something. Scanning
    # is an explicit action ('secbench scan'); running the bare program should
    # never start a scan on its own.
    if args.command is None:
        parser.print_help()
        return 0

    color = _resolve_color(args)
    style = Style(color)
    store = ScanStore(args.store)

    try:
        if args.command == "scan":
            return _cmd_scan(args, store, style)
        if args.command == "list-checks":
            return _cmd_list_checks(args, style)
        if args.command == "history":
            return _cmd_history(args, store, style)
        if args.command == "report":
            return _cmd_report(args, store, style)
        if args.command == "hosts":
            return _cmd_hosts(args, store, style)
        if args.command == "diff":
            return _cmd_diff(args, store, style)
        if args.command == "clean":
            return _cmd_clean(args, store, style)
        if args.command == "suppress":
            return _cmd_suppress(args, store, style)
        if args.command == "unsuppress":
            return _cmd_unsuppress(args, store, style)
        if args.command == "suppressions":
            return _cmd_suppressions(args, store, style)
        if args.command == "serve":
            return _cmd_serve(args, store, style)
        parser.print_help()
        return 0
    except KeyboardInterrupt:
        print("\n" + style.yellow("Interrupted. Any checkpoint was saved; use --resume to continue."), file=sys.stderr)
        return 130
    except BrokenPipeError:  # piping into head/less
        return 0


def _resolve_color(args) -> bool:
    if getattr(args, "no_color", False):
        return False
    if getattr(args, "color", False):
        return True
    return should_colorize()


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #

def _cmd_scan(args, store: ScanStore, style: Style) -> int:
    _load_catalogue()

    # Validate filesystem inputs up front so we fail before touching a host.
    if args.identity and not os.path.isfile(os.path.expanduser(args.identity)):
        print(style.red(f"Identity file not found: {args.identity}"), file=sys.stderr)
        return 2

    # Decide what report files to write and where. Passing -o is an explicit
    # "I want files here", so if no format was named we still produce one (HTML)
    # rather than silently leaving the directory empty.
    output_dir = args.output if args.output is not None else "."
    file_formats = [f for f in args.format if f != "terminal"]
    if args.output is not None and not file_formats:
        file_formats = list(FILE_FORMATS)
        print(style.dim(f"No --format given; writing all report formats "
                        f"({', '.join(FILE_FORMATS)}) to {output_dir} "
                        f"(use --format to narrow)."), file=sys.stderr)
    if file_formats:
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as exc:
            print(style.red(f"Cannot use output directory {output_dir!r}: {exc}"), file=sys.stderr)
            return 2

    # Build the executor and confirm we can reach the target.
    executor = build_executor(args.host, user=args.user, port=args.port,
                              identity=args.identity, use_sudo=args.sudo)
    if isinstance(executor, SSHExecutor):
        print(style.dim(f"Connecting to {executor.host} …"), file=sys.stderr)
        probe = executor.probe()
        if not probe.ok:
            print(style.red(f"Cannot reach {executor.host}: {probe.error or probe.stderr or 'unknown error'}"),
                  file=sys.stderr)
            return 2

    print(style.dim("Detecting platform …"), file=sys.stderr)
    platform = detect_platform(executor)
    ctx = SystemContext(executor, platform)
    ctx.reveal_secrets = args.reveal_secrets
    if args.reveal_secrets:
        print(style.yellow("--reveal-secrets: the report will contain plaintext secret values."),
              file=sys.stderr)
    ctx.active_review = args.active_review
    if args.active_review:
        print(style.yellow("--active-review: will read the memory of running processes for credential "
                           "recovery (intrusive, root-only)."), file=sys.stderr)

    target = _resolve_target(args, platform)
    if not ctx.is_root:
        print(style.yellow("Note: not running as root — some checks (shadow, sudoers, memory) will report MANUAL."),
              file=sys.stderr)

    # Select the in-scope checks.
    checks = registry.select(
        target, ctx,
        sections=args.sections, ids=args.ids, tags=args.tags,
        include_extended=not args.no_extended,
        include_kiosk=args.kiosk,
    )
    if args.kiosk:
        print(style.dim("Kiosk-breakout checks enabled."), file=sys.stderr)
    if not checks:
        print(style.red("No checks matched the given filters."), file=sys.stderr)
        return 2

    # Resume support.
    resume_from = store.find_resumable(ctx.host, target) if args.resume else None
    scan_id = resume_from.scan_id if resume_from else _new_scan_id(ctx.host, target)
    if resume_from:
        done = len(resume_from.completed_ids())
        print(style.cyan(f"Resuming scan {scan_id} ({done} checks already complete)."), file=sys.stderr)

    scorer = RiskScorer()
    progress = _make_progress(style, ctx.host) if not args.quiet else None
    runner = ScanRunner(ctx, target, score_fn=scorer.score, progress=progress)

    banner = f"Assessing {ctx.host} as {target} — {len(checks)} checks"
    print(style.bold(style.cyan(banner)), file=sys.stderr)

    scan = runner.run(
        checks, scan_id, resume_from=resume_from,
        checkpoint=lambda s: store.save(s),  # crash-safe partials
    )
    path = store.save(scan)
    if progress:
        print("", file=sys.stderr)  # finish the progress line cleanly

    # Build the analysis bundle once (with history for trends) and render.
    history = store.history(ctx.host)
    bundle = build_bundle(scan, history=history, scorer=scorer,
                          suppressions=_suppression_store(store))

    if not args.quiet:
        sys.stdout.write(TerminalReporter(color=style.enabled, verbose=args.verbose).render(bundle))

    _write_file_reports(output_dir, file_formats, bundle, scan, style)
    print(style.dim(f"Scan stored: {path}"), file=sys.stderr)

    return _exit_code(bundle, args.fail_on)


def _resolve_target(args, platform) -> ProfileTarget:
    if args.profile == "auto":
        profile = Profile.parse(platform.inferred_profile)
        print(f"Auto-detected profile: {profile.value} "
              f"(override with --profile)", file=sys.stderr)
    else:
        profile = Profile.parse(args.profile)
    return ProfileTarget(profile, Level(args.level))


def _make_progress(style: Style, host: str):
    state = {"fails": 0}

    def progress(index: int, total: int, result):
        if result.status is Status.FAIL:
            state["fails"] += 1
        mark = {
            Status.PASS: style.green("."),
            Status.FAIL: style.red("F"),
            Status.WARN: style.yellow("w"),
            Status.MANUAL: style.cyan("m"),
            Status.ERROR: style.paint("E", "bright_magenta"),
        }.get(result.status, style.gray("-"))
        bar = f"\r  [{index:>3}/{total}] {mark}  {result.id:<14} {style.dim(result.metadata.title[:42])}"
        sys.stderr.write(bar + " " * 8)
        sys.stderr.flush()

    return progress


def _write_file_reports(output_dir: str, file_formats, bundle, scan, style: Style) -> None:
    for fmt in file_formats:
        reporter = get_reporter(fmt)
        filename = f"secbench-{slugify(scan.host)}-{slugify(scan.scan_id)}.{reporter.extension}"
        path = os.path.join(output_dir, filename)
        reporter.write(bundle, path)
        print(style.green(f"Wrote {fmt} report: {path}"), file=sys.stderr)


def _exit_code(bundle, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity.parse(fail_on)
    triggering = [r for r in bundle.scan.findings if r.severity >= threshold]
    return 1 if triggering else 0


# --------------------------------------------------------------------------- #
# list-checks
# --------------------------------------------------------------------------- #

def _cmd_list_checks(args, style: Style) -> int:
    _load_catalogue()
    checks = registry.all()
    if args.section:
        checks = [c for c in checks if any(c.metadata.section.startswith(s) or c.id.startswith(s)
                                           for s in args.section)]
    if args.framework:
        fws = {f.upper() for f in args.framework}
        checks = [c for c in checks if c.metadata.framework.upper() in fws]
    if args.tags:
        wanted = set(args.tags)
        checks = [c for c in checks if wanted & set(c.metadata.tags)]

    if not checks:
        print(style.yellow("No checks match those filters."))
        return 0

    print(style.bold(f"{len(checks)} checks"))
    last_section = None
    for c in checks:
        md = c.metadata
        if md.section != last_section:
            print("\n" + style.cyan(style.bold(md.section)))
            last_section = md.section
        levels = "/".join(f"L{lv.value}" for lv in md.levels)
        profs = "".join(p.value[0].upper() for p in md.profiles)
        sev = style.paint(md.severity.label[:4], _sev_color(md.severity))
        print(f"  {style.bold(md.id):<22} {sev:<6} {levels:<6} {profs:<3} {md.title}")
    return 0


# --------------------------------------------------------------------------- #
# history
# --------------------------------------------------------------------------- #

def _cmd_history(args, store: ScanStore, style: Style) -> int:
    host = args.host or LocalExecutor().host
    history = store.history(host)
    if not history:
        print(style.yellow(f"No scan history for host {host!r} in {store.base_dir}"))
        return 0
    print(style.bold(f"Scan history for {host} ({len(history)} scans)"))
    print(style.dim(f"{'scan id':<28} {'when':<20} {'target':<16} {'compliance':<11} risk  findings"))
    for s in history:
        comp = f"{s.compliance_score():.1f}%"
        status = "" if s.completed else style.yellow(" [partial]")
        print(f"  {s.scan_id:<28} {s.started_at:<20} {str(s.target):<16} "
              f"{comp:<11} {s.total_risk():>5.0f}  {len(s.findings)}{status}")

    # Trend summary using the same analyzer the reports use.
    from .analysis.trends import TrendAnalyzer
    analyzer = TrendAnalyzer()
    points = analyzer.series(history)
    if len(points) >= 2:
        first, last = points[0].compliance, points[-1].compliance
        delta = last - first
        arrow = style.green(f"improved {delta:+.1f}%") if delta > 0 else (
            style.red(f"declined {delta:+.1f}%") if delta < 0 else style.dim("unchanged"))
        print(f"\nTrend: {arrow} over {len(points)} scans (latest {last:.1f}%, EWMA {points[-1].ewma_compliance:.1f}%)")
        reg = analyzer.detect_regression(history)
        if reg:
            print(style.red(f"⚠ Regression: {reg['latest']}% below control limit {reg['lower_control_limit']}%"))
    return 0


# --------------------------------------------------------------------------- #
# report / hosts / diff
# --------------------------------------------------------------------------- #

def _cmd_report(args, store: ScanStore, style: Style) -> int:
    ident = args.file or args.scan_id
    if not ident:
        print(style.red("Nothing to render. Give a scan id (see 'history'), or --file PATH to "
                        "render a scan JSON copied from another host."), file=sys.stderr)
        return 2
    scan, src = _resolve_scan(store, ident, args.host)
    if scan is None:
        if args.file or (ident and os.path.sep in ident):
            print(style.red(f"Could not read scan file {ident!r} — missing or not a valid SecBench "
                            "scan JSON."), file=sys.stderr)
        else:
            print(style.red(f"Scan {ident!r} not found."), file=sys.stderr)
        return 2
    # In file mode we don't depend on a (possibly absent) store, so there's no
    # trend history for a single moved file — that's honest, not a gap.
    history = None if src else store.history(scan.host)
    sup = _suppression_store(store, scan_source=src, override=args.suppressions)
    bundle = build_bundle(scan, history=history, suppressions=sup)

    explicit = [f for f in args.format if f != "terminal"]
    if args.output is not None:
        # Directory mode (mirrors `scan -o`): write all file formats by default,
        # or just the --format subset, auto-named into the directory.
        file_formats = explicit or list(FILE_FORMATS)
        try:
            os.makedirs(args.output, exist_ok=True)
        except OSError as exc:
            print(style.red(f"Cannot use output directory {args.output!r}: {exc}"), file=sys.stderr)
            return 2
        _write_file_reports(args.output, file_formats, bundle, scan, style)
        return 0

    # No -o → stdout. One format only (terminal by default); multiple file
    # formats can't share stdout, so ask for a directory.
    if len(explicit) > 1:
        print(style.red("Multiple report formats need an output directory — pass -o DIR."),
              file=sys.stderr)
        return 2
    if explicit:
        sys.stdout.write(get_reporter(explicit[0]).render(bundle))
    else:
        sys.stdout.write(TerminalReporter(color=style.enabled, verbose=True).render(bundle))
    return 0


def _cmd_hosts(args, store: ScanStore, style: Style) -> int:
    hosts = store.hosts()
    if not hosts:
        print(style.yellow(f"No stored scans under {store.base_dir}"))
        return 0
    print(style.bold(f"Hosts with stored scans ({len(hosts)}):"))
    for h in hosts:
        latest = store.latest(h, completed_only=False)
        when = latest.started_at if latest else "?"
        n = len(store.history(h))
        print(f"  {h:<28} {n:>3} scans   last {when}")
    return 0


def _resolve_scan(store: ScanStore, ident, host=None):
    """Resolve a scan from a file path or a stored id.

    If ``ident`` is a path to an existing file, load it directly (portable
    off-box review — no store directory required) and return the source path so
    callers can default the suppressions file beside it. Otherwise fall back to
    the store: by host+id when a host is given, else by id across all hosts.
    Returns ``(scan_or_None, source_file_or_None)``.
    """
    if ident and os.path.isfile(ident):
        return store.load_path(ident), ident
    if host:
        return store.load(host, ident), None
    return store.load_any(ident), None


def _suppression_store(store: ScanStore, *, scan_source=None, override=None) -> SuppressionStore:
    """Locate the suppressions overlay.

    ``--suppressions`` wins; otherwise a file-mode review keeps its overlay in a
    sibling ``<scanfile>.suppressions.json`` so the moved review is
    self-contained, and the normal case uses the store's shared file.
    """
    if override:
        path = override
    elif scan_source:
        path = scan_source + ".suppressions.json"
    else:
        path = os.path.join(store.base_dir, "suppressions.json")
    return SuppressionStore(path)


def _cmd_suppress(args, store: ScanStore, style: Style) -> int:
    # Host-scoped by default: a false positive on one host may be a real finding
    # on another. Use --all-hosts only for a check that is wrong everywhere.
    host = "*" if args.all_hosts else (args.host or LocalExecutor().host)
    sup = _suppression_store(store)
    s = sup.add(args.check_id, host=host, kind=args.kind, reason=args.reason)
    scope = "all hosts" if s.host == "*" else f"host {s.host}"
    print(style.green(f"Suppressed {s.check_id} ({s.kind}) for {scope}."))
    if not args.reason:
        print(style.dim("Tip: pass --reason to record why (recommended for audit)."))
    return 0


def _cmd_unsuppress(args, store: ScanStore, style: Style) -> int:
    sup = _suppression_store(store)
    n = sup.remove(args.check_id, host=args.host)
    if n:
        print(style.green(f"Removed {n} suppression(s) for {args.check_id}."))
        return 0
    print(style.yellow(f"No suppression found for {args.check_id}."))
    return 0


def _cmd_suppressions(args, store: ScanStore, style: Style) -> int:
    items = _suppression_store(store).all()
    if not items:
        print(style.yellow("No active suppressions."))
        return 0
    print(style.bold(f"{len(items)} active suppression(s):"))
    for s in items:
        scope = "all" if s.host == "*" else s.host
        print(f"  {style.bold(s.check_id):<16} {s.kind:<14} host={scope:<12} "
              f"{s.reason or style.dim('(no reason)')}")
    return 0


def _cmd_serve(args, store: ScanStore, style: Style) -> int:
    from .reporting import serve as serve_mod

    if not serve_mod.is_loopback(args.bind) and not args.i_understand_exposure:
        print(style.red(f"Refusing to bind {args.bind} (non-loopback) — this would expose the report on the "
                        "network. Re-run with --i-understand-exposure if that is intended."), file=sys.stderr)
        return 2

    src = None
    if args.file:
        scan, src = _resolve_scan(store, args.file)
        if scan is None:
            print(style.red(f"Could not read scan file {args.file!r} — missing or not a valid "
                            "SecBench scan JSON."), file=sys.stderr)
            return 2
    else:
        host = args.host or LocalExecutor().host
        scan = store.load(host, args.scan_id) if args.scan_id and args.host else (
            store.load_any(args.scan_id) if args.scan_id else store.latest(host, completed_only=False))
        if scan is None:
            print(style.red("No scan to serve. Run a scan first, or pass --scan-id/--host/--file."),
                  file=sys.stderr)
            return 2

    sup = _suppression_store(store, scan_source=src, override=args.suppressions)
    history = None if src else store.history(scan.host)

    def render_html() -> str:
        sup.load()  # pick up edits made via the API on each request
        bundle = build_bundle(scan, history=history, suppressions=sup)
        return get_reporter("html").render(bundle)

    def do_suppress(check_id, kind, reason, host=None):
        # Default to the served scan's host; the UI's "apply to all hosts" box
        # sends "*". An FP on this host may be real on another, so never assume
        # global.
        sup.add(check_id, host=host or scan.host, kind=kind, reason=reason)

    def do_unsuppress(check_id):
        sup.remove(check_id)

    # Where the in-browser "Regenerate report files" button writes: an explicit
    # --report-dir, else next to the moved scan file (-f), else the CWD.
    report_dir = args.report_dir or (os.path.dirname(os.path.abspath(src)) if src else os.getcwd())

    def do_export():
        sup.load()
        bundle = build_bundle(scan, history=history, suppressions=sup)
        os.makedirs(report_dir, exist_ok=True)
        _write_file_reports(report_dir, FILE_FORMATS, bundle, scan, style)
        files = [f"secbench-{slugify(scan.host)}-{slugify(scan.scan_id)}.{get_reporter(f).extension}"
                 for f in FILE_FORMATS]
        return {"dir": os.path.abspath(report_dir), "files": files}

    if not serve_mod.is_loopback(args.bind):
        print(style.yellow(f"WARNING: serving on {args.bind}:{args.port} — reachable from the network, no auth."),
              file=sys.stderr)
    url = f"http://{'127.0.0.1' if args.bind in ('0.0.0.0', '::') else args.bind}:{args.port}/"
    print(style.bold(style.cyan(f"Serving {scan.host} scan {scan.scan_id} at {url}")))
    print(style.dim("Tick a finding's FP box and 'Save to server' to suppress it live. Ctrl-C to stop."))
    print(style.dim(f"'Regenerate report files' writes all formats to {os.path.abspath(report_dir)}"))
    try:
        serve_mod.run(render_html, do_suppress, do_unsuppress, args.bind, args.port, export=do_export)
    except OSError as exc:
        print(style.red(f"Could not start server on {args.bind}:{args.port}: {exc}"), file=sys.stderr)
        return 2
    return 0


def _cmd_clean(args, store: ScanStore, style: Style) -> int:
    """Remove the saved scan store (and only the store).

    This deletes SecBench's resume/history data under --store. It never touches
    report files written with -o or anything else on the system — those are
    yours. The deletion is hard-guarded to stay inside the store directory.
    """
    base = os.path.abspath(store.base_dir)
    target = os.path.abspath(os.path.join(base, slugify(args.host))) if args.host else base

    # Safety: never delete anything outside the store directory.
    if target != base and not target.startswith(base + os.sep):
        print(style.red("Refusing: resolved target is outside the store directory."), file=sys.stderr)
        return 2

    if not os.path.isdir(target):
        print(f"Nothing to clean (no store at {target}).")
        return 0

    scan_files = [
        os.path.join(root, f)
        for root, _dirs, files in os.walk(target)
        for f in files if f.endswith(".json")
    ]
    label = f"host '{args.host}'" if args.host else "all hosts"
    print(style.bold(f"Will remove the scan store for {label}:"))
    print(f"  {target}")
    print(style.dim(f"  ({len(scan_files)} saved scan file(s))"))

    if args.dry_run:
        print(style.dim("Dry run — nothing deleted."))
        return 0

    if not args.yes:
        if not sys.stdin.isatty():
            print(style.red("Refusing to delete without confirmation. Re-run with --yes."), file=sys.stderr)
            return 1
        try:
            reply = input("Delete this store? [y/N] ").strip().lower()
        except EOFError:
            reply = ""
        if reply not in ("y", "yes"):
            print("Aborted; nothing deleted.")
            return 1

    shutil.rmtree(target)
    print(style.green(f"Removed {target}"))
    return 0


def _cmd_diff(args, store: ScanStore, style: Style) -> int:
    # Each side may be a stored scan id or a path to a scan JSON file, so two
    # scans exported from different machines can be compared off-box.
    old, _ = _resolve_scan(store, args.old, args.host)
    new, _ = _resolve_scan(store, args.new, args.host)
    if old is None or new is None:
        print(style.red("One or both scans not found."), file=sys.stderr)
        return 2

    old_status = {r.id: r.status for r in old.results}
    new_status = {r.id: r.status for r in new.results}
    new_meta = {r.id: r for r in new.results}

    fixed, regressed, still = [], [], []
    for cid, st in new_status.items():
        was = old_status.get(cid)
        if was is None:
            continue
        was_bad = was in (Status.FAIL, Status.WARN)
        now_bad = st in (Status.FAIL, Status.WARN)
        if was_bad and not now_bad:
            fixed.append(cid)
        elif not was_bad and now_bad:
            regressed.append(cid)
        elif was_bad and now_bad:
            still.append(cid)

    print(style.bold(f"Diff {args.old} → {args.new} on {new.host}"))
    print(f"  Compliance: {old.compliance_score():.1f}% → {new.compliance_score():.1f}% "
          f"({new.compliance_score() - old.compliance_score():+.1f})")
    print(style.green(f"\n  Resolved ({len(fixed)}):"))
    for cid in sorted(fixed):
        print(style.green(f"    + {cid}  {new_meta[cid].metadata.title}"))
    print(style.red(f"\n  Regressed ({len(regressed)}):"))
    for cid in sorted(regressed):
        print(style.red(f"    - {cid}  {new_meta[cid].metadata.title}"))
    print(style.dim(f"\n  Still failing: {len(still)}"))
    return 0


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _load_catalogue() -> None:
    """Import every check module exactly once so the registry is populated."""
    if len(registry) == 0:
        registry.autodiscover(list(CHECK_PACKAGES))


def _new_scan_id(host: str, target: ProfileTarget) -> str:
    stamp = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    return f"{stamp}-{slugify(host)}-L{target.level.value}{target.profile.value[0]}"


def _sev_color(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bright_red", Severity.HIGH: "red",
        Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "gray",
    }.get(severity, "white")


if __name__ == "__main__":
    sys.exit(main())
