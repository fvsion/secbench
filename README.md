# Linux SecBench

A modular, production-grade **Linux security & CIS-Benchmark assessment engine**.
Implemented benchmark today is **Ubuntu 24.04 LTS** (Levels 1 & 2, Server &
Workstation profiles); it goes well beyond CIS into a full security audit, and
its checks are **distro- and version-gated** so the engine runs only the
benchmark that matches the host it's on — and **auto-selects the right edition**
(e.g. a future Ubuntu 26.04 module, or the nearest one when a release has no
published benchmark yet). **RHEL 9 and Debian 12/13 benchmarks are being added**;
until a host's benchmark lands it runs the portable
"Security" audit, not a mislabelled Ubuntu one.

It is **pure Python 3.8+ standard library — zero runtime dependencies** — so it
runs on a freshly-imaged host with nothing to `pip install` and nothing to vet
for supply-chain risk on a security tool.

> 🪙 **Support development** — SecBench is free and dependency-free. If it saved you time, a tip is welcome (entirely optional):
>
> <sub>**ETH** `0xb95bB92446CB7beDF93520800F1b050191A37f28` &nbsp;·&nbsp; **BTC** `bc1qcjr4wy0gcymd05ndek4nhjd4auq2clam8v7e3t` &nbsp;·&nbsp; **SOL** `Gp9hD1ar8MWKs2kino4ZNiVJ8HPuLHDRCigbXtgNzpxq`</sub>

📖 **New here?** The [**User Guide**](USER_GUIDE.md) is the full operations manual —
every command and flag, where each file goes, and how to move a scan to another
machine to review it off-box.

---

## Installation

There is nothing to install — it is pure standard library. Copy the directory to
the target host and run it:

```bash
git clone https://github.com/fvsion/secbench secbench && cd secbench
sudo python3 secbench.py scan
```

Optionally, install it as a `secbench` command on your PATH:

```bash
pip install -e .        # provides the `secbench` entry point
secbench scan
```

During development you can also run it as a module: `python3 -m linux_secbench`.

Run as **root** for full coverage (shadow, sudoers, process memory, and
filesystem-wide scans). Without root, those checks report `MANUAL` rather than
guessing — they are never silently skipped.

## Usage

```
secbench <command> [options]

  scan          run an assessment (local or over SSH) and report
  list-checks   show the catalogue of available checks
  history       show a host's scan history and compliance trend
  report        re-render a stored scan (or a scan JSON file, via -f) in any format
  hosts         list hosts with stored scans
  diff          compare two scans (stored ids or scan JSON files)
  suppress      mark a finding as a false positive / accepted risk (leaves the score)
  unsuppress    remove a suppression
  suppressions  list active suppressions
  serve         serve an interactive report with live suppress/unsuppress (local-only; -f for a file)
  clean         remove the saved scan store (resume/history); never touches -o reports

Key scan options:
  --host H --user U --port P --identity KEY --sudo   assess a remote host over SSH
  --profile {auto,server,workstation}                role (default: auto-detect)
  --level {1,2}                                       CIS level (L2 ⊇ L1; default 2)
  --sections 5 6.1 | --ids 5.1.2 | --tags ssh        scope the run
  --no-extended                                       formal CIS only
  --kiosk                                             also run kiosk-breakout checks (opt-in)
  --reveal-secrets                                    show full secret values (default: redacted preview)
  --format terminal html json csv markdown            one or more outputs
  --resume                                            continue an interrupted scan
  --fail-on {none,low,medium,high,critical}           CI exit-code gate
```

Running `secbench` with no command shows help; scanning only happens when you
ask for it explicitly.

### Examples

```bash
secbench scan                                   # assess this machine, auto-detect role
secbench scan --level 2 --profile server        # explicit L2 Server
secbench scan -o ./reports                       # write all report formats (html/json/csv/md) to a dir
secbench scan --format html json -o ./reports    # narrow to just HTML + JSON
secbench list-checks --section 5                # browse the catalogue
secbench history --host db01                     # compliance trend across rescans
secbench report -f scan.json -o ./reports        # regenerate all formats from a scan moved off another host
secbench serve  -f scan.json                     # interactive review of a moved scan (local-only)
```

### Where files go

Two separate things get written, and it's worth knowing which is which:

- **Report files** (HTML/JSON/CSV/Markdown) go to the **directory** given by
  **`--output` / `-o`**, auto-named `secbench-<host>-<scan>.<ext>`. Passing
  `-o <dir>` writes **all four formats by default**; `--format` narrows the set.
  With no `-o` and no file `--format`, the only output is the terminal report on
  stdout (nothing is written to disk).
- **The scan record** goes to the **resume/history store** (`--store`, default
  `~/.linux_secbench/scans` — so `/root/.linux_secbench/scans` under `sudo`).
  This is what powers `--resume`, the `history` command, and trend analysis
  across rescans. It is *separate* from your report files and is kept until you
  remove it. Delete it any time with **`secbench clean`** (which touches only the
  store — never your `-o` reports).

#### Reviewing a scan off-box

Each scan record is a **self-contained JSON file** (it carries its own host,
target, findings and host facts), so you can copy one off the scanned system and
review it anywhere — no store required:

```bash
# on the scanned host: the record lives under the store
scp db01:~/.linux_secbench/scans/db01/20260610T...-db01-L2s.json ./

# on your workstation (no store, no agent): regenerate every format, or serve it
secbench report -f ./20260610T...-db01-L2s.json -o ./db01-reports   # all formats into a dir
secbench serve  -f ./20260610T...-db01-L2s.json      # interactive triage, 127.0.0.1
secbench diff   old-db01.json new-db01.json          # compare two exported scans
```

`-o` is a **directory** (all formats by default; `--format` narrows, e.g.
`--format html`). `--file/-f` never reads or creates a store. Trend lines don't
appear in file mode (a single moved record has no history — that's honest, not
missing). False
-positive suppressions default to a sibling `<scan>.json.suppressions.json` so a
review travels with its file; point elsewhere with `--suppressions PATH`.

### Remote fleet (non-Ubuntu servers)

```bash
secbench scan --host web01 --user ops --identity ~/.ssh/ops --sudo --format html
```

SSH execution shells out to your system `ssh` client (inheriting your config,
agent, and jump hosts) with `BatchMode=yes` so a missing key fails fast instead
of hanging. On a non-Ubuntu host the portable checks still run; the report flags
that the CIS-Ubuntu mapping is *approximate* rather than claiming a false
compliant verdict.

---

## Why it exists

A pass/fail percentage is not a security posture. SecBench treats the benchmark
as the *floor*, then layers on the questions a real assessment asks — who can
become root, where credentials are leaking, what is unexpectedly setuid or
listening — and presents the result so an engineer knows exactly what to fix
first and an executive can read the grade at a glance.

## What it checks

**CIS Ubuntu 24.04 Benchmark v2.0.0** across all 7 sections — deterministic,
automated checks mapped to the benchmark (full §1–§7 re-base complete; see
[dev_notes.md](dev_notes.md) for the section-by-section coverage table). Each
control is assessed deterministically:

| Section | Coverage |
|---|---|
| 1 Initial Setup | filesystem kernel modules, mount options, AppArmor, bootloader, process-hardening sysctls, banners |
| 2 Services | unneeded server daemons, insecure clients, time sync, cron/at hardening |
| 3 Network | protocol-module disablement, IPv4/IPv6 hardening sysctls, wireless |
| 4 Firewall | single-firewall enforcement, ufw/nftables default-deny |
| 5 Access | SSH server, sudo policy, PAM quality & lockout, login.defs aging |
| 6 Logging | auditd presence/immutability/retention, journald/rsyslog, log perms |
| 7 Maintenance | passwd/shadow/group perms, world-writable & unowned files, DB integrity |

**Extended security audit (75 checks, beyond CIS)** — `framework = Security`,
reported separately from formal compliance:

- **Exploitable privilege escalation** — the vectors a pen-tester actually
  uses, cross-referenced against a GTFOBins-style knowledge base: sudo to a
  shell-capable binary, the `SETENV`/`NOPASSWD` tags, exploitable setuid
  binaries and file capabilities, membership in root-equivalent groups
  (`docker`, `lxd`, `disk`, `shadow`), and writable units/cron a root process
  executes — plus a writable directory or `.` on root's `PATH`,
  `ld.so.preload` injection, the PwnKit (CVE-2021-4034) pkexec check, polkit
  rules, NFS `no_root_squash`, writable `ExecStart` targets, risky sudoers
  `Defaults` (secure_path/env_keep/!authenticate), writable critical files
  (`/etc/passwd`, `/etc/sudoers`, …), over-permissive container sockets, and
  writable timers / queued `at` jobs. Each emits a structured escalation edge
  for the attack-path analysis below.
- **Credential hunting (native, no dependencies)** — secrets in
  readable config files, exposed/unencrypted private keys, passwords in shell
  history, live process **environment** *and* **command-line** exposure
  (`/proc/<pid>/environ` + `/proc/<pid>/cmdline` — the whole `ps auxe`), and a
  **filename-heuristic sweep** that catches credential files by *name* rather
  than an extension allowlist (`.rdp_pass`, `vpn.ovpn`, `*.kdbx`, `.env`, …) —
  plus secrets baked into cron/systemd units, web-app configs
  (`wp-config.php`, `settings.py`), git credential leaks, backup/swap files,
  Kerberos keytabs/ccaches, risky `authorized_keys`, and cloud/IaC creds
  (gcloud, azure, `*.tfstate`). Detection blends known-pattern matching with
  statistical (Dempster–Shafer) scoring to keep false positives down; secret
  values are redacted unless `--reveal-secrets` is passed.
- **In-memory credential recovery (native mimipenguin) — `--active-review`** —
  the actual mimipenguin technique, built in with no external tool: it reads the
  heap of login processes (gdm, lightdm, gnome-keyring, sshd, vsftpd, …) via
  `/proc/<pid>/mem`, extracts candidate strings near per-process anchors, and
  **confirms each against `/etc/shadow`** — so a finding is only ever a
  cryptographically verified password, never a guess. sha-crypt (`$5$`/`$6$`) is
  verified natively in pure Python; yescrypt/bcrypt fall back to the host's
  `crypt(3)`. Because it reads other processes' memory it is **intrusive,
  root-only, local-only, and opt-in** — it runs only under `--active-review`
  (every other run reports it SKIP). The external `mimipenguin`/`lynis` tools
  remain optional independent cross-checks if installed.
- **Persistence & backdoor hunting** — fetch-and-execute payloads in scheduled
  jobs (`curl|bash`, base64, `/dev/tcp`), `rc.local`/init content, PAM
  tampering (`pam_exec`), hidden files in scratch dirs, immutable-bit abuse,
  world-writable PATH binaries, package-integrity drift (`dpkg --verify` /
  `rpm -Va`), recently-modified system binaries, writable MOTD/`profile.d`
  login scripts, and a consolidated backdoor-account/setuid indicator.
- **Kernel & runtime hardening** — ASLR, `ptrace_scope`, setuid core dumps,
  `kptr_restrict`/`dmesg_restrict`, unprivileged user namespaces, `perf_event`,
  unprivileged BPF, swap encryption, runtime `nodev/nosuid/noexec` on scratch
  mounts (from `/proc/mounts`, not just fstab), and a running-kernel advisory
  for local-privesc CVE review.
- **Accounts & privilege** — second UID-0 (backdoor) detection, sudo/admin
  inventory, system accounts with login shells, non-expiring passwords, a
  statistical outlier scan over password ages, plus duplicate UID/GID,
  empty-password accounts, expired-but-enabled accounts, never-logged-in
  accounts, direct-root-login exposure, and a weak default umask.
- **Defensive posture** — whether anyone is watching: AppArmor/SELinux in
  enforce vs complain/disabled, auditd running with an actual rule set,
  brute-force protection (fail2ban/sshguard), and remote log forwarding.
- **Filesystem** — unexpected SUID/SGID binaries vs a baseline, dangerous file
  capabilities, world-writable dirs missing the sticky bit.
- **Network exposure** — non-loopback listening-service inventory, sensitive
  services (DBs, RDP, VNC, SMB) exposed to all interfaces.
- **System state** — pending security updates, pending reboot.
- **Optional integrations** — runs `mimipenguin` / `lynis` *if already
  installed*; otherwise a clean SKIP with an install hint. Nothing is
  auto-downloaded.

**Kiosk-breakout checks (57, opt-in via `--kiosk`)** — for locked-down
single-app machines (info kiosks, sign-in screens, digital signage): full-DE
detection, display-manager/autologin/guest/greeter posture, keyboard & window
-manager lockdown, accessibility hotkeys, data-exfil paths (print/save/
screenshot/clipboard/recent), Chrome/Chromium & Firefox kiosk policy, console &
boot (VT switching, sysrq, Ctrl-Alt-Del, GRUB, USB), network/remote listeners,
autostart, and dconf-lock integrity — the ways a user escapes the kiosk app.
Off by default, since they're noise on a normal box. GNOME-first, extensible to
other desktops.

## Analytics & scoring

The analysis layer applies quantitative techniques drawn from several
disciplines to turn raw findings into priorities — all implemented in pure
standard library, no external dependencies:

- **Risk-weighted posture** — each finding is scored by severity, result, and
  detection confidence, then aggregated into a 0–100 posture score and an A–F
  grade. Two hosts with the same pass rate score differently when one is failing
  criticals.
- **Statistical secret & anomaly detection** — the credential scanner and
  account audit use statistical scoring to separate genuine secrets and
  anomalous accounts from noise, keeping false positives low.
- **Trend & drift detection** — across rescans, compliance is smoothed and
  monitored so a genuine regression is flagged rather than single-scan noise.
- **Risk concentration** — highlights the few areas carrying most of the risk so
  remediation effort lands where it pays.
- **Attacker-value re-ranking** — the same findings, re-scored by *offensive*
  value (see below).

## Top penetration-tester targets

Risk scoring answers *what is most broken*; it does not answer *what an attacker
hits first*. A passwordless account or a readable private key is an opening move
regardless of CVSS band, while a missing login banner has near-zero offensive
value. So every report includes a **Top 10 Penetration-Tester Targets** list:
findings mapped to an attacker tactic — **Credential Access, Privilege
Escalation, Vulnerable Software, Initial Access, Persistence, Defense Evasion** —
and ranked by how much that capability is worth to an attacker and how
exploitable it is. It tells a red-teamer where to start and a defender which
gaps actually get them owned. The mapping is driven by the tags checks already
carry, so it stays current as checks are added.

## Attack paths & chokepoints

Going a step further than ranking individual findings, SecBench assembles them
into a **local privilege-escalation attack graph** — nodes are privilege states,
edges are concrete exploitation steps (the exploitable-privilege findings
above) — and reasons over it:

- **Attack paths** — the end-to-end chains, e.g. `attacker → (exposed service)
  → local shell → (sudo python3 with SETENV) → root`. This is the vector, not
  just the condition.
- **Chokepoints** — the minimum set of fixes that makes root unreachable from a
  local foothold. When five users sit in the `docker` group, the chokepoint is
  the one group capability, not five memberships — "fix this and the path is
  gone."
- **Highest-leverage weaknesses** — which findings the most attack paths route
  through, so remediation effort has the widest blast radius.

## Two views: prevent foothold vs. prevent escalation

The report splits the findings into the two ways a host actually gets owned, so
you can tackle them separately:

- **Prevent foothold** — stop an attacker getting onto the box *from the
  network* in the first place. The "estimated chance an attacker can get in"
  counts **only network-reachable entry weaknesses** — a sensitive service
  exposed on a non-loopback socket, a remotely brute-forceable login. Local
  exposures that presuppose a shell (world-readable keys, secrets in files,
  shell history, in-memory credentials) are **not** counted here — they can't be
  reached from outside. When no network entry vector is found, the report says
  so plainly rather than inventing one: initial access is assumed (phishing, an
  app bug, a stolen password) and the analysis moves to escalation.
- **Assume foothold → prevent escalation** — assume they already have a shell and
  stop them reaching root. This view is where local credential access lands: a
  world-readable private key is a lateral-movement / escalation asset for an
  attacker who is *already* on the box, not proof they can get in.

Each view carries a plain-English "estimated chance of compromise" figure for
comparison and trend. In the HTML report you toggle between the two with a tab.

## Triage: scope filtering, ATT&CK, and false positives

- **ATT&CK mapping** — every finding carries MITRE ATT&CK technique ids (e.g.
  setuid → `T1548.001`, an exposed service → `T1046`), shown in the HTML detail,
  terminal `--verbose`, and JSON; the attacker tactics map to ATT&CK tactic ids.
- **Scope filter (HTML)** — a scope selector (All / CIS / Security / Kiosk) that
  filters the findings and **recomputes the grade/score for just that scope**,
  entirely client-side (no server).
- **False positives / accepted risk** — `secbench suppress <id> --reason "…"`
  records a suppression the reports honor as an *overlay*: the raw scan stays
  intact, but the finding leaves the score and moves to a "Suppressed" section.
  Suppressions are **host-scoped by default** (an FP on one host may be real on
  another); use `--all-hosts` for a check that's wrong everywhere. They're
  per-host, not per-scan, so a confirmed FP persists across that host's scans.
  In the HTML you can tick findings and **Export suppressions** (with an "apply
  to all hosts" toggle); or run **`secbench serve`** — a local-only (127.0.0.1,
  no-auth) web view where ticking a finding and "Save to server" persists it live
  (scoped to that host), plus a **Regenerate report files** button. (`serve`
  refuses a non-loopback bind without `--i-understand-exposure`.)

## Reporting

One scan, five renderers, all consistent (they share a single precomputed
analysis bundle):

- **terminal** — colour-coded, read top-down: grade → counts → risk
  concentration → attack paths & chokepoints → top attacker targets → trend →
  prioritized findings.
- **html** — a single self-contained file (inline CSS + hand-built SVG donut,
  bar, risk-concentration and trend charts), no external requests, prints
  cleanly.
- **json** — canonical machine-readable export for CI and diffing.
- **csv** — one row per control, for auditors in spreadsheets.
- **markdown** — for tickets, wikis, and PR bodies.

## Resumability, rescanning, history

Scans persist as per-host JSON under `~/.linux_secbench/scans` (override with
`--store`). From that you get:

- **Resume** — `--resume` continues the most recent interrupted scan for the
  same target; the runner checkpoints every 15 checks, so a `kill -9` mid-scan
  loses nothing.
- **Rescan & trend** — re-running appends a record; `history` shows the
  compliance trend and any regression.
- **Diff** — `secbench diff <old> <new>` shows what was fixed and what
  regressed between two scans.

## Extending it

Adding a check is adding a function — it self-registers, no list to maintain:

```python
from linux_secbench.core import check, Outcome, Severity, Level

@check(
    id="5.1.99",
    title="Ensure SSH uses a non-default port",
    section="5.1 SSH Server",
    severity=Severity.LOW,
    levels=(Level.L2,),
    remediation="Set 'Port' to a non-22 value in sshd_config.",
    tags=("ssh",),
)
def ssh_nondefault_port(ctx):
    port = ctx.sshd_config().get("port", "22")
    if port != "22":
        return Outcome.passed(f"sshd listens on {port}", actual=port)
    return Outcome.warn("sshd listens on the default port 22", actual=port)
```

Drop it in a module under `linux_secbench/checks/` and it appears in the next
scan and in `list-checks`. Supporting a new distro is mostly teaching
`system/platform.py` to classify it; portable checks then adapt automatically.

## Architecture

```
core/         framework primitives — data model, Check, registry, runner
system/        executor (local/SSH), platform detection, caching SystemContext
checks/cis/    CIS controls, one module per benchmark section
checks/extended/ beyond-CIS security audits
analysis/      risk scoring + statistical analysis
reporting/     terminal · html · json · csv · markdown (one shared bundle)
persistence/   per-host JSON store → resume, rescan, history
cli.py          argument parsing, orchestration, exit codes
```

Layering is strict and one-directional: checks depend on `core` + `system`,
never on each other; reporters depend only on the model and analysis; the
runner knows execution policy but not what any check does.

## Testing

```bash
python3 -m pytest tests/ -q
```

The suite drives the entire pipeline through a deterministic in-memory
`FakeHost` (no real system access): platform detection, check execution,
risk scoring, every report format, persistence round-trip, resume, and diff —
plus unit tests for the analysis primitives. A degraded-host pass asserts no
check ever crashes; intentional misconfigurations baked into the fake host
assert the checks actually catch them.

## Scope & honesty notes

- CIS coverage is a high-value subset, not a 1:1 transcription of all ~250
  controls; the framework imposes no cap and new controls are mechanical to add.
- Heuristic findings (secret-detection, anomaly, baseline comparison) carry a
  realistic *confidence* so risk scoring never treats a guess like a certainty,
  and they are labelled as leads to review.
- This is an **authorized self-assessment / defensive** tool. Run it on systems
  you own or are authorized to test.

## License

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). © 2026 fvsion (Brennon Stovall).
```
