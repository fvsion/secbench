# Linux SecBench — User Guide

A complete operator's manual for running scans, understanding **where every file
goes**, and **moving a scan to another machine to review it off-box**.

For *what* the tool checks and the analysis behind the reports, see
[README.md](README.md). This guide is about *operating* it.

---

## Table of contents

1. [Install & run](#1-install--run)
2. [The mental model: two file locations](#2-the-mental-model-two-file-locations)
3. [Report formats & the `-o` rules](#3-report-formats--the--o-rules)
4. [Command reference](#4-command-reference)
5. [Moving a scan to another machine (off-box review)](#5-moving-a-scan-to-another-machine-off-box-review)
6. [Secrets & safety flags](#6-secrets--safety-flags)
7. [Cleaning up](#7-cleaning-up)
8. [Automation & exit codes](#8-automation--exit-codes)
9. [Quick reference card](#9-quick-reference-card)

---

## 1. Install & run

SecBench is **pure Python ≥ 3.8 with zero third-party dependencies** — only the
standard library. There is nothing to `pip install` to run it.

Three equivalent ways to invoke it:

```bash
python3 secbench.py <command> [options]      # standalone launcher (from the repo)
python3 -m linux_secbench <command> [options] # module form
secbench <command> [options]                  # console script, if you `pip install .`
```

This guide uses `python3 secbench.py` throughout; substitute whichever you prefer.

The simplest possible run — assess this machine, auto-detect the profile, print
to the terminal:

```bash
python3 secbench.py scan
```

> SecBench is a **defensive self-assessment** tool. Run it on systems you own or
> are authorized to assess.

---

## 2. The mental model: two file locations

This is the single most important thing to understand. SecBench writes to **two
completely separate places**, for two different purposes:

| | **Reports** | **Resume / history store** |
|---|---|---|
| **What** | Shareable artifacts you read & send (HTML, JSON, CSV, Markdown) | The tool's own record of past scans |
| **Controlled by** | `-o/--output DIR` | `--store DIR` |
| **Default location** | *not written unless you pass `-o`* | `~/.linux_secbench/scans` |
| **Used for** | Reading, archiving, sharing, off-box review | `--resume`, `history`, `diff`, trends |
| **Safe to delete?** | Yes — they're yours | Yes — via `secbench clean` (only the store) |

A third, smaller file — **suppressions** (your false-positive / accepted-risk
decisions) — lives alongside the store by default. More in
[§5](#5-moving-a-scan-to-another-machine-off-box-review) and
[§4 suppress](#suppress--unsuppress--suppressions).

### Where things land on disk

```
~/.linux_secbench/scans/                 ← the STORE (--store), one dir per host
├── db01/
│   ├── 20260612T074221-db01-L2s.json    ← one scan record (self-describing)
│   └── 20260613T091500-db01-L2s.json
├── localhost/
│   └── 20260612T080000-localhost-L2w.json
└── suppressions.json                    ← your suppression decisions (shared)

./reports/                               ← wherever you point -o (REPORTS)
├── secbench-db01-20260612T074221-db01-L2s.html
├── secbench-db01-20260612T074221-db01-L2s.json
├── secbench-db01-20260612T074221-db01-L2s.csv
└── secbench-db01-20260612T074221-db01-L2s.md
```

**Key facts:**

- **Every scan is recorded in the store automatically** (so `--resume`, `history`
  and trends work), *whether or not* you pass `-o`. A scan with `-o` does both:
  writes the report files **and** records to the store.
- **Report files are only written when you pass `-o`.** Without `-o`, you just get
  the terminal view on stdout; nothing is written to disk (the store record still
  happens).
- Under `sudo`, `~` is root's home, so the store is at
  `/root/.linux_secbench/scans`. That's normal and expected — point `--store`
  elsewhere if you prefer.
- Report filenames are `secbench-<host>-<scan-id>.<ext>`. The scan id encodes
  timestamp + host + level/profile (e.g. `20260612T074221-db01-L2s` = a Level-2
  Server scan; `L2w` = Level-2 Workstation).

---

## 3. Report formats & the `-o` rules

Five formats are available:

| Format | Extension | Written to disk? | Notes |
|---|---|---|---|
| `terminal` | `.txt` | Only if explicitly named in `--format` | The interactive stdout view (colourized) |
| `html` | `.html` | Yes | Self-contained, interactive (tabs, drill-down, sortable table) |
| `json` | `.json` | Yes | Machine-readable full report; **reviewable off-box** with `report -f` |
| `csv` | `.csv` | Yes | One row per finding; good for spreadsheets |
| `markdown` | `.md` | Yes | Good for tickets / wikis / PRs |

**"All formats"** means the four file formats — `csv, html, json, markdown`
(everything except `terminal`).

The `-o` / `--format` rules are identical for both `scan` and `report`:

| You run | What you get |
|---|---|
| *(no `-o`)* | The `terminal` view on **stdout**. No files written. |
| `-o DIR` *(no `--format`)* | **All four** file formats written to `DIR`. |
| `-o DIR --format html json` | **Only** those formats written to `DIR`. |
| `--format json` *(no `-o`, `report` only)* | That single format printed to **stdout**. |

```bash
python3 secbench.py scan -o ./reports                 # → 4 files in ./reports/
python3 secbench.py scan -o ./reports --format html   # → just the .html
python3 secbench.py scan                              # → terminal only, no files
```

---

## 4. Command reference

Top-level usage:

```
secbench [--store DIR] {scan,list-checks,history,report,hosts,
                        suppress,unsuppress,suppressions,serve,clean,diff} ...
```

`--store DIR` is global (default `~/.linux_secbench/scans`) and applies to any
command that reads or writes the store.

### `scan` — run an assessment

```bash
python3 secbench.py scan [options]
```

**What to assess**

| Flag | Meaning |
|---|---|
| `--profile {auto,server,workstation}` | Benchmark profile (default: `auto`-detect). |
| `--level {1,2}` | CIS hardening level; L2 includes L1 (default: `2`). |
| `--sections N [N ...]` | Only these section prefixes, e.g. `--sections 5 6.1`. |
| `--ids ID [ID ...]` | Only these exact check ids, e.g. `--ids 1.5.1 EXT-CRED-2`. |
| `--tags TAG [TAG ...]` | Only checks carrying any of these tags. |
| `--no-extended` | Only formal CIS checks; skip the extended Security audits. |
| `--kiosk` | *Also* run kiosk-breakout checks (off by default). |

**Where to assess (omit all to scan this machine)**

| Flag | Meaning |
|---|---|
| `--host HOST` | Assess a remote host over SSH. |
| `--user USER` | SSH user. |
| `--port PORT` | SSH port (default: `22`). |
| `--identity KEY`, `-i KEY` | SSH private key file. |
| `--sudo` | Run remote checks via `sudo -n` (passwordless sudo required). |

**Output & behavior**

| Flag | Meaning |
|---|---|
| `--format FMT [FMT ...]` | Format(s); default `terminal`. See [§3](#3-report-formats--the--o-rules). |
| `--output DIR`, `-o DIR` | Write report files here (all formats by default). |
| `--resume` | Resume the most recent interrupted scan for this target. |
| `--reveal-secrets` | Put **full plaintext** secrets in evidence (see [§6](#6-secrets--safety-flags)). |
| `--active-review` | Enable intrusive in-memory credential recovery (see [§6](#6-secrets--safety-flags)). |
| `--fail-on {none,low,medium,high,critical}` | Exit non-zero if a finding ≥ this severity exists (CI). |
| `--quiet`, `-q` | Suppress the live terminal report (files still written). |
| `--verbose`, `-v` | Include evidence + remediation in the terminal report. |
| `--no-color` / `--color` | Force colour off / on. |

```bash
python3 secbench.py scan --level 2 --profile server -o ./reports
python3 secbench.py scan --host db01 --user ops --sudo --format html json -o ./out
python3 secbench.py scan --sections 5 6.1 --verbose
python3 secbench.py scan --kiosk            # for locked-down single-app machines
```

### `list-checks` — see the catalogue

```bash
python3 secbench.py list-checks [--section N ...] [--framework {CIS,Security} ...] [--tags TAG ...]
```

### `history` — a host's scans & trend

```bash
python3 secbench.py history [--host HOST]
```
Lists every stored scan for the host (oldest first) with compliance %, risk, and
finding counts, plus the trend summary. Reads the **store**.

### `hosts` — list hosts with stored scans

```bash
python3 secbench.py hosts
```

### `report` — re-render a stored scan, or a scan JSON from another host

```bash
python3 secbench.py report [scan_id] [options]
```

| Flag | Meaning |
|---|---|
| `scan_id` (positional) | A scan id from `history` (resolved via the store). |
| `--file PATH`, `-f PATH` | Render this scan JSON **directly — no store needed** (off-box review). |
| `--host HOST` | Host the scan belongs to (searched if omitted). |
| `--format FMT [FMT ...]` | Format(s); same `-o` rules as `scan`. |
| `--output DIR`, `-o DIR` | Write report files here (all formats by default). |
| `--suppressions PATH` | Suppressions JSON to overlay (default: the store's, or a sibling of `--file`). |

```bash
python3 secbench.py report 20260612T074221-db01-L2s --host db01 -o ./out
python3 secbench.py report -f /tmp/moved.json -o ./review     # off-box, no store
python3 secbench.py report -f /tmp/moved.json --format html > review.html
```

If you give neither a `scan_id` nor `--file`, it exits with a usage hint. A bad
`--file` path exits `2` with a file-aware error.

### `suppress` / `unsuppress` / `suppressions`

Record a finding as a false positive or accepted risk; it then leaves the score
and moves to a "Suppressed / accepted" section of the report.

```bash
python3 secbench.py suppress EXT-PRIV-2 --reason "mount is setuid by design"  # this host only
python3 secbench.py suppress 5.1.2 --host db01 --kind accepted-risk --reason "jump box, console-only"
python3 secbench.py suppress EXT-MON-1 --all-hosts --reason "check is over-broad everywhere"
python3 secbench.py unsuppress EXT-PRIV-2
python3 secbench.py suppressions                 # list active suppressions
```

| `suppress` flag | Meaning |
|---|---|
| `check_id` (positional) | The check to suppress, e.g. `EXT-PRIV-2`. |
| `--reason TEXT` | Why (recorded for audit). |
| `--kind {false-positive,accepted-risk,excluded}` | Default `false-positive`. |
| `--host HOST` | The host this applies to (**default: this machine**). |
| `--all-hosts` | Apply on every host — only for a check that's a false positive everywhere. |

**Suppressions are host-scoped by default.** A false positive on one host may be
a real finding on another, so a bare `suppress` (or the FP boxes in the HTML
report) records the decision **for that host only**. Pass `--host` to target a
different host, or `--all-hosts` (HTML: the *"apply to all hosts"* checkbox) for
a genuinely tool-wide false positive. Suppressions are **per-host, not
per-scan** — a confirmed FP persists across that host's future scans, so you
don't re-triage it every run. They live in **one shared
`<store>/suppressions.json`** (a sibling `<scanfile>.suppressions.json` in file
mode, or wherever `--suppressions` points) — see
[§5](#5-moving-a-scan-to-another-machine-off-box-review).

### `serve` — interactive triage (local-only)

```bash
python3 secbench.py serve [--scan-id ID | --file PATH] [--host HOST] [--port 8765] [--bind 127.0.0.1]
```
Serves the HTML report with a tiny zero-dependency web server and **live**
suppress/unsuppress buttons that persist through the suppressions file.

| Flag | Meaning |
|---|---|
| `--scan-id ID` | Scan to serve (default: latest for the host). |
| `--file PATH`, `-f PATH` | Serve a scan JSON directly — no store needed. |
| `--host HOST` | Host whose scan to serve (default: this machine). |
| `--port PORT` | Default `8765`. |
| `--bind ADDR` | Default `127.0.0.1` (loopback only). |
| `--suppressions PATH` | Suppressions JSON to read/write. |
| `--report-dir DIR` | Where the **Regenerate report files** button writes (default: the `--file`'s folder, else CWD). |
| `--i-understand-exposure` | **Required** to bind a non-loopback address. |

**Marking false positives, and refreshing the files.** Tick a finding's FP box
and click **💾 Save to server** — the suppression is written to the
`suppressions.json` (the *scan JSON is never modified*; suppressions are an
overlay). That updates the live page, but your on-disk HTML/CSV/MD/JSON are still
the old ones. Click **⤓ Regenerate report files** to rewrite all four formats
(with the current suppressions applied) into `--report-dir`. So the full loop is:
serve → tick FPs → Save → Regenerate → fresh report files on disk, without ever
leaving the browser. (You can still do it from the CLI instead:
`report -f scan.json -o ./reports --suppressions scan.json.suppressions.json`.)

By design `serve` binds loopback only and has **no authentication**. It refuses a
non-loopback `--bind` unless you pass `--i-understand-exposure`, and warns loudly
when you do. Treat it as a local triage tool, not a hosted service.

### `clean` — remove the store

```bash
python3 secbench.py clean [--host HOST] [--dry-run] [--yes]
```
Removes **only the resume/history store** (or one host's subdir with `--host`).
It never touches report files written with `-o`, or anything else. See
[§7](#7-cleaning-up).

### `diff` — compare two scans

```bash
python3 secbench.py diff <old> <new> [--host HOST]
```
Each of `old`/`new` may be a **stored scan id** *or* a **path to a scan JSON
file** — so you can compare two exported scans off-box. Shows compliance delta,
fixed findings, regressions, and still-failing findings.

```bash
python3 secbench.py diff 20260601T..-db01-L2s 20260612T..-db01-L2s --host db01
python3 secbench.py diff /tmp/old.json /tmp/new.json     # off-box, no store
```

---

## 5. Moving a scan to another machine (off-box review)

**The scenario:** you scan a server, but you want to read and triage the results
on a different machine — an analyst workstation, an air-gapped review box — where
SecBench's local store doesn't exist.

**Why it just works:** a scan is **fully self-describing** — it carries its own
host name, target (profile + level), every finding with full metadata, and the
collected host facts. `report -f` (and `serve -f` / `diff`) accept **either** of
the two JSON layouts SecBench writes — the raw **store record** *or* the full
**`-o` JSON report** (which nests the record under a `"scan"` key) — so whichever
`.json` you grab will load. Loading a standalone file needs **no store
directory**, and reviewing one **never creates** a store on the review machine.

### Step 1 — Get a scan JSON off the scanned host

Either grab the raw record from the store…

```bash
# on the scanned host
ls ~/.linux_secbench/scans/$(hostname)/
cp ~/.linux_secbench/scans/$(hostname)/20260612T074221-*-L2s.json /tmp/scan.json
```

…or scan straight into a folder and take the `.json` report from there:

```bash
# on the scanned host
python3 secbench.py scan -o /tmp/out
# /tmp/out/secbench-<host>-<id>.json is the full JSON report — also loadable with `report -f`
```

### Step 2 — Copy it to the review machine

Any transport works — it's just a JSON file:

```bash
scp /tmp/scan.json analyst@review-box:/home/analyst/incoming/
# or USB, or email, or an artifact store
```

### Step 3 — Review it anywhere, no store required

On the review machine (which may have never run a scan):

```bash
# Regenerate all four report formats into a folder
python3 secbench.py report -f ~/incoming/scan.json -o ./review

# Or render a single format to stdout / a file
python3 secbench.py report -f ~/incoming/scan.json --format html > review.html

# Or triage interactively in a browser (loopback)
python3 secbench.py serve -f ~/incoming/scan.json
#  → open http://127.0.0.1:8765 ; suppress/unsuppress buttons persist to
#    ~/incoming/scan.json.suppressions.json (a sibling file, self-contained)

# Or compare two exported scans
python3 secbench.py diff ~/incoming/old.json ~/incoming/new.json
```

### What travels, and what doesn't

- **Suppressions in file mode** are kept in a **sibling file**
  `<scanfile>.suppressions.json`, so a moved review stays self-contained. Pass
  `--suppressions PATH` to point elsewhere, or copy that sibling along with the
  scan to carry your decisions.
- **Trends/history do not travel.** A single moved file has no history, so trend
  lines simply don't render off-box — that's honest, not a bug. Trends live with
  the **store on the original host**; use `history` / `diff` there for trends.

---

## 6. Secrets & safety flags

SecBench can surface credential material. It defaults to the safe behavior; the
intrusive options are explicit opt-ins that print a warning when enabled.

- **Redaction is the default.** Detected secrets show a redacted preview (e.g.
  `aZ…y6` + length), never the full value.
- **`--reveal-secrets`** puts the **full plaintext** secret into the report.
  Useful for rotation, but the report file then *contains live secrets* — handle
  and store it accordingly. SecBench warns when you pass it.
- **`--active-review`** enables **in-memory credential recovery** (check
  `EXT-CRED-16`): it reads the heap of login-related processes and confirms any
  recovered password against `/etc/shadow`. It is **intrusive, root-only, and
  local-only**, and **off by default** — a routine scan reports it as SKIP. It
  degrades to MANUAL when not root or not local. Recovered values are redacted
  unless you also pass `--reveal-secrets`.
- **`serve` is loopback-only** with no auth; non-loopback binds require
  `--i-understand-exposure`.

---

## 7. Cleaning up

`clean` is deliberately narrow: it removes **only the store** under `--store`.

```bash
python3 secbench.py clean --dry-run            # show what would be removed; delete nothing
python3 secbench.py clean --host db01 --yes    # remove just db01's history
python3 secbench.py clean --yes                # remove the whole store
```

- It **never** deletes report files written with `-o`, or anything outside the
  store path (there's a hard guard).
- Without `--dry-run` or `--yes` it asks for confirmation; in a non-interactive
  shell with no `--yes` it refuses rather than hang.
- To remove **reports**, just delete the folder you passed to `-o` — those are
  plain files SecBench will never touch on its own.

---

## 8. Automation & exit codes

- **`--fail-on <severity>`** makes `scan` exit non-zero when any finding at or
  above that severity exists — drop it straight into CI:

  ```bash
  python3 secbench.py scan --no-extended --fail-on high -o ./reports --quiet || echo "gate failed"
  ```

- **`--quiet`** suppresses the terminal view while still writing files — ideal for
  pipelines that only want the artifacts.
- The **JSON report** (and the store record) is the stable machine-readable
  surface for downstream tooling; every finding carries its status, severity,
  evidence, remediation, and MITRE ATT&CK technique ids.

---

## 9. Quick reference card

```bash
# Assess this machine, all reports into ./reports
python3 secbench.py scan -o ./reports

# Assess a remote host over SSH with sudo, HTML + JSON only
python3 secbench.py scan --host db01 --user ops --sudo --format html json -o ./out

# CI gate: fail the build on any HIGH+ finding, artifacts only
python3 secbench.py scan --fail-on high -o ./reports --quiet

# Review a scan copied from another machine (no store needed)
python3 secbench.py report -f ./scan.json -o ./review
python3 secbench.py serve  -f ./scan.json            # http://127.0.0.1:8765

# Compare two exported scans
python3 secbench.py diff ./old.json ./new.json

# Manage findings you've judged
python3 secbench.py suppress EXT-PRIV-2 --reason "by design"
python3 secbench.py suppressions

# Trends & history (reads the store on the scanning host)
python3 secbench.py history --host db01

# Remove the store (never your -o reports)
python3 secbench.py clean --dry-run
```

| I want to… | File location |
|---|---|
| Read / share a report | The folder you passed to `-o` (`secbench-<host>-<id>.<ext>`) |
| Find a JSON to review off-box | The store record `~/.linux_secbench/scans/<host>/<id>.json`, **or** the `.json` report in your `-o` folder — `report -f` loads either |
| Find my suppressions | `~/.linux_secbench/scans/suppressions.json` (or `<scanfile>.suppressions.json` off-box) |
| Free up space | `secbench clean` (store), or delete your `-o` folders (reports) |

---

*Linux SecBench — defensive CIS & security assessment. Apache-2.0 licensed; see
[LICENSE](LICENSE).*
