"""Kiosk breakout checks (opt-in via --kiosk).

A kiosk is a locked-down machine meant to run exactly one thing — a browser, a
sign-in screen, a digital sign. The whole security model is "the user can only
use the kiosk app." A *breakout* is anything that lets them escape that app to a
shell, a file manager, another app, or a fresh login: a keyboard shortcut, a
gesture, a help link that opens a browser, switching to a text console with
Ctrl+Alt+F2, the on-screen keyboard, sticky-keys, and so on.

These checks look for the settings that leave those doors open. They target
Ubuntu's default GNOME desktop (settings live in dconf/gsettings) plus the
generic X/console controls, and are written to be honest about what they can't
see: if a setting can't be read (no desktop session reachable from the scan),
the check says "review this manually" rather than guessing.

This is its own class of check (`framework = "Kiosk"`) and does not run unless
you pass ``--kiosk`` — the settings are irrelevant noise on a normal box.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence

from ...core import Confidence, Level, Outcome, Profile, Severity, check

KIOSK_FRAMEWORK = "Kiosk"


def _gsettings(ctx, schema: str, key: str) -> Optional[str]:
    """Read a GNOME setting, or None if it can't be read from this scan."""
    res = ctx.run(["gsettings", "get", schema, key])
    return res.out if res.ok and res.out else None


def _dconf_locked(ctx, key_path: str) -> bool:
    """Whether a dconf key is *locked* (users can't override the kiosk policy).

    A setting that is configured but not locked is only a speed bump — the
    logged-in kiosk user can change it back. Locks live under the dconf db
    ``locks/`` directories.
    """
    res = ctx.sh(f"grep -rqs '{key_path}' /etc/dconf/db/*/locks/ /etc/dconf/db/local.d/locks/ 2>/dev/null; echo $?")
    return res.out.strip().endswith("0")


def _kiosk_check(**kw):
    kw.setdefault("framework", KIOSK_FRAMEWORK)
    kw.setdefault("profiles", (Profile.WORKSTATION, Profile.SERVER))
    kw.setdefault("levels", (Level.L1,))
    tags = tuple(kw.pop("tags", ()))
    kw["tags"] = ("kiosk",) + tags
    return check(**kw)


@_kiosk_check(
    id="KIOSK-1",
    title="Ensure switching to a text console (VT) is disabled",
    section="EXT.Kiosk",
    severity=Severity.HIGH,
    rationale="Ctrl+Alt+F2..F6 drops to a login console — a full shell outside the kiosk app. A kiosk should disable VT switching.",
    remediation="Set 'DontVTSwitch' = true in an /etc/X11/xorg.conf.d snippet, or restrict logind NAutoVTs=1; on Wayland, disable the VT-switch keybindings.",
    tags=("breakout", "console"),
)
def vt_switch_disabled(ctx):
    # X11: look for DontVTSwitch in any xorg config.
    xorg = ctx.sh("grep -rils 'dontvtswitch' /etc/X11 2>/dev/null")
    if xorg.out and "true" in (ctx.sh("grep -rhis 'dontvtswitch' /etc/X11 2>/dev/null").out.lower()):
        return Outcome.passed("X11 DontVTSwitch is enabled")
    logind = ctx.parse_keyword_file("/etc/systemd/logind.conf", sep="=")
    nautovts = logind.get("nautovts")
    if nautovts == "0":
        return Outcome.passed("logind NAutoVTs=0 — no spare consoles to switch to")
    return Outcome.warn(
        "Console (VT) switching does not appear to be disabled — Ctrl+Alt+F2 may reach a shell",
        actual={"DontVTSwitch": bool(xorg.out), "NAutoVTs": nautovts},
        expected="DontVTSwitch true or NAutoVTs<=1",
        confidence=Confidence.LIKELY,
    )


@_kiosk_check(
    id="KIOSK-2",
    title="Ensure the command line / run dialog is locked down",
    section="EXT.Kiosk",
    severity=Severity.HIGH,
    rationale="GNOME's disable-command-line stops Alt+F2 'run a command' and terminal access — the most direct breakout.",
    remediation="Set org.gnome.desktop.lockdown disable-command-line = true AND lock it in dconf.",
    tags=("breakout", "gnome", "lockdown"),
)
def command_line_lockdown(ctx):
    val = _gsettings(ctx, "org.gnome.desktop.lockdown", "disable-command-line")
    locked = _dconf_locked(ctx, "/org/gnome/desktop/lockdown/disable-command-line")
    if val is None:
        return Outcome.manual("Could not read GNOME lockdown from this scan; verify disable-command-line is true and locked")
    if val == "true" and locked:
        return Outcome.passed("disable-command-line is true and locked")
    if val == "true":
        return Outcome.warn("disable-command-line is true but NOT locked — the kiosk user can re-enable it", actual=val)
    return Outcome.failed("disable-command-line is not enabled — Alt+F2 / command access is open", actual=val, expected="true (locked)")


@_kiosk_check(
    id="KIOSK-3",
    title="Ensure user switching and logout are disabled",
    section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Switching user or logging out drops the kiosk user back to a greeter/another session — an escape from the locked app.",
    remediation="Set org.gnome.desktop.lockdown disable-user-switching = true and disable-log-out = true, and lock both.",
    tags=("breakout", "gnome", "lockdown"),
)
def user_switching_disabled(ctx):
    sw = _gsettings(ctx, "org.gnome.desktop.lockdown", "disable-user-switching")
    lo = _gsettings(ctx, "org.gnome.desktop.lockdown", "disable-log-out")
    if sw is None and lo is None:
        return Outcome.manual("Could not read GNOME lockdown; verify disable-user-switching and disable-log-out are true")
    if sw == "true" and lo == "true":
        return Outcome.passed("User switching and logout are disabled")
    return Outcome.warn(
        "User switching / logout is not fully locked down",
        actual={"disable-user-switching": sw, "disable-log-out": lo},
        expected="both true",
        confidence=Confidence.LIKELY,
    )


@_kiosk_check(
    id="KIOSK-4",
    title="Review accessibility hotkeys that can break focus or launch tools",
    section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Sticky-keys (tap Shift 5×), the magnifier, and the on-screen keyboard can be triggered by anyone and used to escape or inject keystrokes the kiosk app didn't intend.",
    remediation="Disable the a11y always-on shortcuts you don't need (org.gnome.desktop.a11y.keyboard *-enable = false) and lock them.",
    tags=("breakout", "gnome", "accessibility"),
)
def accessibility_hotkeys(ctx):
    sticky = _gsettings(ctx, "org.gnome.desktop.a11y.keyboard", "stickykeys-enable")
    osk = _gsettings(ctx, "org.gnome.desktop.a11y.applications", "screen-keyboard-enabled")
    if sticky is None and osk is None:
        return Outcome.manual("Could not read a11y settings; verify sticky-keys and on-screen keyboard are off if not needed")
    enabled = [n for n, v in (("sticky-keys", sticky), ("on-screen-keyboard", osk)) if v == "true"]
    if not enabled:
        return Outcome.passed("No always-on accessibility hotkeys enabled")
    return Outcome.warn(f"Accessibility features enabled (review for kiosk): {', '.join(enabled)}", actual=enabled)


@_kiosk_check(
    id="KIOSK-5",
    title="Detect terminal emulators and file managers available as breakout apps",
    section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="If a terminal or file manager is installed, any way to launch an app (a help link, a file dialog, a shortcut) becomes a shell. A kiosk should not ship these.",
    remediation="Remove unneeded terminal emulators / file managers, or confirm the kiosk app cannot spawn them.",
    tags=("breakout", "attack-surface"),
)
def breakout_apps_present(ctx):
    candidates = ["gnome-terminal", "xterm", "konsole", "xfce4-terminal", "kitty", "tilix",
                  "nautilus", "nemo", "dolphin", "thunar", "pcmanfm"]
    present = [c for c in candidates if ctx.run(["sh", "-c", f"command -v {c}"]).ok]
    if not present:
        return Outcome.passed("No common terminal/file-manager breakout apps found")
    return Outcome.warn(f"{len(present)} breakout app(s) installed: {', '.join(present)}",
                        evidence=present, actual=present, confidence=Confidence.LIKELY)


@_kiosk_check(
    id="KIOSK-6",
    title="Review custom keyboard shortcuts that launch applications",
    section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Custom GNOME shortcuts and media keys can be bound to launch a terminal or arbitrary command — a one-keystroke breakout.",
    remediation="Remove custom-keybindings and app-launch media keys not required by the kiosk; lock the schema.",
    tags=("breakout", "gnome", "shortcuts"),
)
def custom_shortcuts(ctx):
    custom = _gsettings(ctx, "org.gnome.settings-daemon.plugins.media-keys", "custom-keybindings")
    if custom is None:
        return Outcome.manual("Could not read custom keybindings; verify none launch a terminal/command")
    # gsettings prints "@as []" when empty.
    if custom.strip() in ("@as []", "[]"):
        return Outcome.passed("No custom application-launch keybindings configured")
    return Outcome.warn("Custom keyboard shortcuts are configured — confirm none launch a shell/terminal",
                        actual=custom, confidence=Confidence.LIKELY)


@_kiosk_check(
    id="KIOSK-7",
    title="Ensure removable-media autorun is disabled",
    section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Autorun/automount of a USB stick lets a passer-by run their own program or open a file manager on the kiosk.",
    remediation="Set org.gnome.desktop.media-handling autorun-never = true (and automount = false) and lock them.",
    tags=("breakout", "gnome", "removable-media"),
)
def autorun_disabled(ctx):
    never = _gsettings(ctx, "org.gnome.desktop.media-handling", "autorun-never")
    if never is None:
        return Outcome.manual("Could not read media-handling settings; verify autorun-never is true")
    if never == "true":
        return Outcome.passed("Removable-media autorun is disabled")
    return Outcome.failed("Removable-media autorun is not disabled", actual=never, expected="true")


@_kiosk_check(
    id="KIOSK-8",
    title="Review touch/touchpad gestures that switch apps or open the overview",
    section="EXT.Kiosk",
    severity=Severity.LOW,
    rationale="Multi-finger gestures and the hot-corner/overview let a user swipe away from the kiosk app to the desktop or other windows.",
    remediation="Disable the GNOME overview gesture / hot-corner and workspace-switch gestures for the kiosk session where supported.",
    tags=("breakout", "gnome", "gestures"),
)
def gestures_review(ctx):
    hot_corner = _gsettings(ctx, "org.gnome.desktop.interface", "enable-hot-corners")
    if hot_corner is None:
        return Outcome.manual("Could not read gesture/hot-corner settings; verify swipe-to-overview and the hot corner are disabled for the kiosk")
    if hot_corner == "false":
        return Outcome.passed("Hot-corner overview is disabled (verify multi-finger gestures separately)")
    return Outcome.warn("Hot-corner overview is enabled — a mouse to the corner opens the activities overview",
                        actual=hot_corner, confidence=Confidence.LIKELY)


# =========================================================================== #
# Expanded kiosk checks (KIOSK-9+). Helpers first, then generated tables, then
# the bespoke checks for sessions, login, browser, console/boot, and privilege.
# =========================================================================== #

# --- helpers --------------------------------------------------------------- #

_FULL_DE = ("gnome-shell", "plasmashell", "xfwm4", "cinnamon", "mate-session",
            "marco", "kwin_x11", "kwin_wayland", "budgie-wm")
_KIOSK_COMP = ("cage", "weston", "gnome-kiosk", "matchbox-window-manager")
_MINIMAL_WM = ("openbox", "i3", "sway", "fluxbox", "icewm", "ratpoison")


def _pgrep(ctx, *names) -> set:
    """Return which of the named processes are currently running."""
    out = set()
    for n in names:
        if ctx.run(["pgrep", "-x", n]).ok:
            out.add(n)
    return out


def _session_kind(ctx) -> str:
    """Classify the graphical session: kiosk-minimal / full-de / minimal-wm / unknown."""
    running = _pgrep(ctx, *(_FULL_DE + _KIOSK_COMP + _MINIMAL_WM))
    if running & set(_KIOSK_COMP):
        return "kiosk-minimal"
    if running & set(_FULL_DE):
        return "full-de"
    if running & set(_MINIMAL_WM):
        return "minimal-wm"
    return "unknown"


def _dm_config(ctx) -> Dict[str, Dict[str, str]]:
    """Merged lightdm + gdm configuration (lowercased keys)."""
    lightdm: Dict[str, str] = {}
    for path in ctx.glob("/etc/lightdm/lightdm.conf") + ctx.glob("/etc/lightdm/lightdm.conf.d/*.conf"):
        lightdm.update(ctx.parse_keyword_file(path, sep="="))
    gdm = ctx.parse_keyword_file("/etc/gdm3/custom.conf", sep="=")
    return {"lightdm": lightdm, "gdm": gdm}


def _read_json(ctx, path: str):
    txt = ctx.read_file(path)
    if not txt:
        return None
    try:
        return json.loads(txt)
    except ValueError:
        return None


def _browser_policies(ctx) -> Dict[str, object]:
    """Merge managed browser policies for Chromium-family and Firefox."""
    chromium: Dict[str, object] = {}
    present = False
    for d in ("/etc/opt/chrome/policies/managed", "/etc/chromium/policies/managed",
              "/etc/opt/chrome/policies/recommended", "/etc/chromium/policies/recommended"):
        for path in ctx.glob(d + "/*.json"):
            data = _read_json(ctx, path)
            if isinstance(data, dict):
                chromium.update(data)
                present = True
    firefox: Dict[str, object] = {}
    for path in ("/etc/firefox/policies/policies.json", "/usr/lib/firefox/distribution/policies.json"):
        data = _read_json(ctx, path)
        if isinstance(data, dict):
            firefox = data.get("policies", data) if isinstance(data.get("policies"), dict) else data
            present = True
    return {"present": present, "chromium": chromium, "firefox": firefox}


def _is_empty_setting(val: Optional[str]) -> bool:
    """True if a gsettings value is an empty list / empty string (a disabled binding)."""
    if val is None:
        return False
    v = val.strip()
    return v in ("@as []", "[]", "['']", "@as ['']", "''", '""')


# --- generated: disabled-keybinding checks --------------------------------- #

# (id, schema, key, title, severity) — passes when the shortcut is unbound.
_DISABLE_KEYBINDINGS = [
    ("KIOSK-16", "org.gnome.desktop.wm.keybindings", "switch-applications", "Disable Alt+Tab application switching", Severity.MEDIUM),
    ("KIOSK-17", "org.gnome.desktop.wm.keybindings", "switch-applications-backward", "Disable Alt+Shift+Tab switching", Severity.LOW),
    ("KIOSK-18", "org.gnome.desktop.wm.keybindings", "switch-windows", "Disable window switching", Severity.MEDIUM),
    ("KIOSK-19", "org.gnome.desktop.wm.keybindings", "cycle-windows", "Disable cycle-windows", Severity.LOW),
    ("KIOSK-20", "org.gnome.desktop.wm.keybindings", "close", "Disable close-window shortcut", Severity.LOW),
    ("KIOSK-21", "org.gnome.desktop.wm.keybindings", "minimize", "Disable minimize-window shortcut", Severity.LOW),
    ("KIOSK-22", "org.gnome.desktop.wm.keybindings", "toggle-maximized", "Disable maximize toggle", Severity.LOW),
    ("KIOSK-23", "org.gnome.desktop.wm.keybindings", "panel-run-dialog", "Disable the Alt+F2 run dialog shortcut", Severity.HIGH),
    ("KIOSK-24", "org.gnome.desktop.wm.keybindings", "show-desktop", "Disable show-desktop", Severity.MEDIUM),
    ("KIOSK-25", "org.gnome.shell.keybindings", "toggle-overview", "Disable the activities overview shortcut", Severity.MEDIUM),
    ("KIOSK-26", "org.gnome.shell.keybindings", "toggle-application-view", "Disable the Show-Applications grid shortcut", Severity.HIGH),
    ("KIOSK-27", "org.gnome.shell.keybindings", "show-screenshot-ui", "Disable the screenshot UI shortcut", Severity.MEDIUM),
    ("KIOSK-28", "org.gnome.mutter", "overlay-key", "Disable the Super (overview) key", Severity.MEDIUM),
]


def _make_kb_check(cid, schema, key, title, sev):
    @_kiosk_check(
        id=cid, title=title, section="EXT.Kiosk", severity=sev,
        rationale="A live keyboard shortcut lets the user leave the kiosk app or reach other windows/apps.",
        remediation=f"Set {schema} {key} to an empty value (e.g. \"[]\") and lock it in dconf.",
        tags=("breakout", "gnome", "shortcuts"),
    )
    def _chk(ctx, _s=schema, _k=key):
        val = _gsettings(ctx, _s, _k)
        if val is None:
            return Outcome.manual(f"Could not read {_k}; verify it is unbound and locked")
        if _is_empty_setting(val):
            return Outcome.passed(f"{_k} is disabled")
        return Outcome.failed(f"{_k} is bound ({val})", actual=val, expected="unbound (empty)")
    return _chk


for _row in _DISABLE_KEYBINDINGS:
    _make_kb_check(*_row)


# --- generated: boolean lockdown checks ------------------------------------ #

# (id, schema, key, want, lock_path, title, severity)
_LOCKDOWN_KEYS = [
    ("KIOSK-29", "org.gnome.desktop.lockdown", "disable-printing", "true",
     "/org/gnome/desktop/lockdown/disable-printing", "Disable printing (data exfiltration)", Severity.MEDIUM),
    ("KIOSK-30", "org.gnome.desktop.lockdown", "disable-save-to-disk", "true",
     "/org/gnome/desktop/lockdown/disable-save-to-disk", "Disable save-to-disk", Severity.MEDIUM),
    ("KIOSK-31", "org.gnome.desktop.privacy", "remember-recent-files", "false",
     "/org/gnome/desktop/privacy/remember-recent-files", "Disable recent-files history (leaks prior activity)", Severity.LOW),
    ("KIOSK-32", "org.gnome.desktop.media-handling", "automount", "false",
     "/org/gnome/desktop/media-handling/automount", "Disable removable-media automount", Severity.MEDIUM),
    ("KIOSK-33", "org.gnome.desktop.media-handling", "automount-open", "false",
     "/org/gnome/desktop/media-handling/automount-open", "Disable auto-open of mounted media", Severity.MEDIUM),
    ("KIOSK-34", "org.gnome.desktop.notifications", "show-in-lock-screen", "false",
     "/org/gnome/desktop/notifications/show-in-lock-screen", "Hide notification content on the lock screen", Severity.LOW),
    ("KIOSK-35", "org.gnome.shell", "disable-user-extensions", "true",
     "/org/gnome/shell/disable-user-extensions", "Disable GNOME Shell extensions", Severity.MEDIUM),
    ("KIOSK-36", "org.gnome.desktop.a11y.applications", "screen-reader-enabled", "false",
     "/org/gnome/desktop/a11y/applications/screen-reader-enabled", "Disable the screen reader (reads any content)", Severity.MEDIUM),
    ("KIOSK-37", "org.gnome.desktop.a11y.applications", "screen-magnifier-enabled", "false",
     "/org/gnome/desktop/a11y/applications/screen-magnifier-enabled", "Disable the screen magnifier", Severity.LOW),
    ("KIOSK-38", "org.gnome.desktop.a11y.keyboard", "enable", "false",
     "/org/gnome/desktop/a11y/keyboard/enable", "Disable accessibility-by-keyboard toggles", Severity.MEDIUM),
    ("KIOSK-39", "org.gnome.desktop.a11y.mouse", "dwell-click-enabled", "false",
     "/org/gnome/desktop/a11y/mouse/dwell-click-enabled", "Disable dwell (hover) click", Severity.LOW),
]


def _make_lockdown_check(cid, schema, key, want, lock_path, title, sev):
    @_kiosk_check(
        id=cid, title=title, section="EXT.Kiosk", severity=sev,
        rationale="This GNOME setting closes a kiosk escape or data-exposure path; it must be set AND locked.",
        remediation=f"Set {schema} {key} = {want} and lock {lock_path} in a dconf profile.",
        tags=("kiosk", "gnome", "lockdown"),
    )
    def _chk(ctx, _s=schema, _k=key, _want=want, _lock=lock_path):
        val = _gsettings(ctx, _s, _k)
        locked = _dconf_locked(ctx, _lock)
        if val is None:
            return Outcome.manual(f"Could not read {_s} {_k}; verify it is '{_want}' and locked")
        if val == _want and locked:
            return Outcome.passed(f"{_k} = {_want} and locked")
        if val == _want:
            return Outcome.warn(f"{_k} = {_want} but NOT locked — the kiosk user can change it back", actual=val)
        return Outcome.failed(f"{_k} = {val}", actual=val, expected=f"{_want} (locked)")
    return _chk


for _row in _LOCKDOWN_KEYS:
    _make_lockdown_check(*_row)


# --- session / desktop footprint ------------------------------------------- #

@_kiosk_check(
    id="KIOSK-9",
    title="Ensure a minimal/kiosk session is used instead of a full desktop",
    section="EXT.Kiosk",
    severity=Severity.HIGH,
    rationale=(
        "A full desktop environment (GNOME/KDE/XFCE) ships dozens of escape routes — file managers, "
        "settings, app grids, terminals, shortcuts. A kiosk should run a single-purpose compositor "
        "(cage, weston --kiosk, GNOME-Kiosk) or a minimal WM launching only the kiosk app."),
    remediation="Replace the full DE with cage/weston-kiosk/GNOME-Kiosk, or lightdm autologin into a minimal WM running only the app.",
    tags=("breakout", "attack-surface", "desktop-environment"),
)
def minimal_session(ctx):
    kind = _session_kind(ctx)
    if kind == "kiosk-minimal":
        return Outcome.passed("A dedicated kiosk compositor is in use")
    if kind == "minimal-wm":
        return Outcome.passed("A minimal window manager is in use (confirm it launches only the kiosk app)")
    if kind == "full-de":
        return Outcome.warn(
            "A full desktop environment is running — large breakout surface for a kiosk",
            actual=sorted(_pgrep(ctx, *_FULL_DE)),
            expected="cage / weston --kiosk / GNOME-Kiosk / minimal WM",
            confidence=Confidence.LIKELY)
    return Outcome.manual("Could not determine the graphical session; verify a minimal/kiosk session is used")


@_kiosk_check(
    id="KIOSK-10",
    title="Ensure only one session type is selectable",
    section="EXT.Kiosk",
    severity=Severity.LOW,
    rationale="Multiple installed session types give a greeter session chooser — a way to start a different, less-locked environment.",
    remediation="Remove unused session files from /usr/share/xsessions and /usr/share/wayland-sessions.",
    tags=("desktop-environment",),
)
def single_session_type(ctx):
    sessions = ctx.sh("ls /usr/share/xsessions/*.desktop /usr/share/wayland-sessions/*.desktop 2>/dev/null").lines()
    if len(sessions) <= 1:
        return Outcome.passed(f"{len(sessions)} session type installed")
    return Outcome.warn(f"{len(sessions)} selectable session types installed", evidence=sessions, actual=sessions)


@_kiosk_check(
    id="KIOSK-11",
    title="Prefer a lightweight display manager",
    section="EXT.Kiosk",
    severity=Severity.LOW,
    rationale="A heavyweight greeter (gdm3) carries more surface than a minimal one (lightdm/greetd) for a single-user kiosk.",
    remediation="Use lightdm or greetd configured for autologin into the kiosk session.",
    tags=("desktop-environment", "display-manager"),
)
def lightweight_dm(ctx):
    if ctx.service_active("gdm.service") or ctx.service_active("gdm3.service"):
        return Outcome.warn("gdm3 is the active display manager; lightdm/greetd is lighter for a kiosk", actual="gdm3")
    for dm in ("lightdm", "greetd"):
        if ctx.service_active(dm + ".service"):
            return Outcome.passed(f"{dm} is the active display manager")
    return Outcome.manual("Could not determine the active display manager")


# --- login / autologin / greeter ------------------------------------------- #

@_kiosk_check(
    id="KIOSK-12",
    title="Ensure autologin into the kiosk account is configured",
    section="EXT.Kiosk",
    severity=Severity.LOW,
    rationale="A kiosk should auto-login one locked-down account. A greeter that asks for a user invites other-account login and lets a passer-by pick a different session.",
    remediation="Configure autologin (lightdm autologin-user / gdm AutomaticLoginEnable) for the restricted kiosk user only.",
    tags=("login", "autologin"),
)
def autologin_configured(ctx):
    dm = _dm_config(ctx)
    if dm["lightdm"].get("autologin-user") or dm["gdm"].get("automaticloginenable", "").lower() == "true":
        return Outcome.passed("Autologin is configured")
    return Outcome.warn("No autologin configured — a greeter is shown", expected="autologin of the kiosk user")


@_kiosk_check(
    id="KIOSK-13",
    title="Ensure the guest session is disabled",
    section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="A guest session is a second, separate environment a walk-up user can start — outside the kiosk app entirely.",
    remediation="Set 'allow-guest=false' in the lightdm config.",
    tags=("login", "guest"),
)
def guest_disabled(ctx):
    allow = _dm_config(ctx)["lightdm"].get("allow-guest")
    if allow is None:
        return Outcome.manual("Could not read lightdm allow-guest; verify the guest session is disabled")
    if allow.lower() == "false":
        return Outcome.passed("Guest session is disabled")
    return Outcome.failed("Guest session is enabled", actual=allow, expected="false")


@_kiosk_check(
    id="KIOSK-14",
    title="Ensure the greeter hides the user list and manual login",
    section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="A user list discloses accounts; manual-login lets a walk-up user try to log into a different (less-locked) account.",
    remediation="Set 'greeter-hide-users=true' and 'greeter-show-manual-login=false' (lightdm) / disable the user list in gdm.",
    tags=("login", "greeter"),
)
def greeter_hardened(ctx):
    ld = _dm_config(ctx)["lightdm"]
    hide = ld.get("greeter-hide-users")
    manual = ld.get("greeter-show-manual-login")
    if hide is None and manual is None:
        return Outcome.manual("Could not read greeter settings; verify the user list and manual login are off")
    problems = []
    if hide is not None and hide.lower() != "true":
        problems.append(f"greeter-hide-users={hide}")
    if manual is not None and manual.lower() == "true":
        problems.append("greeter-show-manual-login=true")
    if problems:
        return Outcome.warn("Greeter exposes accounts / manual login: " + ", ".join(problems), actual=problems)
    return Outcome.passed("Greeter hides users and manual login")


@_kiosk_check(
    id="KIOSK-15",
    title="Ensure the kiosk user is unprivileged",
    section="EXT.Kiosk",
    severity=Severity.HIGH,
    rationale="If the auto-logged-in kiosk user is in sudo/admin, any breakout is instantly root. The kiosk account must be a plain, unprivileged user.",
    remediation="Remove the kiosk user from sudo/admin/wheel and grant it no polkit admin rights.",
    tags=("login", "privilege"),
)
def kiosk_user_unprivileged(ctx):
    dm = _dm_config(ctx)
    user = dm["lightdm"].get("autologin-user") or dm["gdm"].get("automaticlogin")
    if not user:
        return Outcome.manual("Kiosk user unknown (no autologin); verify the kiosk account is not in sudo/admin")
    admin = set()
    for g in ctx.group_entries():
        if g["name"] in ("sudo", "admin", "wheel"):
            admin.update(m for m in g["members"].split(",") if m)
    if user in admin:
        return Outcome.failed(f"Kiosk user '{user}' is in an admin group — a breakout becomes root", actual=user)
    return Outcome.passed(f"Kiosk user '{user}' is not in sudo/admin/wheel")


# --- data exfiltration ----------------------------------------------------- #

_CLIPBOARD_MANAGERS = ("parcellite", "clipit", "copyq", "diodon", "gpaste-client", "xfce4-clipman")


@_kiosk_check(
    id="KIOSK-40",
    title="Detect clipboard managers that retain copied data",
    section="EXT.Kiosk",
    severity=Severity.LOW,
    rationale="A clipboard manager keeps a history of everything copied on the kiosk — including data entered by previous users.",
    remediation="Remove the clipboard manager, or clear/disable its history for the kiosk session.",
    tags=("data-exposure", "clipboard"),
)
def clipboard_manager(ctx):
    present = [c for c in _CLIPBOARD_MANAGERS if ctx.run(["sh", "-c", f"command -v {c}"]).ok]
    if not present:
        return Outcome.passed("No clipboard manager detected")
    return Outcome.warn(f"Clipboard manager(s) installed: {', '.join(present)}", actual=present)


# --- browser kiosk hardening (Chrome/Chromium + Firefox) ------------------- #

def _browser_check(ctx, predicate, ok_msg, bad_msg, expected):
    pol = _browser_policies(ctx)
    if not pol["present"]:
        return Outcome.manual("No managed browser policy found (/etc/opt/chrome, /etc/chromium, /etc/firefox/policies) — "
                              "verify the kiosk browser is policy-locked, or that no browser is installed")
    if predicate(pol["chromium"], pol["firefox"]):
        return Outcome.passed(ok_msg)
    return Outcome.failed(bad_msg, expected=expected)


@_kiosk_check(
    id="KIOSK-41", title="Ensure a managed browser policy is in place", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Without an enterprise/managed policy, a kiosk browser is configured by its (mutable) UI — none of the kiosk lockdowns are enforced.",
    remediation="Deploy managed policies under /etc/opt/chrome/policies/managed (Chromium) or /etc/firefox/policies/policies.json (Firefox).",
    tags=("browser", "policy"),
)
def browser_policy_present(ctx):
    pol = _browser_policies(ctx)
    if pol["present"]:
        return Outcome.passed("A managed browser policy is present")
    return Outcome.warn("No managed browser policy found — kiosk browser settings are not enforced",
                        expected="managed policy under /etc/opt/chrome or /etc/firefox/policies")


@_kiosk_check(
    id="KIOSK-42", title="Ensure browser developer tools are disabled", section="EXT.Kiosk",
    severity=Severity.HIGH,
    rationale="DevTools (F12) is a full JavaScript console and file/network inspector — a direct escape from a kiosk web app.",
    remediation="Chromium: DeveloperToolsAvailability=2. Firefox: DisableDeveloperTools=true.",
    tags=("browser", "devtools", "breakout"),
)
def browser_devtools_disabled(ctx):
    return _browser_check(
        ctx,
        lambda c, f: (c.get("DeveloperToolsAvailability") == 2 or c.get("DeveloperToolsDisabled") is True
                      or f.get("DisableDeveloperTools") is True),
        "Browser developer tools are disabled by policy",
        "Browser developer tools are not disabled by policy",
        "DeveloperToolsAvailability=2 / DisableDeveloperTools=true")


@_kiosk_check(
    id="KIOSK-43", title="Ensure the browser blocks file:// and non-web schemes", section="EXT.Kiosk",
    severity=Severity.HIGH,
    rationale="file:// turns the browser into a file manager over the whole disk; custom schemes can launch external apps — both are breakouts.",
    remediation="Chromium: add 'file://*' (and other schemes) to URLBlocklist. Firefox: restrict with WebsiteFilter/Preferences.",
    tags=("browser", "breakout"),
)
def browser_file_scheme_blocked(ctx):
    def pred(c, f):
        bl = c.get("URLBlocklist") or []
        if any("file:" in str(x) for x in bl):
            return True
        wf = (f.get("WebsiteFilter") or {}).get("Block") or []
        return any("file:" in str(x) for x in wf)
    return _browser_check(ctx, pred,
                          "Browser blocks file:// (and similar) schemes",
                          "Browser does not block file:// — it can browse the local filesystem",
                          "'file://*' in URLBlocklist / WebsiteFilter")


@_kiosk_check(
    id="KIOSK-44", title="Ensure browser downloads are restricted", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Downloads write attacker-chosen files to disk and expose a file picker — a common kiosk escape and exfil path.",
    remediation="Chromium: DownloadRestrictions>=3. Firefox: lock the download behaviour / disable saving.",
    tags=("browser", "downloads"),
)
def browser_downloads_restricted(ctx):
    return _browser_check(
        ctx,
        lambda c, f: (isinstance(c.get("DownloadRestrictions"), int) and c.get("DownloadRestrictions") >= 1)
                     or f.get("DisableDownloads") is True,
        "Browser downloads are restricted by policy",
        "Browser downloads are not restricted by policy",
        "DownloadRestrictions>=1 (Chromium) / DisableDownloads (Firefox)")


@_kiosk_check(
    id="KIOSK-45", title="Ensure the browser enforces a URL allow-list", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Without an allow-list the kiosk can navigate anywhere — search engines, webmail, file hosts — far beyond the intended app.",
    remediation="Chromium: set URLAllowlist (and URLBlocklist '*'). Firefox: WebsiteFilter Block '*' with an allow Exceptions list.",
    tags=("browser", "navigation"),
)
def browser_url_allowlist(ctx):
    def pred(c, f):
        if c.get("URLAllowlist"):
            return True
        wf = f.get("WebsiteFilter") or {}
        return bool(wf.get("Exceptions") and wf.get("Block"))
    return _browser_check(ctx, pred,
                          "Browser enforces a URL allow-list",
                          "Browser has no URL allow-list — it can navigate anywhere",
                          "URLAllowlist / WebsiteFilter Exceptions")


@_kiosk_check(
    id="KIOSK-46", title="Ensure private/incognito browsing is disabled", section="EXT.Kiosk",
    severity=Severity.LOW,
    rationale="Incognito/private windows are a fresh, unmanaged surface and a way to escape session restrictions.",
    remediation="Chromium: IncognitoModeAvailability=1. Firefox: DisablePrivateBrowsing=true.",
    tags=("browser",),
)
def browser_incognito_disabled(ctx):
    return _browser_check(
        ctx,
        lambda c, f: c.get("IncognitoModeAvailability") == 1 or f.get("DisablePrivateBrowsing") is True,
        "Private/incognito browsing is disabled",
        "Private/incognito browsing is not disabled",
        "IncognitoModeAvailability=1 / DisablePrivateBrowsing=true")


@_kiosk_check(
    id="KIOSK-47", title="Ensure browser extension installation is blocked", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="A user who can install an extension can run arbitrary code in the browser and bypass kiosk restrictions.",
    remediation="Chromium: ExtensionInstallBlocklist=['*']. Firefox: InstallAddonsPermission allowed=false.",
    tags=("browser", "extensions"),
)
def browser_extensions_blocked(ctx):
    def pred(c, f):
        bl = c.get("ExtensionInstallBlocklist") or []
        if "*" in bl:
            return True
        perm = f.get("InstallAddonsPermission") or {}
        return perm.get("Default") is False
    return _browser_check(ctx, pred,
                          "Browser extension installation is blocked",
                          "Browser extension installation is not blocked",
                          "ExtensionInstallBlocklist=['*'] / InstallAddonsPermission.Default=false")


# --- console / physical / boot --------------------------------------------- #

@_kiosk_check(
    id="KIOSK-48", title="Ensure Ctrl+Alt+Del reboot and Ctrl+Alt+Backspace are disabled", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Ctrl+Alt+Del reboots the kiosk; Ctrl+Alt+Backspace kills the X server back to a greeter — both let a walk-up user disrupt or escape the session.",
    remediation="Mask ctrl-alt-del.target and set X 'DontZapDisable'/'DontZap' true (or XKB no-terminate).",
    tags=("console", "physical"),
)
def ctrl_alt_del_disabled(ctx):
    masked = ctx.masked("ctrl-alt-del.target")
    dontzap = bool(ctx.sh("grep -rils 'dontzap' /etc/X11 2>/dev/null").out)
    if masked:
        return Outcome.passed("ctrl-alt-del.target is masked" + ("; X DontZap set" if dontzap else ""))
    return Outcome.warn("Ctrl+Alt+Del reboot is not masked", actual={"cad_masked": masked, "dontzap": dontzap},
                        expected="ctrl-alt-del.target masked", confidence=Confidence.LIKELY)


@_kiosk_check(
    id="KIOSK-49", title="Ensure magic SysRq key is disabled", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Magic SysRq key combinations can kill processes, remount, or invoke the kernel debugger directly from the keyboard.",
    remediation="Set kernel.sysrq = 0 in /etc/sysctl.d/ and apply.",
    tags=("console", "kernel"),
)
def sysrq_disabled(ctx):
    val = ctx.sysctl("kernel.sysrq")
    if val is None:
        return Outcome.manual("Could not read kernel.sysrq")
    if val == "0":
        return Outcome.passed("Magic SysRq is disabled (kernel.sysrq=0)")
    return Outcome.warn(f"Magic SysRq is enabled (kernel.sysrq={val})", actual=val, expected="0")


@_kiosk_check(
    id="KIOSK-50", title="Ensure no extra login consoles (gettys) are enabled", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="Each enabled getty is another text-login prompt a user reaching a VT could use.",
    remediation="Disable/mask getty@ttyN for the VTs the kiosk does not use.",
    tags=("console",),
)
def extra_gettys(ctx):
    res = ctx.run(["systemctl", "list-units", "--type=service", "--state=running", "getty@*", "serial-getty@*"])
    running = [l for l in res.lines() if "getty@" in l]
    if len(running) <= 1:
        return Outcome.passed(f"{len(running)} login console(s) running")
    return Outcome.warn(f"{len(running)} login consoles running", evidence=running[:10], actual=len(running))


@_kiosk_check(
    id="KIOSK-51", title="Ensure GRUB recovery / single-user boot is restricted", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="GRUB recovery (single-user) boots to a root shell with physical access; a kiosk must disable it and password-protect the bootloader.",
    remediation="Set GRUB_DISABLE_RECOVERY=\"true\" in /etc/default/grub and configure a GRUB superuser password (see CIS 1.4).",
    tags=("boot", "grub", "physical"),
)
def grub_recovery_restricted(ctx):
    if ctx.platform.is_container:
        return Outcome.skip("No bootloader inside a container")
    grub_default = ctx.parse_keyword_file("/etc/default/grub", sep="=")
    disabled = grub_default.get("grub_disable_recovery", "").strip('"').lower() == "true"
    if disabled:
        return Outcome.passed("GRUB recovery entries are disabled")
    return Outcome.warn("GRUB recovery (single-user) is not disabled", expected="GRUB_DISABLE_RECOVERY=true",
                        confidence=Confidence.LIKELY)


@_kiosk_check(
    id="KIOSK-52", title="Ensure USB mass storage is restricted", section="EXT.Kiosk",
    severity=Severity.HIGH,
    rationale="A USB stick is the classic kiosk attack: auto-run payloads, swap config, or exfiltrate data. usb-storage should be blocked unless required.",
    remediation="Blacklist the usb-storage module (or deploy USBGuard) so unknown USB storage cannot mount.",
    tags=("physical", "usb", "removable-media"),
)
def usb_storage_restricted(ctx):
    if ctx.run(["sh", "-c", "command -v usbguard"]).ok and ctx.service_active("usbguard.service"):
        return Outcome.passed("USBGuard is active")
    if not ctx.module_loadable("usb-storage") and not ctx.module_loaded("usb-storage"):
        return Outcome.passed("usb-storage module is not available")
    return Outcome.warn("USB mass storage is permitted (usb-storage loadable, no active USBGuard)",
                        expected="usb-storage blacklisted or USBGuard active", confidence=Confidence.LIKELY)


# --- network / wireless / remote ------------------------------------------- #

@_kiosk_check(
    id="KIOSK-53", title="Ensure the kiosk user cannot reconfigure networking", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="If the user can edit NetworkManager connections they can connect the kiosk to attacker networks or expose it; the network applet is also an escape surface.",
    remediation="Add a polkit rule denying org.freedesktop.NetworkManager.settings.modify.* to the kiosk user, and hide the applet.",
    tags=("network",),
)
def network_locked(ctx):
    if not ctx.service_active("NetworkManager.service"):
        return Outcome.skip("NetworkManager is not active")
    rules = ctx.sh("grep -rils 'org.freedesktop.NetworkManager' /etc/polkit-1 2>/dev/null").out
    if rules:
        return Outcome.passed("A polkit rule scoping NetworkManager is present (verify it denies the kiosk user)")
    return Outcome.manual("Verify the kiosk user cannot modify NetworkManager connections (no polkit restriction found)")


@_kiosk_check(
    id="KIOSK-54", title="Ensure Bluetooth is disabled", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="An enabled/discoverable Bluetooth stack lets a nearby attacker pair an input device (keyboard) or push files (OBEX).",
    remediation="Disable and mask bluetooth.service unless the kiosk requires it.",
    tags=("network", "bluetooth", "wireless"),
)
def bluetooth_disabled(ctx):
    if ctx.service_active("bluetooth.service"):
        return Outcome.warn("Bluetooth service is active", actual="active", expected="disabled/masked")
    return Outcome.passed("Bluetooth service is not active")


@_kiosk_check(
    id="KIOSK-55", title="Ensure no remote-access services are listening", section="EXT.Kiosk",
    severity=Severity.MEDIUM,
    rationale="SSH/VNC/RDP on a kiosk is remote attack surface that bypasses all the physical/session lockdowns.",
    remediation="Disable sshd/VNC/RDP on the kiosk unless used for managed remote support (then firewall it).",
    tags=("network", "remote"),
)
def no_remote_access(ctx):
    remote_ports = {"22": "SSH", "5900": "VNC", "5901": "VNC", "3389": "RDP"}
    found = []
    for s in ctx.listening_sockets():
        port = s["local"].rsplit(":", 1)[-1]
        if port in remote_ports:
            found.append(f"{remote_ports[port]} on {s['local']}")
    if not found:
        return Outcome.passed("No SSH/VNC/RDP listeners detected")
    return Outcome.warn(f"Remote-access service(s) listening: {', '.join(found)}", evidence=found, actual=found)


# --- autostart / lockdown integrity ---------------------------------------- #

@_kiosk_check(
    id="KIOSK-56", title="Inventory session autostart entries", section="EXT.Kiosk",
    severity=Severity.LOW,
    rationale="Everything in the autostart directories launches with the session; an unexpected entry is a persistence or escape mechanism.",
    remediation="Review /etc/xdg/autostart and the kiosk user's ~/.config/autostart; keep only the kiosk app.",
    tags=("autostart", "persistence"),
)
def autostart_inventory(ctx):
    entries = ctx.sh("ls /etc/xdg/autostart/*.desktop 2>/dev/null").lines()
    if not entries:
        return Outcome.info("No system autostart entries found")
    return Outcome.info(f"{len(entries)} system autostart entr(ies) — review for a kiosk", evidence=entries[:25])


@_kiosk_check(
    id="KIOSK-57", title="Ensure kiosk lockdown settings are locked in dconf", section="EXT.Kiosk",
    severity=Severity.HIGH,
    rationale="Most kiosk gsettings (command-line, switching, shortcuts) are only enforced if locked in a dconf profile; otherwise the logged-in user can simply change them back.",
    remediation="Place the kiosk keys under /etc/dconf/db/<profile>.d/locks/ and run 'dconf update'.",
    tags=("lockdown", "dconf", "integrity"),
)
def dconf_locks_present(ctx):
    res = ctx.sh("find /etc/dconf/db -path '*/locks/*' -type f 2>/dev/null | head -5")
    if res.out:
        return Outcome.passed("dconf lock files are present (verify they cover the kiosk keys)")
    return Outcome.warn("No dconf lock files found — kiosk gsettings can be reverted by the user",
                        expected="locks under /etc/dconf/db/*/locks/")
