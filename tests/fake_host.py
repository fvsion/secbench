"""A deterministic in-memory fake of a Linux host for tests.

Implements the :class:`Executor` interface by pattern-matching the commands the
checks actually issue and returning canned, realistic Ubuntu 24.04 responses.
This lets the whole pipeline — context, runner, scoring, reporting,
persistence — be exercised fast and deterministically on any developer machine,
with no real system access and no filesystem walking.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Dict, List, Optional, Sequence, Union

from linux_secbench.system.executor import CommandResult, Executor


class FakeHost(Executor):
    """A configurable fake host. Defaults model a partially-hardened Ubuntu."""

    def __init__(self, host: str = "fake01", is_root: bool = True) -> None:
        self.host = host
        self.is_root = is_root
        self.files: Dict[str, str] = dict(_DEFAULT_FILES)
        self.sysctls: Dict[str, str] = dict(_DEFAULT_SYSCTLS)
        self.installed: set = set(_DEFAULT_INSTALLED)
        self.enabled: set = set(_DEFAULT_ENABLED)
        self.active: set = set(_DEFAULT_ACTIVE)
        self.stat: Dict[str, str] = dict(_DEFAULT_STAT)
        #: `ss` output — listening sockets. Per-instance so a profile can open
        #: or close ports (e.g. a hardened host with no exposed database).
        self.listening: str = _DEFAULT_SS
        self.command_map: Dict[str, CommandResult] = {}
        #: process names considered "running" for pgrep (kiosk session detection).
        self.processes: set = set()
        #: pid -> {"cmdline", "environ", "comm"} for /proc scans (EXT-CRED-4/7).
        #: cmdline/environ are stored with literal NUL separators as the kernel
        #: exposes them; comm is the short process name.
        self.procs: Dict[str, Dict[str, str]] = {}

    # -- Executor interface --------------------------------------------------

    def run(self, command, *, timeout=30.0, shell=False, input_text=None) -> CommandResult:
        argv = list(command) if not isinstance(command, str) else command.split()
        joined = " ".join(argv)

        # head -c <n> <path>  → read_file
        if argv[:2] == ["head", "-c"] and len(argv) >= 4:
            return self._file_result(argv[3], argv)

        if argv[:1] == ["test"] and len(argv) == 3 and argv[1] == "-e":
            exists = argv[2] in self.files or argv[2] in self.stat or argv[2] in _DEFAULT_DIRS
            return CommandResult(argv, 0 if exists else 1)

        if argv[0] == "uname":
            return CommandResult(argv, 0, "6.8.0-31-generic\n" if "-r" in argv else "x86_64\n")

        # A fixed wall-clock so date-relative checks (account expiry) are
        # deterministic. 1700000000s ≈ day 19675 since the epoch.
        if argv[0] == "date":
            return CommandResult(argv, 0, "1700000000\n")

        if argv[:2] == ["pgrep", "-x"] and len(argv) >= 3:
            return CommandResult(argv, 0 if argv[2] in self.processes else 1)

        if argv[:2] == ["sysctl", "-n"] and len(argv) == 3:
            val = self.sysctls.get(argv[2])
            # Real `sysctl -n` exits non-zero for an unknown key; mirror that so
            # checks can distinguish "absent" (→ WARN/skip) from a real value.
            if val is None:
                return CommandResult(argv, 255, "", f"sysctl: cannot stat /proc/sys/{argv[2].replace('.', '/')}: No such file or directory")
            return CommandResult(argv, 0, val + "\n")

        if argv[0] == "systemctl":
            return self._systemctl(argv)

        if argv[0] == "dpkg-query":
            pkg = argv[-1]
            return CommandResult(argv, 0, "install ok installed" if pkg in self.installed else "unknown")

        if argv[0] == "rpm" and "-q" in argv:
            pkg = argv[-1]
            return CommandResult(argv, 0 if pkg in self.installed else 1)

        if argv[:2] == ["stat", "-L"] or argv[0] == "stat":
            return self._stat(argv)

        if argv[0] == "ss":
            return CommandResult(argv, 0, self.listening)

        if argv[0] == "sshd" and "-T" in argv:
            return CommandResult(argv, 0, self.files.get("@sshd-T", ""))

        if argv[0] == "aa-status":
            if "aa-status" in self.command_map:    # let tests override the MAC posture
                return self.command_map["aa-status"]
            return CommandResult(argv, 0, "apparmor module is loaded.\n40 profiles are loaded.\n"
                                          "40 profiles are in enforce mode.\n0 profiles are in complain mode.\n"
                                          "0 processes are unconfined.\n")

        if joined.startswith("ufw status"):
            return CommandResult(argv, 0, "Status: active\nDefault: deny (incoming), allow (outgoing)\n")

        # find ... → no offenders by default (fast + clean baseline)
        if argv[0] == "sh" and len(argv) >= 3 and argv[1] == "-c":
            return self._shell(argv[2])
        if argv[0] == "find":
            return CommandResult(argv, 0, "")

        # command -v <x>
        if "command -v" in joined:
            prog = joined.split("command -v", 1)[1].split()[0]
            present = prog in _DEFAULT_BINARIES or prog in self.installed
            return CommandResult(argv, 0 if present else 1, ("/usr/bin/" + prog + "\n") if present else "")

        # Anything explicitly overridden by a test.
        if joined in self.command_map:
            return self.command_map[joined]

        return CommandResult(argv, 0, "")

    # -- helpers -------------------------------------------------------------

    def _shell(self, script: str) -> CommandResult:
        argv = ["sh", "-c", script]
        # /proc pid enumeration for the process secret scans (EXT-CRED-4/7).
        if "ls /proc" in script and "grep" in script:
            pids = "\n".join(sorted(self.procs))
            return CommandResult(argv, 0, pids + ("\n" if pids else ""))
        # Per-pid environ/cmdline reads. Fixtures store the already-translated
        # text (the check pipes through `tr` to swap NULs for newlines/spaces).
        m = re.search(r"/proc/(\d+)/(environ|cmdline)", script)
        if m and "tr " in script:
            return CommandResult(argv, 0, self.procs.get(m.group(1), {}).get(m.group(2), ""))
        # glob expansion (ctx.glob): "for f in <pattern>; do ... done"
        if script.startswith("for f in "):
            pattern = script[len("for f in "):].split(";", 1)[0].strip()
            hits = [k for k in self.files if fnmatch.fnmatch(k, pattern)]
            return CommandResult(argv, 0, "\n".join(hits) + ("\n" if hits else ""))
        if "command -v systemctl" in script:
            return CommandResult(argv, 0, "/usr/bin/systemctl\n")
        if "command -v" in script:
            prog = script.split("command -v", 1)[1].replace("||", " ").split()[0]
            present = prog in _DEFAULT_BINARIES or prog in self.installed
            return CommandResult(argv, 0 if present else 1, ("/usr/bin/" + prog + "\n") if present else "")
        if "lsmod" in script:
            return CommandResult(argv, 0, "ext4\nvfat\n")
        if "systemctl get-default" in script:
            return CommandResult(argv, 0, "multi-user.target\n")
        if "cat /etc/audit/rules.d" in script:
            return CommandResult(argv, 0, self.files.get("@audit-rules", ""))
        if "xsessions" in script or "wireless" in script:
            return CommandResult(argv, 0, "")
        # Exploitable setuid binary present (find) → GTFOBins privesc vector.
        if "-perm -4000" in script:
            return CommandResult(argv, 0, "/usr/bin/find\n/usr/bin/sudo\n/usr/bin/passwd\n")
        # Shell-history scan: return any planted *_history files (lets tests
        # confirm we look beyond /home).
        if "_history" in script:
            hits = [k for k in self.files if k.endswith("_history")]
            return CommandResult(argv, 0, "\n".join(hits) + ("\n" if hits else ""))
        # Readable-config secret scan (EXT-CRED-1 uses 'find ... -perm /0044').
        if "-perm /0044" in script:
            hits = [k for k in self.files if k.endswith(".conf")]
            return CommandResult(argv, 0, "\n".join(hits) + ("\n" if hits else ""))
        # Generic name/path-based find: return planted files whose basename (for
        # -name) or full path (for -path) matches any predicate. This lets the
        # name-driven credential/persistence sweeps see fixtures without a
        # bespoke branch each. Specific -perm/_history finds are handled above.
        if "find " in script and ("-name" in script or "-path" in script):
            pats = re.findall(r"-(?:i?name|i?path)\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))", script)
            flat = [a or b or c for (a, b, c) in pats]
            hits = []
            for k in self.files:
                base = k.rsplit("/", 1)[-1]
                for p in flat:
                    target = k if "/" in p else base
                    if fnmatch.fnmatch(target, p):
                        hits.append(k)
                        break
            return CommandResult(argv, 0, "\n".join(sorted(set(hits))) + ("\n" if hits else ""))
        # find pipelines and everything else: empty, clean baseline.
        return CommandResult(argv, 0, "")

    def _file_result(self, path: str, argv) -> CommandResult:
        if path in self.files:
            return CommandResult(argv, 0, self.files[path])
        # /proc/<pid>/comm resolves from the proc fixtures.
        m = re.fullmatch(r"/proc/(\d+)/comm", path)
        if m and m.group(1) in self.procs:
            return CommandResult(argv, 0, self.procs[m.group(1)].get("comm", "") + "\n")
        return CommandResult(argv, 1, "", "No such file")

    def _systemctl(self, argv) -> CommandResult:
        sub = argv[1] if len(argv) > 1 else ""
        unit = argv[-1]
        if sub == "is-enabled":
            return CommandResult(argv, 0, "enabled" if unit in self.enabled else "disabled")
        if sub == "is-active":
            return CommandResult(argv, 0, "active" if unit in self.active else "inactive")
        if sub == "list-unit-files":
            present = any(unit.split(".")[0] in u for u in self.enabled | self.active)
            return CommandResult(argv, 0, unit if present else "")
        return CommandResult(argv, 0, "")

    def _stat(self, argv) -> CommandResult:
        path = argv[-1]
        if path in self.stat:
            return CommandResult(argv, 0, self.stat[path] + "\n")
        return CommandResult(argv, 1, "", "No such file")


# --------------------------------------------------------------------------- #
# Canned data modelling a realistic, partially-hardened Ubuntu 24.04 host.
# --------------------------------------------------------------------------- #

_DEFAULT_DIRS = {"/etc", "/opt", "/srv", "/var/www", "/proc", "/var/log", "/var/log/journal",
                 "/root", "/home/alice", "/opt/svc", "/opt/rdp"}
_DEFAULT_BINARIES = {"systemctl", "sshd", "ufw", "auditctl", "ss", "stat", "find", "sudo",
                     "aa-status", "sysctl", "modprobe", "getcap"}
_DEFAULT_INSTALLED = {"apparmor", "ufw", "sudo", "auditd", "audispd-plugins", "openssh-server",
                      "libpam-runtime", "libpam-modules", "libpam-pwquality",
                      "cracklib-runtime", "rsyslog", "rsyslog-gnutls", "aide", "aide-common",
                      "telnet"}  # telnet present → an intentional failure
_DEFAULT_ENABLED = {"ufw.service", "auditd.service", "ssh.service", "systemd-journald.service",
                    "rsyslog.service", "dailyaidecheck.timer"}
_DEFAULT_ACTIVE = {"ufw.service", "auditd.service", "ssh.service", "systemd-journald.service",
                   "systemd-timesyncd.service", "rsyslog.service"}

_DEFAULT_SYSCTLS = {
    "kernel.randomize_va_space": "2",
    "kernel.yama.ptrace_scope": "1",
    "fs.suid_dumpable": "0",
    "kernel.kptr_restrict": "1",
    "kernel.dmesg_restrict": "1",
    "kernel.perf_event_paranoid": "3",
    "kernel.unprivileged_bpf_disabled": "1",
    "net.ipv4.ip_forward": "1",          # intentional failure
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
}

_DEFAULT_STAT = {
    "/etc/passwd": "644 0 0 root root regular file",
    "/etc/shadow": "640 0 42 root shadow regular file",
    "/etc/group": "644 0 0 root root regular file",
    "/etc/gshadow": "640 0 42 root shadow regular file",
    "/etc/crontab": "600 0 0 root root regular file",
    "/etc/cron.allow": "640 0 0 root root regular file",
    "/etc/shells": "644 0 0 root root regular file",
    "/home/alice": "750 1000 1000 alice alice directory",
    # SSH config + host keys (CIS 5.1.1–5.1.3)
    "/etc/ssh/sshd_config": "600 0 0 root root regular file",
    "/etc/ssh/ssh_host_ed25519_key": "600 0 0 root root regular file",
    "/etc/ssh/ssh_host_ed25519_key.pub": "644 0 0 root root regular file",
    "/etc/ssh/ssh_host_rsa_key": "600 0 0 root root regular file",
    "/etc/ssh/ssh_host_rsa_key.pub": "644 0 0 root root regular file",
    # auditd log dir/files, config, and tools (CIS 6.2.4.*)
    "/var/log/audit": "750 0 0 root root directory",
    "/var/log/audit/audit.log": "600 0 0 root root regular file",
    "/etc/audit/auditd.conf": "640 0 0 root root regular file",
    "/etc/audit/audit.rules": "640 0 0 root root regular file",
    "/etc/audit/rules.d/audit.rules": "640 0 0 root root regular file",
    "/sbin/auditctl": "755 0 0 root root regular file",
    "/sbin/aureport": "755 0 0 root root regular file",
    "/sbin/ausearch": "755 0 0 root root regular file",
    "/sbin/autrace": "755 0 0 root root regular file",
    "/sbin/auditd": "755 0 0 root root regular file",
    "/sbin/augenrules": "755 0 0 root root regular file",
}

_SSHD_T = """permitrootlogin no
permitemptypasswords no
maxauthtries 4
logingracetime 60
x11forwarding no
ignorerhosts yes
hostbasedauthentication no
permituserenvironment no
usepam yes
loglevel info
maxsessions 10
maxstartups 10:30:60
clientaliveinterval 300
clientalivecountmax 3
banner /etc/issue.net
allowtcpforwarding no
disableforwarding yes
gssapiauthentication no
allowgroups sudo
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-512-etm@openssh.com
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
"""

# A reasonably complete v2.0.0 auditd ruleset — exercises most 6.2.3.* checks.
_AUDIT_RULES_TEXT = """-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-w /var/log/sudo.log -p wa -k sudo_log_file
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,setxattr -k perm_mod
-a always,exit -F arch=b64 -S mount -k mounts
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -k delete
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-a always,exit -F path=/usr/bin/chcon -F perm=x -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -k perm_chng
-a always,exit -F path=/usr/sbin/usermod -F perm=x -k usermod
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules
-e 2
"""

_DEFAULT_SS = (
    "tcp   LISTEN 0 128 127.0.0.1:631   0.0.0.0:* users:((\"cupsd\",pid=900,fd=7))\n"
    "tcp   LISTEN 0 128 0.0.0.0:22      0.0.0.0:* users:((\"sshd\",pid=1000,fd=3))\n"
    "tcp   LISTEN 0 128 0.0.0.0:3306    0.0.0.0:* users:((\"mysqld\",pid=1200,fd=20))\n"  # exposed db → fail
)

_DEFAULT_FILES = {
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
        'ID=ubuntu\nID_LIKE=debian\nVERSION_CODENAME=noble\n'
    ),
    "/proc/1/comm": "systemd\n",
    "/etc/issue.net": "Authorized access only. Activity is monitored.\n",
    "/etc/issue": "Authorized access only.\n",
    "/etc/motd": "Welcome.\n",
    "/etc/login.defs": (
        "PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n"
        "UMASK 027\nENCRYPT_METHOD yescrypt\n"
    ),
    "/etc/security/pwquality.conf": (
        "minlen = 14\ndcredit = -1\nucredit = -1\ndifok = 2\n"
        "maxrepeat = 3\nmaxsequence = 3\ndictcheck = 1\nenforcing = 1\nenforce_for_root\n"
    ),
    "/etc/security/faillock.conf": "deny = 5\nunlock_time = 900\neven_deny_root\n",
    "/etc/pam.d/common-auth": (
        "auth required pam_faillock.so preauth\n"
        "auth [success=1 default=ignore] pam_unix.so\n"
        "auth required pam_faillock.so authfail\n"
    ),
    "/etc/pam.d/common-account": "account required pam_faillock.so\naccount required pam_unix.so\n",
    "/etc/pam.d/common-password": (
        "password requisite pam_pwquality.so retry=3 enforcing=1 enforce_for_root\n"
        "password requisite pam_pwhistory.so remember=24 use_authtok enforce_for_root\n"
        "password [success=1 default=ignore] pam_unix.so obscure yescrypt use_authtok\n"
    ),
    "/etc/pam.d/su": "auth required pam_wheel.so use_uid group=sugroup\n",
    "/etc/shells": "/bin/sh\n/bin/bash\n/usr/bin/bash\n",
    "/etc/default/useradd": "SHELL=/bin/sh\nINACTIVE=30\n",
    "/etc/profile": "umask 027\nreadonly TMOUT=900\nexport TMOUT\n",
    # Includes two intentional GTFOBins escalation grants: alice can sudo
    # python with SETENV, bob can sudo find with NOPASSWD — both = instant root.
    "/etc/sudoers": (
        "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n"
        "%sudo ALL=(ALL:ALL) ALL\n"
        "alice ALL=(ALL) SETENV: /usr/bin/python3\n"
        "bob ALL=(ALL) NOPASSWD: /usr/bin/find\n"
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "backdoor:x:0:0:hidden:/root:/bin/bash\n"           # UID 0 backdoor → critical fail
        "svc:x:998:998:service:/opt/svc:/bin/bash\n"        # system acct w/ shell → fail
    ),
    "/etc/shadow": (
        "root:$y$j9T$abcdef:19000:0:99999:7:::\n"
        "alice:$y$j9T$ghijkl:19500:1:365:7:::\n"
        "guest::19000:0:99999:7:::\n"                       # empty password → critical fail
    ),
    # carol is in the docker group → root-equivalent escalation vector.
    "/etc/group": "root:x:0:\nsudo:x:27:alice\nshadow:x:42:\ndocker:x:998:carol\nsugroup:x:1001:\n",
    # SSH host key files so ctx.glob('/etc/ssh/ssh_host_*_key[.pub]') resolves
    # them; their permissions live in _DEFAULT_STAT (CIS 5.1.2/5.1.3).
    "/etc/ssh/ssh_host_ed25519_key": "",
    "/etc/ssh/ssh_host_ed25519_key.pub": "ssh-ed25519 AAAA...\n",
    "/etc/ssh/ssh_host_rsa_key": "",
    "/etc/ssh/ssh_host_rsa_key.pub": "ssh-rsa AAAA...\n",
    # A service account whose home is NOT under /home, with a password leaked in
    # its shell history — exercises scanning every real home, not just /home.
    "/opt/svc/.bash_history": "ls -la\nmysql -psecret123 -h db01\nexit\n",
    # A world-readable config with an embedded high-entropy secret — exercises
    # EXT-CRED-1 and the redacted-preview behaviour.
    "/etc/app/secret.conf": "host = db01\napi_key = aZ3kP9xQ2mL7vB4nR8wT1yU6QwErTy\n",
    # A password file named for what it holds, with no recognised extension and
    # not on any credential-store allowlist — the exact shape EXT-CRED-1/5 miss
    # and EXT-CRED-6 (filename-heuristic sweep) is built to catch.
    "/opt/rdp/.rdp_pass": "username=rdpadmin\npassword=R3m0teD3skt0p!secret\n",
    "@sshd-T": _SSHD_T,
    "@audit-rules": _AUDIT_RULES_TEXT,
    "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro audit=1 audit_backlog_limit=8192\n",
    "/etc/systemd/journald.conf": (
        "[Journal]\nStorage=persistent\nForwardToSyslog=yes\nCompress=yes\n"
        "SystemMaxUse=500M\n"
    ),
    "/etc/audit/auditd.conf": (
        "max_log_file = 8\nmax_log_file_action = keep_logs\n"
        "space_left_action = email\nadmin_space_left_action = halt\n"
    ),
    # Glob targets for the 6.2.4 file-access checks (perms live in _DEFAULT_STAT).
    "/var/log/audit/audit.log": "",
    "/etc/audit/audit.rules": _AUDIT_RULES_TEXT,
    "/etc/audit/rules.d/audit.rules": _AUDIT_RULES_TEXT,
    # rsyslog: restrictive file mode, no remote receiver, TLS driver referenced.
    "/etc/rsyslog.conf": (
        "$FileCreateMode 0640\nmodule(load=\"imuxsock\")\n"
        "$DefaultNetstreamDriver gtls\n*.* @@loghost.example.com:6514\n"
    ),
    # AIDE config references the audit tools (CIS 6.3.3).
    "/etc/aide/aide.conf": (
        "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512\n"
        "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512\n"
        "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512\n"
    ),
}
