"""Fleet of realistic test-host profiles built on top of :class:`FakeHost`.

The base ``FakeHost`` models a *partially-hardened* Ubuntu 24.04 with a handful
of deliberate flaws. These builders specialise it into distinct, believable
profiles so the end-to-end suite can exercise the whole application across a
range of real-world postures and distributions:

  * ``neglected_ubuntu``   — Ubuntu 24.04 server, many findings (incl. critical)
  * ``hardened_ubuntu``    — Ubuntu 24.04 server, remediated / mostly compliant
  * ``kiosk_workstation``  — Ubuntu 24.04 single-app kiosk (for ``--kiosk``)
  * ``rhel9_host``         — RHEL 9.3 (exercises edition-routing: Ubuntu CIS skips)
  * ``debian12_host``      — Debian 12 (likewise)

Each returns a ready-to-use ``FakeHost``; callers set ``.host`` if they want a
specific hostname.
"""

from __future__ import annotations

from tests.fake_host import FakeHost


# --------------------------------------------------------------------------- #
# Ubuntu 24.04 — neglected (the catalogue's natural "lots of findings" host)
# --------------------------------------------------------------------------- #
def neglected_ubuntu(host: str = "neglected01") -> FakeHost:
    """The stock partially-hardened host, made a little worse on a few axes so
    it reliably produces critical/high findings across families."""
    h = FakeHost(host=host)
    # Weaken a couple of process-hardening sysctls (in addition to the stock
    # ip_forward=1 and the planted backdoor/empty-password/NOPASSWD flaws).
    h.sysctls["kernel.randomize_va_space"] = "0"   # ASLR off
    h.sysctls["kernel.yama.ptrace_scope"] = "0"    # unrestricted ptrace
    return h


# --------------------------------------------------------------------------- #
# Ubuntu 24.04 — hardened (remediated; should be mostly compliant)
# --------------------------------------------------------------------------- #
def hardened_ubuntu(host: str = "hardened01") -> FakeHost:
    h = FakeHost(host=host)

    # Remove the planted UID-0 backdoor and give the service account no shell.
    h.files["/etc/passwd"] = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "svc:x:998:998:service:/opt/svc:/usr/sbin/nologin\n"
    )
    # No empty-password account; svc is locked.
    h.files["/etc/shadow"] = (
        "root:$y$j9T$abcdef:19000:0:99999:7:::\n"
        "alice:$y$j9T$ghijkl:19500:1:365:7:::\n"
        "svc:!:19000:0:99999:7:::\n"
    )
    # No SETENV / NOPASSWD escalation grants; keep the safe Defaults.
    h.files["/etc/sudoers"] = (
        "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n"
        "Defaults timestamp_timeout=15\n"
        "%sudo ALL=(ALL:ALL) ALL\n"
    )
    # Drop the docker-group (root-equivalent) membership.
    h.files["/etc/group"] = (
        "root:x:0:\nsudo:x:27:alice\nshadow:x:42:\nsugroup:x:1001:\n"
    )
    # Remove the world-readable secret files / leaked-credential bait.
    for planted in ("/etc/app/secret.conf", "/opt/rdp/.rdp_pass",
                    "/opt/svc/.bash_history"):
        h.files.pop(planted, None)
    # Close the exposed database; keep only loopback cups + ssh.
    h.listening = (
        "tcp   LISTEN 0 128 127.0.0.1:631   0.0.0.0:* users:((\"cupsd\",pid=900,fd=7))\n"
        "tcp   LISTEN 0 128 0.0.0.0:22      0.0.0.0:* users:((\"sshd\",pid=1000,fd=3))\n"
    )
    # IP forwarding off (the stock host leaves it on as an intentional fail).
    h.sysctls["net.ipv4.ip_forward"] = "0"
    return h


# --------------------------------------------------------------------------- #
# Ubuntu 24.04 — single-app kiosk workstation
# --------------------------------------------------------------------------- #
def kiosk_workstation(host: str = "kiosk01") -> FakeHost:
    h = FakeHost(host=host)
    # A locked-down single-application session (cage compositor), not a full DE.
    h.processes = {"cage"}
    # A managed Chrome policy that disables developer tools (a kiosk staple).
    h.files["/etc/opt/chrome/policies/managed/kiosk.json"] = (
        '{"DeveloperToolsAvailability": 2, "URLBlocklist": ["*"]}'
    )
    return h


# --------------------------------------------------------------------------- #
# Non-Ubuntu hosts — exercise the version-aware edition routing
# (Ubuntu CIS content is gated to ubuntu:24.04, so it auto-skips here; the
#  portable extended checks still run.)
# --------------------------------------------------------------------------- #
def rhel9_host(host: str = "rhel9") -> FakeHost:
    h = FakeHost(host=host)
    h.files["/etc/os-release"] = (
        'NAME="Red Hat Enterprise Linux"\n'
        'VERSION="9.3 (Plow)"\n'
        'ID="rhel"\n'
        'ID_LIKE="fedora"\n'
        'VERSION_ID="9.3"\n'
        'PRETTY_NAME="Red Hat Enterprise Linux 9.3 (Plow)"\n'
    )
    return h


def debian12_host(host: str = "debian12") -> FakeHost:
    h = FakeHost(host=host)
    h.files["/etc/os-release"] = (
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        'NAME="Debian GNU/Linux"\n'
        'ID=debian\n'
        'VERSION_ID="12"\n'
        'VERSION_CODENAME=bookworm\n'
    )
    return h
