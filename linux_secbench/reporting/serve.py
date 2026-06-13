"""`secbench serve` — a tiny local server for interactive triage.

Serves the HTML report for one stored scan and exposes two JSON endpoints —
``POST /suppress`` and ``POST /unsuppress`` — that write through the
SuppressionStore and re-render. This is the "live" version of the report: tick a
finding false-positive and Save, and it persists and drops out of the score on
the spot.

Deliberately minimal and **local-only**: it is stdlib `http.server` (zero
dependencies), binds 127.0.0.1 by default, has no authentication, and is meant
for a single operator triaging on their own machine — not a hosted service.
Adding a network listener to a security tool is real surface, so the CLI refuses
a non-loopback bind unless the operator explicitly accepts the exposure.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def is_loopback(bind: str) -> bool:
    return bind in _LOOPBACK


def make_handler(render_html: Callable[[], str], suppress, unsuppress, export=None):
    """Build a request handler bound to the given render/suppress callables.

    ``render_html()`` returns the current report HTML (re-built each call so
    suppression edits show immediately). ``suppress(check_id, kind, reason, host)``
    (``host`` may be None → the served scan's host, or "*" for all hosts) and
    ``unsuppress(check_id)`` persist changes. ``export()`` (optional) writes the
    current report — with suppressions applied — to disk in every file format and
    returns ``{"dir": ..., "files": [...]}``; when omitted, ``POST /export`` says
    regeneration is unavailable.
    """

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html", "/report"):
                self._send(200, render_html(), "text/html; charset=utf-8")
            else:
                self._send(404, json.dumps({"error": "not found"}))

        def do_POST(self):
            if self.path == "/export":
                if export is None:
                    self._send(501, json.dumps({"error": "report regeneration not available"}))
                    return
                try:
                    result = export()
                except Exception as exc:  # never let a bad write kill the server
                    self._send(500, json.dumps({"error": str(exc)}))
                    return
                self._send(200, json.dumps({"ok": True, **result}))
                return
            if self.path not in ("/suppress", "/unsuppress"):
                self._send(404, json.dumps({"error": "not found"}))
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, TypeError):
                self._send(400, json.dumps({"error": "invalid JSON"}))
                return
            check_id = str(payload.get("check_id", "")).strip()
            if not check_id:
                self._send(400, json.dumps({"error": "check_id required"}))
                return
            if self.path == "/suppress":
                # An optional "host" scopes the suppression (default: the served
                # scan's host); "*" suppresses on every host.
                suppress(check_id, payload.get("kind", "false-positive"),
                         payload.get("reason", ""), payload.get("host") or None)
            else:
                unsuppress(check_id)
            self._send(200, json.dumps({"ok": True, "check_id": check_id}))

        def log_message(self, *args):  # keep the console quiet
            pass

    return Handler


def run(render_html, suppress, unsuppress, bind: str, port: int, export=None):
    """Start the server (blocking until Ctrl-C). Returns nothing."""
    handler = make_handler(render_html, suppress, unsuppress, export)
    httpd = HTTPServer((bind, port), handler)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
