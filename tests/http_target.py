"""A real HTTP server for the S8 suite to fetch from.

`tests/mock_fs_server.py` exists because a *deliberately obedient* downstream
proves that a block came from Aegis. This is the same idea one layer out: an
origin that answers everything, records exactly what it received, and follows
whatever redirect script the test hands it. If a request never arrives here,
Aegis stopped it.

Every request is appended to a JSONL file, headers included, so a test can ask
the byte-level question S8 exists for: did the credential reach the wire, and
did it reach only the host it was granted for.

Routes:
    /ok                  200, a fixed body
    /echo                200, a JSON dump of what this server received
    /redirect/<n>        302 to /redirect/<n-1>, ending at /ok
    /to?target=<url>     302 to an arbitrary absolute URL
    /status/<code>       that status code
    /big                 a body larger than the read cap
    anything else        404
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

RECORD_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    record_path = None

    def log_message(self, *args):  # keep the suite's output readable
        pass

    def _record(self, body: bytes) -> None:
        if not self.record_path:
            return
        entry = {
            "method": self.command,
            "path": self.path,
            "host_header": self.headers.get("Host"),
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
        }
        with RECORD_LOCK:
            with open(self.record_path, "a") as fh:
                fh.write(json.dumps(entry) + "\n")

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, code: int, body: bytes = b"", extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._route(self._read_body())

    def do_POST(self):
        self._route(self._read_body())

    do_PUT = do_POST
    do_DELETE = do_GET
    do_HEAD = do_GET

    def _route(self, body: bytes) -> None:
        self._record(body)
        parts = urlsplit(self.path)
        path = parts.path

        if path == "/ok":
            self._send(200, b"AEGIS-TARGET-OK")
        elif path == "/echo":
            self._send(200, json.dumps({
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body.decode("utf-8", "replace"),
            }).encode())
        elif path.startswith("/redirect/"):
            try:
                n = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._send(400, b"bad hop count")
                return
            target = "/ok" if n <= 1 else f"/redirect/{n - 1}"
            self._send(302, b"", {"Location": target})
        elif path == "/to":
            target = (parse_qs(parts.query).get("target") or [""])[0]
            self._send(302, b"", {"Location": target})
        elif path.startswith("/status/"):
            self._send(int(path.rsplit("/", 1)[-1]), b"AEGIS-TARGET-STATUS")
        elif path == "/big":
            self._send(200, b"x" * 200_000)
        else:
            self._send(404, b"no such route")


def serve(record_path=None, port: int = 0):
    """(server, port). Bound to 127.0.0.1 — this must never listen off-host."""
    Handler.record_path = record_path
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


if __name__ == "__main__":
    srv, port = serve(sys.argv[1] if len(sys.argv) > 1 else None)
    print(port, flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
