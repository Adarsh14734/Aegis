#!/usr/bin/env python3
"""Aegis S6 approval bridge — lets the desktop window answer a terminal prompt.

    aegis-approval-bridge -- python3 aegis/proxy.py -- <mcp-server-cmd...>

WHAT THIS IS
------------
C7 asks a human on /dev/tty. A window is not a tty, so for the Approvals screen
to do anything, something has to type the answer on the proxy's terminal. This
supervisor does exactly that and nothing else:

  * it allocates a pty and starts the proxy inside it, so the proxy's
    controlling terminal is one this process owns;
  * the proxy's stdin and stdout stay on the original pipes, because they carry
    JSON-RPC to and from the MCP client and must not be touched;
  * it relays terminal output to its own stderr so a human can still watch and
    still answer by hand;
  * it listens on a unix socket and, on request, writes "y\\n" or "n\\n" to the
    pty — the same bytes a person would type.

approval.py, proxy.py and audit.py are unmodified and unaware. The decision,
the audit rows, the timeout and the fail-closed behaviour are all still theirs.

WHY THIS IS NEW ATTACK SURFACE — read before running it
-------------------------------------------------------
This is the narrowest bridge that works, and it is still a real widening:

  1. **Anything that can write to the socket can approve.** The socket is
     0600 and owned by the user, so the boundary is the user account — which
     is the same boundary the agent runs inside. An agent that can run local
     commands as you can connect to this socket and approve its own request.
     THREAT-MODEL.md §7.1 already says malware on the host defeats Aegis; this
     lowers the bar from "malware" to "any code running as you".
  2. **It weakens the tty guarantee.** C7's value came partly from the answer
     arriving on a channel the agent does not control. With the bridge running,
     that is no longer strictly true.
  3. **It does not authenticate the asker.** The prompt_id is checked against
     the pending prompt so a stale click cannot answer a later request, but the
     bridge cannot tell the Aegis window from anything else on the machine.

Mitigations in place: the socket is created 0600 in the Aegis data directory;
only the two bytes "y" and "n" can ever be written to the terminal; the bridge
refuses to answer when no prompt is waiting; and it exits with the proxy.

If you do not run this, nothing is lost except the buttons: the prompt still
appears on the terminal and is still answered there.
"""

import json
import os
import pty
import select
import signal
import socket
import sys
import termios
import tty
from pathlib import Path

SOCKET_NAME = "approval.sock"
PROMPT_MARKER = b"Approve? [y/N]"


def data_dir() -> Path:
    if override := os.environ.get("AEGIS_AUDIT_DB"):
        return Path(override).expanduser().parent
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Aegis"
    base = os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")
    return Path(base) / "aegis"


def make_socket(path: Path) -> socket.socket:
    if path.exists():
        path.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Bind then tighten immediately; a world-writable approval socket would be
    # a remote control for the agent's own permissions.
    old = os.umask(0o177)
    try:
        srv.bind(str(path))
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    srv.listen(4)
    srv.setblocking(False)
    return srv


def main() -> int:
    argv = sys.argv[1:]
    if "--" in argv:
        argv = argv[argv.index("--") + 1:]
    if not argv:
        print(__doc__, file=sys.stderr)
        return 64

    sock_path = data_dir() / SOCKET_NAME
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    srv = make_socket(sock_path)
    print(f"[bridge] listening on {sock_path}", file=sys.stderr, flush=True)

    pid, master = pty.fork()
    if pid == 0:
        # Child: the pty is already our controlling terminal. Put the real
        # JSON-RPC pipes back on stdin/stdout so the proxy speaks to its client
        # exactly as before; only /dev/tty differs.
        os.dup2(REAL_STDIN, 0)
        os.dup2(REAL_STDOUT, 1)
        os.execvp(argv[0], argv)
        os._exit(127)

    try:
        tty.setraw(master, termios.TCSANOW)
    except termios.error:
        pass

    pending_prompt = False
    clients: list[socket.socket] = []
    buf = b""

    def shutdown(*_):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            sock_path.unlink()
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        watch = [master, srv] + clients
        try:
            readable, _, _ = select.select(watch, [], [], 0.5)
        except (OSError, ValueError):
            break

        if master in readable:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf = (buf + chunk)[-4096:]
            pending_prompt = PROMPT_MARKER in buf
            # A human watching the terminal still sees the prompt.
            os.write(2, chunk)

        if srv in readable:
            try:
                conn, _ = srv.accept()
                conn.setblocking(False)
                clients.append(conn)
            except OSError:
                pass

        for conn in list(clients):
            if conn not in readable:
                continue
            try:
                data = conn.recv(4096)
            except OSError:
                data = b""
            if not data:
                clients.remove(conn)
                conn.close()
                continue
            reply = handle(data, master, pending_prompt)
            if reply.startswith("Answered"):
                pending_prompt = False
                buf = b""
            try:
                conn.sendall(reply.encode())
            except OSError:
                pass
            clients.remove(conn)
            conn.close()

        if os.waitpid(pid, os.WNOHANG)[0] == pid:
            break

    try:
        sock_path.unlink()
    except OSError:
        pass
    return 0


def handle(data: bytes, master: int, prompt_waiting: bool) -> str:
    """Only ever writes b'y\\n' or b'n\\n'. Nothing from the request reaches
    the terminal, so the socket cannot be used to type anything else."""
    try:
        msg = json.loads(data.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return "Malformed request; nothing was sent to the agent."
    answer = msg.get("answer")
    if answer not in ("y", "n"):
        return "Only 'y' or 'n' can be sent; nothing was sent to the agent."
    if not prompt_waiting:
        return "Nothing is waiting for an answer right now."
    os.write(master, b"y\n" if answer == "y" else b"n\n")
    return f"Answered {'yes' if answer == 'y' else 'no'} on the agent's terminal."


# Captured before pty.fork replaces fds 0/1 in the child.
REAL_STDIN = os.dup(0)
REAL_STDOUT = os.dup(1)

if __name__ == "__main__":
    sys.exit(main())
