"""Aegis S5 human approval — control C7.

ASK stops collapsing to DENY. The proxy blocks the call and asks a human.

**The prompt goes to the controlling terminal, /dev/tty — never to stdin or
stdout.** stdout is the JSON-RPC channel to the client; a single stray byte
there corrupts the protocol. stdin carries client frames. Both are already
spoken for, and neither is a human. /dev/tty is the process's controlling
terminal regardless of how stdin and stdout have been redirected, which is
exactly the property needed here.

Every path that is not an explicit human "yes" is a denial:

  - no controlling terminal        -> DENY, rule_id ask_no_tty
  - timeout (default 120s)         -> DENY, rule_id approval_timeout
  - EOF, empty line, anything not affirmative -> DENY, rule_id approval_denied
  - any error reading or writing the terminal -> DENY, rule_id ask_no_tty

There is deliberately no configuration that turns an unanswered prompt into an
approval. T5 in THREAT-MODEL.md is approval fatigue: a control that a tired
human bypasses is not a control, and a control that approves *itself* when
nobody answers is worse than not having asked.
"""

import getpass
import os
import select
import socket
import sys
import time
from dataclasses import dataclass

TTY_PATH = "/dev/tty"
DEFAULT_TIMEOUT_SECONDS = 120.0

AFFIRMATIVE = {"y", "yes"}


@dataclass(frozen=True)
class Resolution:
    approved: bool
    rule_id: str
    resolver: str
    detail: str


def _who(tty_name: str) -> str:
    """Who answered. Best effort — this is provenance for the audit trail, not
    authentication. Anyone who can write to the terminal can answer the
    prompt, and Aegis cannot tell one such person from another."""
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no account name is not worth failing over
        user = "?"
    try:
        host = socket.gethostname()
    except Exception:  # noqa: BLE001
        host = "?"
    return f"{user}@{host} via {tty_name}"


def describe(tool: str, rule_id: str, reason: str, paths) -> str:
    """The prompt a human actually reads. Plain English, no jargon, and the
    consequence of doing nothing stated explicitly."""
    lines = [
        "",
        "=" * 66,
        "  AEGIS — approval required",
        "=" * 66,
        f"  Tool:  {tool}",
    ]
    paths = list(paths)
    if paths:
        lines.append(f"  Files: {paths[0]}")
        for p in paths[1:6]:
            lines.append(f"         {p}")
        if len(paths) > 6:
            lines.append(f"         ...and {len(paths) - 6} more ({len(paths)} total)")
    else:
        lines.append("  Files: (none named in this call)")
    lines += [
        f"  Why:   {reason}",
        f"  Rule:  {rule_id}",
        "",
        "  Approving lets this call through to the server. Denying stops it.",
    ]
    return "\n".join(lines) + "\n"


def prompt_on(stream, tool: str, rule_id: str, reason: str, paths,
              timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Resolution:
    """Ask on an already-open terminal stream. Split out from resolve() so the
    prompt, the timeout and the parsing can be tested against a real pty
    without needing a controlling terminal."""
    tty_name = getattr(stream, "name", TTY_PATH)
    try:
        tty_name = os.ttyname(stream.fileno())
    except (OSError, ValueError, AttributeError):
        pass

    try:
        stream.write(describe(tool, rule_id, reason, paths).encode("utf-8"))
        stream.write(
            f"  Denied automatically in {int(timeout)}s if nobody answers.\n"
            f"  Approve? [y/N] ".encode("utf-8")
        )
    except (OSError, ValueError) as exc:
        return Resolution(False, "ask_no_tty", "none",
                          f"could not write the prompt to {tty_name}: {exc}")

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _say(stream, "\n  TIMED OUT — denied.\n")
            return Resolution(False, "approval_timeout", "timeout",
                              f"nobody answered within {int(timeout)}s")
        try:
            readable, _, _ = select.select([stream], [], [], min(remaining, 1.0))
        except (OSError, ValueError) as exc:
            return Resolution(False, "ask_no_tty", "none",
                              f"terminal became unreadable: {exc}")
        if not readable:
            continue

        try:
            line = stream.readline()
        except (OSError, ValueError) as exc:
            return Resolution(False, "ask_no_tty", "none",
                              f"could not read the answer: {exc}")

        if not line:  # EOF — the terminal went away
            return Resolution(False, "approval_denied", "eof",
                              "the terminal closed without an answer")

        answer = line.decode("utf-8", errors="replace").strip().lower()
        who = _who(tty_name)
        if answer in AFFIRMATIVE:
            _say(stream, "  APPROVED.\n")
            return Resolution(True, "approval_granted", who, "answered yes")
        _say(stream, "  DENIED.\n")
        return Resolution(
            False, "approval_denied", who,
            f"answered {answer!r}" if answer else "answered with an empty line",
        )


def _say(stream, text: str) -> None:
    try:
        stream.write(text.encode("utf-8"))
    except (OSError, ValueError):
        pass


def controlling_tty_available(tty_path: str = TTY_PATH) -> tuple[bool, str]:
    """Is there a controlling terminal to prompt on? (available, why not).

    Checked *before* anything is written, so the headless case is answered
    immediately instead of after the timeout. O_NOCTTY because probing for a
    terminal must never have the side effect of acquiring one.
    """
    try:
        fd = os.open(tty_path, os.O_RDWR | os.O_NOCTTY)
    except OSError as exc:
        return False, f"{tty_path}: {exc.strerror}"
    try:
        if not os.isatty(fd):
            return False, f"{tty_path} is not a terminal"
    finally:
        os.close(fd)
    return True, ""


def resolve(tool: str, rule_id: str, reason: str, paths,
            timeout: float = DEFAULT_TIMEOUT_SECONDS,
            tty_path: str = TTY_PATH) -> Resolution:
    """Open the controlling terminal and ask. Blocking; the proxy runs this in
    an executor so the server->client pump keeps flowing while a human thinks.

    No controlling terminal means DENY, **immediately**. That is the headless
    case — a proxy launched by a GUI client, a daemon, CI — and it must never
    silently become an approval.

    The absence is detected before prompting rather than discovered by nobody
    answering. Two reasons, and the second is the one that matters:

      - waiting out a 120s timeout on every ASK makes headless operation look
        like a hang, once per call;
      - "nobody was present to ask" and "a human was asked and did not answer"
        are different events. Recording both as approval_timeout would put a
        claim in the audit trail — that a person saw this and let it lapse —
        which is not true. They get different rule_ids because they are
        different facts.
    """
    available, why = controlling_tty_available(tty_path)
    if not available:
        return Resolution(
            False, "ask_no_tty", "none",
            f"no controlling terminal ({why}), so no human could be asked; "
            f"denied immediately without waiting {int(timeout)}s, and recorded "
            f"as nobody-present rather than as an unanswered prompt",
        )

    try:
        stream = open(tty_path, "r+b", buffering=0)
    except OSError as exc:
        # Raced between the probe and the open — still nobody to ask.
        return Resolution(
            False, "ask_no_tty", "none",
            f"controlling terminal disappeared ({tty_path}: {exc.strerror}); "
            f"denying rather than assuming consent",
        )
    try:
        return prompt_on(stream, tool, rule_id, reason, paths, timeout)
    finally:
        try:
            stream.close()
        except OSError:
            pass
