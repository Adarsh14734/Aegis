"""Aegis S9b — making kernel denials visible to the audit log. Closes S9 gap 7.

S9 shipped C11 enforcing without observing: `cat ~/.ssh/id_rsa` inside the
sandbox failed with EPERM, the agent saw it, and **no audit row existed**. The
two strongest controls — the kernel boundary and the tamper-evident log — did
not meet. This module makes them meet, for the part that is genuinely
observable, and is explicit about the part that is not.

WHERE THE DATA COMES FROM, AND WHY NOT FROM ASRT

`@anthropic-ai/sandbox-runtime` has a violation store with a real API
(`getViolationsForCommand`, `annotateStderrWithSandboxFailures`). It is
**unreachable from the CLI**: `grep -c -i violation dist/cli.js` is 0. Aegis
wraps the `srt` binary, not the Node library, so that API is not available to
us without embedding a Node host inside the audit path.

What ASRT's store actually does on macOS is spawn:

    log stream --predicate '(eventMessage ENDSWITH "<session-suffix>")' --style compact

and filter for lines containing `Sandbox:` and `deny`. So the *source* is the
macOS unified log, which is equally available to us. This module reads that same
source directly. It is not a reimplementation of ASRT's isolation — D2 is about
not writing a sandbox, and this writes no sandbox. It reads an OS log.

WHAT IS OBSERVABLE, MEASURED RATHER THAN ASSUMED

Every line below was captured on this machine; the raw output is in
`evidence/S9b-violation-observability.txt`.

  **Filesystem denials: yes, fully.**

      Sandbox: cat(7866) deny(1) file-read-data /private/tmp/.../.ssh/id_rsa

  Process, pid, operation and the full path. This is what `sandbox_denied` rows
  are made of.

  **Network denials: no, not usefully.** Two separate reasons:

  1. A *domain* refusal never reaches the kernel at all. ASRT permits the
     sandbox to reach its own loopback proxy and the proxy refuses the domain,
     so `curl https://evil.xyz/` returns nothing and the kernel logs nothing.
     Measured: one `network-outbound` line across the whole session, and it was
     not curl's.
  2. A *raw socket* denial does reach the kernel, but with no host:

         Sandbox: nc(7936) deny(1) network-outbound remote:*:443

     Port only. The hostname is not in the line and cannot be recovered from it.

  So Aegis cannot record the host of a blocked request, and this module does not
  pretend to. See `NETWORK_NOT_OBSERVABLE`.

ATTRIBUTION, AND WHY IT IS DELIBERATELY NARROW

The unified log is machine-wide. During a five-second capture it carried
denials from `imagent`, `assistantd`, `biomesyncd` and `triald` — macOS's own
daemons, sandboxed by macOS, nothing to do with Aegis. Ordinary processes also
produce constant benign noise (`sysctl-read kern.iossupportversion` fired for
bash, curl and nc in one short run).

Writing a row for any of that would be inventing rows, which is the one thing
worse than admitting the gap. So a line becomes an audit row only when **the
denied path matches a deny pattern in the profile Aegis generated from
policy.json**. That is the exact claim worth recording — "a path this policy
denies was denied by the kernel" — and it is checked against our own profile
rather than inferred from process names.

Everything else the observer sees is counted and reported in the session
summary, never recorded as an individual row. The log therefore says what it
saw and could not attribute, instead of silently dropping it.
"""

import base64
import fnmatch
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from queue import Empty, Queue

try:  # S7 import plumbing: package when installed, flat when run as a script
    from .audit import default_db_path
except ImportError:  # pragma: no cover
    from audit import default_db_path

# `Sandbox: cat(7866) deny(1) file-read-data /private/tmp/x`, optionally
# prefixed by `N duplicate reports for `.
VIOLATION_RE = re.compile(
    r"Sandbox:\s+(?:\d+ duplicate reports for\s+Sandbox:\s+)?"
    r"(?P<proc>[^\s(]+)\((?P<pid>\d+)\)\s+deny\((?P<code>\d+)\)\s+"
    r"(?P<op>[a-z0-9-]+\*?)\s*(?P<detail>.*)$"
)

# Operations worth an audit row. Filesystem only, deliberately: these are the
# ones whose detail field is a path we can check against our own policy.
FILE_OPS = (
    "file-read-data", "file-read-metadata", "file-read-xattr", "file-read*",
    "file-write-data", "file-write-create", "file-write-unlink",
    "file-write-mode", "file-write-owner", "file-write-xattr", "file-write*",
)

# Seen constantly for ordinary processes and carrying no security meaning here.
# Counted, never recorded, and named so the omission is a decision.
BENIGN_OPS = ("sysctl-read", "mach-lookup", "iokit-open-user-client",
              "user-preference-read", "mach-register", "process-info*")

NETWORK_NOT_OBSERVABLE = (
    "Blocked destinations are not recorded as individual rows. A domain refusal "
    "is made by the sandbox runtime's loopback proxy and never reaches the "
    "kernel log at all; a raw-socket denial does reach it but carries only "
    "'remote:*:<port>', with no hostname. Aegis will not invent a host it "
    "cannot see. Egress that Aegis itself performs IS fully recorded — see C4 "
    "and the host/status/bytes columns."
)


# ---------------------------------------------------------------------------
# where per-denial lines go when the terminal is busy being a terminal
# ---------------------------------------------------------------------------

# S9g. `aegis run` used to print one line per denial to the child's stderr
# while the child was running. For a batch command that is exactly right. For a
# full-screen TUI it is unusable: the client owns the alternate screen and
# repaints it continuously, so every `[aegis] kernel denied ...` line lands on
# top of whatever the client had drawn, mid-line and mid-frame, and one denied
# file can emit dozens of them in a single turn. The session becomes unreadable
# and the notices themselves are unreadable with it.
#
# So they go to a file instead, and the file is rotated rather than allowed to
# grow forever. The audit log is unchanged and remains the record — this is a
# convenience for tailing during a session, not a second source of truth. It is
# deliberately NOT hash-chained and must never be described as evidence: it is
# a copy of what the audit database already holds, written where a person can
# watch it go by.
DENIAL_LOG_NAME = "denials.log"
DENIAL_LOG_MAX_BYTES = 1_000_000
DENIAL_LOG_KEEP = 3


def denial_log_path() -> Path:
    if override := os.environ.get("AEGIS_DENIAL_LOG"):
        return Path(override).expanduser()
    return default_db_path().parent / DENIAL_LOG_NAME


class DenialLog:
    """Append-only, size-rotated, 0600. Never raises at the caller.

    A logging failure must not end a sandboxed session — the session is the
    thing with value, and the audit database has already recorded the denial by
    the time this is called. The first failure is remembered so the exit
    summary can say the file is incomplete instead of quietly implying it is
    not.
    """

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else denial_log_path()
        self.error: str | None = None
        self.written = 0

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.stat().st_size < DENIAL_LOG_MAX_BYTES:
                return
        except OSError:
            return
        # denials.log.2 -> .3, .1 -> .2, denials.log -> .1. Oldest falls off.
        for index in range(DENIAL_LOG_KEEP - 1, 0, -1):
            older = self.path.with_name(f"{self.path.name}.{index}")
            newer = self.path.with_name(f"{self.path.name}.{index + 1}")
            if older.exists():
                try:
                    os.replace(older, newer)
                except OSError:
                    pass
        try:
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        except OSError:
            pass

    def write(self, line: str) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_if_needed()
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, f"{stamp} {line}\n".encode("utf-8"))
            finally:
                os.close(fd)
            os.chmod(self.path, 0o600)
            self.written += 1
        except OSError as exc:  # noqa: PERF203 - one try per line is the point
            if self.error is None:
                self.error = f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# whose denial is this?  (S9j)
# ---------------------------------------------------------------------------

# The unified log is MACHINE-WIDE. Until S9j a line became a `sandbox_denied`
# row whenever its path matched a deny pattern in this session's profile — and
# nothing checked that this session's agent was the process denied. Two
# `aegis run` sessions, or one session and a test suite, produce denials that
# look identical under that rule. Measured: a session running `bash -c "sleep
# 22"`, which touched nothing at all, recorded a `sandbox_denied` row for a
# file an entirely different sandbox had read.
#
# The row's claim — "a path this policy denies was denied by the kernel" — was
# true. The implied claim, that this session's agent did it, was never
# established. For a product whose central claim is a tamper-evident audit log,
# that is the wrong kind of imprecision.
#
# WHAT MAKES ATTRIBUTION POSSIBLE
#
# The sandbox runtime tags every rule it emits with a per-invocation string:
#
#     (deny default (with message "CMD64_<base64>_END_<suffix>_SBX"))
#
# and macOS prints that tag on its own line, immediately after the violation:
#
#     Sandbox: cat(10178) deny(1) file-read-data /…/.ssh/id_rsa
#     CMD64_Y2F0IC9wcml2YXRl…_END__srv5ti0e3_SBX
#
# The base64 is the SANDBOXED COMMAND, space-joined and truncated to 100
# characters — which is a string Aegis computes, because Aegis chose it. So a
# session can recognise its own denials without asking the process table
# anything.
#
# WHY NOT PID ANCESTRY, WHICH IS THE OBVIOUS IDEA
#
# The violation line carries a pid, and `aegis run` knows the pid it launched.
# Walking from one to the other requires the denied process to still exist, and
# it does not. Measured: a denied `cat` finished 0.10s after it started, and the
# line describing it had not reached `log stream` by then — six seconds later
# the pid was gone from the process table. Every short-lived denial, which is
# most of them, would be unattributable. Pid reuse makes the residual worse
# rather than better.
TAG_MARKER = "CMD64_"
TAG_RE = re.compile(r"^CMD64_(?P<b64>[A-Za-z0-9+/=]*)_END_(?P<suffix>.*)$")

# The runtime truncates the command before encoding it. Kept as its own
# constant because a change to it upstream silently narrows attribution.
TAG_COMMAND_LIMIT = 100


def session_tag_prefix(command) -> str:
    """The tag prefix the runtime will stamp on THIS session's denials.

    `CMD64_<base64 of the command>_END_`. The suffix after it is random per
    runtime invocation and is deliberately not predicted: the prefix already
    separates this session's command from every other one, and demanding a
    suffix Aegis cannot compute would mean attributing nothing at all.

    The command is SHELL-QUOTED, not space-joined, because that is what the
    runtime encodes — it re-executes the argv through a shell and quotes each
    argument to survive the re-parse. `shlex.quote` and the runtime's quoting
    agree on ordinary arguments and on arguments containing spaces, which is
    the whole of what `aegis run` produces; where they might not, the caller
    fails SAFE rather than silently dropping denials. See Observer.drain().
    """
    joined = " ".join(shlex.quote(part) for part in command)[:TAG_COMMAND_LIMIT]
    encoded = base64.b64encode(joined.encode("utf-8")).decode("ascii")
    return f"{TAG_MARKER}{encoded}_END_"


@dataclass(frozen=True)
class Violation:
    process: str
    pid: int
    operation: str
    detail: str
    raw: str
    # The runtime's per-invocation tag, from the line after this one, or "" if
    # the kernel printed none — which is what a denial from outside any
    # sandbox-runtime session looks like (macOS confining its own daemons).
    tag: str = ""
    # Set by drain(). False only in the fallback regime, where it means "this
    # row could not be tied to this session" and the row says so.
    attributed: bool = True

    @property
    def path(self) -> str:
        return self.detail.strip()

    def reason(self) -> str:
        attribution = (
            "Attributed to this session by the sandbox runtime's own log tag, "
            "so it was this session's process tree that was refused."
            if self.attributed else
            "NOT attributed to this session: the runtime stamped no session "
            "tag on it, and the macOS violation log is machine-wide, so this "
            "may have been caused by a different sandbox. What is established "
            "is that a path this policy denies was refused by the kernel."
        )
        return (
            f"the kernel refused {self.operation} on {self.path} to "
            f"{self.process}(pid {self.pid}) inside the Aegis sandbox. This is "
            f"an OS-level denial (EPERM), not a policy-engine decision: the "
            f"process never reached the MCP layer and there was nothing to ask "
            f"a human about. Reported by the macOS sandbox violation log. "
            f"{attribution}"
        )


@dataclass
class Observation:
    """What the observer saw, including what it could not attribute."""

    attributed: list = field(default_factory=list)
    unattributed: int = 0
    benign: int = 0
    network: int = 0
    # S9j. Denials of a path this policy denies, by a sandbox that is NOT this
    # session. Counted and reported, never recorded: they are somebody else's.
    foreign: int = 0
    # Denials recorded WITHOUT attribution, because this session had not seen
    # its own tag and would not discard on an unproven prefix.
    unproven: int = 0
    # "log tag" when this session could recognise its own denials, "none" when
    # it could not and rows are marked unattributed instead.
    attributed_by: str = "log tag"
    available: bool = True
    unavailable_reason: str = ""

    def summary(self) -> str:
        if not self.available:
            return f"kernel-denial observation UNAVAILABLE ({self.unavailable_reason})"
        if self.attributed_by == "none":
            parts = [
                f"{len(self.attributed)} kernel denial(s) recorded, NOT "
                f"attributed to this session — the sandbox runtime stamped no "
                f"session tag, so a denial by another sandbox cannot be told "
                f"from this one's. Those rows say so"
            ]
        else:
            parts = [f"{len(self.attributed)} kernel denial(s) recorded, "
                     f"attributed to this session by its sandbox log tag"]
        if self.unproven:
            parts.append(
                f"{self.unproven} recorded WITHOUT attribution — this session "
                f"never saw its own sandbox tag, so it would not discard them "
                f"on an unproven match"
            )
        if self.foreign:
            parts.append(
                f"{self.foreign} denial(s) of a path this policy denies came "
                f"from a DIFFERENT sandbox session and were not recorded here"
            )
        if self.unattributed:
            parts.append(
                f"{self.unattributed} other sandbox denial(s) seen but not "
                f"attributable to this policy, so not recorded"
            )
        if self.network:
            parts.append(
                f"{self.network} network-outbound denial(s) seen, host not "
                f"available from the kernel"
            )
        if self.benign:
            parts.append(f"{self.benign} benign denial(s) ignored")
        return "; ".join(parts)


def deny_patterns(profile: dict) -> tuple[str, ...]:
    fs = profile.get("filesystem", {})
    return tuple(set(fs.get("denyRead", []) + fs.get("denyWrite", [])))


def matches_policy(path: str, patterns) -> bool:
    """Whether this denied path is one the Aegis profile actually denies.

    The profile's globs are the anchored `/**/…` forms `sandbox.py` generates,
    and `fnmatch` treats `*` as crossing `/`, so `/**/id_rsa` matches
    `/private/tmp/x/.ssh/id_rsa`. Loose in the same direction the profile is
    loose, which keeps this check and the enforced rule in agreement.
    """
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, pattern + "/*"):
            return True
    return False


class Observer:
    """Streams macOS sandbox violations for the life of a sandboxed session.

    Non-fatal by construction. If the log stream cannot start, the session still
    runs and the audit records that observation was unavailable — an agent that
    refused to launch because a *log reader* failed would be trading a working
    control for a missing one.
    """

    def __init__(self, profile: dict, command=None):
        self.patterns = deny_patterns(profile)
        # S9j. The command this session sandboxed, so its own denials can be
        # told from every other sandbox's. Absent, attribution is impossible
        # and every recorded row says so rather than implying otherwise —
        # see drain().
        self.tag_prefix = session_tag_prefix(command) if command else None
        self.proc: subprocess.Popen | None = None
        self.pending: Violation | None = None
        self.queue: Queue = Queue()
        # Set the moment ANY line — a real denial or the benign sysctl noise
        # every sandboxed process generates — carries this session's tag. Until
        # it is set, Aegis has no evidence its computed prefix is the one the
        # runtime is stamping, and drain() refuses to discard anything on the
        # strength of an unproven prefix.
        self.saw_own_tag = False
        self.observation = Observation(
            attributed_by="log tag" if self.tag_prefix else "none")
        self._thread: threading.Thread | None = None

    def supported(self) -> bool:
        return sys.platform == "darwin"

    def start(self) -> Observation:
        if not self.supported():
            self.observation.available = False
            self.observation.unavailable_reason = (
                f"kernel-denial observation is implemented for macOS only; this "
                f"is {sys.platform}. The sandbox still enforces — nothing is "
                f"recorded about what it stopped."
            )
            return self.observation
        try:
            self.proc = subprocess.Popen(
                ["log", "stream", "--predicate",
                 'eventMessage CONTAINS "Sandbox: "', "--style", "compact"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.observation.available = False
            self.observation.unavailable_reason = (
                f"could not start the macOS log stream ({type(exc).__name__}: "
                f"{exc}); the sandbox still enforces, but what it stops is not "
                f"being recorded"
            )
            return self.observation

        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()
        # The stream takes a moment to attach. Starting it before the agent and
        # giving it this beat is the difference between catching the first
        # denial and missing it.
        time.sleep(1.5)
        return self.observation

    def _pump(self) -> None:
        """Read the stream, pairing each violation with the tag line after it.

        macOS prints the rule's `(with message ...)` on its OWN line, directly
        following the `Sandbox: …` line — measured as a strict `vTvTvT…`
        alternation. So a violation is held back one line to see whether a tag
        follows it, and flushed when the next line arrives or the stream ends.
        A violation with no tag line is still emitted, carrying `tag=""`; that
        is what a denial from outside any sandbox-runtime session looks like
        and it must not be silently dropped.
        """
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            stripped = line.strip()
            if self.pending is not None:
                if stripped.startswith(TAG_MARKER):
                    self.queue.put(replace(self.pending, tag=stripped))
                    self.pending = None
                    continue
                self.queue.put(self.pending)
                self.pending = None
            match = VIOLATION_RE.search(line)
            if match:
                self.pending = Violation(
                    process=match.group("proc"),
                    pid=int(match.group("pid")),
                    operation=match.group("op"),
                    detail=match.group("detail"),
                    raw=line.rstrip(),
                )
        if self.pending is not None:
            self.queue.put(self.pending)
            self.pending = None

    def drain(self) -> list:
        """Classify everything seen so far; return the rows worth recording."""
        rows = []
        batch = []
        while True:
            try:
                batch.append(self.queue.get_nowait())
            except Empty:
                break

        # First pass: has this session's tag appeared at all? A sandboxed
        # process emits benign tagged denials (`sysctl-read kern.iossupportversion`)
        # within moments of starting, so this is normally true before the first
        # interesting denial — and it is what licenses discarding anything.
        if self.tag_prefix:
            for violation in batch:
                if violation.tag.startswith(self.tag_prefix):
                    self.saw_own_tag = True
                    break

        for violation in batch:
            if violation.operation in BENIGN_OPS:
                self.observation.benign += 1
            elif violation.operation == "network-outbound":
                self.observation.network += 1
            elif violation.operation in FILE_OPS and matches_policy(
                violation.path, self.patterns
            ):
                # S9j. The path is one this policy denies. The remaining
                # question — and the one that was never asked — is whether
                # THIS session's process tree is what the kernel refused.
                if self.tag_prefix and violation.tag.startswith(self.tag_prefix):
                    self.observation.attributed.append(violation)
                    rows.append(violation)
                elif self.tag_prefix and self.saw_own_tag:
                    # This session's tag has been seen, so the prefix is known
                    # to be the one the runtime stamps — and this line does not
                    # carry it. Another sandbox's denial, or an untagged one.
                    # Counted, reported in the closing row, and NOT recorded:
                    # it is not this session's to claim, and claiming it is the
                    # bug S9j exists to fix.
                    self.observation.foreign += 1
                else:
                    # FAIL SAFE. Either no command was given, or this session
                    # has never seen its own tag — in which case the prefix may
                    # simply be wrong, and discarding on the strength of it
                    # would silently delete real denials, which is a worse
                    # failure than the one being fixed. Record it, and mark it:
                    # the row carries `sandbox_denied_unattributed` and its
                    # reason says the session could not be established.
                    self.observation.attributed.append(violation)
                    self.observation.unproven += 1
                    rows.append(replace(violation, attributed=False))
            else:
                self.observation.unattributed += 1
        return rows

    def stop(self) -> list:
        """Stop streaming and return any remaining rows."""
        if self.proc is not None:
            # The kernel and logd both buffer; give late lines a chance to land
            # rather than losing the denial that ended the session.
            time.sleep(1.5)
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                try:
                    self.proc.kill()
                except OSError:
                    pass
        return self.drain()
