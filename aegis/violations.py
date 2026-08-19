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

import fnmatch
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from queue import Empty, Queue

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


@dataclass(frozen=True)
class Violation:
    process: str
    pid: int
    operation: str
    detail: str
    raw: str

    @property
    def path(self) -> str:
        return self.detail.strip()

    def reason(self) -> str:
        return (
            f"the kernel refused {self.operation} on {self.path} to "
            f"{self.process}(pid {self.pid}) inside the Aegis sandbox. This is "
            f"an OS-level denial (EPERM), not a policy-engine decision: the "
            f"process never reached the MCP layer and there was nothing to ask "
            f"a human about. Reported by the macOS sandbox violation log."
        )


@dataclass
class Observation:
    """What the observer saw, including what it could not attribute."""

    attributed: list = field(default_factory=list)
    unattributed: int = 0
    benign: int = 0
    network: int = 0
    available: bool = True
    unavailable_reason: str = ""

    def summary(self) -> str:
        if not self.available:
            return f"kernel-denial observation UNAVAILABLE ({self.unavailable_reason})"
        parts = [f"{len(self.attributed)} kernel denial(s) recorded"]
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

    def __init__(self, profile: dict):
        self.patterns = deny_patterns(profile)
        self.proc: subprocess.Popen | None = None
        self.queue: Queue = Queue()
        self.observation = Observation()
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
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            match = VIOLATION_RE.search(line)
            if match:
                self.queue.put(Violation(
                    process=match.group("proc"),
                    pid=int(match.group("pid")),
                    operation=match.group("op"),
                    detail=match.group("detail"),
                    raw=line.rstrip(),
                ))

    def drain(self) -> list:
        """Classify everything seen so far; return the rows worth recording."""
        rows = []
        while True:
            try:
                violation = self.queue.get_nowait()
            except Empty:
                break
            if violation.operation in BENIGN_OPS:
                self.observation.benign += 1
            elif violation.operation == "network-outbound":
                self.observation.network += 1
            elif violation.operation in FILE_OPS and matches_policy(
                violation.path, self.patterns
            ):
                self.observation.attributed.append(violation)
                rows.append(violation)
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
