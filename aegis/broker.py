"""Aegis S4 credential broker — control C6 (partial).

The model writes a handle; Aegis writes the secret.

    model:  {"headers": ["Authorization: token ${aegis:github_token}"]}
    server: {"headers": ["Authorization: token ghp_<the real one>"]}

Substitution happens after the policy chain has returned ALLOW and immediately
before the frame is handed to the MCP server. The value never travels back
toward the model: it is not in the audit database, not in stderr, not in a
denial frame, and if the server echoes it in a response it is redacted out
before the model sees the frame.

WHAT THIS ACHIEVES, AND WHAT IT DOES NOT

THREAT-MODEL.md B4 states the goal as "secrets never cross the boundary in
plaintext. The broker performs the operation; the agent receives a result."
This module does NOT meet that. It keeps the secret out of the *model's
context*, which defeats T2 (an injected instruction cannot read a value the
model never saw). It hands the plaintext credential to the MCP server, which
THREAT-MODEL.md §3 names as adversary T3. A hostile or compromised server
receives a working credential and can do as it likes with it.

So: C6 against T2, not against T3. Response redaction stops an *accidental*
echo and a naive exfiltration-via-response; it does nothing about a server
that simply keeps the value. Described accordingly in S4-REPORT.md.

DISCLOSURE RULES (the entire point of the file)

  - No function here returns, logs, or formats a secret value except
    `substitute`, which puts it into the outbound arguments, and `Redactor`,
    which holds values in order to remove them.
  - Every exception raised on the substitution path is re-raised as a
    BrokerError whose message has been scrubbed, with `from None` so the
    original traceback — whose frames hold the value in locals — is not
    chained onto it.
  - There is no debug mode that prints a secret. Do not add one.
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ${aegis:name}. Deliberately narrow: a handle is an identifier, not an
# expression. Nothing here interpolates, evaluates or path-resolves it.
HANDLE_RE = re.compile(r"\$\{aegis:([A-Za-z0-9_][A-Za-z0-9_.\-]{0,63})\}")

# keyring service name. Secrets live under this service, one entry per handle.
KEYRING_SERVICE = "aegis"

REDACTION_TEMPLATE = "[AEGIS-REDACTED:{handle}]"

MAX_DEPTH = 16


class BrokerError(Exception):
    """A credential could not be resolved. Message is always scrubbed."""


def _scrub(text: str, values) -> str:
    """Remove any secret value from a string about to be shown to anyone."""
    for value in values:
        if value:
            text = text.replace(value, "[AEGIS-REDACTED]")
    return text


# Every failure below follows one shape: build the BrokerError inside the
# `except`, then raise it *after* the block has ended.
#
# `raise BrokerError(...) from None` is not sufficient and was the first
# version of this file. It clears __cause__ and suppresses *display* of the
# original, but __context__ still points at the original exception, whose
# traceback frames hold the secret in their locals. Anything that walks
# __context__ — a logger, a debugger, a crash reporter, an LLM asked to
# explain an error — can still reach the value. __context__ is set from the
# thread's currently-handled exception at raise time, so a helper function
# cannot fix this on the caller's behalf: the raise has to happen outside the
# except block. Verified in tests/s4.py §6.


# ---- handles -------------------------------------------------------------


def find_handles(obj, path: str = "arguments", depth: int = 0) -> list[tuple[str, str]]:
    """[(argument_path, handle)] for every ${aegis:...} in the tree.

    Pure text inspection: no keyring access, nothing fetched. policy.py calls
    this to authorize handles *before* deciding, so a call that will be denied
    never causes a keychain read.
    """
    out: list[tuple[str, str]] = []
    _find(obj, path, depth, out)
    return out


def _find(obj, path: str, depth: int, out: list) -> None:
    if depth > MAX_DEPTH:
        return
    if isinstance(obj, str):
        for match in HANDLE_RE.finditer(obj):
            out.append((path, match.group(1)))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            _find(value, f"{path}.{key}", depth + 1, out)
    elif isinstance(obj, (list, tuple)):
        for i, value in enumerate(obj):
            _find(value, f"{path}[{i}]", depth + 1, out)


# ---- keychain ------------------------------------------------------------


def _keyring():
    """Imported lazily and never at module scope: policy.py imports this file,
    and the proxy must still start on a machine without the library so that
    calls carrying no handle keep working."""
    error = None
    try:
        import keyring  # noqa: PLC0415 - deliberate lazy import

        return keyring
    except ImportError:
        error = BrokerError(
            "the 'keyring' library is not installed, so no credential can be "
            "resolved. Install it with: pip install keyring"
        )
    raise error


def get_secret(handle: str) -> str:
    """Read one secret from the OS keychain.

    Every failure path is scrubbed and unchained. A keyring backend that puts
    the value into an exception message — some do, on encoding errors — must
    not be able to surface it through us.
    """
    error = None
    value = None
    try:
        value = _keyring().get_password(KEYRING_SERVICE, handle)
    except BrokerError as exc:
        error = exc
    except BaseException as exc:  # noqa: BLE001 - scrub anything at all
        error = BrokerError(
            f"keychain lookup for {handle!r} failed with "
            f"{type(exc).__name__}; details withheld in case they carry the value"
        )
    if error is not None:
        error.__context__ = None
        raise error
    if value is None:
        raise BrokerError(
            f"no secret is stored for handle {handle!r}. "
            f"Set it with: aegis-secret set {handle}"
        )
    if not isinstance(value, str) or value == "":
        raise BrokerError(f"stored secret for handle {handle!r} is empty")
    return value


def set_secret(handle: str, value: str) -> None:
    error = None
    try:
        _keyring().set_password(KEYRING_SERVICE, handle, value)
    except BrokerError as exc:
        error = exc
    except BaseException as exc:  # noqa: BLE001
        error = BrokerError(
            f"could not store {handle!r}: {type(exc).__name__}; details withheld"
        )
    if error is not None:
        error.__context__ = None
        raise error


def delete_secret(handle: str) -> None:
    error = None
    try:
        _keyring().delete_password(KEYRING_SERVICE, handle)
    except BrokerError as exc:
        error = exc
    except BaseException as exc:  # noqa: BLE001
        error = BrokerError(
            f"could not delete {handle!r}: {type(exc).__name__}; details withheld"
        )
    if error is not None:
        error.__context__ = None
        raise error


def secret_exists(handle: str) -> bool:
    """Whether a handle has a value. Never returns or logs the value."""
    try:
        return _keyring().get_password(KEYRING_SERVICE, handle) is not None
    except BaseException:  # noqa: BLE001
        return False


def keyring_available() -> tuple[bool, str]:
    """(usable, why not). S7: `secret_exists` answers False both when the
    library is absent and when the handle is simply unset, which is the right
    answer for the substitution path — neither can produce a secret — and the
    wrong thing to print at a user, who would go looking for a handle that was
    never the problem. The CLI asks this first so the two read differently.
    """
    try:
        _keyring()
    except BrokerError as exc:
        return False, str(exc)
    except BaseException as exc:  # noqa: BLE001 - a broken backend, same outcome
        return False, f"the keyring library failed to load ({type(exc).__name__})"
    return True, ""


# ---- substitution --------------------------------------------------------


@dataclass
class Redactor:
    """Holds the plaintext values substituted during this session so they can
    be stripped from anything travelling back toward the model.

    This is the one place Aegis deliberately keeps secrets in memory. It
    widens the trusted computing base (B3) for the life of the process, which
    is the price of catching a server that echoes a credential back. Values
    are never written anywhere from here.
    """

    values: dict = field(default_factory=dict)  # value -> handle

    def remember(self, handle: str, value: str) -> None:
        if value:
            self.values[value] = handle

    def all_values(self):
        return tuple(self.values)

    def redact(self, text: str) -> tuple[str, dict]:
        """(redacted text, {handle: occurrences removed}).

        Also matches the JSON-escaped spelling of each value, because the
        frames travelling back are JSON: a secret containing a quote or a
        backslash appears on the wire in escaped form and a naive scan for the
        raw value would sail straight past it.

        Only exact occurrences are found. A server that returns the credential
        base64'd, hashed, split across fields or otherwise transformed is not
        caught, and cannot be — see S4-REPORT.md.
        """
        hits: dict[str, int] = {}
        for value, handle in self.values.items():
            replacement = REDACTION_TEMPLATE.format(handle=handle)
            for needle in (value, json.dumps(value)[1:-1]):
                if needle and needle in text:
                    hits[handle] = hits.get(handle, 0) + text.count(needle)
                    text = text.replace(needle, replacement)
        return text, hits

    def scrub(self, text: str) -> str:
        return _scrub(text, self.all_values())


def substitute(obj, resolver=get_secret, redactor: Redactor | None = None):
    """Replace every ${aegis:handle} with its secret. Returns (new_obj, used).

    `used` maps handle -> value and is for the caller's Redactor; it is never
    logged. Callers must treat the returned object as radioactive: it goes to
    the server and nowhere else.

    Any failure is a BrokerError with a scrubbed, unchained message. The whole
    body is wrapped because a partially substituted tree is itself a hazard —
    on failure the caller gets nothing and denies the call.
    """
    resolved: dict[str, str] = {}
    error = None
    new_obj = None
    try:
        new_obj = _sub(obj, resolver, resolved, 0)
    except BrokerError as exc:
        error = BrokerError(_scrub(str(exc), resolved.values()))
    except BaseException as exc:  # noqa: BLE001
        error = BrokerError(
            f"credential substitution failed with {type(exc).__name__}; "
            f"details withheld in case they carry a secret"
        )
    if error is not None:
        # Belt and braces: the raise below is already outside the except
        # block, so __context__ is empty; this makes that explicit and
        # survives someone later moving the raise back inside.
        error.__context__ = None
        error.__cause__ = None
        raise error
    if redactor is not None:
        for handle, value in resolved.items():
            redactor.remember(handle, value)
    return new_obj, resolved


def _sub(obj, resolver, resolved: dict, depth: int):
    if depth > MAX_DEPTH:
        return obj
    if isinstance(obj, str):
        if "${aegis:" not in obj:
            return obj

        def replace(match):
            handle = match.group(1)
            if handle not in resolved:
                resolved[handle] = resolver(handle)
            return resolved[handle]

        return HANDLE_RE.sub(replace, obj)
    if isinstance(obj, dict):
        return {k: _sub(v, resolver, resolved, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sub(v, resolver, resolved, depth + 1) for v in obj]
    return obj


# ---- aegis-secret CLI ----------------------------------------------------


def _default_policy_path() -> Path:
    """A local copy rather than an import from proxy.py, which imports this
    module. Same rule the verifier follows: duplication beats a cycle."""
    if override := os.environ.get("AEGIS_POLICY"):
        return Path(override).expanduser()
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Aegis"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "aegis"
    return base / "policy.json"


def _cmd_set(handle: str) -> int:
    """Read a secret from the terminal with no echo.

    Never from argv: a command line is visible in `ps`, in shell history, and
    in any process listing the agent itself can run. Never from a pipe either
    — `echo $TOKEN | aegis-secret set x` is the same mistake wearing a
    different hat, so a non-TTY stdin is refused rather than accommodated.
    """
    import getpass  # noqa: PLC0415

    if not sys.stdin.isatty():
        print(
            "aegis-secret: refusing to read a secret from a pipe or file.\n"
            "Run this in a terminal; the value must not pass through argv, "
            "shell history or a redirect.",
            file=sys.stderr,
        )
        return 2

    value = getpass.getpass(f"secret for {handle!r} (input hidden): ")
    if not value:
        print("aegis-secret: empty, nothing stored", file=sys.stderr)
        return 1
    if value != getpass.getpass("repeat: "):
        print("aegis-secret: the two entries differ, nothing stored", file=sys.stderr)
        return 1
    try:
        set_secret(handle, value)
    except BrokerError as exc:
        print(f"aegis-secret: {exc}", file=sys.stderr)
        return 1
    finally:
        del value
    print(f"stored {handle!r} in the OS keychain under service {KEYRING_SERVICE!r}")
    print("Aegis will substitute it for ${aegis:%s} in tool calls that policy "
          "permits. Grant it in policy.json under \"credentials\"." % handle)
    return 0


def _cmd_list() -> int:
    """Which handles the policy grants, and whether each has a value stored.

    Reads policy.json for the handle names — keyring has no portable way to
    enumerate a service. Prints presence, never values.
    """
    path = _default_policy_path()
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"aegis-secret: cannot read {path}: {exc}", file=sys.stderr)
        return 1
    creds = doc.get("credentials") or {}
    if not creds:
        print(f"no credentials declared in {path}")
        return 0
    print(f"handles declared in {path}:\n")
    for handle, grant in sorted(creds.items()):
        stored = "set" if secret_exists(handle) else "MISSING"
        tools = ",".join(grant.get("tools") or []) or "-"
        hosts = ",".join(grant.get("hosts") or []) or "-"
        print(f"  {handle:<24} {stored:<8} tools={tools} hosts={hosts}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = (
        "usage: aegis-secret set <name>     store a secret (prompts, no echo)\n"
        "       aegis-secret delete <name>  remove a secret\n"
        "       aegis-secret check <name>   report whether one is stored\n"
        "       aegis-secret list           handles in policy.json and their status\n"
    )
    if not argv or argv[0] in ("-h", "--help"):
        print(usage)
        return 0 if argv else 64

    command, rest = argv[0], argv[1:]

    # S7: say so once, up front, rather than reporting every handle as MISSING
    # and letting the user hunt for a secret that was never the problem.
    usable, why = keyring_available()
    if not usable:
        print(f"aegis-secret: {why}", file=sys.stderr)
        print(
            "aegis-secret: install it with: pip install 'aegis-mcp[keyring]'",
            file=sys.stderr,
        )
        if command in ("set", "delete", "check"):
            return 1

    if command == "list":
        return _cmd_list()
    if command not in ("set", "delete", "check") or len(rest) != 1:
        print(usage, file=sys.stderr)
        return 64
    handle = rest[0]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}", handle):
        print(f"aegis-secret: {handle!r} is not a valid handle name", file=sys.stderr)
        return 64

    if command == "set":
        return _cmd_set(handle)
    if command == "check":
        print(f"{handle}: {'set' if secret_exists(handle) else 'MISSING'}")
        return 0
    try:
        delete_secret(handle)
    except BrokerError as exc:
        print(f"aegis-secret: {exc}", file=sys.stderr)
        return 1
    print(f"deleted {handle!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
