"""Aegis — an MCP-layer policy proxy with a tamper-evident audit trail.

Read THREAT-MODEL.md before believing anything this package claims. §7 in
particular lists what Aegis does not protect against; `aegis doctor` prints an
abbreviated copy of it because that is where a new user will actually read it.

Nothing is imported here. `aegis.policy` pulls in the whole decision path and
`aegis.proxy` pulls in asyncio; a CLI that only wants `aegis.clients` should
not pay for either.

ONE side effect, added deliberately: the interpreter version is checked. It is
here because it is the only code in the package guaranteed to run before any
other — every `aegis.*` import goes through this file — and because the
alternative was what a user actually saw:

    File ".../aegis/cli.py", line 401, in <module>
      def main(argv: list[str] | None = None) -> int:
    TypeError: unsupported operand type(s) for |: 'types.GenericAlias' and
    'NoneType'

`list[str] | None` is valid syntax on 3.9 and a TypeError the instant the `def`
is evaluated, so an old interpreter fails at import with a traceback about an
annotation. That traceback tells a person nothing they can act on, and it
arrives on screens whose whole job is to be readable. requires-python in
pyproject.toml has said >=3.10 since the beginning; this makes the package say
it in a sentence when something runs it anyway.

Written without f-strings or annotations on purpose: it has to run on the
interpreters it is refusing.
"""

import sys

__version__ = "0.7.0"

# Kept in agreement, by hand, with `requires-python` in pyproject.toml and with
# MIN_PYTHON in aegis/verify.py — which cannot import this, by design (S0 open
# question #4), and with MIN_PYTHON in ui/src-tauri/src/python.rs, which is a
# different language. tests/bundle.py asserts all four agree.
MIN_PYTHON = (3, 10)

if sys.version_info < MIN_PYTHON:
    _need = ".".join(str(n) for n in MIN_PYTHON)
    _have = ".".join(str(n) for n in sys.version_info[:3])
    sys.stderr.write(
        "Aegis needs Python %s or newer, and this is Python %s.\n"
        "  interpreter: %s\n"
        "Nothing was read and nothing was changed.\n"
        "Install Python %s or newer and run Aegis with it. If you have one\n"
        "already, set AEGIS_PYTHON to its full path.\n"
        % (_need, _have, sys.executable, _need)
    )
    raise SystemExit(2)
