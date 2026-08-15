"""A fake `keyring` module for the S4 tests.

Put this directory on PYTHONPATH and `import keyring` resolves to this instead
of the real library. That keeps the test suite from touching the real macOS
login keychain — which would prompt, would persist, and would make the tests
depend on the state of the developer's machine.

Secrets come from AEGIS_TEST_SECRETS, a JSON object in the environment. That
is a terrible way to handle real secrets and is why this file lives under
tests/fixtures and is never importable from aegis/. tests/s4.py also runs the
real library once, against a temporary file backend, so the production path is
not verified solely against this stub.

The API surface mirrors only what aegis/broker.py uses.
"""

import json
import os


class errors:  # noqa: N801 - mirrors the real module's layout
    class KeyringError(Exception):
        pass

    class PasswordSetError(KeyringError):
        pass

    class PasswordDeleteError(KeyringError):
        pass


def _store() -> dict:
    return json.loads(os.environ.get("AEGIS_TEST_SECRETS", "{}"))


def get_password(service: str, name: str):
    if os.environ.get("AEGIS_TEST_KEYRING_RAISES"):
        # Simulates a backend that puts the secret into its own exception, the
        # case broker.get_secret must never let through.
        raise errors.KeyringError(
            f"backend exploded while reading {name}; "
            f"value was {_store().get(name)!r}"
        )
    # Recorded so a test can assert the keychain was never consulted for a
    # call that policy denied.
    if path := os.environ.get("AEGIS_TEST_KEYRING_LOG"):
        with open(path, "a") as fh:
            fh.write(f"get_password {service} {name}\n")
    return _store().get(name)


def set_password(service: str, name: str, value: str) -> None:
    raise errors.PasswordSetError("the test fixture is read-only")


def delete_password(service: str, name: str) -> None:
    raise errors.PasswordDeleteError("the test fixture is read-only")
