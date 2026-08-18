"""Aegis — an MCP-layer policy proxy with a tamper-evident audit trail.

Read THREAT-MODEL.md before believing anything this package claims. §7 in
particular lists what Aegis does not protect against; `aegis doctor` prints an
abbreviated copy of it because that is where a new user will actually read it.

Nothing is imported here. `aegis.policy` pulls in the whole decision path and
`aegis.proxy` pulls in asyncio; a CLI that only wants `aegis.clients` should
not pay for either, and `import aegis` should never have a side effect.
"""

__version__ = "0.7.0"
