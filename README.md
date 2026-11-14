# xmip-core-library-postgresql

PostgreSQL's frontend/backend protocol 3.0 for Xmip, one copy, both halves:
what a client and a server send, read and written; a client that logs in,
queries and executes in the simple query flow; and the far end the tests and
the Essentials serve. What a row means to Xmip stays with the transport and
the archive target.

| Item | What it is |
| --- | --- |
| `wire` | The framing — a type byte where there is one, a big-endian length that counts itself, a body — held to `net::MAX_BODY`, and the protocol's own fields on codec's `Cursor` and beside its writer: the i16 count, the NUL-ended string; the startup's version and the authentication methods by number |
| `frontend` | What a client sends: the SSL request, the startup, a password, a query, the goodbye |
| `backend` | What a server sends: the authentication request, a parameter's status, the key data, ready for a query, the row description, a row, the tag that completes a statement, an error |
| `Client` | Connects inside one deadline (`net::connect`); logs in by trust or with a cleartext password; `query`, `execute`, `parameter`, `close`, and `socket`, which a caller keeping the connection asks whether the server still holds it. A server asking for MD5 or SCRAM is told this client speaks trust and cleartext only |
| `Session` | The far end: a login by trust or a password it demands and checks (a wrong one told as `28P01`), a request for TLS declined; then any SELECT answered from one table or a closure, an INSERT of one literal reported as an `Insert`, anything else completed with its verb |

**A refusal is `net::NetError`**, as every library's is. An error the server
answered is retryable where its SQLSTATE class says the trouble is the
connection, a rollback, a resource or an operator (`sql_error`); a wrong
password, a missing table, a syntax error are not.

Who uses it: `xmip-core-transport-postgresql` and
`xmip-core-archive-postgresql`, and the Essentials' archive cabinet serves its
far end. Until 2026-11-13 all of it sat in the PostgreSQL transport, and the
archive target reached it through that.

`architecture.toml` carries the maturity.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
