#![forbid(unsafe_code)]

//! `PostgreSQL`'s frontend/backend protocol, version 3.0, both halves, once.
//!
//! What a client speaks on port 5432 in the simple query flow: the framing,
//! a type byte, a length that counts itself and a body (`wire.rs`); what a
//! client sends — the startup, a password, a query, the goodbye
//! (`frontend.rs`) — and what a server sends — the authentication request,
//! the parameters and key it reports, the row description, the rows, the
//! tag that completes a statement, an error (`backend.rs`). [`Client`] is
//! the near end: it logs in by trust or a cleartext password, queries and
//! executes, and closes; [`Session`] is the far end a test or the
//! Essentials serves, not a database. MD5 and SCRAM are not implemented,
//! and a server that asks for either is told so.
//!
//! **A refusal is [`net::NetError`]**, as every library's is: a
//! connection's failure keeps its kind, and an error the server answered is
//! retryable where its SQLSTATE class says the trouble is the connection, a
//! rollback, a resource or an operator ([`sql_error`]).
//!
//! Who uses it: `xmip-core-transport-postgresql` and
//! `xmip-core-archive-postgresql`. Until 2026-11-13 all of it sat in the
//! `PostgreSQL` transport, and the archive target reached it through that.

pub mod backend;
pub mod client;
pub mod frontend;
pub mod session;
pub mod wire;

pub use client::{Client, QueryResult, sql_error};
pub use session::{Answer, Event, Insert, Session};

/// What this library answers: a value, or why not.
pub type Result<T> = core::result::Result<T, net::NetError>;

/// What a peer sent that is not the protocol: the peer's, and never
/// retried.
#[must_use]
pub fn protocol_error(message: impl Into<String>) -> net::NetError {
    net::NetError::new(message)
}

/// A connection's failure while `doing`, keeping its kind.
#[must_use]
pub fn classify(doing: &str, error: &std::io::Error) -> net::NetError {
    net::NetError::from_io(doing, error)
}
