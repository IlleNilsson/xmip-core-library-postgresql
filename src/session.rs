//! The server's side of one connection: what a test puts at the far end,
//! and what the System Tests drive.
//!
//! Not a database. One session does the login for one client — trust, or
//! a cleartext password it demands and checks — and answers each query
//! from a closure or from one fixed table: any SELECT gets the table's
//! rows, an INSERT of one literal into one column is reported as an
//! [`Insert`], anything else is completed with its own verb. What the
//! literal stands for is the caller's to read. Planning, storage and SQL
//! are a database's.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpStream};

use sql::{Literal, POSTGRESQL, Verb};

use crate::backend::{Backend, encode_backend};
use crate::frontend::{Frontend, read_frontend, read_startup};
use crate::wire::{AUTH_CLEARTEXT, AUTH_OK};
use crate::{Result, classify, protocol_error};

/// One literal a client inserted into one column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insert {
    pub table: String,
    pub column: String,
    pub literal: Literal,
}

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one value; here it is.
    Inserted(Insert),
    /// The client ran something else; here it is.
    Executed(String),
}

/// What answers a query before the fixed table: `None` declines.
type Answering = Box<dyn FnMut(&str) -> Option<Answer> + Send>;

/// How a query is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
    },
    Complete(String),
    Error {
        code: String,
        message: String,
    },
}

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    user: String,
    database: String,
    columns: Vec<String>,
    rows: Vec<Vec<Option<String>>>,
    answering: Option<Answering>,
}

impl Session {
    /// Log the client on `stream` in: with `password`, by demanding it in
    /// the clear and checking; without, by trust.
    ///
    /// # Errors
    /// Where the client did not open with a startup message, or gave the
    /// wrong password — which is told to the client as `28P01` before this
    /// returns.
    pub fn accept(stream: TcpStream, password: Option<&str>) -> Result<Self> {
        let peer = stream
            .peer_addr()
            .map_err(|e| classify("reading the peer's address", &e))?;
        let writer = stream
            .try_clone()
            .map_err(|e| classify("cloning the connection", &e))?;
        let mut session = Self {
            reader: BufReader::new(stream),
            writer,
            peer,
            user: String::new(),
            database: String::new(),
            columns: Vec::new(),
            rows: Vec::new(),
            answering: None,
        };
        session.startup()?;
        if let Some(expected) = password {
            session.write(&Backend::Authentication(AUTH_CLEARTEXT))?;
            let Some(Frontend::Password(given)) = read_frontend(&mut session.reader)? else {
                return Err(protocol_error("the client did not answer with a password"));
            };
            if !codec::constant_time::equal(given.as_bytes(), expected.as_bytes()) {
                let message = format!(
                    "password authentication failed for user \"{}\"",
                    session.user
                );
                session.write(&Backend::ErrorResponse {
                    severity: "FATAL".to_string(),
                    code: "28P01".to_string(),
                    message: message.clone(),
                })?;
                return Err(protocol_error(message));
            }
        }
        session.write(&Backend::Authentication(AUTH_OK))?;
        session.write(&Backend::ParameterStatus {
            name: "server_version".to_string(),
            value: "16.0 (xmip)".to_string(),
        })?;
        session.write(&Backend::BackendKeyData {
            process: 1,
            secret: 0,
        })?;
        session.write(&Backend::ReadyForQuery(b'I'))?;
        Ok(session)
    }

    /// The startup message, a request for TLS declined on the way.
    fn startup(&mut self) -> Result<()> {
        loop {
            match read_startup(&mut self.reader)? {
                Some(Frontend::SslRequest) => self
                    .writer
                    .write_all(b"N")
                    .map_err(|e| classify("declining TLS", &e))?,
                Some(Frontend::Startup { user, database }) => {
                    self.user = user;
                    self.database = database;
                    return Ok(());
                }
                _ => {
                    return Err(protocol_error(
                        "the client did not open with a startup message",
                    ));
                }
            }
        }
    }

    /// The user the client logged in as.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The database the client asked for.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    /// Where the client connected from.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Answer any SELECT with these `columns` and `rows`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&str>]]) -> Self {
        self.columns = columns.iter().map(ToString::to_string).collect();
        self.rows = rows
            .iter()
            .map(|row| row.iter().map(|v| v.map(ToString::to_string)).collect())
            .collect();
        self
    }

    /// Answer queries with `answering` first; what it declines falls to the
    /// table.
    #[must_use]
    pub fn answering(
        mut self,
        answering: impl FnMut(&str) -> Option<Answer> + Send + 'static,
    ) -> Self {
        self.answering = Some(Box::new(answering));
        self
    }

    /// The next value the client inserts, or `None` when it closed.
    /// Everything else is answered on the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_insert(&mut self) -> Result<Option<Insert>> {
        while let Some(event) = self.next_event()? {
            if let Event::Inserted(insert) = event {
                return Ok(Some(insert));
            }
        }
        Ok(None)
    }

    /// The next query the client ran, answered, or `None` when it closed.
    ///
    /// # Errors
    /// Where the connection broke, nothing arrived before the timeout, or
    /// the client sent what the simple flow does not.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            match read_frontend(&mut self.reader)? {
                Some(Frontend::Query(sql)) => {
                    let (answer, event) = self.answer(&sql);
                    self.write_answer(&answer)?;
                    self.write(&Backend::ReadyForQuery(b'I'))?;
                    return Ok(Some(event));
                }
                Some(Frontend::Terminate) | None => return Ok(None),
                Some(Frontend::Password(_)) => {}
                Some(other) => {
                    return Err(protocol_error(format!("{other:?} after the login")));
                }
            }
        }
    }

    fn answer(&mut self, sql: &str) -> (Answer, Event) {
        if let Some(answer) = self.answering.as_mut().and_then(|f| f(sql)) {
            return (answer, Event::Executed(sql.to_string()));
        }
        let verb = Verb::of_statement(sql);
        match verb {
            Some(Verb::Select) => (
                Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                },
                Event::Selected(sql.to_string()),
            ),
            Some(Verb::Insert) => match POSTGRESQL.parse_insert_literal(sql) {
                Some((table, column, literal)) => (
                    Answer::Complete("INSERT 0 1".to_string()),
                    Event::Inserted(Insert {
                        table,
                        column,
                        literal,
                    }),
                ),
                None => (
                    Answer::Error {
                        code: "42601".to_string(),
                        message: "only INSERT INTO t (c) VALUES ('v') is served here".to_string(),
                    },
                    Event::Executed(sql.to_string()),
                ),
            },
            _ => {
                // The command tag names the verb, as the server's does.
                let tag = verb.map_or_else(String::new, |verb| verb.name().to_ascii_uppercase());
                (Answer::Complete(tag), Event::Executed(sql.to_string()))
            }
        }
    }

    fn write_answer(&mut self, answer: &Answer) -> Result<()> {
        match answer {
            Answer::Rows { columns, rows } => {
                self.write(&Backend::RowDescription(columns.clone()))?;
                for row in rows {
                    self.write(&Backend::DataRow(row.clone()))?;
                }
                self.write(&Backend::CommandComplete(format!("SELECT {}", rows.len())))
            }
            Answer::Complete(tag) => self.write(&Backend::CommandComplete(tag.clone())),
            Answer::Error { code, message } => self.write(&Backend::ErrorResponse {
                severity: "ERROR".to_string(),
                code: code.clone(),
                message: message.clone(),
            }),
        }
    }

    fn write(&mut self, message: &Backend) -> Result<()> {
        self.writer
            .write_all(&encode_backend(message))
            .map_err(|e| classify("writing a message", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a message", &e))
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::Duration;

    use super::*;
    use crate::Client;

    /// A far end on `listener` for one client, logging it in with
    /// `password` and serving one row until it says goodbye.
    fn far_end(
        listener: TcpListener,
        password: Option<&'static str>,
    ) -> std::thread::JoinHandle<Result<Vec<Event>>> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().map_err(|e| classify("accepting", &e))?;
            let mut session = Session::accept(stream, password)?
                .with_table(&["id", "payload"], &[&[Some("41"), None]]);
            assert_eq!((session.user(), session.database()), ("xmip", "orders"));
            let mut events = Vec::new();
            while let Some(event) = session.next_event()? {
                events.push(event);
            }
            Ok(events)
        })
    }

    #[test]
    fn a_client_logs_in_selects_and_inserts_and_the_session_reports_each() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let served = far_end(listener, Some("secret"));
        let timeout = Some(Duration::from_secs(2));
        let mut client =
            Client::connect(&address, "xmip", "orders", Some("secret"), timeout).expect("login");
        assert_eq!(client.parameter("server_version"), Some("16.0 (xmip)"));
        let selected = client.query("SELECT id, payload FROM inbox").expect("rows");
        assert_eq!(selected.rows, [[Some("41".to_string()), None]]);
        assert_eq!(selected.tag, "SELECT 1");
        let insert = POSTGRESQL.insert("inbox", "payload", &POSTGRESQL.quote_bytes(b"it's"));
        assert_eq!(client.execute(&insert).expect("inserted"), "INSERT 0 1");
        assert_eq!(client.execute("DELETE FROM inbox").expect("done"), "DELETE");
        client.close().expect("goodbye");
        let events = served.join().expect("thread").expect("served");
        assert_eq!(
            events[0],
            Event::Selected("SELECT id, payload FROM inbox".into())
        );
        assert_eq!(
            events[1],
            Event::Inserted(Insert {
                table: "inbox".into(),
                column: "payload".into(),
                literal: Literal::Text("\\x69742773".into()),
            })
        );
        assert_eq!(events[2], Event::Executed("DELETE FROM inbox".into()));
    }

    #[test]
    fn a_wrong_password_is_told_to_the_client_and_refused_at_both_ends() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let served = far_end(listener, Some("secret"));
        let timeout = Some(Duration::from_secs(2));
        let refused = Client::connect(&address, "xmip", "orders", Some("wrong"), timeout)
            .err()
            .expect("wrong password");
        assert!(refused.message.contains("28P01"), "{refused}");
        assert!(refused.io.is_none(), "never retried");
        let failed = served.join().expect("thread").expect_err("refused");
        assert!(failed.message.contains("password authentication failed"));
    }
}
