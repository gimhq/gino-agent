//! Synchronous client for the local agent API.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use super::protocol::{ErrorCode, PROTOCOL_VERSION, Request, Response};

/// Read and write timeout on the socket.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// A client-side failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClientError {
    #[error("the agent is not running")]
    NotRunning(#[source] std::io::Error),
    #[error("{code}: {message}")]
    Api { code: ErrorCode, message: String },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("talking to the agent failed: {0}")]
    Io(#[from] std::io::Error),
}

/// One connection to the agent API.
#[derive(Debug)]
pub(crate) struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl Client {
    /// Connect to the socket at `path`.
    pub(crate) fn connect(path: &Path) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path).map_err(ClientError::NotRunning)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
            next_id: 0,
        })
    }

    /// Authenticate this connection with a run token.
    pub(crate) fn auth(&mut self, token: &str) -> Result<Value, ClientError> {
        self.call("auth", json!({ "token": token }))
    }

    /// Send one request and wait for its result.
    pub(crate) fn call(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        self.next_id += 1;
        let id = self.next_id.to_string();
        let request = Request {
            v: PROTOCOL_VERSION,
            id: id.clone(),
            method: method.to_owned(),
            params: Some(params),
        };
        let mut line = serde_json::to_vec(&request)
            .map_err(|err| ClientError::Protocol(format!("encoding the request: {err}")))?;
        line.push(b'\n');
        self.writer.write_all(&line)?;
        self.writer.flush()?;

        let mut reply = String::new();
        if self.reader.read_line(&mut reply)? == 0 {
            return Err(ClientError::Protocol(
                "the agent closed the connection".to_owned(),
            ));
        }
        let response: Response = serde_json::from_str(&reply)
            .map_err(|err| ClientError::Protocol(format!("malformed response: {err}")))?;
        if response.v != PROTOCOL_VERSION {
            return Err(ClientError::Protocol(format!(
                "unexpected protocol version {}",
                response.v
            )));
        }
        if response.id.as_deref() != Some(id.as_str()) {
            return Err(ClientError::Protocol(format!(
                "response id {:?} does not match request id {id}",
                response.id
            )));
        }
        match (response.result, response.error) {
            (_, Some(err)) => Err(ClientError::Api {
                code: err.code,
                message: err.message,
            }),
            (Some(result), None) => Ok(result),
            (None, None) => Err(ClientError::Protocol(
                "response has neither result nor error".to_owned(),
            )),
        }
    }
}
