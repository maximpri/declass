// SPDX-License-Identifier: GPL-3.0-or-later
//! JSON-RPC 2.0 over standard input and output, one message per line, as
//! the protocol's stdio transport defines it.
//!
//! Standard output is the transport, so nothing else may write to it.
//! [`take_stdio`] moves the process's descriptors before anything runs:
//! the protocol keeps private, close-on-exec copies of standard input and
//! output; descriptor 1 becomes standard error and descriptor 0 `/dev/null`.
//! A `println!` anywhere in the process, or a child process that inherited
//! the descriptors (a command, a server, `git`), then writes to the log and
//! reads nothing, and no child can reach the protocol's copies.

use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, Write};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

/// JSON-RPC's and the protocol's error codes, and Declass's own (outside
/// the reserved ranges, as the protocol asks).
pub(crate) const PARSE_ERROR: i64 = -32700;
pub(crate) const INVALID_REQUEST: i64 = -32600;
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
pub(crate) const INVALID_PARAMS: i64 = -32602;
pub(crate) const RESOURCE_NOT_FOUND: i64 = -32002;
/// Declass is not set up for this mode (`declass setup`).
pub(crate) const NOT_SET_UP: i64 = -31001;
/// The turn, or the session's start, failed.
pub(crate) const TURN_FAILED: i64 = -31002;
/// Declass is already working on a prompt.
pub(crate) const BUSY: i64 = -31003;
/// The workspace's configuration refuses the session.
pub(crate) const REFUSED: i64 = -31004;

/// The longest message read; a longer line is skipped, and the request it
/// held is answered with an error.
pub(crate) const MAX_LINE: usize = 64 * 1024 * 1024;

/// Takes standard input and output for the protocol (see the module
/// documentation). Returns the protocol's input and output.
pub(crate) fn take_stdio() -> std::io::Result<(File, File)> {
    let _ = std::io::stdout().flush();
    let input = rustix::io::fcntl_dupfd_cloexec(std::io::stdin(), 3)?;
    let output = rustix::io::fcntl_dupfd_cloexec(std::io::stdout(), 3)?;
    rustix::stdio::dup2_stdout(std::io::stderr())?;
    let null = File::open("/dev/null")?;
    rustix::stdio::dup2_stdin(&null)?;
    Ok((File::from(input), File::from(output)))
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    pub(crate) fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub(crate) fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// The protocol's output: whole lines, one writer at a time.
pub(crate) struct Wire {
    out: Mutex<Box<dyn Write + Send>>,
}

impl Wire {
    pub(crate) fn new(out: impl Write + Send + 'static) -> Self {
        Self {
            out: Mutex::new(Box::new(out)),
        }
    }

    fn send(&self, message: &Value) {
        // A serialized value holds no raw newline: inside strings it is `\n`.
        let Ok(mut line) = serde_json::to_vec(message) else {
            return;
        };
        line.push(b'\n');
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        // A client that went away is noticed by the reader (end of input).
        let _ = out.write_all(&line).and_then(|()| out.flush());
    }

    pub(crate) fn respond(&self, id: &Value, result: impl Serialize) {
        let result = serde_json::to_value(result).unwrap_or(Value::Null);
        self.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
    }

    pub(crate) fn fail(&self, id: &Value, error: &RpcError) {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "error": error}));
    }

    pub(crate) fn notify(&self, method: &str, params: impl Serialize) {
        let params = serde_json::to_value(params).unwrap_or(Value::Null);
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    pub(crate) fn request(&self, id: u64, method: &str, params: impl Serialize) {
        let params = serde_json::to_value(params).unwrap_or(Value::Null);
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
    }
}

/// One message read from the client.
#[derive(Debug, PartialEq)]
pub(crate) enum Message {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
    /// The answer to a request Declass sent: its result, or its error.
    Response {
        id: Value,
        outcome: Result<Value, Value>,
    },
}

/// A line that is not a message Declass can take: the error to answer with,
/// and the id to answer (null when the line had none).
#[derive(Debug, PartialEq)]
pub(crate) struct Refusal {
    pub id: Value,
    pub error: RpcError,
}

fn refusal(id: Option<Value>, code: i64, why: &str) -> Box<Refusal> {
    Box::new(Refusal {
        id: id.unwrap_or(Value::Null),
        error: RpcError::new(code, why),
    })
}

/// Reads one line as a JSON-RPC message.
pub(crate) fn parse(line: &[u8]) -> Result<Message, Box<Refusal>> {
    let value: Value =
        serde_json::from_slice(line).map_err(|_| refusal(None, PARSE_ERROR, "parse error"))?;
    let Value::Object(mut map) = value else {
        return Err(refusal(
            None,
            INVALID_REQUEST,
            "not a JSON-RPC object (batches are not accepted)",
        ));
    };
    let id = map.remove("id");
    // JSON-RPC ids are strings, numbers or null; any other is not echoed.
    if id
        .as_ref()
        .is_some_and(|id| !(id.is_string() || id.is_number() || id.is_null()))
    {
        return Err(refusal(
            None,
            INVALID_REQUEST,
            "an id is a string, a number or null",
        ));
    }
    let invalid = |id: Option<Value>, why: &str| Err(refusal(id, INVALID_REQUEST, why));
    if map.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid(id, "not JSON-RPC 2.0");
    }
    let params = map.remove("params").unwrap_or(Value::Null);
    match (map.remove("method"), id) {
        (Some(Value::String(method)), Some(id)) => Ok(Message::Request { id, method, params }),
        (Some(Value::String(method)), None) => Ok(Message::Notification { method, params }),
        (None, Some(id)) => match (map.remove("result"), map.remove("error")) {
            (Some(result), None) => Ok(Message::Response {
                id,
                outcome: Ok(result),
            }),
            (None, Some(error)) => Ok(Message::Response {
                id,
                outcome: Err(error),
            }),
            _ => invalid(Some(id), "a response has a result or an error"),
        },
        (_, id) => invalid(id, "a request names its method"),
    }
}

/// What reading the next line found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Read {
    Line(Vec<u8>),
    /// A line longer than the limit (it was skipped): its start, to find
    /// the id of the request it held.
    TooLong(Vec<u8>),
    End,
}

/// Bytes of an over-long line kept to find its id in.
const HEAD: usize = 4096;

/// The next line of `input` (without its newline), at most `max` bytes.
pub(crate) fn read_line(input: &mut impl BufRead, max: usize) -> Read {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buf = match input.fill_buf() {
            Ok(buf) => buf,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Read::End,
        };
        if buf.is_empty() {
            return match (too_long, line.is_empty()) {
                (true, _) => Read::TooLong(line),
                (false, true) => Read::End,
                // A last line without a newline still counts.
                (false, false) => Read::Line(line),
            };
        }
        let (take, newline) = match buf.iter().position(|&b| b == b'\n') {
            Some(at) => (at, true),
            None => (buf.len(), false),
        };
        if !too_long {
            line.extend_from_slice(&buf[..take]);
            if line.len() > max {
                too_long = true;
                line.truncate(HEAD);
            }
        }
        input.consume(take + usize::from(newline));
        if newline {
            return if too_long {
                Read::TooLong(line)
            } else {
                Read::Line(line)
            };
        }
    }
}

/// The id of the request an over-long line starts (a number or a string
/// near its start), so the request is answered rather than left waiting.
pub(crate) fn head_id(head: &[u8]) -> Value {
    let text = String::from_utf8_lossy(head);
    let Some(at) = text.find("\"id\"") else {
        return Value::Null;
    };
    let rest = text[at + 4..].trim_start();
    let Some(rest) = rest.strip_prefix(':') else {
        return Value::Null;
    };
    let rest = rest.trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        return quoted
            .find('"')
            .filter(|&end| !quoted[..end].contains('\\'))
            .map_or(Value::Null, |end| Value::String(quoted[..end].to_owned()));
    }
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse::<i64>().map_or(Value::Null, Value::from)
}

/// Requests Declass sent and waits on, by id, with their answers once
/// they arrive.
#[derive(Default)]
pub(crate) struct Pending {
    slots: Mutex<HashMap<u64, Option<Result<Value, Value>>>>,
    ready: Condvar,
}

impl Pending {
    /// Expects an answer to request `id`.
    pub(crate) fn expect(&self, id: u64) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, None);
    }

    /// Hands an answer to whoever waits for it; false when nobody does.
    pub(crate) fn deliver(&self, id: &Value, outcome: Result<Value, Value>) -> bool {
        let Some(id) = id.as_u64() else {
            return false;
        };
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(slot) = slots.get_mut(&id) else {
            return false;
        };
        *slot = Some(outcome);
        drop(slots);
        self.ready.notify_all();
        true
    }

    /// Wakes every waiter to check whether to give up.
    pub(crate) fn wake(&self) {
        self.ready.notify_all();
    }

    /// Waits for the answer to `id`; `None` once `give_up` says so, even
    /// when an answer is there too. Messages are read in order, so an answer
    /// read after what made `give_up` true (a cancellation) never counts.
    pub(crate) fn wait(&self, id: u64, give_up: impl Fn() -> bool) -> Option<Result<Value, Value>> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if give_up() {
                slots.remove(&id);
                return None;
            }
            if slots.get(&id).is_some_and(Option::is_some) {
                return slots.remove(&id).flatten();
            }
            slots = self
                .ready
                .wait_timeout(slots, Duration::from_millis(100))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn lines_are_messages_and_bad_ones_are_answered() {
        assert_eq!(
            parse(
                br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}"#
            ),
            Ok(Message::Request {
                id: json!(1),
                method: "initialize".into(),
                params: json!({"protocolVersion": 1})
            })
        );
        assert_eq!(
            parse(br#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s"}}"#),
            Ok(Message::Notification {
                method: "session/cancel".into(),
                params: json!({"sessionId": "s"})
            })
        );
        assert_eq!(
            parse(br#"{"jsonrpc":"2.0","id":"x","error":{"code":1,"message":"no"}}"#),
            Ok(Message::Response {
                id: json!("x"),
                outcome: Err(json!({"code": 1, "message": "no"}))
            })
        );
        let code = |line: &[u8]| parse(line).unwrap_err();
        assert_eq!(code(b"{not json").error.code, PARSE_ERROR);
        assert_eq!(code(b"[1,2]").error.code, INVALID_REQUEST);
        let refused = code(br#"{"jsonrpc":"1.0","id":7,"method":"x"}"#);
        assert_eq!(
            (refused.id, refused.error.code),
            (json!(7), INVALID_REQUEST)
        );
        assert_eq!(
            code(br#"{"jsonrpc":"2.0","id":7}"#).error.code,
            INVALID_REQUEST
        );
        // Ids other than strings, numbers and null are refused, never echoed.
        for id in [r#"{"a":1}"#, "[1]", "true"] {
            let line = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize"}}"#);
            let refused = code(line.as_bytes());
            assert_eq!(
                (refused.id, refused.error.code),
                (Value::Null, INVALID_REQUEST)
            );
        }
        assert!(parse(br#"{"jsonrpc":"2.0","id":null,"method":"x"}"#).is_ok());
    }

    #[test]
    fn written_messages_are_single_lines() {
        let out = Arc::new(Mutex::new(Vec::new()));
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let wire = Wire::new(Shared(out.clone()));
        wire.respond(&json!(3), json!({"text": "two\nlines"}));
        wire.notify("session/update", json!({"a": "\r\n"}));
        wire.fail(&Value::Null, &RpcError::new(PARSE_ERROR, "parse error"));
        let written = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 3, "{written}");
        for line in lines {
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["jsonrpc"], "2.0");
        }
    }

    #[test]
    fn long_lines_are_skipped_whole_and_the_next_one_is_read() {
        let long = format!(
            r#"{{"jsonrpc":"2.0","id":42,"params":"{}"}}"#,
            "x".repeat(50)
        );
        let input = format!("{long}\nshort\nlast");
        let mut reader = std::io::BufReader::with_capacity(8, input.as_bytes());
        let Read::TooLong(head) = read_line(&mut reader, 30) else {
            panic!("not too long")
        };
        assert!(head.starts_with(br#"{"jsonrpc":"2.0","id":42"#));
        assert_eq!(head_id(&head), json!(42));
        assert_eq!(read_line(&mut reader, 30), Read::Line(b"short".to_vec()));
        assert_eq!(read_line(&mut reader, 30), Read::Line(b"last".to_vec()));
        assert_eq!(read_line(&mut reader, 30), Read::End);
        assert_eq!(head_id(br#"{"id" : "p-7", "method""#), json!("p-7"));
        assert_eq!(head_id(br#"{"jsonrpc":"2.0","method":"x""#), Value::Null);
        assert_eq!(head_id(br#"{"id":"a\"b"}"#), Value::Null);
    }

    #[test]
    fn a_waiter_gets_its_answer_or_gives_up() {
        let pending = Arc::new(Pending::default());
        pending.expect(1);
        let feed = pending.clone();
        let answer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            assert!(feed.deliver(&json!(1), Ok(json!("yes"))));
        });
        assert_eq!(pending.wait(1, || false), Some(Ok(json!("yes"))));
        answer.join().unwrap();
        // Nobody waits for an id never sent, or one already answered.
        assert!(!pending.deliver(&json!(1), Ok(json!("again"))));
        assert!(!pending.deliver(&json!("1"), Ok(json!("text id"))));
        pending.expect(2);
        let stop = Arc::new(AtomicBool::new(false));
        let raise = stop.clone();
        let waker = pending.clone();
        let cancel = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            raise.store(true, Ordering::SeqCst);
            waker.wake();
        });
        assert_eq!(pending.wait(2, || stop.load(Ordering::SeqCst)), None);
        cancel.join().unwrap();
        assert!(!pending.deliver(&json!(2), Ok(json!("late"))));
        // A cancellation and then an answer, both read before the waiter
        // looks: the answer came after the cancellation and does not count.
        pending.expect(3);
        assert!(pending.deliver(&json!(3), Ok(json!("allow after cancel"))));
        assert_eq!(pending.wait(3, || true), None);
        assert!(!pending.deliver(&json!(3), Ok(json!("later still"))));
    }
}
