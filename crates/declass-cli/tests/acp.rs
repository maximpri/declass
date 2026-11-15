// SPDX-License-Identifier: GPL-3.0-or-later
//! `declass acp` end to end: the binary started as an editor starts it and
//! driven over standard input and output with the Agent Client Protocol,
//! against a scripted frontier on loopback (no model server, no network
//! beyond 127.0.0.1), in hybrid mode without a local model.
//!
//! The editor initializes, offers an MCP server of its own (never started),
//! opens a session and sends prompts with an @-mentioned `.env` embedded in
//! them, a linked source file, pasted text holding a secret and an image.
//! The tool calls and replies arrive as `session/update` notifications; a
//! write that needs approval is asked with `session/request_permission`:
//! rejected, it is not run; answered with an error, it is not run; allowed,
//! it is. A cancelled turn ends `cancelled` and the session continues. No
//! planted value reaches any frontier request, every line on standard output
//! is a JSON-RPC message (a line printed during the session lands on standard
//! error), and the session is left open with one verified audit log.
//! Without models chosen, `initialize` says to run `declass setup`.

use declass_boundary::testing::canary::Canaries;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A payment key in `.env` (sensitive by the default policy).
const ENV_KEY: &str = concat!("sk_", "live_Wq7Zp3Lx9Cv2Rb8Nm4Kd");
/// A customer's email in `data/customers.csv` (sensitive data file).
const EMAIL: &str = "teodora.vance@quillmere.example";
/// A secret in text the editor attached (pasted text: sanitized).
const PASTED_KEY: &str = concat!("sk_", "live_Pd5Hn2Qs8Tx4Vy6Zc1Ma");

/// What the scripted frontier answers one request with.
enum Step {
    Call(&'static str, Value),
    /// Accept the request and never answer.
    Hang,
}

/// A loopback server speaking just enough HTTP/1.1 and SSE for one provider;
/// it keeps each request body.
struct Frontier {
    port: u16,
    steps: Arc<Mutex<VecDeque<Step>>>,
    bodies: Arc<Mutex<Vec<String>>>,
}

impl Frontier {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let steps: Arc<Mutex<VecDeque<Step>>> = Arc::default();
        let bodies: Arc<Mutex<Vec<String>>> = Arc::default();
        let (s, b) = (steps.clone(), bodies.clone());
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                if let Some(hung) = serve(stream, &s, &b) {
                    held.push(hung);
                }
            }
        });
        Self {
            port,
            steps,
            bodies,
        }
    }

    fn script(&self, steps: Vec<Step>) {
        self.steps.lock().unwrap().extend(steps);
    }

    fn requests(&self) -> usize {
        self.bodies.lock().unwrap().len()
    }

    fn body(&self, i: usize) -> String {
        self.bodies.lock().unwrap()[i].clone()
    }

    fn bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }

    fn wait_for_requests(&self, n: usize) {
        let started = Instant::now();
        while self.requests() < n {
            assert!(
                started.elapsed() < Duration::from_secs(90),
                "the frontier got {} request(s), not {n}",
                self.requests()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn serve(
    stream: TcpStream,
    steps: &Mutex<VecDeque<Step>>,
    bodies: &Mutex<Vec<String>>,
) -> Option<TcpStream> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        if line.trim().is_empty() {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    let n = {
        let mut b = bodies.lock().unwrap();
        b.push(String::from_utf8_lossy(&body).into_owned());
        b.len()
    };
    let step = steps
        .lock()
        .unwrap()
        .pop_front()
        .expect("unscripted request");
    let (name, args) = match step {
        Step::Hang => return Some(stream),
        Step::Call(name, args) => (name, args),
    };
    let call = json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": format!("c{n}"),
        "type": "function", "function": {"name": name, "arguments": args.to_string()}}]}}]});
    let sse = format!(
        "data: {call}\n\n\
data: {{\"choices\":[{{\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}]}}\n\n\
data: {{\"choices\":[],\"usage\":{{\"prompt_tokens\":1000,\"completion_tokens\":20}}}}\n\n\
data: [DONE]\n\n"
    );
    let mut out = stream;
    let _ = write!(
        out,
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{sse}",
        sse.len()
    );
    None
}

struct Env {
    _dir: tempfile::TempDir,
    home: PathBuf,
    ws: PathBuf,
}

/// A git repository holding code, a gitignored `.env` and a customer file.
fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (home, ws) = (root.join("owner"), root.join("ws"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::create_dir_all(ws.join("data")).unwrap();
    std::fs::write(ws.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
    std::fs::write(ws.join(".gitignore"), ".env\n").unwrap();
    std::fs::write(
        ws.join(".env"),
        format!("PAYMENTS_API_KEY={ENV_KEY}\nPORT=8443\n"),
    )
    .unwrap();
    std::fs::write(
        ws.join("data/customers.csv"),
        format!("id,name,email\n1,Teodora Vance,{EMAIL}\n"),
    )
    .unwrap();
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(&ws)
                .status()
                .unwrap()
                .success()
        )
    };
    git(&["init", "-q"]);
    git(&["add", "."]);
    git(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.org",
        "commit",
        "-qm",
        "start",
    ]);
    Env {
        _dir: dir,
        home,
        ws,
    }
}

fn owner_config(e: &Env, text: &str) {
    std::fs::write(e.home.join("config.toml"), text).unwrap();
}

/// The owner's setup: the scripted frontier, no local model, approval of
/// risky actions on.
fn configured(e: &Env, f: &Frontier) {
    owner_config(
        e,
        &format!(
            "[frontier]\nbase_url = \"http://127.0.0.1:{}/v1\"\nmodel = \"glm-5.3-flash\"\napi_key_env = \"ZAI_API_KEY\"\n\
             [local]\nenabled = false\n\
             [oversight]\napprove = \"risky\"\n",
            f.port
        ),
    );
}

fn declass(e: &Env, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_declass"));
    c.args(args)
        .current_dir(&e.home)
        .env("DECLASS_CONFIG_HOME", &e.home)
        .env("ZAI_API_KEY", "loopback-test-key")
        .env_remove("DECLASS_LOCAL_PORTS");
    c
}

/// The editor's end of `declass acp`: what it sent, and every line the agent
/// wrote, in order.
struct Editor {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<String>>,
    next: i64,
    /// Messages already looked at by `next_message`.
    seen: usize,
}

impl Editor {
    fn start(e: &Env) -> Self {
        let mut child = declass(e, &["acp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let stderr: Arc<Mutex<String>> = Arc::default();
        let out = child.stdout.take().unwrap();
        let sink = lines.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });
        let err = child.stderr.take().unwrap();
        let sink = stderr.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let mut s = sink.lock().unwrap();
                s.push_str(&line);
                s.push('\n');
            }
        });
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            lines,
            stderr,
            next: 0,
            seen: 0,
        }
    }

    fn log(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn send_raw(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> i64 {
        self.next += 1;
        let id = self.next;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        id
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn messages(&self) -> Vec<Value> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .map(|l| serde_json::from_str(l).unwrap_or(Value::Null))
            .collect()
    }

    /// Waits for a message not looked at yet that matches, and returns it.
    fn next_message(&mut self, what: &str, matches: impl Fn(&Value) -> bool) -> Value {
        let started = Instant::now();
        loop {
            let messages = self.messages();
            if let Some(i) = (self.seen..messages.len()).find(|&i| matches(&messages[i])) {
                self.seen = i + 1;
                return messages[i].clone();
            }
            assert!(
                started.elapsed() < Duration::from_secs(120),
                "waited for {what}; the agent wrote:\n{}\nand logged:\n{}",
                self.lines.lock().unwrap().join("\n"),
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits for the answer to request `id`.
    fn answer(&mut self, id: i64) -> Value {
        let found = self.messages().into_iter().find(|m| is_answer(m, id));
        found.unwrap_or_else(|| {
            self.next_message(&format!("the answer to request {id}"), |m| is_answer(m, id))
        })
    }

    fn finish(mut self) -> (i32, Vec<String>, String) {
        drop(self.stdin.take());
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(120) {
                let _ = self.child.kill();
                panic!("declass acp did not end; it logged:\n{}", self.log());
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        std::thread::sleep(Duration::from_millis(300));
        let lines = self.lines.lock().unwrap().clone();
        (status.code().unwrap_or(-1), lines, self.log())
    }
}

fn is_answer(m: &Value, id: i64) -> bool {
    m["id"] == json!(id) && (m.get("result").is_some() || m.get("error").is_some())
}

fn updates_of(messages: &[Value], kind: &str) -> Vec<Value> {
    messages
        .iter()
        .filter(|m| {
            m["method"] == "session/update" && m["params"]["update"]["sessionUpdate"] == kind
        })
        .map(|m| m["params"]["update"].clone())
        .collect()
}

/// The agent's message text sent so far.
fn said(messages: &[Value]) -> String {
    updates_of(messages, "agent_message_chunk")
        .iter()
        .filter_map(|u| u["content"]["text"].as_str().map(str::to_owned))
        .collect()
}

fn uri(path: &Path) -> String {
    format!("file://{}", path.display())
}

#[test]
fn an_editor_session_keeps_the_boundary_asks_permission_and_cancels() {
    let e = env();
    let f = Frontier::start();
    configured(&e, &f);
    let marker = e.ws.join("editor-mcp-started");
    let mut editor = Editor::start(&e);

    let id = editor.request(
        "initialize",
        json!({"protocolVersion": 1, "clientCapabilities": {"fs": {"readTextFile": true,
            "writeTextFile": true}, "terminal": true}, "clientInfo": {"name": "test-editor", "version": "1.0"}}),
    );
    let init = editor.answer(id);
    let result = &init["result"];
    assert_eq!(result["protocolVersion"], 1, "{init}");
    assert_eq!(result["agentInfo"]["name"], "declass");
    assert_eq!(result["agentCapabilities"]["loadSession"], false);
    assert_eq!(
        result["agentCapabilities"]["promptCapabilities"],
        json!({"image": false, "audio": false, "embeddedContext": true})
    );
    assert_eq!(
        result["agentCapabilities"]["mcpCapabilities"],
        json!({"http": false, "sse": false})
    );
    assert_eq!(result["authMethods"], json!([]));

    // The editor's own MCP server is never started.
    let id = editor.request(
        "session/new",
        json!({"cwd": e.ws, "mcpServers": [{"name": "editor-tools", "command": "/bin/sh",
            "args": ["-c", format!("touch '{}'", marker.display())], "env": []}]}),
    );
    let created = editor.answer(id);
    let session = created["result"]["sessionId"]
        .as_str()
        .unwrap_or_else(|| panic!("{created}"))
        .to_owned();

    // Turn 1: an @-mentioned `.env` (embedded), a linked source file, pasted
    // text with a secret, and an image, which is not used.
    f.script(vec![
        Step::Call("read_file", json!({"path": ".env"})),
        Step::Call("reply", json!({"message": "The key is configured."})),
    ]);
    let id = editor.request(
        "session/prompt",
        json!({"sessionId": session, "prompt": [
            {"type": "text", "text": "Is the key in "},
            {"type": "resource", "resource": {"uri": uri(&e.ws.join(".env")), "mimeType": "text/plain",
                "text": format!("PAYMENTS_API_KEY={ENV_KEY}\nPORT=8443\n")}},
            {"type": "text", "text": " used by "},
            {"type": "resource_link", "uri": uri(&e.ws.join("src/lib.rs")), "name": "lib.rs"},
            {"type": "text", "text": "?"},
            {"type": "resource", "resource": {"uri": "zed:///agent/rule/1",
                "text": format!("Rotate STRIPE_SECRET_KEY={PASTED_KEY} before release.")}},
            {"type": "image", "mimeType": "image/png", "data": "iVBORw0KGgo="}
        ]}),
    );
    let first = editor.answer(id);
    assert_eq!(first["result"]["stopReason"], "end_turn", "{first}");
    let messages = editor.messages();
    let calls = updates_of(&messages, "tool_call");
    let read = calls
        .iter()
        .find(|c| c["toolCallId"] == "c1")
        .unwrap_or_else(|| panic!("no read_file card: {messages:?}"));
    assert_eq!(read["title"], "read .env");
    assert_eq!(read["kind"], "read");
    let read_done = updates_of(&messages, "tool_call_update")
        .into_iter()
        .rfind(|u| u["toolCallId"] == "c1")
        .unwrap();
    assert_eq!(read_done["status"], "completed", "{read_done}");
    let text = said(&messages);
    assert!(text.contains("The key is configured."), "{text}");
    assert!(
        text.contains("Not used, and nothing of it was sent: an image"),
        "{text}"
    );
    // The mention is the path, never the embedded content.
    let sent = f.body(0);
    assert!(
        sent.contains("`.env`") && sent.contains("`src/lib.rs`"),
        "{sent}"
    );
    assert!(sent.contains("their content was not attached"), "{sent}");
    assert!(sent.contains("Rotate STRIPE_SECRET_KEY="), "{sent}");

    // Turn 2: a write that needs approval, rejected: it is not run.
    f.script(vec![
        Step::Call(
            "write_file",
            json!({"path": "notes.txt", "content": "rejected\n"}),
        ),
        Step::Call("reply", json!({"message": "Not written."})),
    ]);
    let id = editor.request(
        "session/prompt",
        json!({"sessionId": session, "prompt": [{"type": "text", "text": "Write the notes."}]}),
    );
    let ask = editor.next_message("a permission request", |m| {
        m["method"] == "session/request_permission"
    });
    assert_eq!(ask["params"]["sessionId"], session.as_str());
    assert_eq!(ask["params"]["toolCall"]["toolCallId"], "c3", "{ask}");
    assert_eq!(ask["params"]["toolCall"]["status"], "pending", "{ask}");
    let options: Vec<&str> = ask["params"]["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["kind"].as_str().unwrap())
        .collect();
    assert_eq!(options, ["allow_once", "reject_once"]);
    assert!(
        ask["params"]["toolCall"]
            .to_string()
            .contains("approval needed"),
        "{ask}"
    );
    editor.send(&json!({"jsonrpc": "2.0", "id": ask["id"],
        "result": {"outcome": {"outcome": "selected", "optionId": "reject-once"}}}));
    let second = editor.answer(id);
    assert_eq!(second["result"]["stopReason"], "end_turn", "{second}");
    assert!(!e.ws.join("notes.txt").exists(), "a rejected write ran");
    assert!(f.body(3).contains("did not approve"), "{}", f.body(3));

    // Turn 3: the permission request fails (an error answer): denied too.
    f.script(vec![
        Step::Call(
            "write_file",
            json!({"path": "notes.txt", "content": "errored\n"}),
        ),
        Step::Call("reply", json!({"message": "Still not written."})),
    ]);
    let id = editor.request(
        "session/prompt",
        json!({"sessionId": session, "prompt": [{"type": "text", "text": "Try again."}]}),
    );
    let ask = editor.next_message("a permission request", |m| {
        m["method"] == "session/request_permission"
    });
    editor.send(&json!({"jsonrpc": "2.0", "id": ask["id"],
        "error": {"code": -32603, "message": "the dialog closed"}}));
    assert_eq!(editor.answer(id)["result"]["stopReason"], "end_turn");
    assert!(!e.ws.join("notes.txt").exists(), "a failed approval ran");

    // Turn 4: allowed once: the write runs.
    f.script(vec![
        Step::Call(
            "write_file",
            json!({"path": "notes.txt", "content": "approved\n"}),
        ),
        Step::Call("reply", json!({"message": "Written."})),
    ]);
    let id = editor.request(
        "session/prompt",
        json!({"sessionId": session, "prompt": [{"type": "text", "text": "Write them now."}]}),
    );
    let ask = editor.next_message("a permission request", |m| {
        m["method"] == "session/request_permission"
    });
    editor.send(&json!({"jsonrpc": "2.0", "id": ask["id"],
        "result": {"outcome": {"outcome": "selected", "optionId": "allow-once"}}}));
    assert_eq!(editor.answer(id)["result"]["stopReason"], "end_turn");
    assert_eq!(
        std::fs::read_to_string(e.ws.join("notes.txt")).unwrap(),
        "approved\n"
    );
    let edits: Vec<Value> = updates_of(&editor.messages(), "tool_call")
        .into_iter()
        .filter(|c| c["kind"] == "edit")
        .collect();
    let diff = &edits.last().unwrap()["content"][0];
    assert_eq!(diff["type"], "diff", "{edits:?}");
    assert_eq!(diff["newText"], "approved\n");
    assert_eq!(diff["path"], e.ws.join("notes.txt").display().to_string());

    // Turn 5: cancelled while the frontier is answering. The editor sends its
    // next prompt at once: it waits for the cancelled turn, then runs.
    f.script(vec![
        Step::Hang,
        Step::Call("reply", json!({"message": "Still here."})),
    ]);
    let before = f.requests();
    let cancelled_id = editor.request(
        "session/prompt",
        json!({"sessionId": session, "prompt": [{"type": "text", "text": "Think for a long time."}]}),
    );
    f.wait_for_requests(before + 1);
    editor.notify("session/cancel", json!({"sessionId": session}));
    let next_id = editor.request(
        "session/prompt",
        json!({"sessionId": session, "prompt": [{"type": "text", "text": "Are you there?"}]}),
    );
    let cancelled = editor.answer(cancelled_id);
    assert_eq!(
        cancelled["result"]["stopReason"], "cancelled",
        "{cancelled}"
    );
    assert_eq!(editor.answer(next_id)["result"]["stopReason"], "end_turn");
    let last = f.body(f.requests() - 1);
    assert!(last.contains("interrupted your previous turn"), "{last}");
    assert!(last.contains("Are you there?"), "{last}");

    let (code, lines, log) = editor.finish();
    assert_eq!(code, 0, "{log}");
    // Standard output carried only protocol messages; the session's closing
    // line, printed as a terminal session prints it, went to the log.
    for line in &lines {
        let v: Value = serde_json::from_str(line)
            .unwrap_or_else(|_| panic!("not JSON-RPC on standard output: {line:?}"));
        assert_eq!(v["jsonrpc"], "2.0", "{line}");
        assert!(v.get("method").is_some() || v.get("id").is_some(), "{line}");
    }
    assert!(
        log.contains(&format!("session {session} left open")),
        "{log}"
    );
    assert!(
        log.contains("not starting the 1 MCP server(s) the editor offered (editor-tools)"),
        "{log}"
    );
    assert!(
        log.contains("risky actions wait for your answer in the editor"),
        "{log}"
    );
    assert!(!marker.exists(), "the editor's MCP server was started");

    // No planted value reached any frontier request, in any encoding.
    let canaries = Canaries::new([ENV_KEY, EMAIL, PASTED_KEY]);
    for (i, body) in f.bodies().iter().enumerate() {
        let found = canaries.find(body);
        assert!(found.is_empty(), "request {i} carried {found:?}");
    }
    // The session is Declass's: its run, resumable, with one verified log.
    assert!(
        e.ws.join(".declass/runs")
            .join(&session)
            .join("run.json")
            .exists()
    );
    let o = declass(
        &e,
        &[
            "--workspace",
            e.ws.to_str().unwrap(),
            "audit",
            "verify",
            &session,
        ],
    )
    .output()
    .unwrap();
    assert!(
        o.status.success(),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn protocol_errors_and_a_missing_setup_are_answered_on_the_protocol() {
    let e = env();
    // Nothing chosen: initialize says what to do.
    owner_config(&e, "");
    let mut editor = Editor::start(&e);
    let id = editor.request("initialize", json!({"protocolVersion": 1}));
    let refused = editor.answer(id);
    let error = &refused["error"];
    assert_eq!(error["code"], -31001, "{refused}");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("no cloud model is chosen") && message.contains("declass setup"),
        "{message}"
    );
    let (code, lines, log) = editor.finish();
    assert_eq!(code, 0, "{log}");
    assert_eq!(lines.len(), 1, "{lines:?}");

    // A key variable the editor's environment lacks is named.
    let f = Frontier::start();
    configured(&e, &f);
    let mut child = declass(&e, &["acp"])
        .env_remove("ZAI_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.as_mut().unwrap(),
        "{}",
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
    )
    .unwrap();
    drop(child.stdin.take());
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child.wait().unwrap();
    assert!(
        out.contains("ZAI_API_KEY is not set") && out.contains("(env)"),
        "{out}"
    );

    // Set up: requests before initialize, bad JSON, unknown methods, a cwd
    // that is not absolute and an unknown session are errors.
    let mut editor = Editor::start(&e);
    let id = editor.request("session/new", json!({"cwd": e.ws, "mcpServers": []}));
    assert_eq!(editor.answer(id)["error"]["code"], -32600);
    editor.send_raw("{this is not json");
    let parse = editor.next_message("a parse error", |m| m["error"]["code"] == -32700);
    assert!(parse["id"].is_null(), "{parse}");
    let id = editor.request("initialize", json!({"protocolVersion": 7}));
    assert_eq!(
        editor.answer(id)["result"]["protocolVersion"],
        1,
        "a later version is answered with the one Declass speaks"
    );
    let id = editor.request(
        "session/load",
        json!({"sessionId": "x", "cwd": e.ws, "mcpServers": []}),
    );
    assert_eq!(editor.answer(id)["error"]["code"], -32601);
    let id = editor.request(
        "session/new",
        json!({"cwd": "relative/dir", "mcpServers": []}),
    );
    assert_eq!(editor.answer(id)["error"]["code"], -32602);
    let id = editor.request(
        "session/prompt",
        json!({"sessionId": "20260101-000000-abcdef", "prompt": [{"type": "text", "text": "hi"}]}),
    );
    let unknown = editor.answer(id);
    assert_eq!(unknown["error"]["code"], -32002, "{unknown}");
    assert_eq!(
        unknown["error"]["data"]["sessionId"],
        "20260101-000000-abcdef"
    );
    // A prompt with nothing usable ends at once, sending nothing.
    let id = editor.request("session/new", json!({"cwd": e.ws, "mcpServers": []}));
    let session = editor.answer(id)["result"]["sessionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = editor.request(
        "session/prompt",
        json!({"sessionId": session, "prompt": [{"type": "resource_link",
            "uri": "file:///etc/hosts", "name": "hosts"}]}),
    );
    assert_eq!(editor.answer(id)["result"]["stopReason"], "end_turn");
    assert!(
        said(&editor.messages()).contains("hosts: outside the workspace"),
        "{:?}",
        editor.messages()
    );
    let (code, lines, log) = editor.finish();
    assert_eq!(code, 0, "{log}");
    assert_eq!(f.requests(), 0, "nothing was sent to the frontier");
    for line in &lines {
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
    }
    assert!(!e.ws.join(".declass/runs").exists(), "no session started");
}
