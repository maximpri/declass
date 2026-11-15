// SPDX-License-Identifier: GPL-3.0-or-later
//! `declass acp` (experimental): Declass in an editor, over the Agent Client
//! Protocol (JSON-RPC 2.0, one message per line on standard input and
//! output). The editor (Zed, a JetBrains IDE, Neovim, Emacs) starts it and
//! becomes the operator's terminal: each thread is a `declass` session in the
//! thread's directory, with the same boundary, sandbox, approvals, limits and
//! audit, composed by the same code (`chat::converse`, `prepare`).
//!
//! What the editor gets is what the workspace shows the operator (see
//! `updates`), and what it sends is the operator's message (see `prompt`).
//! It gains no way around Declass's checks: Declass never uses the client's
//! file system or terminal methods (its own sandboxed tools, write journal
//! and undo do the work), MCP servers the client names are not started (they
//! would bypass the owner's pins, advisories and approval: servers come only
//! from Declass's configuration), and every permission answer other than the
//! one "allow once" option denies.
//!
//! A thread's session starts with its first prompt (as a `declass` session
//! starts with the first message); its id is the session's run id, so it can
//! be continued in a terminal with `declass --resume <id>` and audited with
//! `declass audit show <id>`. One session runs at a time, as the workspace
//! lock requires: a prompt to another thread leaves the running session open
//! and starts or resumes that thread's (as `declass --resume` resumes it), so
//! every thread stays usable. While a turn runs, another thread's prompt is
//! refused with its own error. When the editor goes away (the end of input,
//! SIGTERM or SIGINT) a running turn is stopped and the session is left open.

mod prompt;
mod schema;
mod updates;
mod wire;

use crate::chat::{self, Front, NewSession, Open, SessionChange};
use crate::{Embedding, Mode, RunManifest, approve, load_config, local_enabled, new_run_id};
use anyhow::{Context, Result};
use declass_agent::oversight::Action;
use declass_agent::questions::QuestionOptions;
use declass_agent::session::Steering;
use declass_agent::transcript::Entry;
use declass_agent::{ApproveMode, Approver, Oversight, Session, Terminal, TurnEnd};
use declass_boundary::live::{StreamEvent, StreamTap};
use declass_tui::term::safe;
use futures_util::FutureExt;
use schema::{
    AgentCapabilities, Implementation, InitializeParams, InitializeResult, McpCapabilities,
    NewSessionParams, NewSessionResult, PermissionRequest, PromptCapabilities, PromptParams,
    PromptResult, StopReason,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::future::Future;
use std::io::BufReader;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use updates::Updates;
use wire::{Message, Pending, RpcError, Wire};

/// `declass acp`'s options.
pub(crate) struct AcpArgs {
    pub mode: Option<Mode>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Serves the editor until it goes away. Returns the exit code.
pub(crate) async fn serve(args: AcpArgs, emb: &Embedding) -> Result<i32> {
    anyhow::ensure!(
        args.mode != Some(Mode::Passthrough),
        "declass acp runs in hybrid mode or top clearance: passthrough turns the privacy \
boundary off and is not offered to an editor"
    );
    let (input, output) =
        wire::take_stdio().context("taking standard input and output for the protocol")?;
    let shared = Arc::new(Shared {
        wire: Arc::new(Wire::new(output)),
        pending: Pending::default(),
        closed: AtomicBool::new(false),
        next_id: AtomicU64::new(0),
        flags: Mutex::new(HashMap::new()),
    });
    let (to, from) = unbounded_channel();
    let reader = shared.clone();
    std::thread::Builder::new()
        .name("acp-reader".into())
        .spawn(move || read(&reader, input, &to))
        .context("starting the protocol reader")?;
    eprintln!(
        "declass acp (experimental): serving the Agent Client Protocol on standard input and output"
    );
    let mut server = Server {
        shared,
        emb,
        mode: args.mode,
        initialized: false,
        sessions: HashMap::new(),
        running: None,
    };
    server.run(from).await;
    Ok(0)
}

/// What the reader thread, the dispatcher, the session and its approver share.
struct Shared {
    wire: Arc<Wire>,
    /// Requests Declass sent (permission questions) and their answers.
    pending: Pending,
    /// The editor went away, or the process is stopping.
    closed: AtomicBool,
    next_id: AtomicU64,
    /// Each session's flags, by session id.
    flags: Mutex<HashMap<String, Arc<Flags>>>,
}

impl Shared {
    fn session(&self, id: &str) -> Option<Arc<Flags>> {
        lock(&self.flags).get(id).cloned()
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.pending.wake();
    }
}

/// A session's state that the reader thread changes as messages arrive, so
/// a cancellation reaches the turn while the dispatcher and the session are
/// busy (or blocked in a permission question).
#[derive(Default)]
struct Flags {
    /// Prompts read for the session so far: each prompt gets the next number.
    read: AtomicU64,
    /// Every prompt numbered up to this one was cancelled.
    cancelled: AtomicU64,
    /// Prompts accepted and not answered yet (they are answered in order).
    outstanding: AtomicU64,
    /// The session's interrupt (what Ctrl-C raises in a terminal session).
    interrupted: Arc<AtomicBool>,
    /// The open session's steering (its stop at the safe point).
    steering: Mutex<Option<Arc<Steering>>>,
    /// While a turn runs: what the approver shows its question with.
    turn: Mutex<Option<TurnLink>>,
}

#[derive(Clone)]
struct TurnLink {
    follow: Arc<Mutex<chat::Follow>>,
    updates: Arc<Mutex<Updates>>,
}

impl Flags {
    /// `session/cancel`: every prompt read so far is cancelled, and the
    /// running turn stops as an interrupt stops it.
    fn cancel(&self) {
        self.cancelled
            .fetch_max(self.read.load(Ordering::SeqCst), Ordering::SeqCst);
        if self.busy() {
            self.stop();
        }
    }

    fn busy(&self) -> bool {
        self.outstanding.load(Ordering::SeqCst) > 0
    }

    /// A prompt was answered.
    fn answered(&self) {
        let _ = self
            .outstanding
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
    }

    fn stop(&self) {
        self.interrupted.store(true, Ordering::SeqCst);
        if let Some(steering) = lock(&self.steering).as_ref() {
            steering.stop();
        }
    }

    fn cancelled(&self, prompt: u64) -> bool {
        self.cancelled.load(Ordering::SeqCst) >= prompt
    }
}

/// A request for the dispatcher. Prompts are numbered as they are read.
struct Incoming {
    id: Value,
    method: String,
    params: Value,
    prompt: Option<u64>,
}

/// Reads the editor's messages until its end of input. Answers to Declass's
/// own requests and cancellations are handled here, so they arrive while a
/// turn runs or waits for a permission answer; requests go to the dispatcher.
fn read(shared: &Shared, input: std::fs::File, to: &UnboundedSender<Incoming>) {
    let mut input = BufReader::with_capacity(64 * 1024, input);
    loop {
        let line = match wire::read_line(&mut input, wire::MAX_LINE) {
            wire::Read::End => break,
            wire::Read::TooLong(head) => {
                shared.wire.fail(
                    &wire::head_id(&head),
                    &RpcError::new(
                        wire::INVALID_REQUEST,
                        "message too large (more than 64 MiB); nothing of it was used",
                    ),
                );
                continue;
            }
            wire::Read::Line(line) => line,
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match wire::parse(&line) {
            Err(refused) => shared.wire.fail(&refused.id, &refused.error),
            Ok(Message::Response { id, outcome }) => {
                shared.pending.deliver(&id, outcome);
            }
            Ok(Message::Notification { method, params }) => {
                // Other notifications ($/cancel_request among them) are not acted on.
                if method == "session/cancel"
                    && let Some(flags) = params
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .and_then(|id| shared.session(id))
                {
                    flags.cancel();
                    shared.pending.wake();
                }
            }
            Ok(Message::Request { id, method, params }) => {
                let prompt = (method == "session/prompt")
                    .then(|| {
                        params
                            .get("sessionId")
                            .and_then(Value::as_str)
                            .and_then(|id| shared.session(id))
                    })
                    .flatten()
                    .map(|flags| flags.read.fetch_add(1, Ordering::SeqCst) + 1);
                let incoming = Incoming {
                    id,
                    method,
                    params,
                    prompt,
                };
                if to.send(incoming).is_err() {
                    break;
                }
            }
        }
    }
    shared.close();
}

/// A prompt for a session.
struct Prompt {
    id: Value,
    /// Its number among the session's prompts (see [`Flags::cancelled`]).
    number: u64,
    /// The operator's own words (and the workspace paths they name).
    message: String,
    /// Third-party text the editor attached, presented when the turn runs.
    attached: Vec<prompt::Attached>,
}

/// Where a thread's session is.
#[derive(Debug)]
enum Phase {
    /// Created: the session starts with its first prompt.
    New,
    /// It runs ([`Server::running`]).
    Running,
    /// Left open (another thread's session runs): its next prompt resumes it.
    Open,
    /// It ended: why prompts are refused now.
    Ended(String),
}

struct Thread {
    ws: PathBuf,
    flags: Arc<Flags>,
    phase: Phase,
}

/// The running session: where its prompts go, and the work that answers
/// them, which ends saying where the session is then.
struct Running<'e> {
    id: String,
    prompts: UnboundedSender<Prompt>,
    work: Pin<Box<dyn Future<Output = Phase> + 'e>>,
}

struct Server<'e> {
    shared: Arc<Shared>,
    emb: &'e Embedding,
    mode: Option<Mode>,
    initialized: bool,
    sessions: HashMap<String, Thread>,
    running: Option<Running<'e>>,
}

enum Event {
    Request(Incoming),
    /// The running session's work ended, saying where the session is.
    Ended(Phase),
    /// The editor went away, or a signal asks to stop.
    Gone,
}

impl<'e> Server<'e> {
    async fn run(&mut self, mut from: UnboundedReceiver<Incoming>) {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        loop {
            let event = {
                let work = self.running.as_mut().map(|r| &mut r.work);
                tokio::select! {
                    incoming = from.recv() => incoming.map_or(Event::Gone, Event::Request),
                    phase = async {
                        match work {
                            Some(work) => work.await,
                            None => std::future::pending().await,
                        }
                    } => Event::Ended(phase),
                    _ = tokio::signal::ctrl_c() => Event::Gone,
                    () = async {
                        match terminate.as_mut() {
                            Some(signal) => {
                                signal.recv().await;
                            }
                            None => std::future::pending().await,
                        }
                    } => Event::Gone,
                }
            };
            match event {
                Event::Request(incoming) => self.request(incoming).await,
                Event::Ended(phase) => {
                    if let Some(r) = self.running.take() {
                        self.settle(&r.id, phase);
                    }
                }
                Event::Gone => break,
            }
        }
        self.shared.close();
        if let Some(r) = self.running.take() {
            // Nobody can see the rest of the turn: it stops now, and the
            // session stays open to resume.
            if let Some(flags) = self.shared.session(&r.id) {
                flags.stop();
            }
            self.leave(r).await;
        }
    }

    /// Where a thread's session is once its work ended.
    fn settle(&mut self, id: &str, phase: Phase) {
        if let Some(thread) = self.sessions.get_mut(id) {
            thread.phase = phase;
        }
    }

    /// Ends the running session's work (its queue is empty): the session is
    /// left open, as `/quit` leaves it.
    async fn leave(&mut self, running: Running<'e>) {
        let Running { id, prompts, work } = running;
        drop(prompts);
        let phase = work.await;
        self.settle(&id, phase);
    }

    async fn request(&mut self, incoming: Incoming) {
        let Incoming {
            id,
            method,
            params,
            prompt,
        } = incoming;
        let outcome = match method.as_str() {
            "initialize" => self.initialize(params).map(Some),
            _ if !self.initialized => Err(RpcError::new(
                wire::INVALID_REQUEST,
                "initialize the connection first",
            )),
            "session/new" => self.new_session(params).map(Some),
            "session/prompt" => self.prompt(&id, params, prompt).await,
            other => Err(RpcError::new(
                wire::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )),
        };
        match outcome {
            Ok(Some(result)) => self.shared.wire.respond(&id, result),
            Ok(None) => {}
            Err(error) => self.shared.wire.fail(&id, &error),
        }
    }

    fn initialize(&mut self, params: Value) -> Result<Value, RpcError> {
        let params: InitializeParams = serde_json::from_value(params).map_err(invalid)?;
        let client = params
            .client_info
            .as_ref()
            .and_then(|c| c.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("an editor");
        eprintln!(
            "declass acp: {} asks for protocol version {}; Declass speaks version {}",
            safe(client),
            params.protocol_version,
            schema::PROTOCOL_VERSION
        );
        // Setup is the owner's (each workspace is checked again at session/new).
        let cfg = declass_config::Config::load_with(
            &declass_config::owner_config_path(),
            None,
            self.emb.policy_source(),
        )
        .map_err(refused)?;
        let mode = crate::overrides::resolve_mode(&cfg, self.mode, false).map_err(refused)?;
        set_up(&cfg, mode)?;
        self.initialized = true;
        let product = self.emb.product();
        Ok(json!(InitializeResult {
            protocol_version: schema::PROTOCOL_VERSION,
            agent_capabilities: AgentCapabilities {
                load_session: false,
                prompt_capabilities: PromptCapabilities {
                    image: false,
                    audio: false,
                    // Accepted, and read as a mention of the file, never its text.
                    embedded_context: true,
                },
                mcp_capabilities: McpCapabilities {
                    http: false,
                    sse: false,
                },
            },
            agent_info: Implementation {
                name: product.name.to_owned(),
                title: if product.is_declass() {
                    "Declass".to_owned()
                } else {
                    product.name.to_owned()
                },
                version: product.version.to_owned(),
            },
            auth_methods: Vec::new(),
        }))
    }

    fn new_session(&mut self, params: Value) -> Result<Value, RpcError> {
        let params: NewSessionParams = serde_json::from_value(params).map_err(invalid)?;
        let cwd = PathBuf::from(&params.cwd);
        if !cwd.is_absolute() {
            return Err(invalid("cwd must be an absolute path"));
        }
        let ws = cwd
            .canonicalize()
            .ok()
            .filter(|p| p.is_dir())
            .ok_or_else(|| invalid(format!("cwd {} is not a directory", params.cwd)))?;
        // The workspace's own configuration, as a `declass` session there reads
        // it (read again whenever the session starts or resumes).
        let cfg = load_config(&ws, self.emb).map_err(refused)?;
        let mode = crate::overrides::resolve_mode(&cfg, self.mode, false).map_err(refused)?;
        set_up(&cfg, mode)?;
        approve::editor_oversight(&cfg, |_| -> Arc<dyn Approver> { Arc::new(Deny) })
            .map_err(refused)?;
        let id = new_run_id();
        let flags = Arc::new(Flags::default());
        let servers = params.mcp_servers.unwrap_or_default();
        if !servers.is_empty() {
            let names: Vec<String> = servers
                .iter()
                .map(|s| safe(s.get("name").and_then(Value::as_str).unwrap_or("unnamed")))
                .collect();
            eprintln!(
                "declass acp: not starting the {} MCP server(s) the editor offered ({}): Declass \
starts only the servers in its own configuration, where they are pinned, checked and approved",
                servers.len(),
                names.join(", ")
            );
        }
        if params
            .additional_directories
            .is_some_and(|dirs| !dirs.is_empty())
        {
            eprintln!(
                "declass acp: the session's only workspace is {}; other directories the editor named are not used",
                ws.display()
            );
        }
        eprintln!(
            "declass acp: session {id} in {} ({})",
            ws.display(),
            mode.as_str()
        );
        lock(&self.shared.flags).insert(id.clone(), flags.clone());
        self.sessions.insert(
            id.clone(),
            Thread {
                ws,
                flags,
                phase: Phase::New,
            },
        );
        Ok(json!(NewSessionResult { session_id: id }))
    }

    /// `session/prompt`: answered by the session once its turn ends
    /// (`Ok(None)`; prompts that arrive meanwhile wait their turn), or at once.
    async fn prompt(
        &mut self,
        id: &Value,
        params: Value,
        number: Option<u64>,
    ) -> Result<Option<Value>, RpcError> {
        let params: PromptParams = serde_json::from_value(params).map_err(invalid)?;
        let session = params.session_id;
        let unknown = |why: &str| {
            RpcError::new(wire::RESOURCE_NOT_FOUND, why).with_data(json!({"sessionId": session}))
        };
        let (Some(thread), Some(number)) = (self.sessions.get(&session), number) else {
            return Err(unknown("no such session on this connection"));
        };
        if let Phase::Ended(why) = &thread.phase {
            return Err(unknown(why));
        }
        let flags = thread.flags.clone();
        let composed = prompt::compose(&params.prompt, &thread.ws);
        if !composed.declined.is_empty() {
            updates::say(
                &self.shared.wire,
                &session,
                &format!(
                    "Not used, and nothing of it was sent: {}.\n\n",
                    composed.declined.join("; ")
                ),
            );
        }
        let done = |reason: StopReason| {
            Ok(Some(json!(PromptResult {
                stop_reason: reason
            })))
        };
        if flags.cancelled(number) {
            return done(StopReason::Cancelled);
        }
        if composed.is_empty() {
            return done(StopReason::EndTurn);
        }
        let prompt = Prompt {
            id: id.clone(),
            number,
            message: composed.message,
            attached: composed.attached,
        };
        if matches!(thread.phase, Phase::Running) {
            flags.outstanding.fetch_add(1, Ordering::SeqCst);
            if let Some(r) = self.running.as_ref().filter(|r| r.id == session)
                && r.prompts.send(prompt).is_ok()
            {
                return Ok(None);
            }
            flags.answered();
            return Err(unknown("the session ended"));
        }
        // One session runs at a time (the workspace lock): another thread's is
        // left open first, unless it is working.
        if let Some(other) = &self.running
            && self.sessions.get(&other.id).is_some_and(|t| t.flags.busy())
        {
            return Err(RpcError::new(
                wire::BUSY,
                "Declass is working in another thread; send this again when that turn ends, or \
stop it first",
            )
            .with_data(json!({"sessionId": session, "busy": other.id})));
        }
        if let Some(other) = self.running.take() {
            self.leave(other).await;
        }
        let Some(thread) = self.sessions.get_mut(&session) else {
            return Err(unknown("no such session on this connection"));
        };
        let resume = match std::mem::replace(&mut thread.phase, Phase::Running) {
            Phase::New => false,
            Phase::Open => true,
            other => {
                thread.phase = other;
                return Err(unknown("the session is not available"));
            }
        };
        flags.outstanding.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = unbounded_channel();
        let work = hold(
            Start {
                shared: self.shared.clone(),
                emb: self.emb,
                id: session.clone(),
                ws: thread.ws.clone(),
                flags,
                mode: self.mode,
                resume,
            },
            prompt,
            rx,
        );
        self.running = Some(Running {
            id: session,
            prompts: tx,
            work: Box::pin(work),
        });
        Ok(None)
    }
}

/// An approver for a configuration check: it is never asked.
struct Deny;

impl Approver for Deny {
    fn approve(&self, _: &Action) -> bool {
        false
    }
}

fn invalid(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(wire::INVALID_PARAMS, format!("invalid params: {e}"))
}

fn refused(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(wire::REFUSED, format!("{e:#}"))
}

/// Refuses a mode whose models are not chosen, saying what to do: the
/// setup screen is a terminal's, not the editor's.
fn set_up(cfg: &declass_config::Config, mode: Mode) -> Result<(), RpcError> {
    let frontier = mode != Mode::TopClearance;
    let local = local_enabled(cfg, mode).map_err(refused)?;
    let missing = crate::setup::missing(cfg, frontier, local).map_err(refused)?;
    if missing.is_empty() {
        return Ok(());
    }
    let mut message = format!(
        "Declass is not set up: {}. Run `declass setup` in a terminal, then start the agent again.",
        missing.join("; ")
    );
    let key_env = cfg.str("frontier.api_key_env").unwrap_or_default();
    if frontier && !key_env.is_empty() && missing.iter().any(|m| m.starts_with(&key_env)) {
        message.push_str(
            " An editor may not start agents with your shell's environment: pass the variable in \
the editor's settings for this agent (env), or save the key with `declass setup`.",
        );
    }
    Err(RpcError::new(wire::NOT_SET_UP, message).with_data(json!({"missing": missing})))
}

/// What starting (or resuming) a thread's session takes.
struct Start<'e> {
    shared: Arc<Shared>,
    emb: &'e Embedding,
    id: String,
    ws: PathBuf,
    flags: Arc<Flags>,
    /// `declass acp --mode`.
    mode: Option<Mode>,
    /// The session was left open and continues (as `declass --resume`).
    resume: bool,
}

/// One session invocation, from the prompt that starts or resumes it to its
/// end, as `chat::chat` runs one: its manifest, the workspace lock and run
/// directory, the conversation (`chat::converse` with [`Editor`]), and its
/// conclusion. Returns where the session is then: left open (its thread's
/// next prompt resumes it), ended, or, when it could not start, as it was.
async fn hold(start: Start<'_>, first: Prompt, mut prompts: UnboundedReceiver<Prompt>) -> Phase {
    let Start {
        shared,
        emb,
        id,
        ws,
        flags,
        mode,
        resume,
    } = start;
    // Every prompt not answered yet (queued ones too) is answered with `why`.
    let refuse = |prompts: &mut UnboundedReceiver<Prompt>, first: Option<Value>, why: &str| {
        prompts.close();
        let mut ids: Vec<Value> = first.into_iter().collect();
        while let Ok(queued) = prompts.try_recv() {
            ids.push(queued.id);
        }
        for prompt in ids {
            flags.answered();
            shared
                .wire
                .fail(&prompt, &RpcError::new(wire::TURN_FAILED, why));
        }
    };
    // A session that could not start (or resume) can be tried again.
    let before = || if resume { Phase::Open } else { Phase::New };
    let verb = if resume { "resume" } else { "start" };
    let found = setup(&shared, emb, &id, &ws, &flags, mode, resume, &first).await;
    let (cfg, manifest, oversight) = match found {
        Ok(found) => found,
        Err(why) => {
            refuse(
                &mut prompts,
                Some(first.id),
                &format!("the session could not {verb}: {why}"),
            );
            return before();
        }
    };
    let (workspace_lock, run_dir) =
        match chat::session_dir(&ws, &manifest).and_then(|(held, dir)| {
            if resume {
                chat::recover_plans(&dir)
            } else {
                chat::save_manifest(&dir, &manifest)
            }
            .map(|()| (held, dir))
        }) {
            Ok(found) => found,
            Err(e) => {
                refuse(
                    &mut prompts,
                    Some(first.id),
                    &format!("the session could not {verb}: {e:#}"),
                );
                return before();
            }
        };
    let limits = chat::session_limits(&flags.interrupted);
    let mut audit = None;
    let mut editor = Editor {
        shared: shared.clone(),
        session: id.clone(),
        flags: flags.clone(),
        first: Some(first),
        prompts,
        current: None,
    };
    let driven = std::panic::AssertUnwindSafe(chat::converse(
        &ws,
        &manifest,
        &cfg,
        oversight,
        &run_dir,
        resume,
        &limits,
        &mut audit,
        emb.hooks(),
        &mut editor,
    ))
    .catch_unwind()
    .await;
    let (terminal, stats, _) = chat::settle(driven);
    // Prompts left unanswered: the session failed before or during a turn.
    let why = match &terminal {
        Terminal::Failed { reason } => format!("this turn failed: {reason}"),
        _ => "this turn failed: the session ended".to_owned(),
    };
    let first = editor
        .first
        .take()
        .map(|p| p.id)
        .or_else(|| editor.current.take());
    refuse(&mut editor.prompts, first, &why);
    *lock(&flags.steering) = None;
    if let Err(e) =
        chat::conclude_session(&ws, &manifest, &cfg, emb, audit, &terminal, &stats, resume)
    {
        eprintln!("declass acp: session {id} not concluded: {e:#}");
    }
    drop(workspace_lock);
    for line in crate::triggers::report(&crate::audit_log_path(&ws, &manifest.run_id)) {
        eprintln!("{}", safe(&line));
    }
    // Printed as a terminal session prints it: on the log, never the protocol.
    chat::farewell(&manifest.run_id, &terminal, &stats);
    match terminal {
        Terminal::Completed { .. } => Phase::Ended(format!("session {id} was closed")),
        // Left open, stopped by a limit, or failed after a turn: it resumes.
        _ if declass_agent::resumable(&run_dir).is_ok() => Phase::Open,
        Terminal::Failed { reason } => Phase::Ended(format!("session {id} stopped: {reason}")),
        _ => Phase::Ended(format!("session {id} cannot be continued")),
    }
}

/// The session's configuration (read now, as a `declass` session reads it
/// when it starts), its manifest and its oversight. A new session's first
/// prompt is its objective, and the configuration gives everything else (an
/// editor passes no overrides); a resumed one keeps its own record.
#[allow(clippy::too_many_arguments)]
async fn setup(
    shared: &Arc<Shared>,
    emb: &Embedding,
    id: &str,
    ws: &std::path::Path,
    flags: &Arc<Flags>,
    mode: Option<Mode>,
    resume: bool,
    first: &Prompt,
) -> Result<(declass_config::Config, RunManifest, Oversight), String> {
    let error = |e: anyhow::Error| format!("{e:#}");
    let cfg = load_config(ws, emb).map_err(error)?;
    let oversight = approve::editor_oversight(&cfg, |mode| -> Arc<dyn Approver> {
        Arc::new(EditorApprover {
            mode,
            session: id.to_owned(),
            shared: shared.clone(),
            flags: flags.clone(),
        })
    })
    .map_err(error)?;
    if resume {
        let manifest = chat::resumed(ws, Some(id.to_owned())).map_err(error)?;
        crate::overrides::check(&cfg, &manifest).map_err(error)?;
        return Ok((cfg, manifest, oversight));
    }
    let mode = crate::overrides::resolve_mode(&cfg, mode, false).map_err(error)?;
    set_up(&cfg, mode).map_err(|e| e.message)?;
    if mode != Mode::TopClearance {
        crate::setup::require_frontier(&cfg, None, None).map_err(error)?;
    }
    let local = match chat::local_endpoint(&cfg, mode).await.map_err(error)? {
        Ok(local) => local,
        Err(_) => {
            return Err(
                "no single local model server could be chosen (the agent's log says why); run \
`declass setup` in a terminal"
                    .to_owned(),
            );
        }
    };
    let objective = if first.message.is_empty() {
        "(content the operator attached in the editor)".to_owned()
    } else {
        first.message.clone()
    };
    let manifest = chat::new_manifest(
        &cfg,
        NewSession {
            run_id: id.to_owned(),
            mode,
            first: objective,
            frontier_url: None,
            frontier_model: None,
            checks: &[],
            local,
            images: Vec::new(),
            files: Vec::new(),
        },
    )
    .map_err(error)?;
    crate::overrides::check(&cfg, &manifest).map_err(error)?;
    Ok((cfg, manifest, oversight))
}

/// The editor's side of an open session: one turn per prompt.
struct Editor {
    shared: Arc<Shared>,
    session: String,
    flags: Arc<Flags>,
    first: Option<Prompt>,
    prompts: UnboundedReceiver<Prompt>,
    /// The prompt being answered, until it is.
    current: Option<Value>,
}

impl Front for Editor {
    async fn hold(
        &mut self,
        session: &mut Session<'_>,
        open: &Open<'_>,
    ) -> Result<(bool, Option<SessionChange>)> {
        let updates = Arc::new(Mutex::new(Updates::new(
            self.shared.wire.clone(),
            self.session.clone(),
            open.ws.to_path_buf(),
            open.shown.clone(),
            crate::policy(open.cfg)?,
        )));
        *lock(&self.flags.steering) = Some(session.steering());
        let mut next = self.first.take();
        loop {
            let prompt = match next.take() {
                Some(p) => p,
                None => match self.prompts.recv().await {
                    Some(p) => p,
                    None => break,
                },
            };
            self.current = Some(prompt.id.clone());
            let answer = if self.shared.closed.load(Ordering::SeqCst) {
                // The editor went away: no turn starts for prompts still queued.
                Ok(StopReason::Cancelled)
            } else {
                self.answer(session, open, &updates, &prompt).await
            };
            self.current = None;
            self.flags.answered();
            match answer {
                Ok(reason) => self.shared.wire.respond(
                    &prompt.id,
                    PromptResult {
                        stop_reason: reason,
                    },
                ),
                Err(error) => self.shared.wire.fail(&prompt.id, &error),
            }
        }
        Ok((false, None))
    }
}

impl Editor {
    /// One prompt: its turn, what the editor is told at its end, and its stop
    /// reason (a failed turn is the prompt's error).
    async fn answer(
        &self,
        session: &mut Session<'_>,
        open: &Open<'_>,
        updates: &Arc<Mutex<Updates>>,
        prompt: &Prompt,
    ) -> Result<StopReason, RpcError> {
        if self.flags.cancelled(prompt.number) {
            return Ok(StopReason::Cancelled);
        }
        // The answer to declass's question, as a terminal session sends it.
        let mut message = match session.history().last().and_then(|x| x.end.as_ref()) {
            Some(TurnEnd::Asked {
                options: Some(options),
                ..
            }) if !prompt.message.is_empty() => match answer(options, &prompt.message) {
                Ok(message) => message,
                Err(why) => {
                    lock(updates).paragraph(&why);
                    return Ok(StopReason::EndTurn);
                }
            },
            _ => prompt.message.clone(),
        };
        // What the editor attached from elsewhere: data the boundary presents
        // (as a fetched page), framed so it cannot pass for these words.
        for attached in &prompt.attached {
            if !message.is_empty() {
                message.push_str("\n\n");
            }
            message.push_str(&prompt::framed(open.presenter, attached));
        }
        let end = self
            .turn(session, open, updates, &message, prompt.number)
            .await;
        let cancelled = self.flags.cancelled(prompt.number);
        let mut shown = lock(updates);
        shown.end(&end, cancelled);
        if let Some(which) = session.spent() {
            shown.paragraph(&format!(
                "The session limit {which} is reached; no further turn can start. Raise it, then \
continue the session in a terminal with `declass --resume {}`.",
                self.session
            ));
        }
        drop(shown);
        stop_reason(&end, cancelled)
    }

    /// Runs one turn, following its transcript and its stream to the editor
    /// as the workspace follows them to the screen (`chat::take_turn`).
    async fn turn(
        &self,
        session: &mut Session<'_>,
        open: &Open<'_>,
        updates: &Arc<Mutex<Updates>>,
        message: &str,
        number: u64,
    ) -> TurnEnd {
        let path = open.run_dir.join("transcript.jsonl");
        let from = std::fs::metadata(&path).map_or(0, |m| m.len());
        let sink: Box<dyn FnMut(Entry) + Send> = {
            let updates = updates.clone();
            Box::new(move |entry| lock(&updates).entry(&entry))
        };
        let follow = Arc::new(Mutex::new(chat::Follow::new(path, from, sink)));
        let done = Arc::new(AtomicBool::new(false));
        let follower = tokio::spawn(chat::following(follow.clone(), done.clone()));
        *lock(&self.flags.turn) = Some(TurnLink {
            follow: follow.clone(),
            updates: updates.clone(),
        });
        lock(updates).begin();
        let steering = session.steering();
        let tap = Arc::new(chat::Ordered {
            follow,
            inner: Arc::new(Tap(updates.clone())),
        });
        let end = {
            let turn = declass_boundary::live::observe(tap, session.turn(message));
            let mut turn = std::pin::pin!(turn);
            loop {
                tokio::select! {
                    end = &mut turn => break end,
                    () = tokio::time::sleep(Duration::from_millis(50)) => {
                        // A cancellation stops the turn whenever it was read
                        // (the turn clears the interrupt as it starts).
                        if self.flags.cancelled(number) {
                            self.flags.interrupted.store(true, Ordering::SeqCst);
                            steering.stop();
                        }
                    }
                }
            }
        };
        done.store(true, Ordering::SeqCst);
        let _ = follower.await;
        *lock(&self.flags.turn) = None;
        end
    }
}

/// The frontier's response as it streams, to the editor.
struct Tap(Arc<Mutex<Updates>>);

impl StreamTap for Tap {
    fn event(&self, event: StreamEvent<'_>) {
        lock(&self.0).stream(event);
    }
}

/// How a turn's end reads as a stop reason. A cancelled prompt is
/// `cancelled` however its turn ended; a failed turn is an error (version 1
/// has no failure stop reason); a time limit, which has no stop reason
/// either, ends the turn with the message saying which limit.
fn stop_reason(end: &TurnEnd, cancelled: bool) -> Result<StopReason, RpcError> {
    if cancelled {
        return Ok(StopReason::Cancelled);
    }
    match end {
        TurnEnd::Replied { .. } | TurnEnd::Asked { .. } | TurnEnd::Completed { .. } => {
            Ok(StopReason::EndTurn)
        }
        TurnEnd::Interrupted | TurnEnd::Stopped => Ok(StopReason::Cancelled),
        TurnEnd::BudgetStopped { which } if which.ends_with("frontier_requests") => {
            Ok(StopReason::MaxTurnRequests)
        }
        TurnEnd::BudgetStopped { .. } => Ok(StopReason::EndTurn),
        TurnEnd::Failed { reason } => Err(RpcError::new(
            wire::TURN_FAILED,
            format!("this turn failed: {}", safe(reason)),
        )
        .with_data(json!({"sessionOpen": true}))),
    }
}

/// The operator's answer to declass's question: an option's number, or
/// their own words where the question allows them.
fn answer(options: &QuestionOptions, reply: &str) -> Result<String, String> {
    let reply = reply.trim();
    let chosen = reply
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| options.choices.get(i));
    let answer = match chosen {
        Some(choice) => choice.label.clone(),
        None if options.allow_freeform || options.choices.is_empty() => reply.to_owned(),
        None => {
            return Err(format!(
                "Choose one of the listed options by its number (1 to {}).",
                options.choices.len()
            ));
        }
    };
    Ok(format!("Answer to question {}: {answer}", options.id))
}

/// Approval in the editor: a `session/request_permission` on the call the
/// action is about. Only "allow once" approves; a rejection, a cancellation,
/// an error, an unknown option or the editor going away denies.
struct EditorApprover {
    mode: ApproveMode,
    session: String,
    shared: Arc<Shared>,
    flags: Arc<Flags>,
}

impl EditorApprover {
    fn ask(&self, action: &Action) -> bool {
        let Some(link) = lock(&self.flags.turn).clone() else {
            return false;
        };
        // What the turn recorded before the question shows first.
        lock(&link.follow).drain();
        let question = approve::describe(self.mode, action);
        let tool_call = lock(&link.updates).permission(action, &question);
        let card = tool_call.tool_call_id.clone();
        let id = self.shared.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        self.shared.pending.expect(id);
        self.shared.wire.request(
            id,
            "session/request_permission",
            PermissionRequest {
                session_id: &self.session,
                tool_call,
                options: schema::permission_options(),
            },
        );
        let answer = self.shared.pending.wait(id, || {
            self.flags.interrupted.load(Ordering::SeqCst)
                || self.shared.closed.load(Ordering::SeqCst)
        });
        let approved = matches!(&answer, Some(Ok(result)) if schema::approved(result));
        lock(&link.updates).decided(&card, approved);
        approved
    }
}

impl Approver for EditorApprover {
    fn approve(&self, action: &Action) -> bool {
        // Waiting blocks; the runtime's other tasks keep running.
        match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
                tokio::task::block_in_place(|| self.ask(action))
            }
            _ => self.ask(action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use declass_agent::questions::QuestionOption;

    #[test]
    fn turn_ends_map_to_honest_stop_reasons() {
        let reason = |end: TurnEnd, cancelled| stop_reason(&end, cancelled);
        let ok = |r: Result<StopReason, RpcError>| r.unwrap();
        assert_eq!(
            ok(reason(
                TurnEnd::Replied {
                    message: "m".into()
                },
                false
            )),
            StopReason::EndTurn
        );
        assert_eq!(
            ok(reason(
                TurnEnd::Asked {
                    question: "q".into(),
                    options: None
                },
                false
            )),
            StopReason::EndTurn
        );
        assert_eq!(
            ok(reason(
                TurnEnd::Completed {
                    summary: "s".into()
                },
                false
            )),
            StopReason::EndTurn
        );
        // A cancelled prompt is cancelled, whatever the turn did meanwhile.
        assert_eq!(
            ok(reason(
                TurnEnd::Replied {
                    message: "m".into()
                },
                true
            )),
            StopReason::Cancelled
        );
        assert_eq!(
            ok(reason(TurnEnd::Interrupted, false)),
            StopReason::Cancelled
        );
        assert_eq!(ok(reason(TurnEnd::Stopped, false)), StopReason::Cancelled);
        for which in ["limits.frontier_requests", "session.frontier_requests"] {
            assert_eq!(
                ok(reason(
                    TurnEnd::BudgetStopped {
                        which: which.into()
                    },
                    false
                )),
                StopReason::MaxTurnRequests
            );
        }
        assert_eq!(
            ok(reason(
                TurnEnd::BudgetStopped {
                    which: "limits.wall_clock_minutes".into()
                },
                false
            )),
            StopReason::EndTurn
        );
        let failed = reason(
            TurnEnd::Failed {
                reason: "blocked\x1b[2J".into(),
            },
            false,
        )
        .unwrap_err();
        assert_eq!(failed.code, wire::TURN_FAILED);
        assert_eq!(failed.message, "this turn failed: blocked");
    }

    #[test]
    fn a_reply_to_a_question_is_sent_as_its_answer() {
        let mut options = QuestionOptions {
            id: "q1-abc".into(),
            choices: vec![
                QuestionOption {
                    id: "unit".into(),
                    label: "unit".into(),
                    description: None,
                },
                QuestionOption {
                    id: "u32".into(),
                    label: "u32".into(),
                    description: None,
                },
            ],
            allow_freeform: true,
            recommended: None,
        };
        assert_eq!(
            answer(&options, " 2 ").unwrap(),
            "Answer to question q1-abc: u32"
        );
        assert_eq!(
            answer(&options, "u64, please").unwrap(),
            "Answer to question q1-abc: u64, please"
        );
        options.allow_freeform = false;
        assert!(answer(&options, "3").unwrap_err().contains("1 to 2"));
        assert!(answer(&options, "0").is_err());
        options.choices.clear();
        assert_eq!(
            answer(&options, "anything").unwrap(),
            "Answer to question q1-abc: anything"
        );
    }

    #[test]
    fn a_cancellation_reaches_every_prompt_read_before_it() {
        let flags = Flags::default();
        flags.read.store(2, Ordering::SeqCst);
        flags.cancel();
        assert!(flags.cancelled(1) && flags.cancelled(2) && !flags.cancelled(3));
        // Idle: nothing runs, so nothing is interrupted.
        assert!(!flags.interrupted.load(Ordering::SeqCst));
        // A prompt runs and another waits: both are cancelled, the turn stops.
        flags.outstanding.store(2, Ordering::SeqCst);
        *lock(&flags.steering) = Some(Arc::new(Steering::default()));
        flags.read.store(4, Ordering::SeqCst);
        flags.cancel();
        assert!(flags.cancelled(3) && flags.cancelled(4) && !flags.cancelled(5));
        assert!(flags.interrupted.load(Ordering::SeqCst));
        flags.answered();
        flags.answered();
        flags.answered();
        assert!(!flags.busy(), "answers never count below zero");
    }

    #[test]
    fn content_blocks_reach_the_composer_by_kind() {
        use schema::ContentBlock;
        // Only kinds the schema reads are composed; the rest are declined.
        let blocks = vec![
            ContentBlock::Text {
                text: "hello".into(),
            },
            ContentBlock::Audio,
        ];
        let composed = prompt::compose(&blocks, std::path::Path::new("/nonexistent-ws"));
        assert_eq!(composed.message, "hello");
        assert_eq!(composed.declined.len(), 1);
    }
}
