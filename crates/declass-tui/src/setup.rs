// SPDX-License-Identifier: GPL-3.0-or-later
//! First-run setup, full screen: the operator chooses the cloud model (which
//! writes the code) and the local model (which reads sensitive files), sees
//! what will be saved, and saves it. Declass has no default models: nothing
//! is sent anywhere until both are chosen here (or one is deliberately
//! skipped).
//!
//! Like the settings screens, this holds no provider code: discovery, model
//! listings, the ChatGPT sign-in and saving are the CLI's ([`SetupBackend`]),
//! run on worker threads so the screen stays responsive. Saving goes through
//! the audited owner-config path, and only after the review screen.

use crate::models::Job;
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A cloud provider the operator can choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudProvider {
    /// The preset name (`declass config preset <name>`).
    pub name: String,
    pub label: String,
    /// The environment variable holding its key; empty for a ChatGPT plan.
    pub key_env: String,
    /// Its key is in the environment.
    pub key_found: bool,
    /// Paid for with a ChatGPT plan (browser sign-in) instead of a key.
    pub plan: bool,
    /// The plan is signed in already.
    pub signed_in: bool,
    /// The preset's model, offered when the provider lists none.
    pub default_model: String,
    /// The host requests go to, for the review.
    pub host: String,
}

impl CloudProvider {
    fn ready(&self) -> bool {
        if self.plan {
            self.signed_in
        } else {
            self.key_found
        }
    }
}

/// A local model server found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalServer {
    pub base_url: String,
    /// The identified backend (Ollama, LM Studio, ...), or a generic name.
    pub backend: String,
    pub models: Vec<String>,
    /// The variable its key is read from, when the backend uses one.
    pub api_key_env: Option<String>,
}

/// What setup found, before the operator chooses anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    pub providers: Vec<CloudProvider>,
    pub servers: Vec<LocalServer>,
    /// The owner config file the choices are saved to.
    pub config_path: String,
    /// Problems worth knowing first (the command sandbox is unavailable, ...).
    pub warnings: Vec<String>,
}

/// A server address the operator typed, as the backend reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlInfo {
    /// `host:port`, the local allowlist's form.
    pub host_port: String,
    /// On this machine: no allowlist entry needed.
    pub loopback: bool,
    /// Plain HTTP.
    pub plaintext: bool,
}

/// An API key typed on the screen: held in memory until it is saved, and
/// never shown or printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(…)")
    }
}

/// Where an API key comes from: `$NAME`, an environment variable (only its
/// name is saved), or the key itself, pasted (saved in Declass's
/// credentials, owner-only, never in the configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    Env(String),
    Pasted(Secret),
}

/// Reads what was typed at a key prompt: nothing (no key), `$NAME` (a set
/// environment variable) or the key itself.
pub fn parse_key(input: &str) -> Result<Option<KeySource>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    let Some(name) = input.strip_prefix('$') else {
        if input.chars().any(char::is_whitespace) {
            return Err("A key has no spaces. Paste the key itself, or type $VARIABLE.".into());
        }
        return Ok(Some(KeySource::Pasted(Secret::new(input))));
    };
    let name = name.trim_start_matches('{').trim_end_matches('}');
    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(format!("${name} is not a variable name."));
    }
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(Some(KeySource::Env(name.to_owned()))),
        _ => Err(format!(
            "${name} is not set in the shell that started Declass. Paste the key itself, or set it and start again."
        )),
    }
}

/// Where a chosen key comes from, for the review.
fn key_origin(key: &KeySource) -> String {
    match key {
        KeySource::Env(name) => format!("key from ${name}"),
        KeySource::Pasted(_) => "key saved in Declass's credentials".to_owned(),
    }
}

/// An HTTP 401 or 403: the key is missing or wrong.
fn unauthorized(error: &str) -> bool {
    error.contains("401") || error.contains("403") || error.contains("rejected the key")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudChoice {
    pub provider: String,
    pub label: String,
    pub model: String,
    /// `None`: the provider's own variable (found in the environment) or
    /// its plan sign-in.
    pub key: Option<KeySource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalChoice {
    pub base_url: String,
    pub model: String,
    pub key: Option<KeySource>,
    /// A remote host the operator allowed to receive sensitive files
    /// (`local.allowlist`).
    pub allow_host: Option<String>,
    /// The operator accepted plain HTTP to it (`local.allow_plaintext`).
    pub plaintext: bool,
}

/// What to save. `None` is a deliberate skip: no cloud model means every
/// session is local-only; no local model means sensitive files are only ever
/// handles. Never both.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    pub cloud: Option<CloudChoice>,
    pub local: Option<LocalChoice>,
}

/// What setup asks of the rest of Declass. Every method may block (network,
/// browser); the screen calls them on worker threads. None may print.
pub trait SetupBackend: Send + Sync {
    /// Keys in the environment, the ChatGPT sign-in, local servers on this
    /// machine's ports. Lists no cloud provider's models.
    fn scan(&self) -> Found;
    /// The provider's agent models, most suitable first.
    fn cloud_models(&self, provider: &str, key: Option<&KeySource>) -> Result<Vec<String>, String>;
    /// The ChatGPT plan sign-in: opens the browser, passes the address to
    /// `show` (for when it does not open), waits; returns who signed in.
    fn sign_in(&self, show: Box<dyn Fn(String) + Send>) -> Result<String, String>;
    /// Reads a typed server address.
    fn check_url(&self, url: &str) -> Result<UrlInfo, String>;
    /// The models a local server lists (`choice.model` is ignored); a remote
    /// host is contacted only with the operator's `allow_host`.
    fn local_models(&self, choice: &LocalChoice) -> Result<Vec<String>, String>;
    /// Saves the plan through the audited owner-config path; returns the
    /// settings written.
    fn save(&self, plan: &Plan) -> Result<Vec<String>, String>;
}

/// How setup ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Saved { plan: Box<Plan>, lines: Vec<String> },
    Cancelled,
}

/// Takes the terminal, runs setup, and gives the terminal back (also on a
/// panic).
pub fn run(backend: Arc<dyn SetupBackend>) -> std::io::Result<Outcome> {
    let mut out = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    ratatui::crossterm::terminal::enable_raw_mode()?;
    let _restore = Restore;
    execute!(out, EnterAlternateScreen, EnableBracketedPaste)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(out))?;
    let mut wizard = Wizard::new(backend);
    loop {
        terminal.draw(|f| wizard.draw(f))?;
        if let Some(outcome) = wizard.outcome.take() {
            return Ok(outcome);
        }
        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => wizard.key(key),
                Event::Paste(text) => wizard.paste(&text),
                _ => {}
            }
        }
        wizard.tick();
    }
}

struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        if let Ok(mut out) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
            let _ = execute!(
                out,
                DisableBracketedPaste,
                LeaveAlternateScreen,
                ratatui::crossterm::cursor::Show
            );
        }
        let _ = ratatui::crossterm::terminal::disable_raw_mode();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Welcome,
    Cloud,
    SignIn,
    CloudKey,
    CloudModel,
    Local,
    LocalUrl,
    AllowHost,
    Plaintext,
    KeyEnv,
    LocalModel,
    ModelName,
    Review,
    Saving,
    Saved,
}

/// One row of the cloud list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudRow {
    Provider(usize),
    Skip,
}

/// One row of the local list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalRow {
    Model { server: usize, model: String },
    Other,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    Info,
    Good,
    Problem,
}

/// The setup screen's state; [`run`] feeds it keys and draws it, tests do the
/// same against a test backend.
pub struct Wizard {
    backend: Arc<dyn SetupBackend>,
    step: Step,
    found: Option<Found>,
    scanning: Option<Job<Found>>,
    cursor: usize,
    /// The provider chosen on the cloud list.
    provider: Option<usize>,
    /// The key typed for it, when its own variable is not set.
    cloud_key: Option<KeySource>,
    /// Models listed for the step showing them (cloud or local).
    models: Option<Vec<String>>,
    listing: Option<Job<Result<Vec<String>, String>>>,
    signing: Option<Job<Result<String, String>>>,
    sign_in_url: Arc<Mutex<Option<String>>>,
    saving: Option<Job<Result<Vec<String>, String>>>,
    /// The local server being set up (model filled in last).
    local_draft: LocalChoice,
    url_info: Option<UrlInfo>,
    input: String,
    plan: Plan,
    /// Whether each side was decided (chosen or skipped).
    cloud_decided: bool,
    local_decided: bool,
    message: Option<(Tone, String)>,
    saved: Vec<String>,
    ticks: usize,
    outcome: Option<Outcome>,
}

impl Wizard {
    pub fn new(backend: Arc<dyn SetupBackend>) -> Self {
        let scan = backend.clone();
        Self {
            scanning: Some(Job::spawn(move || scan.scan())),
            backend,
            step: Step::Welcome,
            found: None,
            cursor: 0,
            provider: None,
            cloud_key: None,
            models: None,
            listing: None,
            signing: None,
            sign_in_url: Arc::default(),
            saving: None,
            local_draft: LocalChoice::default(),
            url_info: None,
            input: String::new(),
            plan: Plan::default(),
            cloud_decided: false,
            local_decided: false,
            message: None,
            saved: Vec::new(),
            ticks: 0,
            outcome: None,
        }
    }

    /// How setup ended, once it has.
    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    /// Whether a worker is still running (tests wait on it).
    pub fn busy(&self) -> bool {
        self.scanning.is_some()
            || self.listing.is_some()
            || self.signing.is_some()
            || self.saving.is_some()
    }

    /// Collects finished workers.
    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
        if let Some(r) = self.scanning.as_ref().and_then(Job::poll) {
            self.scanning = None;
            self.found = Some(r.unwrap_or_default());
            self.cursor = 0;
        }
        if let Some(r) = self.listing.as_ref().and_then(Job::poll) {
            self.listing = None;
            match r.unwrap_or_else(|()| Err("the listing stopped unexpectedly".into())) {
                Ok(ids) if !ids.is_empty() => self.models = Some(ids),
                Err(e) if unauthorized(&e) && self.step == Step::CloudModel => {
                    let label = self
                        .chosen_provider()
                        .map_or(String::new(), |p| p.label.clone());
                    self.message = Some((
                        Tone::Problem,
                        format!(
                            "{label} refused the key ({e}). Paste the right key, or type $VARIABLE."
                        ),
                    ));
                    self.input.clear();
                    self.go(Step::CloudKey);
                }
                Err(e) if unauthorized(&e) => {
                    self.message = Some((
                        Tone::Problem,
                        format!(
                            "The server needs an API key ({e}). Paste it, or type $VARIABLE for one in your environment."
                        ),
                    ));
                    self.input.clear();
                    self.go(Step::KeyEnv);
                }
                Ok(_) | Err(_) if self.step == Step::CloudModel => {
                    // The provider listed nothing usable: its preset's model.
                    let fallback = self.chosen_provider().map(|p| p.default_model.clone());
                    match fallback.filter(|m| !m.is_empty()) {
                        Some(model) => {
                            self.message = Some((
                                Tone::Info,
                                "The provider's model list is unavailable; its usual model is offered."
                                    .into(),
                            ));
                            self.models = Some(vec![model]);
                        }
                        None => {
                            self.message = Some((
                                Tone::Problem,
                                "The provider listed no models. Check its key, then choose it again."
                                    .into(),
                            ));
                            self.go(Step::Cloud);
                        }
                    }
                }
                Ok(_) => {
                    self.message = Some((
                        Tone::Problem,
                        "That server lists no models. Load one (for example `ollama pull qwen3:8b`), then try again."
                            .into(),
                    ));
                    self.go(Step::Local);
                }
                Err(e) => {
                    self.message = Some((Tone::Problem, format!("Could not reach it: {e}")));
                    self.go(Step::Local);
                }
            }
            self.cursor = 0;
        }
        if let Some(r) = self.signing.as_ref().and_then(Job::poll) {
            self.signing = None;
            match r.unwrap_or_else(|()| Err("the sign-in stopped unexpectedly".into())) {
                Ok(who) => {
                    if let (Some(found), Some(i)) = (self.found.as_mut(), self.provider) {
                        found.providers[i].signed_in = true;
                    }
                    self.message = Some((Tone::Good, format!("Signed in as {who}.")));
                    self.list_cloud_models();
                }
                Err(e) if self.step == Step::SignIn => {
                    self.message = Some((Tone::Problem, format!("Sign-in failed: {e}")));
                    self.go(Step::Cloud);
                }
                Err(_) => {}
            }
        }
        if let Some(r) = self.saving.as_ref().and_then(Job::poll) {
            self.saving = None;
            match r.unwrap_or_else(|()| Err("saving stopped unexpectedly".into())) {
                Ok(lines) => {
                    self.saved = lines;
                    self.message = None;
                    self.go(Step::Saved);
                }
                Err(e) => {
                    self.message = Some((Tone::Problem, format!("Not saved: {e}")));
                    self.go(Step::Review);
                }
            }
        }
    }

    fn go(&mut self, step: Step) {
        self.step = step;
        self.cursor = 0;
    }

    fn chosen_provider(&self) -> Option<&CloudProvider> {
        Some(&self.found.as_ref()?.providers[self.provider?])
    }

    fn cloud_rows(&self) -> Vec<CloudRow> {
        let Some(found) = &self.found else {
            return Vec::new();
        };
        let mut rows: Vec<usize> = (0..found.providers.len()).collect();
        // Ready providers first, then the plan sign-in, then the rest.
        rows.sort_by_key(|&i| {
            let p = &found.providers[i];
            (!p.ready(), !p.plan)
        });
        let mut out: Vec<CloudRow> = rows.into_iter().map(CloudRow::Provider).collect();
        out.push(CloudRow::Skip);
        out
    }

    fn local_rows(&self) -> Vec<LocalRow> {
        let mut out = Vec::new();
        if let Some(found) = &self.found {
            for (server, s) in found.servers.iter().enumerate() {
                for model in &s.models {
                    out.push(LocalRow::Model {
                        server,
                        model: model.clone(),
                    });
                }
            }
        }
        out.push(LocalRow::Other);
        out.push(LocalRow::Skip);
        out
    }

    fn rows(&self) -> usize {
        match self.step {
            Step::Cloud => self.cloud_rows().len(),
            Step::Local => self.local_rows().len(),
            Step::CloudModel => self.models.as_ref().map_or(0, Vec::len),
            // The listed models, then "Type a model name…".
            Step::LocalModel => self.models.as_ref().map_or(0, |m| m.len() + 1),
            _ => 0,
        }
    }

    fn list_cloud_models(&mut self) {
        let Some(p) = self.chosen_provider() else {
            return;
        };
        let (backend, name, key) = (self.backend.clone(), p.name.clone(), self.cloud_key.clone());
        self.models = None;
        self.listing = Some(Job::spawn(move || {
            backend.cloud_models(&name, key.as_ref())
        }));
        self.go(Step::CloudModel);
    }

    fn list_local_models(&mut self) {
        let (backend, choice) = (self.backend.clone(), self.local_draft.clone());
        self.models = None;
        self.listing = Some(Job::spawn(move || backend.local_models(&choice)));
        self.go(Step::LocalModel);
    }

    pub fn paste(&mut self, text: &str) {
        if matches!(
            self.step,
            Step::LocalUrl | Step::KeyEnv | Step::CloudKey | Step::ModelName
        ) {
            self.input.extend(text.chars().filter(|c| !c.is_control()));
        }
    }

    pub fn key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.outcome = Some(Outcome::Cancelled);
            return;
        }
        let typing = matches!(
            self.step,
            Step::LocalUrl | Step::KeyEnv | Step::CloudKey | Step::ModelName
        );
        if typing {
            self.type_key(key);
            return;
        }
        match key.code {
            KeyCode::Char('q') if self.step != Step::Saving => {
                self.outcome = Some(Outcome::Cancelled);
            }
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = (self.cursor + 1).min(self.rows().saturating_sub(1));
            }
            KeyCode::Char('r') if matches!(self.step, Step::Cloud | Step::Local) => {
                let backend = self.backend.clone();
                self.found = None;
                self.scanning = Some(Job::spawn(move || backend.scan()));
                self.message = None;
            }
            KeyCode::Esc => self.back(),
            KeyCode::Enter => self.enter(),
            KeyCode::Char('y') if matches!(self.step, Step::AllowHost | Step::Plaintext) => {
                self.enter()
            }
            KeyCode::Char('n') if matches!(self.step, Step::AllowHost | Step::Plaintext) => {
                self.message = Some((
                    Tone::Info,
                    "Not allowed. Choose another server, or skip the local model.".into(),
                ));
                self.go(Step::Local);
            }
            _ => {}
        }
    }

    fn type_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.back(),
            KeyCode::Enter => self.enter(),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input.push(c)
            }
            _ => {}
        }
    }

    fn back(&mut self) {
        self.message = None;
        let to = match self.step {
            Step::Welcome => {
                self.outcome = Some(Outcome::Cancelled);
                return;
            }
            Step::Cloud => Step::Welcome,
            Step::SignIn | Step::CloudModel | Step::CloudKey => {
                self.listing = None;
                self.signing = None;
                Step::Cloud
            }
            Step::Local => Step::Cloud,
            Step::LocalUrl | Step::AllowHost | Step::Plaintext | Step::KeyEnv => Step::Local,
            Step::LocalModel => {
                self.listing = None;
                Step::Local
            }
            Step::ModelName => Step::LocalModel,
            Step::Review => Step::Local,
            Step::Saving | Step::Saved => return,
        };
        self.go(to);
    }

    fn enter(&mut self) {
        self.message = None;
        match self.step {
            Step::Welcome => {
                if self.found.is_some() {
                    self.go(Step::Cloud);
                }
            }
            Step::Cloud => {
                let rows = self.cloud_rows();
                match rows.get(self.cursor).copied() {
                    Some(CloudRow::Provider(i)) => {
                        let p = &self.found.as_ref().expect("rows need a scan").providers[i];
                        self.provider = Some(i);
                        self.cloud_key = None;
                        if p.plan && !p.signed_in {
                            *self.sign_in_url.lock().unwrap() = None;
                            let (backend, url) = (self.backend.clone(), self.sign_in_url.clone());
                            self.signing = Some(Job::spawn(move || {
                                backend.sign_in(Box::new(move |u| *url.lock().unwrap() = Some(u)))
                            }));
                            self.go(Step::SignIn);
                        } else if p.ready() {
                            self.list_cloud_models();
                        } else {
                            self.input.clear();
                            self.go(Step::CloudKey);
                        }
                    }
                    Some(CloudRow::Skip) => {
                        self.plan.cloud = None;
                        self.cloud_decided = true;
                        self.go(Step::Local);
                    }
                    None => {}
                }
            }
            Step::CloudModel => {
                let (Some(models), Some(p)) = (&self.models, self.chosen_provider()) else {
                    return;
                };
                let Some(model) = models.get(self.cursor) else {
                    return;
                };
                self.plan.cloud = Some(CloudChoice {
                    provider: p.name.clone(),
                    label: p.label.clone(),
                    model: model.clone(),
                    key: self.cloud_key.clone(),
                });
                self.cloud_decided = true;
                self.go(Step::Local);
            }
            Step::SignIn => {}
            Step::CloudKey => match parse_key(&self.input) {
                Ok(Some(key)) => {
                    self.cloud_key = Some(key);
                    self.list_cloud_models();
                }
                Ok(None) => {
                    self.message = Some((
                        Tone::Info,
                        "Paste the key, or type $VARIABLE for one in your environment.".into(),
                    ))
                }
                Err(e) => self.message = Some((Tone::Problem, e)),
            },
            Step::Local => match self.local_rows().get(self.cursor).cloned() {
                Some(LocalRow::Model { server, model }) => {
                    let s = &self.found.as_ref().expect("rows need a scan").servers[server];
                    self.plan.local = Some(LocalChoice {
                        base_url: s.base_url.clone(),
                        model,
                        key: s.api_key_env.clone().map(KeySource::Env),
                        allow_host: None,
                        plaintext: false,
                    });
                    self.local_decided = true;
                    self.go(Step::Review);
                }
                Some(LocalRow::Other) => {
                    self.input.clear();
                    self.go(Step::LocalUrl);
                }
                Some(LocalRow::Skip) => {
                    if self.cloud_decided && self.plan.cloud.is_none() {
                        self.message = Some((
                            Tone::Problem,
                            "Without a cloud model, Declass needs a local one. Choose a server, or go back (Esc) and choose a cloud model."
                                .into(),
                        ));
                        return;
                    }
                    self.plan.local = None;
                    self.local_decided = true;
                    self.go(Step::Review);
                }
                None => {}
            },
            Step::LocalUrl => {
                let url = self.input.trim().to_owned();
                if url.is_empty() {
                    return;
                }
                match self.backend.check_url(&url) {
                    Ok(info) => {
                        self.local_draft = LocalChoice {
                            base_url: url,
                            ..LocalChoice::default()
                        };
                        let loopback = info.loopback;
                        self.url_info = Some(info);
                        if loopback {
                            self.ask_key_env();
                        } else {
                            self.go(Step::AllowHost);
                        }
                    }
                    Err(e) => self.message = Some((Tone::Problem, e)),
                }
            }
            Step::AllowHost => {
                let info = self.url_info.clone().expect("a checked address");
                self.local_draft.allow_host = Some(info.host_port);
                if info.plaintext {
                    self.go(Step::Plaintext);
                } else {
                    self.ask_key_env();
                }
            }
            Step::Plaintext => {
                self.local_draft.plaintext = true;
                self.ask_key_env();
            }
            Step::ModelName => {
                let model = self.input.trim().to_owned();
                if model.is_empty() {
                    return;
                }
                let mut choice = self.local_draft.clone();
                choice.model = model;
                self.plan.local = Some(choice);
                self.local_decided = true;
                self.go(Step::Review);
            }
            Step::KeyEnv => match parse_key(&self.input) {
                Ok(key) => {
                    self.local_draft.key = key;
                    self.list_local_models();
                }
                Err(e) => self.message = Some((Tone::Problem, e)),
            },
            Step::LocalModel => {
                let Some(models) = &self.models else {
                    return;
                };
                if self.cursor == models.len() {
                    self.input.clear();
                    self.step = Step::ModelName;
                    return;
                }
                let Some(model) = models.get(self.cursor) else {
                    return;
                };
                let mut choice = self.local_draft.clone();
                choice.model = model.clone();
                self.plan.local = Some(choice);
                self.local_decided = true;
                self.go(Step::Review);
            }
            Step::Review => {
                if self.plan.cloud.is_none() && self.plan.local.is_none() {
                    self.message = Some((Tone::Problem, "Choose at least one model.".into()));
                    return;
                }
                let (backend, plan) = (self.backend.clone(), self.plan.clone());
                self.saving = Some(Job::spawn(move || backend.save(&plan)));
                self.go(Step::Saving);
            }
            Step::Saving => {}
            Step::Saved => {
                self.outcome = Some(Outcome::Saved {
                    plan: Box::new(self.plan.clone()),
                    lines: self.saved.clone(),
                });
            }
        }
    }

    fn ask_key_env(&mut self) {
        self.input.clear();
        self.go(Step::KeyEnv);
    }

    fn spinner(&self) -> &'static str {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        FRAMES[self.ticks % FRAMES.len()]
    }

    pub fn draw(&self, f: &mut Frame) {
        let area = f.area();
        f.render_widget(Clear, area);
        let width = area.width.min(96);
        let x = area.x + (area.width - width) / 2;
        let outer = Rect::new(x, area.y, width, area.height);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Color::DarkGray))
            .title(Line::from(vec![
                Span::styled(" declass ", Style::new().add_modifier(Modifier::BOLD)),
                Span::styled("setup ", Style::new().fg(Color::DarkGray)),
            ]));
        let inner = block.inner(outer);
        f.render_widget(block, outer);
        let [steps, _, body, message, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .areas(inner.inner(ratatui::layout::Margin::new(2, 1)));
        f.render_widget(Paragraph::new(self.steps_line()), steps);
        f.render_widget(
            Paragraph::new(self.body(body.height as usize)).wrap(Wrap { trim: false }),
            body,
        );
        if let Some((tone, text)) = &self.message {
            let colour = match tone {
                Tone::Info => Color::Cyan,
                Tone::Good => Color::Green,
                Tone::Problem => Color::Yellow,
            };
            f.render_widget(
                Paragraph::new(Line::styled(text.clone(), Style::new().fg(colour)))
                    .wrap(Wrap { trim: true }),
                message,
            );
        }
        f.render_widget(
            Paragraph::new(Line::styled(self.hints(), Style::new().fg(Color::DarkGray))),
            footer,
        );
    }

    fn steps_line(&self) -> Line<'static> {
        let current = match self.step {
            Step::Welcome => 0,
            Step::Cloud | Step::SignIn | Step::CloudKey | Step::CloudModel => 1,
            Step::Local
            | Step::LocalUrl
            | Step::AllowHost
            | Step::Plaintext
            | Step::KeyEnv
            | Step::LocalModel
            | Step::ModelName => 2,
            Step::Review | Step::Saving | Step::Saved => 3,
        };
        let mut spans = Vec::new();
        for (i, name) in ["Welcome", "Cloud model", "Local model", "Review"]
            .into_iter()
            .enumerate()
        {
            if i > 0 {
                spans.push(Span::styled("  ›  ", Style::new().fg(Color::DarkGray)));
            }
            let style = if i == current {
                Style::new().add_modifier(Modifier::BOLD)
            } else if i < current {
                Style::new().fg(Color::Green)
            } else {
                Style::new().fg(Color::DarkGray)
            };
            spans.push(Span::styled(name, style));
        }
        Line::from(spans)
    }

    fn hints(&self) -> String {
        match self.step {
            Step::Welcome => "Enter start · q quit",
            Step::Cloud | Step::Local => {
                "↑↓ move · Enter choose · r look again · Esc back · q quit"
            }
            Step::CloudModel | Step::LocalModel => "↑↓ move · Enter choose · Esc back · q quit",
            Step::SignIn => "Esc cancel · q quit",
            Step::LocalUrl | Step::ModelName => "type or paste · Enter continue · Esc back",
            Step::KeyEnv | Step::CloudKey => {
                "paste the key, or $VARIABLE · Enter continue · Esc back"
            }
            Step::AllowHost | Step::Plaintext => "y allow · n don't · Esc back",
            Step::Review => "Enter save · Esc back · q quit without saving",
            Step::Saving => "saving…",
            Step::Saved => "Enter start Declass",
        }
        .into()
    }

    /// The rows of a list of `total` that fit in `room` lines, keeping the
    /// cursor in view.
    fn window(&self, total: usize, room: usize) -> std::ops::Range<usize> {
        let room = room.max(3).min(total);
        let start = self.cursor.saturating_sub(room - 1).min(total - room);
        start..start + room
    }

    /// `rows` (already drawn) cut to the room left under `l`, with a line
    /// saying how many more there are.
    fn list(&self, l: &mut Vec<Line<'static>>, rows: Vec<Line<'static>>, height: usize) {
        if rows.is_empty() {
            return;
        }
        let room = height.saturating_sub(l.len() + 1);
        let shown = self.window(rows.len(), room);
        let (above, below) = (shown.start, rows.len() - shown.end);
        let more = Style::new().fg(Color::DarkGray);
        if above > 0 {
            l.push(Line::styled(format!("    ↑ {above} more"), more));
        }
        l.extend(rows[shown.clone()].iter().cloned());
        if below > 0 {
            l.push(Line::styled(format!("    ↓ {below} more"), more));
        }
    }

    fn body(&self, height: usize) -> Vec<Line<'static>> {
        let dim = Style::new().fg(Color::DarkGray);
        let bold = Style::new().add_modifier(Modifier::BOLD);
        let mut l: Vec<Line<'static>> = Vec::new();
        match self.step {
            Step::Welcome => {
                l.push(Line::styled("Welcome to Declass.", bold));
                l.push(Line::default());
                l.push(Line::from("Declass works with two models:"));
                l.push(Line::from(vec![
                    Span::styled("  Cloud model  ", bold),
                    Span::raw("writes the code. It never opens your sensitive files."),
                ]));
                l.push(Line::from(vec![
                    Span::styled("  Local model  ", bold),
                    Span::raw("runs on your machine and reads them for it."),
                ]));
                l.push(Line::default());
                l.push(Line::from(
                    "Nothing is configured and nothing is sent anywhere until you choose both here.",
                ));
                l.push(Line::default());
                match &self.found {
                    None => l.push(Line::styled(
                        format!(
                            "{} Looking for API keys and local model servers…",
                            self.spinner()
                        ),
                        dim,
                    )),
                    Some(found) => {
                        let keys: Vec<_> = found
                            .providers
                            .iter()
                            .filter(|p| p.ready())
                            .map(|p| p.label.clone())
                            .collect();
                        l.push(Line::from(vec![
                            Span::styled("Found  ", dim),
                            Span::raw(if keys.is_empty() {
                                "no cloud API keys in your environment".to_owned()
                            } else {
                                format!("keys for {}", keys.join(", "))
                            }),
                        ]));
                        let servers: Vec<_> = found
                            .servers
                            .iter()
                            .filter(|s| !s.models.is_empty())
                            .map(|s| format!("{} ({})", s.backend, s.base_url))
                            .collect();
                        l.push(Line::from(vec![
                            Span::styled("       ", dim),
                            Span::raw(if servers.is_empty() {
                                "no local model server on this machine".to_owned()
                            } else {
                                servers.join(", ")
                            }),
                        ]));
                        for w in &found.warnings {
                            l.push(Line::styled(
                                format!("!  {w}"),
                                Style::new().fg(Color::Yellow),
                            ));
                        }
                        l.push(Line::default());
                        l.push(Line::styled(
                            format!("Your choices are saved to {}.", found.config_path),
                            dim,
                        ));
                    }
                }
            }
            Step::Cloud => {
                l.push(Line::styled("Which cloud model writes the code?", bold));
                l.push(Line::styled(
                    "Your code and the task go to this provider. Sensitive files never do.",
                    dim,
                ));
                l.push(Line::default());
                match &self.found {
                    None => l.push(Line::styled(format!("{} Looking…", self.spinner()), dim)),
                    Some(found) => {
                        let mut rows = Vec::new();
                        for (i, row) in self.cloud_rows().into_iter().enumerate() {
                            let (mark, label, note) = match row {
                                CloudRow::Provider(p) => {
                                    let p = &found.providers[p];
                                    let note = if p.plan {
                                        if p.signed_in {
                                            "signed in".to_owned()
                                        } else {
                                            "sign in with your browser".to_owned()
                                        }
                                    } else if p.key_found {
                                        format!("{} found", p.key_env)
                                    } else {
                                        format!("paste a key, or set {}", p.key_env)
                                    };
                                    (if p.ready() { "✓" } else { "·" }, p.label.clone(), note)
                                }
                                CloudRow::Skip => (
                                    " ",
                                    "No cloud model".to_owned(),
                                    "everything stays on this machine (local-only)".to_owned(),
                                ),
                            };
                            rows.push(self.row(i, mark, &label, &note));
                        }
                        self.list(&mut l, rows, height);
                    }
                }
            }
            Step::SignIn => {
                l.push(Line::styled("Sign in with ChatGPT", bold));
                l.push(Line::default());
                l.push(Line::from(
                    "Your browser should open. Sign in and allow Declass to use your plan.",
                ));
                l.push(Line::from(
                    "Requests then count against your plan's usage, which you can limit in ChatGPT's settings.",
                ));
                l.push(Line::default());
                if let Some(url) = self.sign_in_url.lock().unwrap().clone() {
                    l.push(Line::styled("If it doesn't open, visit:", dim));
                    l.push(Line::from(url));
                    l.push(Line::default());
                }
                l.push(Line::styled(
                    format!(
                        "{} Waiting for the sign-in (up to 5 minutes)…",
                        self.spinner()
                    ),
                    dim,
                ));
            }
            Step::CloudModel | Step::LocalModel => {
                let title = if self.step == Step::CloudModel {
                    format!(
                        "Which {} model?",
                        self.chosen_provider().map_or("", |p| p.label.as_str())
                    )
                } else {
                    format!("Which model on {}?", self.local_draft.base_url)
                };
                l.push(Line::styled(title, bold));
                l.push(Line::default());
                match &self.models {
                    None => l.push(Line::styled(
                        format!("{} Listing models…", self.spinner()),
                        dim,
                    )),
                    Some(models) => {
                        let mut rows: Vec<Line<'static>> = models
                            .iter()
                            .enumerate()
                            .map(|(i, m)| {
                                self.row(i, " ", m, if i == 0 { "suggested" } else { "" })
                            })
                            .collect();
                        if self.step == Step::LocalModel {
                            rows.push(self.row(
                                models.len(),
                                " ",
                                "Type a model name…",
                                "a model the server serves but does not list",
                            ));
                        }
                        self.list(&mut l, rows, height);
                    }
                }
            }
            Step::Local => {
                l.push(Line::styled(
                    "Which local model reads your sensitive files?",
                    bold,
                ));
                l.push(Line::styled(
                    "Files such as .env, data and logs are read only by this model, on this machine or a server you control.",
                    dim,
                ));
                l.push(Line::default());
                match &self.found {
                    None => l.push(Line::styled(format!("{} Looking…", self.spinner()), dim)),
                    Some(found) => {
                        if found.servers.iter().all(|s| s.models.is_empty()) {
                            l.push(Line::styled(
                                "No local model server found on this machine. Install Ollama (https://ollama.com),",
                                Style::new().fg(Color::Yellow),
                            ));
                            l.push(Line::styled(
                                "run `ollama pull qwen3:8b`, then press r. LM Studio, llama.cpp, vLLM and others work too.",
                                Style::new().fg(Color::Yellow),
                            ));
                            l.push(Line::default());
                        }
                        let mut rows = Vec::new();
                        for (i, row) in self.local_rows().into_iter().enumerate() {
                            match row {
                                LocalRow::Model { server, model } => {
                                    let s = &found.servers[server];
                                    let note = format!("{} · {}", s.backend, s.base_url);
                                    rows.push(self.row(i, "✓", &model, &note));
                                }
                                LocalRow::Other => rows.push(self.row(
                                    i,
                                    " ",
                                    "A server at another address…",
                                    "another port, or a machine on your network",
                                )),
                                LocalRow::Skip => rows.push(self.row(
                                    i,
                                    " ",
                                    "No local model",
                                    "the cloud model sees sensitive files only as placeholders",
                                )),
                            }
                        }
                        self.list(&mut l, rows, height);
                    }
                }
            }
            Step::LocalUrl => {
                l.push(Line::styled("Where is your local model server?", bold));
                l.push(Line::styled(
                    "Its OpenAI-compatible address, for example http://127.0.0.1:11434/v1 or https://gpu.lan:8443/v1",
                    dim,
                ));
                l.push(Line::default());
                l.push(self.field());
            }
            Step::AllowHost => {
                let host = self
                    .url_info
                    .as_ref()
                    .map_or(String::new(), |i| i.host_port.clone());
                l.push(Line::styled(format!("Allow {host}?"), bold));
                l.push(Line::default());
                l.push(Line::from(format!(
                    "{host} is not this machine. Declass sends it your sensitive files for the local model to read."
                )));
                l.push(Line::from(
                    "Allow it only if you control that machine and the network between.",
                ));
            }
            Step::Plaintext => {
                l.push(Line::styled("Allow plain HTTP?", bold));
                l.push(Line::default());
                l.push(Line::from(
                    "This server uses http://, so your sensitive files would cross the network unencrypted.",
                ));
                l.push(Line::from(
                    "Prefer TLS, or an SSH tunnel to a port on this machine (ssh -N -L).",
                ));
            }
            Step::KeyEnv => {
                l.push(Line::styled("Does it need an API key?", bold));
                l.push(Line::styled(
                    "Paste the key itself, or type $VARIABLE for one in your environment. Enter for none.",
                    dim,
                ));
                l.push(Line::styled(
                    "A pasted key is kept in Declass's credentials (owner-only), never in its configuration.",
                    dim,
                ));
                l.push(Line::default());
                l.push(self.field());
            }
            Step::ModelName => {
                l.push(Line::styled("Which model name?", bold));
                l.push(Line::styled(
                    format!(
                        "The model id {} should run, exactly as the server knows it.",
                        self.local_draft.base_url
                    ),
                    dim,
                ));
                l.push(Line::default());
                l.push(self.field());
            }
            Step::CloudKey => {
                let p = self.chosen_provider();
                l.push(Line::styled(
                    format!("{} API key", p.map_or("", |p| p.label.as_str())),
                    bold,
                ));
                l.push(Line::styled(
                    format!(
                        "Paste the key itself, or type ${} (or another $VARIABLE) if it is in your environment.",
                        p.map_or("", |p| p.key_env.as_str())
                    ),
                    dim,
                ));
                l.push(Line::styled(
                    "A pasted key is kept in Declass's credentials (owner-only), never in its configuration.",
                    dim,
                ));
                l.push(Line::default());
                l.push(self.field());
            }
            Step::Review | Step::Saving => {
                l.push(Line::styled("Ready to save", bold));
                l.push(Line::default());
                let found = self.found.as_ref();
                match &self.plan.cloud {
                    Some(c) => {
                        let p =
                            found.and_then(|f| f.providers.iter().find(|p| p.name == c.provider));
                        let how = match (p, &c.key) {
                            (Some(p), _) if p.plan => "paid by your ChatGPT plan".to_owned(),
                            (_, Some(k)) => key_origin(k),
                            (Some(p), None) => format!("key from ${}", p.key_env),
                            (None, None) => String::new(),
                        };
                        l.push(Line::from(vec![
                            Span::styled("Cloud model   ", bold),
                            Span::raw(format!("{} · {}", c.label, c.model)),
                        ]));
                        l.push(Line::styled(
                            format!(
                                "              receives your code and the task at {} ({how})",
                                p.map_or("", |p| p.host.as_str())
                            ),
                            dim,
                        ));
                    }
                    None => {
                        l.push(Line::from(vec![
                            Span::styled("Cloud model   ", bold),
                            Span::raw("none: every session is local-only"),
                        ]));
                        l.push(Line::styled(
                            "              (clearance.required = top; lift it later in F2 settings)",
                            dim,
                        ));
                    }
                }
                l.push(Line::default());
                match &self.plan.local {
                    Some(c) => {
                        l.push(Line::from(vec![
                            Span::styled("Local model   ", bold),
                            Span::raw(format!("{} · {}", c.model, c.base_url)),
                        ]));
                        l.push(Line::styled(
                            match &c.key {
                                Some(k) => format!(
                                    "              reads your sensitive files ({})",
                                    key_origin(k)
                                ),
                                None => "              reads your sensitive files (no API key)"
                                    .to_owned(),
                            },
                            dim,
                        ));
                        if let Some(host) = &c.allow_host {
                            l.push(Line::styled(
                                format!("              {host} is allowed to receive them"),
                                Style::new().fg(Color::Yellow),
                            ));
                        }
                        if c.plaintext {
                            l.push(Line::styled(
                                "              over plain HTTP, unencrypted",
                                Style::new().fg(Color::Yellow),
                            ));
                        }
                    }
                    None => {
                        l.push(Line::from(vec![
                            Span::styled("Local model   ", bold),
                            Span::raw("none: nothing reads sensitive files"),
                        ]));
                        l.push(Line::styled(
                            "              the cloud model sees them only as placeholders (local.enabled = false)",
                            dim,
                        ));
                    }
                }
                l.push(Line::default());
                if let Some(f) = found {
                    l.push(Line::styled(format!("Saved to {}.", f.config_path), dim));
                }
                l.push(Line::styled(
                    "Change these any time: F2 in a session, or `declass setup`.",
                    dim,
                ));
                if self.step == Step::Saving {
                    l.push(Line::default());
                    l.push(Line::styled(format!("{} Saving…", self.spinner()), dim));
                }
            }
            Step::Saved => {
                l.push(Line::styled(
                    "Saved.",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                ));
                l.push(Line::default());
                for line in &self.saved {
                    l.push(Line::styled(format!("  {line}"), dim));
                }
                l.push(Line::default());
                l.push(Line::from(
                    "Press Enter, then describe what you want to build or fix.",
                ));
            }
        }
        l
    }

    fn row(&self, i: usize, mark: &str, label: &str, note: &str) -> Line<'static> {
        let selected = i == self.cursor;
        let pointer = if selected { "›" } else { " " };
        let mark_style = if mark == "✓" {
            Style::new().fg(Color::Green)
        } else {
            Style::new().fg(Color::DarkGray)
        };
        let label_style = if selected {
            Style::new().add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::new()
        };
        Line::from(vec![
            Span::styled(format!("{pointer} "), Style::new().fg(Color::Cyan)),
            Span::styled(format!("{mark} "), mark_style),
            Span::styled(format!(" {label} "), label_style),
            Span::styled(
                if note.is_empty() {
                    String::new()
                } else {
                    format!("  {note}")
                },
                Style::new().fg(Color::DarkGray),
            ),
        ])
    }

    fn field(&self) -> Line<'static> {
        // A key is never shown: only a `$VARIABLE` or an address is.
        let masked = matches!(self.step, Step::KeyEnv | Step::CloudKey)
            && !self.input.trim_start().starts_with('$');
        let shown = if masked {
            "•".repeat(self.input.chars().count().min(48))
        } else {
            crate::term::safe(&self.input)
        };
        Line::from(vec![
            Span::styled("› ", Style::new().fg(Color::Cyan)),
            Span::raw(shown),
            Span::styled("▏", Style::new().fg(Color::Cyan)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[derive(Default)]
    struct Fake {
        saved: Mutex<Option<Plan>>,
        signed: Mutex<bool>,
    }

    impl SetupBackend for Fake {
        fn scan(&self) -> Found {
            let provider = |name: &str, label: &str, key_env: &str, found: bool| CloudProvider {
                name: name.into(),
                label: label.into(),
                key_env: key_env.into(),
                key_found: found,
                plan: false,
                signed_in: false,
                default_model: format!("{name}-default"),
                host: format!("api.{name}.example"),
            };
            Found {
                providers: vec![
                    provider("zai", "z.ai GLM", "ZAI_API_KEY", false),
                    provider("anthropic", "Anthropic", "ANTHROPIC_API_KEY", true),
                    CloudProvider {
                        plan: true,
                        signed_in: *self.signed.lock().unwrap(),
                        key_env: String::new(),
                        ..provider("chatgpt", "ChatGPT plan", "", false)
                    },
                ],
                servers: vec![LocalServer {
                    base_url: "http://127.0.0.1:11434/v1".into(),
                    backend: "Ollama".into(),
                    models: vec!["qwen3:8b".into()],
                    api_key_env: None,
                }],
                config_path: "/home/owner/.config/declass/config.toml".into(),
                warnings: Vec::new(),
            }
        }
        fn cloud_models(
            &self,
            provider: &str,
            key: Option<&KeySource>,
        ) -> Result<Vec<String>, String> {
            match (provider, key) {
                ("zai", Some(KeySource::Pasted(k))) if k.expose() != "zk-right" => {
                    Err("HTTP 401".into())
                }
                ("zai", None) => Err("HTTP 401".into()),
                _ => Ok(vec![format!("{provider}-big"), format!("{provider}-small")]),
            }
        }
        fn sign_in(&self, show: Box<dyn Fn(String) + Send>) -> Result<String, String> {
            show("https://auth.example/sign-in".into());
            *self.signed.lock().unwrap() = true;
            Ok("owner@example.com".into())
        }
        fn check_url(&self, url: &str) -> Result<UrlInfo, String> {
            let loopback = url.contains("127.0.0.1");
            Ok(UrlInfo {
                host_port: "192.0.2.7:8080".into(),
                loopback,
                plaintext: url.starts_with("http://"),
            })
        }
        fn local_models(&self, choice: &LocalChoice) -> Result<Vec<String>, String> {
            if choice.allow_host.is_none() && !choice.base_url.contains("127.0.0.1") {
                return Err("not allowed".into());
            }
            if choice.base_url.contains("needs-key") && choice.key.is_none() {
                return Err("HTTP 401".into());
            }
            Ok(vec!["remote-27b".into()])
        }
        fn save(&self, plan: &Plan) -> Result<Vec<String>, String> {
            *self.saved.lock().unwrap() = Some(plan.clone());
            Ok(vec!["frontier.model = \"x\"".into()])
        }
    }

    fn press(w: &mut Wizard, code: KeyCode) {
        w.key(KeyEvent::new(code, KeyModifiers::NONE));
        settle(w);
    }

    fn typed(w: &mut Wizard, text: &str) {
        for c in text.chars() {
            w.key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
    }

    fn settle(w: &mut Wizard) {
        for _ in 0..500 {
            w.tick();
            if !w.busy() {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("a worker never finished");
    }

    fn screen(w: &Wizard) -> String {
        let mut t = Terminal::new(TestBackend::new(100, 30)).unwrap();
        t.draw(|f| w.draw(f)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn wizard() -> (Wizard, Arc<Fake>) {
        let fake = Arc::new(Fake::default());
        let mut w = Wizard::new(fake.clone());
        settle(&mut w);
        (w, fake)
    }

    #[test]
    fn the_operator_chooses_both_models_and_nothing_is_saved_before_the_review() {
        let (mut w, fake) = wizard();
        assert!(screen(&w).contains("keys for Anthropic"));
        press(&mut w, KeyCode::Enter);
        // The provider with a key is listed first; nothing was preselected.
        assert!(screen(&w).contains("ANTHROPIC_API_KEY found"));
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("anthropic-big"));
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("qwen3:8b"));
        press(&mut w, KeyCode::Enter);
        let review = screen(&w);
        assert!(review.contains("Anthropic · anthropic-small"), "{review}");
        assert!(
            review.contains("qwen3:8b · http://127.0.0.1:11434/v1"),
            "{review}"
        );
        assert!(fake.saved.lock().unwrap().is_none());
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("Saved."));
        press(&mut w, KeyCode::Enter);
        let Some(Outcome::Saved { plan, .. }) = w.outcome() else {
            panic!("not saved")
        };
        assert_eq!(plan.cloud.as_ref().unwrap().model, "anthropic-small");
        assert_eq!(plan.local.as_ref().unwrap().model, "qwen3:8b");
        assert_eq!(fake.saved.lock().unwrap().as_ref(), Some(&**plan));
    }

    #[test]
    fn a_provider_without_its_key_takes_a_pasted_key_that_is_never_shown() {
        let (mut w, fake) = wizard();
        press(&mut w, KeyCode::Enter);
        // Anthropic, ChatGPT plan, then z.ai (no key in the environment).
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("z.ai GLM API key"), "{}", screen(&w));
        typed(&mut w, "zk-wrong");
        assert!(!screen(&w).contains("zk-wrong"));
        assert!(screen(&w).contains("••••••••"));
        press(&mut w, KeyCode::Enter);
        // Refused: back at the key, which is asked again.
        assert!(screen(&w).contains("refused the key"), "{}", screen(&w));
        typed(&mut w, "zk-right");
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("zai-big"), "{}", screen(&w));
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        let review = screen(&w);
        assert!(review.contains("key saved in Declass"), "{review}");
        assert!(!review.contains("zk-right"));
        press(&mut w, KeyCode::Enter);
        let plan = fake.saved.lock().unwrap().clone().unwrap();
        assert_eq!(
            plan.cloud.unwrap().key,
            Some(KeySource::Pasted(Secret::new("zk-right")))
        );
        assert!(!format!("{:?}", Secret::new("zk-right")).contains("zk-right"));
    }

    #[test]
    fn a_dollar_names_a_variable_that_must_be_set() {
        assert_eq!(parse_key("").unwrap(), None);
        assert_eq!(
            parse_key("$PATH").unwrap(),
            Some(KeySource::Env("PATH".into()))
        );
        assert_eq!(
            parse_key("${PATH}").unwrap(),
            Some(KeySource::Env("PATH".into()))
        );
        assert!(
            parse_key("$DECLASS_SETUP_TEST_UNSET_VARIABLE")
                .unwrap_err()
                .contains("not set")
        );
        assert!(parse_key("$1BAD").is_err());
        assert_eq!(
            parse_key(" k3y-for-test \n").unwrap(),
            Some(KeySource::Pasted(Secret::new("k3y-for-test")))
        );
        assert!(parse_key("two words").is_err());
    }

    #[test]
    fn a_server_that_needs_a_key_asks_for_it_again() {
        let (mut w, fake) = wizard();
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        typed(&mut w, "http://127.0.0.1:9000/needs-key/v1");
        press(&mut w, KeyCode::Enter);
        // No key: the server answers 401 and the key is asked for.
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("needs an API key"), "{}", screen(&w));
        typed(&mut w, "local-key-1");
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        let local = fake.saved.lock().unwrap().clone().unwrap().local.unwrap();
        assert_eq!(
            local.key,
            Some(KeySource::Pasted(Secret::new("local-key-1")))
        );
        assert_eq!(local.base_url, "http://127.0.0.1:9000/needs-key/v1");
    }

    #[test]
    fn a_local_model_the_server_does_not_list_can_be_typed() {
        let (mut w, fake) = wizard();
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        typed(&mut w, "http://127.0.0.1:9000/v1");
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("Type a model name"), "{}", screen(&w));
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        typed(&mut w, "Org/Some-27B-q4");
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        let local = fake.saved.lock().unwrap().clone().unwrap().local.unwrap();
        assert_eq!(local.model, "Org/Some-27B-q4");
    }

    #[test]
    fn quitting_saves_nothing() {
        let (mut w, fake) = wizard();
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Char('q'));
        assert_eq!(w.outcome(), Some(&Outcome::Cancelled));
        assert!(fake.saved.lock().unwrap().is_none());
    }

    #[test]
    fn the_chatgpt_plan_signs_in_on_screen() {
        let (mut w, _) = wizard();
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("chatgpt-big"), "{}", screen(&w));
        assert!(screen(&w).contains("Signed in as owner@example.com"));
    }

    #[test]
    fn a_remote_server_needs_both_consents_and_skipping_both_models_is_refused() {
        let (mut w, fake) = wizard();
        press(&mut w, KeyCode::Enter);
        // Skip the cloud model (the last row).
        for _ in 0..3 {
            press(&mut w, KeyCode::Down);
        }
        press(&mut w, KeyCode::Enter);
        // Skipping the local model too is refused.
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("needs a local one"), "{}", screen(&w));
        // Another address: a LAN host over plain HTTP.
        press(&mut w, KeyCode::Up);
        press(&mut w, KeyCode::Enter);
        typed(&mut w, "http://192.0.2.7:8080/v1");
        press(&mut w, KeyCode::Enter);
        assert!(screen(&w).contains("Allow 192.0.2.7:8080?"));
        press(&mut w, KeyCode::Char('y'));
        assert!(screen(&w).contains("Allow plain HTTP?"));
        press(&mut w, KeyCode::Char('y'));
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        let review = screen(&w);
        assert!(review.contains("every session is local-only"), "{review}");
        assert!(review.contains("192.0.2.7:8080 is allowed"), "{review}");
        assert!(review.contains("plain HTTP"), "{review}");
        press(&mut w, KeyCode::Enter);
        let plan = fake.saved.lock().unwrap().clone().unwrap();
        assert!(plan.cloud.is_none());
        let local = plan.local.unwrap();
        assert_eq!(local.allow_host.as_deref(), Some("192.0.2.7:8080"));
        assert!(local.plaintext);
        assert_eq!(local.model, "remote-27b");
    }

    #[test]
    fn long_lists_scroll_with_the_cursor_on_a_small_terminal() {
        let (mut w, _) = wizard();
        press(&mut w, KeyCode::Enter);
        let small = |w: &Wizard| {
            let mut t = Terminal::new(TestBackend::new(80, 20)).unwrap();
            t.draw(|f| w.draw(f)).unwrap();
            let buf = t.backend().buffer().clone();
            (0..buf.area.height)
                .map(|y| {
                    (0..buf.area.width)
                        .map(|x| buf[(x, y)].symbol().to_owned())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        for _ in 0..3 {
            press(&mut w, KeyCode::Down);
        }
        let s = small(&w);
        assert!(s.contains("No cloud model"), "{s}");
        assert!(s.contains("↑"), "{s}");
    }

    #[test]
    fn refusing_a_remote_host_contacts_nothing() {
        let (mut w, _) = wizard();
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        typed(&mut w, "https://gpu.lan:8443/v1");
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Char('n'));
        assert!(screen(&w).contains("Not allowed"));
        assert!(screen(&w).contains("Which local model"));
    }
}
