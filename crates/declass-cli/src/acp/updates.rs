// SPDX-License-Identifier: GPL-3.0-or-later
//! What the editor shows of a turn: the transcript's entries and the
//! frontier's streamed response become `session/update` notifications, by
//! the rules the workspace follows on the operator's screen
//! (`declass_tui::workspace::cells`): declass's text and a tool call's
//! arguments with placeholders restored; a tool's result as the frontier saw
//! it (placeholders kept); an edit with its diff, except in a file the policy
//! makes sensitive, which is named only; what the boundary withheld, and how
//! the turn ended. Nothing else reaches the editor: not the vault, not a
//! handle's content, not what the local model read.

use super::schema::{
    Content, Location, SessionNotification, SessionUpdate, ToolCall, ToolCallUpdate, ToolContent,
    ToolKind, ToolStatus,
};
use super::wire::Wire;
use declass_agent::TurnEnd;
use declass_agent::oversight::Action;
use declass_agent::questions::QuestionOptions;
use declass_agent::transcript::Entry;
use declass_boundary::live::StreamEvent;
use declass_boundary::model::{Item, ToolCall as Call};
use declass_boundary::policy::Policy;
use declass_boundary::vault::OPEN;
use declass_boundary::view::ViewClass;
use declass_tui::term::feed::Restore;
use declass_tui::term::safe;
use declass_tui::term::stream::{Detok, FieldReader};
use declass_tui::term::words::{describe_end, progress};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// Lines and bytes of a tool's result shown (the workspace keeps 400 lines).
const KEEP_LINES: usize = 400;
const KEEP_BYTES: usize = 64 * 1024;
/// The largest text sent as one side of a diff.
const KEEP_DIFF: usize = 256 * 1024;
/// Tool calls kept for later updates, and lines of a sub-agent's steps.
const KEEP_CALLS: usize = 512;
const KEEP_STEPS: usize = 200;
/// Withholding descriptions kept to tell new ones from repeated ones.
const KEEP_NOTES: usize = 500;

/// Sends one piece of the agent's message to the editor.
pub(crate) fn say(wire: &Wire, session: &str, text: &str) {
    let text = safe(text);
    if text.is_empty() {
        return;
    }
    wire.notify(
        "session/update",
        SessionNotification {
            session_id: session,
            update: SessionUpdate::AgentMessageChunk {
                content: Content::Text { text },
            },
        },
    );
}

/// One card in the editor: a tool call, or one of declass's own (what the
/// boundary withheld, a context note, a sub-agent, an approval).
struct Card {
    id: String,
    /// The tool's name (declass's own cards: what they are).
    name: String,
    /// A tool call the frontier made (it runs in order with the others).
    tool: bool,
    title: String,
    tags: Vec<String>,
    status: ToolStatus,
    /// An edit's diff.
    diffs: Vec<ToolContent>,
    /// Text lines shown before the result (a command in full, questions,
    /// a sub-agent's steps, the boundary's descriptions).
    lines: Vec<String>,
    /// The approval question, and the answer once given.
    approval: Option<(String, Option<bool>)>,
    result: Option<String>,
}

impl Card {
    fn new(id: String, name: &str, tool: bool, title: String, status: ToolStatus) -> Self {
        Card {
            id,
            name: name.to_owned(),
            tool,
            title,
            tags: Vec::new(),
            status,
            diffs: Vec::new(),
            lines: Vec::new(),
            approval: None,
            result: None,
        }
    }

    fn title(&self) -> String {
        if self.tags.is_empty() {
            self.title.clone()
        } else {
            format!("{} · {}", self.title, self.tags.join(" · "))
        }
    }

    fn content(&self) -> Vec<ToolContent> {
        let mut out = self.diffs.clone();
        let mut text = Vec::new();
        if !self.lines.is_empty() {
            text.push(self.lines.join("\n"));
        }
        if let Some((question, answer)) = &self.approval {
            text.push(fenced(question));
            match answer {
                Some(true) => text.push("Approved.".into()),
                Some(false) => text.push("Not approved: it was not run.".into()),
                None => {}
            }
        }
        if let Some(result) = &self.result {
            text.push(fenced(result));
        }
        if !text.is_empty() {
            out.push(ToolContent::Content {
                content: Content::Text {
                    text: text.join("\n\n"),
                },
            });
        }
        out
    }

    fn unfinished(&self) -> bool {
        matches!(self.status, ToolStatus::Pending | ToolStatus::InProgress)
    }

    /// The card as it now is (what it shows only grows, so an empty list is
    /// left out rather than sent).
    fn update(&self) -> ToolCallUpdate {
        let content = self.content();
        ToolCallUpdate {
            tool_call_id: self.id.clone(),
            title: Some(self.title()),
            status: Some(self.status),
            content: (!content.is_empty()).then_some(content),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Text,
    Call(usize),
}

/// The frontier's text being shown as it streams.
struct Block {
    source: Source,
    detok: Detok,
    /// What was shown so far, restored.
    text: String,
}

#[derive(Default)]
struct Stream {
    /// The current response's tool calls; `reply` and `ask_operator` are read
    /// out of their arguments as they arrive.
    calls: HashMap<usize, Option<FieldReader>>,
    block: Option<Block>,
    /// The last block of the turn, restored, to compare with how it ended.
    last: Option<String>,
    /// The current response's text was shown as it streamed.
    response_text: bool,
    /// The current attempt showed something.
    shown: bool,
    /// The agent's message has text since the last card: the next piece is a
    /// new paragraph.
    paragraph: bool,
}

/// One session's translation, shared by the transcript's follower, the
/// stream tap and the approver.
pub(crate) struct Updates {
    wire: Arc<Wire>,
    session: String,
    ws: PathBuf,
    restore: Restore,
    policy: Policy,
    cards: VecDeque<Card>,
    stream: Stream,
    notes: VecDeque<String>,
    own: u64,
}

impl Updates {
    pub(crate) fn new(
        wire: Arc<Wire>,
        session: String,
        ws: PathBuf,
        restore: Restore,
        policy: Policy,
    ) -> Self {
        Self {
            wire,
            session,
            ws,
            restore,
            policy,
            cards: VecDeque::new(),
            stream: Stream::default(),
            notes: VecDeque::new(),
            own: 0,
        }
    }

    fn send(&self, update: SessionUpdate) {
        self.wire.notify(
            "session/update",
            SessionNotification {
                session_id: &self.session,
                update,
            },
        );
    }

    fn say(&self, text: &str) {
        say(&self.wire, &self.session, text);
    }

    /// Whole text of declass's own (or the frontier's, not streamed), as a
    /// paragraph of the agent's message.
    pub(crate) fn paragraph(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        if std::mem::take(&mut self.stream.paragraph) {
            self.say("\n\n");
        }
        self.say(text);
        self.stream.paragraph = true;
    }

    /// A turn starts (the editor shows it as a message of its own).
    pub(crate) fn begin(&mut self) {
        self.stream = Stream::default();
    }

    /// An event of the response streaming in.
    pub(crate) fn stream(&mut self, event: StreamEvent<'_>) {
        match event {
            StreamEvent::Attempt(n) => {
                self.close_block();
                if n > 1 && self.stream.shown {
                    self.paragraph("*(the response was cut off; it starts again)*");
                }
                self.stream.calls.clear();
                self.stream.response_text = false;
                self.stream.shown = false;
            }
            StreamEvent::Text(t) => self.show(Source::Text, t),
            StreamEvent::Reasoning(_) => {}
            StreamEvent::Call { index, name } => {
                let field = match name {
                    "reply" => Some("message"),
                    "ask_operator" => Some("question"),
                    _ => None,
                };
                self.stream.calls.insert(index, field.map(FieldReader::new));
            }
            StreamEvent::Arguments { index, delta } => {
                let text = self
                    .stream
                    .calls
                    .get_mut(&index)
                    .and_then(Option::as_mut)
                    .map(|r| r.push(delta));
                if let Some(text) = text {
                    self.show(Source::Call(index), &text);
                }
            }
            StreamEvent::End => self.close_block(),
        }
    }

    fn show(&mut self, source: Source, text: &str) {
        if self
            .stream
            .block
            .as_ref()
            .is_some_and(|b| b.source != source)
        {
            self.close_block();
        }
        if self.stream.block.is_none() {
            if text.trim().is_empty() {
                return;
            }
            if std::mem::take(&mut self.stream.paragraph) {
                self.say("\n\n");
            }
            self.stream.block = Some(Block {
                source,
                detok: Detok::default(),
                text: String::new(),
            });
        }
        let restore = self.restore.clone();
        let Some(block) = self.stream.block.as_mut() else {
            return;
        };
        // A placeholder is held back until it is complete, then restored.
        let shown = block.detok.push(text, restore.as_ref());
        block.text.push_str(&shown);
        if source == Source::Text {
            self.stream.response_text = true;
        }
        self.stream.shown = true;
        self.say(&shown);
    }

    fn close_block(&mut self) {
        let Some(mut block) = self.stream.block.take() else {
            return;
        };
        let rest = block.detok.finish(self.restore.as_ref());
        block.text.push_str(&rest);
        self.say(&rest);
        self.stream.last = Some(block.text);
        self.stream.paragraph = true;
    }

    /// A transcript entry.
    pub(crate) fn entry(&mut self, entry: &Entry) {
        match entry {
            Entry::Item {
                item: Item::Assistant {
                    text, tool_calls, ..
                },
            } => {
                let streamed = std::mem::take(&mut self.stream.response_text);
                let narrates = tool_calls.iter().any(|c| !to_operator(&c.name));
                if !streamed && narrates && !text.trim().is_empty() {
                    let restored = (self.restore)(text);
                    self.paragraph(&restored);
                }
                for c in tool_calls.iter().filter(|c| !to_operator(&c.name)) {
                    self.open(c);
                }
                self.advance();
            }
            Entry::Item {
                item: Item::ToolResult { call_id, content },
            } => {
                self.result(call_id, content);
                self.advance();
            }
            Entry::Shown { call_id, class } => {
                if let Some(tag) = shown(*class) {
                    self.change(call_id, |c| c.tags.push(tag.to_owned()));
                }
            }
            Entry::Usage {
                turn,
                interventions,
                ..
            } if !interventions.is_empty() => self.withheld(*turn, interventions),
            Entry::Masked { items, .. } => {
                self.note(&format!("context: {items} old tool result(s) shortened"))
            }
            Entry::Compacted {
                head,
                upto,
                tokens_before,
                tokens_after,
                ..
            } => self.note(&format!(
                "context: {} earlier item(s) condensed by the local model (~{tokens_before} → ~{tokens_after} tokens)",
                upto.saturating_sub(*head)
            )),
            Entry::Interrupted { call_id, tool } => {
                if self.find(call_id).is_some() {
                    self.change(call_id, |c| {
                        c.status = ToolStatus::Failed;
                        c.tags.push("stopped".into());
                    });
                } else {
                    self.note(&format!("{tool} stopped"));
                }
            }
            Entry::SubagentStart {
                child, mode, task, ..
            } => {
                let task = first_line(&(self.restore)(task), 80);
                let card = Card::new(
                    format!("declass-subagent-{child}"),
                    "delegate",
                    false,
                    format!("sub-agent {child} ({mode}): {task}"),
                    ToolStatus::InProgress,
                );
                self.announce(card, ToolKind::Think, Vec::new());
            }
            Entry::Subagent { child, entry } => {
                // A sub-agent's own steps, as the workspace lists them.
                let lines = progress(entry, &mut HashMap::new(), self.restore.as_ref());
                if !lines.is_empty() {
                    self.change(&format!("declass-subagent-{child}"), |c| {
                        c.lines.extend(lines.iter().map(|l| safe(l.trim_start())));
                        let over = c.lines.len().saturating_sub(KEEP_STEPS);
                        c.lines.drain(..over);
                    });
                }
            }
            Entry::SubagentEnd {
                child,
                terminal,
                requests,
                written,
                ..
            } => {
                let state = terminal.state();
                self.change(&format!("declass-subagent-{child}"), |c| {
                    c.status = if state == "completed" {
                        ToolStatus::Completed
                    } else {
                        ToolStatus::Failed
                    };
                    c.tags.push(format!(
                        "{state} · {requests} request(s) · {} file(s) written",
                        written.len()
                    ));
                });
            }
            _ => {}
        }
    }

    /// The card a tool call opens (its result follows).
    fn open(&mut self, c: &Call) {
        if matches!(c.name.as_str(), "write_file" | "edit_file") {
            let (card, locations) = self.edit(c);
            self.announce(card, ToolKind::Edit, locations);
            return;
        }
        let arg = |k: &str| {
            c.arguments
                .get(k)
                .and_then(Value::as_str)
                .map(|a| first_line(&(self.restore)(a), 100))
                .unwrap_or_default()
        };
        let (what, detail) = match c.name.as_str() {
            "read_file" => ("read", arg("path")),
            "read_raw" => ("read", arg("handle")),
            "list_files" => ("list", {
                let d = arg("dir");
                if d.is_empty() { ".".into() } else { d }
            }),
            "search" => ("search", arg("pattern")),
            "code_nav" => ("navigate", {
                let s = arg("symbol");
                if s.is_empty() { arg("path") } else { s }
            }),
            "run_command" => {
                let sensitive = c
                    .arguments
                    .get("sensitive_data")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                (
                    if sensitive {
                        "run on sensitive data"
                    } else {
                        "run"
                    },
                    arg("command"),
                )
            }
            "ask_local" => ("ask local", arg("handle")),
            "explore" => ("explore", arg("question")),
            "web_fetch" => ("fetch", arg("url")),
            "web_search" => ("search the web", arg("query")),
            "synthetic_sample" => ("sample", arg("handle")),
            "diff" => ("diff", arg("path")),
            "finish" => ("finish", "running the checks".to_owned()),
            "delegate" => ("delegate", arg("task")),
            "edit_protected" => ("edit protected", arg("path")),
            n if n.starts_with("git_") => ("git", n.trim_start_matches("git_").to_owned()),
            other => (
                other,
                c.arguments
                    .values()
                    .find_map(Value::as_str)
                    .map(|a| first_line(&(self.restore)(a), 100))
                    .unwrap_or_default(),
            ),
        };
        let title = format!("{what} {detail}").trim_end().to_owned();
        let mut card = Card::new(
            c.id.clone(),
            &c.name,
            true,
            safe(&title),
            ToolStatus::Pending,
        );
        // The title is a locator; a long or multi-line command is shown whole,
        // as the frontier wrote it (as the workspace shows it).
        if c.name == "run_command"
            && let Some(command) = c.arguments.get("command").and_then(Value::as_str)
            && (command.lines().count() > 1 || command.chars().count() > 100)
        {
            card.lines.push(fenced(&bounded(command)));
        }
        // Questions to the local model, as the frontier wrote them.
        if let Some(questions) = c.arguments.get("questions").and_then(Value::as_array) {
            for (i, q) in questions.iter().filter_map(Value::as_str).enumerate() {
                card.lines.push(format!("Q{}: {}", i + 1, bounded(q)));
            }
        } else if c.name == "ask_local"
            && let Some(q) = c.arguments.get("question").and_then(Value::as_str)
        {
            card.lines.push(format!("Question: {}", bounded(q)));
        }
        let mut locations = Vec::new();
        if matches!(
            c.name.as_str(),
            "read_file" | "diff" | "code_nav" | "edit_protected"
        ) && let Some(path) = c
            .arguments
            .get("path")
            .and_then(Value::as_str)
            .and_then(|p| self.located(p))
        {
            let line = c.arguments.get("start_line").and_then(Value::as_u64);
            locations.push(Location { path, line });
        }
        self.announce(card, kind(&c.name), locations);
    }

    /// A write or an edit: its diff with placeholders restored, or for a
    /// file the policy makes sensitive only its name.
    fn edit(&self, c: &Call) -> (Card, Vec<Location>) {
        let raw = c
            .arguments
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let path = safe(raw);
        let write = c.name == "write_file";
        let mut card = Card::new(
            c.id.clone(),
            &c.name,
            true,
            format!("{} {path}", if write { "write" } else { "edit" })
                .trim_end()
                .to_owned(),
            ToolStatus::Pending,
        );
        let located = self.located(raw);
        let locations = located
            .iter()
            .map(|p| Location {
                path: p.clone(),
                line: None,
            })
            .collect();
        if self.policy.is_sensitive_path(Path::new(&path)) {
            card.tags.push("sensitive: content not shown".into());
            return (card, locations);
        }
        let restore = |t: &str| safe(&(self.restore)(t));
        let (mut added, mut removed) = (0, 0);
        let mut pairs: Vec<(Option<String>, String)> = Vec::new();
        if write {
            let content = restore(
                c.arguments
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            added += content.lines().count();
            pairs.push((None, content));
        } else if let Some(edits) = c.arguments.get("edits").and_then(Value::as_array) {
            for e in edits {
                let text = |k: &str| e.get(k).and_then(Value::as_str).map(&restore);
                let (old, new) = (
                    text("old").unwrap_or_default(),
                    text("new").unwrap_or_default(),
                );
                removed += old.lines().count();
                added += new.lines().count();
                pairs.push((Some(old), new));
            }
        }
        if let Some(path) = located {
            for (old, new) in pairs {
                if old.as_ref().map_or(0, String::len) + new.len() <= KEEP_DIFF {
                    card.diffs.push(ToolContent::Diff {
                        path: path.clone(),
                        old_text: old,
                        new_text: new,
                    });
                }
            }
        }
        card.tags.push(format!("+{added} −{removed}"));
        (card, locations)
    }

    /// The absolute path of a plain workspace-relative path an argument
    /// names (none for anything else, or one holding a placeholder).
    fn located(&self, raw: &str) -> Option<String> {
        if raw.is_empty() || raw.contains(OPEN) {
            return None;
        }
        let p = Path::new(raw);
        let rel = if p.is_absolute() {
            p.strip_prefix(&self.ws).ok()?
        } else {
            p
        };
        if rel
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return None;
        }
        Some(self.ws.join(rel).to_string_lossy().into_owned())
    }

    fn announce(&mut self, card: Card, kind: ToolKind, locations: Vec<Location>) {
        self.close_block();
        self.send(SessionUpdate::ToolCall(ToolCall {
            tool_call_id: card.id.clone(),
            title: card.title(),
            name: card.name.clone(),
            kind,
            status: card.status,
            content: card.content(),
            locations,
        }));
        self.cards.push_back(card);
        if self.cards.len() > KEEP_CALLS {
            self.cards.pop_front();
        }
        // The agent's next text follows the card.
        self.stream.paragraph = false;
    }

    fn find(&self, id: &str) -> Option<usize> {
        self.cards.iter().rposition(|c| c.id == id)
    }

    /// Changes a card and shows it as it now is.
    fn change(&mut self, id: &str, change: impl FnOnce(&mut Card)) {
        let Some(i) = self.find(id) else {
            return;
        };
        let card = &mut self.cards[i];
        change(card);
        let update = card.update();
        self.send(SessionUpdate::ToolCallUpdate(update));
    }

    /// A tool's result: done or failed, and what the frontier received.
    fn result(&mut self, call_id: &str, content: &str) {
        let content = safe(content);
        let failed = content.starts_with("error:")
            || content.starts_with("checks failed")
            || content.starts_with("timed out")
            || content
                .lines()
                .next()
                .and_then(|l| l.strip_prefix("exit code "))
                .is_some_and(|code| code.trim() != "0");
        let redactions = content.matches("⟨redacted:").count();
        self.change(call_id, |c| {
            c.status = if failed {
                ToolStatus::Failed
            } else {
                ToolStatus::Completed
            };
            if redactions > 0 {
                c.tags.push(format!("{redactions} redaction(s) in result"));
            }
            c.result = Some(bounded(&content));
        });
    }

    /// Calls run one after another: the first not yet run is the one running.
    fn advance(&mut self) {
        if self
            .cards
            .iter()
            .any(|c| c.tool && c.status == ToolStatus::InProgress)
        {
            return;
        }
        if let Some(id) = self
            .cards
            .iter()
            .find(|c| c.tool && c.status == ToolStatus::Pending)
            .map(|c| c.id.clone())
        {
            self.change(&id, |c| c.status = ToolStatus::InProgress);
        }
    }

    /// What the boundary withheld from a request: the descriptions not shown
    /// before (each request checks the whole history again).
    fn withheld(&mut self, turn: u64, notes: &[String]) {
        let (mut new, mut repeated) = (Vec::new(), 0);
        for note in notes {
            let note = bounded(note);
            // Counts from older releases have no source identity: never "repeated".
            if note.contains("model's own message") || !self.notes.contains(&note) {
                if !note.contains("model's own message") {
                    self.notes.push_back(note.clone());
                    if self.notes.len() > KEEP_NOTES {
                        self.notes.pop_front();
                    }
                }
                new.push(note);
            } else {
                repeated += 1;
            }
        }
        if new.is_empty() {
            return;
        }
        self.own += 1;
        let mut card = Card::new(
            format!("declass-privacy-{}", self.own),
            "privacy",
            false,
            format!(
                "privacy filtering · request {turn} · {} new detail(s), {repeated} repeated",
                new.len()
            ),
            ToolStatus::Completed,
        );
        card.lines = new.iter().map(|n| format!("- {n}")).collect();
        self.announce(card, ToolKind::Other, Vec::new());
    }

    /// A note of declass's own, as a card.
    fn note(&mut self, text: &str) {
        self.own += 1;
        let card = Card::new(
            format!("declass-note-{}", self.own),
            "note",
            false,
            safe(text),
            ToolStatus::Completed,
        );
        self.announce(card, ToolKind::Other, Vec::new());
    }

    /// An approval question for `action`, on the card of the call it is about
    /// (the first of that tool not yet run), or on a card of its own (a
    /// sub-agent's action). Returns the tool call the editor asks about.
    pub(crate) fn permission(&mut self, action: &Action, question: &str) -> ToolCallUpdate {
        let id = match self
            .cards
            .iter()
            .find(|c| c.tool && c.unfinished() && c.name == action.tool)
        {
            Some(c) => c.id.clone(),
            None => {
                self.own += 1;
                let card = Card::new(
                    format!("declass-approval-{}", self.own),
                    &action.tool,
                    false,
                    safe(&format!(
                        "approval: {} {}",
                        action.tool,
                        action.risk.describe()
                    )),
                    ToolStatus::Pending,
                );
                let id = card.id.clone();
                self.announce(card, kind(&action.tool), Vec::new());
                id
            }
        };
        let i = self.find(&id).expect("the card was just found or made");
        let card = &mut self.cards[i];
        card.approval = Some((safe(question.trim_matches('\n')), None));
        // It waits for approval: it has not started.
        card.status = ToolStatus::Pending;
        card.update()
    }

    /// The operator's answer to the question on card `id`.
    pub(crate) fn decided(&mut self, id: &str, approved: bool) {
        self.change(id, |c| {
            if let Some((_, answer)) = &mut c.approval {
                *answer = Some(approved);
            }
            c.status = match (c.tool, approved) {
                // A denied call stays pending until its result (a refusal) arrives.
                (true, true) => ToolStatus::InProgress,
                (true, false) => ToolStatus::Pending,
                (false, true) => ToolStatus::Completed,
                (false, false) => ToolStatus::Failed,
            };
        });
    }

    /// The turn ended: what is still open is stopped, and how it ended is
    /// said (a reply or question already shown as it streamed is not
    /// repeated; a failure is the prompt's error, a cancellation the
    /// editor's own).
    pub(crate) fn end(&mut self, end: &TurnEnd, cancelled: bool) {
        self.close_block();
        let streamed = self.stream.last.take();
        let open: Vec<String> = self
            .cards
            .iter()
            .filter(|c| c.unfinished())
            .map(|c| c.id.clone())
            .collect();
        for id in open {
            self.change(&id, |c| {
                c.status = ToolStatus::Failed;
                c.tags.push("stopped".into());
            });
        }
        match end {
            TurnEnd::Replied { message } => {
                if !streamed.is_some_and(|s| same(&s, message)) {
                    self.paragraph(message);
                }
            }
            TurnEnd::Asked { question, options } => {
                match streamed.as_deref().and_then(|s| after(question, s)) {
                    Some(rest) => self.paragraph(rest),
                    None => self.paragraph(question),
                }
                if let Some(options) = options.as_ref().filter(|o| !o.choices.is_empty()) {
                    self.paragraph(&choices(options));
                }
            }
            TurnEnd::Completed { summary } => {
                self.paragraph(&format!("**Finished.** {}", summary.trim()));
            }
            TurnEnd::Failed { .. } => {}
            _ if cancelled => {}
            other => self.paragraph(&describe_end(other)),
        }
    }
}

/// `reply` and `ask_operator` are the turn's end, not cards.
fn to_operator(name: &str) -> bool {
    name == "reply" || name == "ask_operator"
}

/// How the editor draws a tool.
fn kind(name: &str) -> ToolKind {
    match name {
        "read_file" | "read_raw" | "list_files" | "synthetic_sample" | "diff" | "list_skills"
        | "load_skill" => ToolKind::Read,
        "search" | "code_nav" | "explore" => ToolKind::Search,
        "run_command" | "finish" | "git_commit" => ToolKind::Execute,
        "write_file" | "edit_file" | "edit_protected" | "rename" => ToolKind::Edit,
        "web_fetch" | "web_search" => ToolKind::Fetch,
        "ask_local" | "delegate" => ToolKind::Think,
        n if n.starts_with("git_") => ToolKind::Read,
        _ => ToolKind::Other,
    }
}

/// What the boundary did with a result, as the workspace tags it.
fn shown(class: ViewClass) -> Option<&'static str> {
    Some(match class {
        ViewClass::Raw => return None,
        ViewClass::Tokenized => "values replaced by placeholders",
        ViewClass::HandleSummary => "sensitive: raw content held; filtered view prepared",
        ViewClass::LocalAnswer => "local answer prepared",
        ViewClass::BulkyHandle => "large: outline prepared; raw ranges available",
        ViewClass::Protected => "protected: restricted view prepared",
    })
}

/// A question's numbered choices and how to answer.
fn choices(options: &QuestionOptions) -> String {
    let mut out = String::new();
    for (i, choice) in options.choices.iter().enumerate() {
        let recommended = if options.recommended.as_ref() == Some(&choice.id) {
            " (recommended)"
        } else {
            ""
        };
        out.push_str(&format!("{}. {}{recommended}", i + 1, choice.label.trim()));
        if let Some(description) = &choice.description {
            out.push_str(&format!(": {}", description.trim()));
        }
        out.push('\n');
    }
    out.push('\n');
    out.push_str(if options.allow_freeform {
        "Reply with an option's number, or with your own answer."
    } else {
        "Reply with an option's number."
    });
    out
}

/// The first non-empty line, at most `max` characters.
fn first_line(text: &str, max: usize) -> String {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let mut out: String = line.chars().take(max).collect();
    if line.chars().count() > max {
        out.push('…');
    }
    safe(&out)
}

/// `text` safe for display, cut to [`KEEP_LINES`] lines and [`KEEP_BYTES`].
fn bounded(text: &str) -> String {
    let mut out = String::new();
    let safe = safe(text);
    for (shown, line) in safe.lines().enumerate() {
        if shown == KEEP_LINES || out.len() + line.len() > KEEP_BYTES {
            let total = safe.lines().count();
            out.push_str(&format!(
                "… {} more line(s)",
                total.saturating_sub(shown).max(1)
            ));
            return out;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.truncate(out.trim_end_matches('\n').len());
    out
}

/// `text` in a Markdown code block whose fence no line of it can close.
fn fenced(text: &str) -> String {
    let longest = text
        .split(|c: char| c != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest.max(2) + 1);
    format!("{fence}\n{text}\n{fence}")
}

/// Whether two texts say the same (however their whitespace is laid out).
fn same(a: &str, b: &str) -> bool {
    a.split_whitespace().eq(b.split_whitespace())
}

/// What `full` says after `start`, if it starts with it.
fn after<'a>(full: &'a str, start: &str) -> Option<&'a str> {
    full.trim_start().strip_prefix(start.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use declass_agent::Terminal;
    use serde_json::json;
    use std::io::Write;
    use std::sync::Mutex;

    const VALUE: &str = "ana@example.org";
    const TOKEN: &str = "⟨email:EMAIL#1⟩";

    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn updates() -> (Updates, Arc<Mutex<Vec<u8>>>) {
        let out = Arc::new(Mutex::new(Vec::new()));
        let wire = Arc::new(Wire::new(Sink(out.clone())));
        let restore: Restore = Arc::new(|t: &str| t.replace(TOKEN, VALUE));
        let policy = Policy {
            sensitive_globs: vec![".env*".into()],
            ..Policy::default()
        };
        let u = Updates::new(wire, "s1".into(), PathBuf::from("/w"), restore, policy);
        (u, out)
    }

    /// The `update`s sent so far.
    fn sent(out: &Arc<Mutex<Vec<u8>>>) -> Vec<Value> {
        String::from_utf8(out.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                assert_eq!(v["method"], "session/update");
                assert_eq!(v["params"]["sessionId"], "s1");
                v["params"]["update"].clone()
            })
            .collect()
    }

    /// The agent's message: every chunk, joined.
    fn message(out: &Arc<Mutex<Vec<u8>>>) -> String {
        sent(out)
            .iter()
            .filter(|u| u["sessionUpdate"] == "agent_message_chunk")
            .map(|u| u["content"]["text"].as_str().unwrap().to_owned())
            .collect()
    }

    fn call(id: &str, name: &str, args: Value) -> Call {
        let Value::Object(arguments) = args else {
            unreachable!()
        };
        Call {
            id: id.into(),
            name: name.into(),
            raw_arguments: String::new(),
            arguments,
        }
    }

    fn assistant(text: &str, calls: Vec<Call>) -> Entry {
        Entry::Item {
            item: Item::Assistant {
                text: text.into(),
                reasoning: None,
                tool_calls: calls,
                replay: None,
            },
        }
    }

    fn result(id: &str, content: &str) -> Entry {
        Entry::Item {
            item: Item::ToolResult {
                call_id: id.into(),
                content: content.into(),
            },
        }
    }

    #[test]
    fn streamed_text_is_restored_once_complete_and_not_repeated_at_the_end() {
        let (mut u, out) = updates();
        u.begin();
        u.stream(StreamEvent::Attempt(1));
        u.stream(StreamEvent::Call {
            index: 0,
            name: "reply",
        });
        for piece in ["{\"message\": \"Mail ⟨email:EM", "AIL#1⟩ about it.\"}"] {
            u.stream(StreamEvent::Arguments {
                index: 0,
                delta: piece,
            });
        }
        u.stream(StreamEvent::End);
        u.end(
            &TurnEnd::Replied {
                message: format!("Mail {VALUE} about it."),
            },
            false,
        );
        // The next turn is a message of its own: no break carried over.
        u.begin();
        u.stream(StreamEvent::Attempt(1));
        u.stream(StreamEvent::Text("Next."));
        u.stream(StreamEvent::End);
        let chunks: Vec<String> = sent(&out)
            .iter()
            .map(|u| u["content"]["text"].as_str().unwrap().to_owned())
            .collect();
        // The placeholder was held back until it closed, then restored.
        assert_eq!(chunks, ["Mail ", "ana@example.org about it.", "Next."]);
    }

    #[test]
    fn tool_calls_run_in_order_with_restored_arguments_and_results_as_sent() {
        let (mut u, out) = updates();
        u.begin();
        u.entry(&assistant(
            "Looking.",
            vec![
                call(
                    "c1",
                    "read_file",
                    json!({"path": "notes.txt", "start_line": 3}),
                ),
                call(
                    "c2",
                    "run_command",
                    json!({"command": format!("grep {TOKEN} log.txt")}),
                ),
            ],
        ));
        u.entry(&result("c1", &format!("1 line mentioning {TOKEN}")));
        u.entry(&Entry::Shown {
            call_id: "c1".into(),
            class: ViewClass::Tokenized,
        });
        u.entry(&result("c2", "exit code 1\nnothing"));
        let updates = sent(&out);
        assert_eq!(updates[0]["sessionUpdate"], "agent_message_chunk");
        assert_eq!(updates[0]["content"]["text"], "Looking.");
        let first = &updates[1];
        assert_eq!(first["sessionUpdate"], "tool_call");
        assert_eq!(first["title"], "read notes.txt");
        assert_eq!(first["kind"], "read");
        assert_eq!(first["status"], "pending");
        assert_eq!(
            first["locations"],
            json!([{"path": "/w/notes.txt", "line": 3}])
        );
        assert_eq!(updates[2]["title"], format!("run grep {VALUE} log.txt"));
        assert_eq!(updates[2]["kind"], "execute");
        // c1 runs first, then c2 once c1 has its result.
        assert_eq!(
            (&updates[3]["toolCallId"], &updates[3]["status"]),
            (&json!("c1"), &json!("in_progress"))
        );
        let done = &updates[4];
        assert_eq!(done["status"], "completed");
        // The result as the frontier saw it: the placeholder kept.
        let text = done["content"][0]["content"]["text"].as_str().unwrap();
        assert!(text.contains(TOKEN) && !text.contains(VALUE), "{text}");
        assert_eq!(updates[5]["toolCallId"], "c2");
        assert_eq!(updates[5]["status"], "in_progress");
        assert_eq!(
            updates[6]["title"],
            "read notes.txt · values replaced by placeholders"
        );
        assert_eq!(updates[7]["toolCallId"], "c2");
        assert_eq!(updates[7]["status"], "failed");
    }

    #[test]
    fn a_long_command_is_shown_whole_as_the_frontier_wrote_it() {
        let (mut u, out) = updates();
        let command = format!("echo {TOKEN} && \\\n  cargo test --workspace");
        u.entry(&assistant(
            "",
            vec![call("c1", "run_command", json!({"command": command}))],
        ));
        let card = &sent(&out)[0];
        // The title's first line restored, as the workspace's title is.
        assert_eq!(card["title"], format!("run echo {VALUE} && \\"));
        // The whole command as written: the placeholder kept.
        let body = card["content"][0]["content"]["text"].as_str().unwrap();
        assert!(body.contains(TOKEN) && !body.contains(VALUE), "{body}");
    }

    #[test]
    fn an_edit_shows_its_diff_unless_the_file_is_sensitive() {
        let (mut u, out) = updates();
        u.entry(&assistant(
            "",
            vec![
                call(
                    "c1",
                    "edit_file",
                    json!({"path": "src/a.rs", "edits": [{"old": "x", "new": format!("// {TOKEN}\ny")}]}),
                ),
                call(
                    "c2",
                    "write_file",
                    json!({"path": ".env", "content": "KEY=secret-value"}),
                ),
                call("c3", "write_file", json!({"path": "../outside.rs", "content": "z"})),
            ],
        ));
        let updates = sent(&out);
        let edit = &updates[0];
        assert_eq!(edit["kind"], "edit");
        assert_eq!(edit["title"], "edit src/a.rs · +2 −1");
        assert_eq!(
            edit["content"],
            json!([{"type": "diff", "path": "/w/src/a.rs", "oldText": "x",
                "newText": format!("// {VALUE}\ny")}])
        );
        let held = &updates[1];
        assert_eq!(held["title"], "write .env · sensitive: content not shown");
        assert!(held.get("content").is_none(), "{held}");
        assert!(
            !updates
                .iter()
                .any(|u| u.to_string().contains("secret-value"))
        );
        // A path outside the workspace is neither located nor diffed.
        let outside = &updates[2];
        assert!(outside.get("locations").is_none() && outside.get("content").is_none());
    }

    #[test]
    fn withheld_details_show_once_and_unfinished_calls_stop_at_the_end() {
        let (mut u, out) = updates();
        let usage = |turn| Entry::Usage {
            turn,
            usage: Default::default(),
            interventions: vec!["1 secret replaced in the read_file result".into()],
        };
        u.entry(&usage(1));
        u.entry(&usage(2));
        u.entry(&assistant("", vec![call("c1", "list_files", json!({}))]));
        u.end(&TurnEnd::Interrupted, true);
        let updates = sent(&out);
        let privacy: Vec<&Value> = updates
            .iter()
            .filter(|u| {
                u["toolCallId"]
                    .as_str()
                    .is_some_and(|i| i.starts_with("declass-privacy"))
            })
            .collect();
        assert_eq!(
            privacy.len(),
            1,
            "a repeated description is not shown again"
        );
        assert_eq!(
            privacy[0]["title"],
            "privacy filtering · request 1 · 1 new detail(s), 0 repeated"
        );
        let last = updates.last().unwrap();
        assert_eq!(
            (&last["toolCallId"], &last["status"]),
            (&json!("c1"), &json!("failed"))
        );
        // A cancelled turn says nothing more: the editor knows.
        assert!(message(&out).is_empty());
    }

    #[test]
    fn a_question_lists_its_choices_and_an_approval_asks_on_its_call() {
        let (mut u, out) = updates();
        u.entry(&assistant(
            "",
            vec![call(
                "c1",
                "write_file",
                json!({"path": "Makefile", "content": "all:\n"}),
            )],
        ));
        let action = Action {
            tool: "write_file".into(),
            risk: declass_agent::oversight::Risk::WriteOutsideSources,
            path: Some("Makefile".into()),
            command: None,
            bytes: Some(5),
        };
        let asked = u.permission(&action, "\ndeclass: approval needed\n  path: Makefile\n");
        assert_eq!(asked.tool_call_id, "c1");
        // Waiting for approval, it has not started.
        assert_eq!(asked.status, Some(ToolStatus::Pending));
        let content = serde_json::to_string(&asked.content).unwrap();
        assert!(
            content.contains("approval needed") && content.contains("diff"),
            "{content}"
        );
        u.decided("c1", false);
        // A sub-agent's action has a card of its own.
        let other = Action {
            tool: "run_command".into(),
            risk: declass_agent::oversight::Risk::SensitiveData,
            path: None,
            command: Some("python3 x.py".into()),
            bytes: None,
        };
        let asked = u.permission(&other, "run it?");
        assert!(asked.tool_call_id.starts_with("declass-approval-"));
        u.decided(&asked.tool_call_id, true);
        let last = sent(&out).last().unwrap().clone();
        assert_eq!(last["status"], "completed");
        let mut options = QuestionOptions {
            id: "q1".into(),
            choices: vec![
                declass_agent::questions::QuestionOption {
                    id: "unit".into(),
                    label: "unit".into(),
                    description: Some("No value".into()),
                },
                declass_agent::questions::QuestionOption {
                    id: "u32".into(),
                    label: "u32".into(),
                    description: None,
                },
            ],
            allow_freeform: false,
            recommended: Some("unit".into()),
        };
        u.end(
            &TurnEnd::Asked {
                question: "Return type?".into(),
                options: Some(options.clone()),
            },
            false,
        );
        assert_eq!(
            message(&out),
            "Return type?\n\n1. unit (recommended): No value\n2. u32\n\nReply with an option's number."
        );
        options.allow_freeform = true;
        assert!(choices(&options).ends_with("or with your own answer."));
    }

    #[test]
    fn sub_agents_and_notes_are_cards_and_text_is_fenced_safely() {
        let (mut u, out) = updates();
        u.entry(&Entry::SubagentStart {
            child: "a1".into(),
            call_id: "c9".into(),
            mode: "read".into(),
            task: format!("Find {TOKEN}"),
            paths: vec![],
            journal_next: 0,
        });
        u.entry(&Entry::Subagent {
            child: "a1".into(),
            entry: Box::new(assistant(
                "",
                vec![call("x", "read_file", json!({"path": "a"}))],
            )),
        });
        u.entry(&Entry::SubagentEnd {
            child: "a1".into(),
            call_id: "c9".into(),
            terminal: Terminal::Completed {
                summary: "done".into(),
            },
            requests: 2,
            seconds: 1.0,
            written: vec![],
            journal_end: 0,
        });
        u.entry(&Entry::Masked {
            items: 3,
            tokens_before: 10,
            tokens_after: 5,
            positions: vec![],
        });
        let updates = sent(&out);
        assert_eq!(
            updates[0]["title"],
            format!("sub-agent a1 (read): Find {VALUE}")
        );
        assert!(updates[1].to_string().contains("· read_file a"));
        assert_eq!(updates[2]["status"], "completed");
        assert_eq!(
            updates[3]["title"],
            "context: 3 old tool result(s) shortened"
        );
        assert_eq!(fenced("a ``` b"), "````\na ``` b\n````");
        assert_eq!(fenced("plain"), "```\nplain\n```");
        let long = "x\n".repeat(KEEP_LINES + 5);
        assert!(bounded(&long).ends_with("… 5 more line(s)"));
    }
}
