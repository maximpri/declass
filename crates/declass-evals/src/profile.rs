// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-turn token profile of a batch (M5.2 instrumentation).
//!
//! Frontier traffic is turns × context: every request re-sends the conversation.
//! A run's profile keeps, for each frontier request, the context it sent
//! (uncached input + cache reads + cache writes) and its output, from the
//! provider's own usage in the leak proxy's capture, so every lane is profiled
//! the same way. What each turn was for comes from Declass's transcript (the
//! tools the turn called), so only Declass lanes have turns by cause.

use crate::lanes::RunRecord;
use crate::stats;
use crate::usage::{RequestUsage, Usage};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// What a frontier turn was for, from the tools it called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    Reading,
    Editing,
    Commands,
    AskLocal,
    Other,
}

impl Cause {
    pub const ALL: [Cause; 5] = [
        Cause::Reading,
        Cause::Editing,
        Cause::Commands,
        Cause::AskLocal,
        Cause::Other,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Cause::Reading => "reading",
            Cause::Editing => "editing",
            Cause::Commands => "commands",
            Cause::AskLocal => "ask_local",
            Cause::Other => "other",
        }
    }

    /// The cause a call of Declass's tool `name` counts toward. Tools that only
    /// look (files, handles, search, git history, the web, code navigation,
    /// the local explorer) are reading; tools that change the repository are editing; `finish`,
    /// `delegate`, questions to the operator and MCP tools are other.
    pub fn of_tool(name: &str) -> Self {
        match name {
            "ask_local" => Cause::AskLocal,
            "run_command" => Cause::Commands,
            "edit_file" | "write_file" | "edit_protected" | "rename" | "git_commit" => {
                Cause::Editing
            }
            "read_file" | "read_raw" | "list_files" | "search" | "diff" | "code_nav"
            | "web_fetch" | "web_search" | "git_log" | "git_status" | "git_show" | "git_blame"
            | "explore" => Cause::Reading,
            _ => Cause::Other,
        }
    }
}

/// Turns per cause (fractional: see [`causes_from_transcript`]).
pub type Causes = BTreeMap<Cause, f64>;

fn no_causes() -> Causes {
    Cause::ALL.iter().map(|c| (*c, 0.0)).collect()
}

/// The tools an assistant message called, if `entry` is one (a sub-agent's
/// entries are nested under its id).
fn assistant_tools(entry: &Value) -> Option<Vec<&str>> {
    match entry.get("kind")?.as_str()? {
        "subagent" => assistant_tools(entry.get("entry")?),
        "item" => {
            let item = entry.get("item")?;
            (item.get("type")?.as_str()? == "assistant").then(|| {
                item.get("tool_calls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c.get("name")?.as_str())
                    .collect()
            })
        }
        _ => None,
    }
}

/// Turns by cause in a Declass transcript, sub-agents' turns included. Each
/// assistant message is one turn; a turn with k tool calls counts 1/k toward
/// each call's cause, and a turn with none counts as other, so the causes sum
/// to the turns.
pub fn causes_from_transcript(text: &str) -> Causes {
    let mut out = no_causes();
    for line in text.lines() {
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(tools) = assistant_tools(&entry) else {
            continue;
        };
        if tools.is_empty() {
            *out.entry(Cause::Other).or_default() += 1.0;
            continue;
        }
        let share = 1.0 / tools.len() as f64;
        for t in tools {
            *out.entry(Cause::of_tool(t)).or_default() += share;
        }
    }
    out
}

/// One frontier request that reported usage.
#[derive(Debug, Clone, Serialize)]
pub struct Turn {
    pub model: String,
    /// What the request sent: see [`context_of`].
    pub context: u64,
    pub usage: Usage,
}

/// The context a request sent: uncached input, cache reads and cache writes.
pub fn context_of(u: &Usage) -> u64 {
    u.uncached_input + u.cache_read + u.cache_write
}

/// One run's profile.
#[derive(Debug, Clone, Serialize)]
pub struct RunProfile {
    pub run_id: String,
    pub task: String,
    pub lane: String,
    pub seed: u64,
    /// Frontier requests, as the proxy counted them.
    pub requests: u64,
    /// Requests that reported usage, in order (empty when the capture is gone).
    pub turns: Vec<Turn>,
    /// Usage per model over the run (the run record's).
    pub usage_by_model: BTreeMap<String, Usage>,
    /// Turns by cause (Declass lanes with a transcript).
    pub causes: Option<Causes>,
}

impl RunProfile {
    fn total(&self) -> Usage {
        let mut t = Usage::default();
        for u in self.usage_by_model.values() {
            t.add(*u);
        }
        t
    }
}

/// A run's profile from its record, its proxy capture and (Declass lanes) its
/// transcript.
pub fn build(
    record: &RunRecord,
    requests: &[RequestUsage],
    transcript: Option<&str>,
) -> RunProfile {
    let turns = requests
        .iter()
        .filter_map(|r| {
            let usage = r.usage?;
            Some(Turn {
                model: r.model.clone(),
                context: context_of(&usage),
                usage,
            })
        })
        .collect();
    RunProfile {
        run_id: record.run_id.clone(),
        task: record.task.clone(),
        lane: record.lane.clone(),
        seed: record.seed,
        requests: record.frontier_requests as u64,
        turns,
        usage_by_model: record.usage_by_model.clone(),
        causes: transcript.map(causes_from_transcript),
    }
}

/// The profile of the run in `run_dir` (its capture and transcript may be
/// missing: the profile then has no turns or no causes).
pub fn load(run_dir: &Path, record: &RunRecord) -> Result<RunProfile> {
    let proxy = run_dir.join("proxy");
    let requests = if proxy.join("requests.jsonl").is_file() {
        crate::usage::requests_from_proxy_log(&proxy)
            .with_context(|| format!("reading {}", proxy.display()))?
    } else {
        Vec::new()
    };
    let transcript = match record.lane_kind {
        crate::lanes::LaneKind::Declass => {
            crate::ledger::newest_run_dir(&run_dir.join("workspace"))
                .and_then(|d| fs::read_to_string(d.join("transcript.jsonl")).ok())
        }
        crate::lanes::LaneKind::External => None,
    };
    Ok(build(record, &requests, transcript.as_deref()))
}

/// Profiles of the valid `records` of the batch in `batch_dir`.
pub fn load_batch(batch_dir: &Path, records: &[RunRecord]) -> Result<Vec<RunProfile>> {
    records
        .iter()
        .filter(|r| r.invalid.is_none())
        .map(|r| load(&batch_dir.join(&r.run_id), r))
        .collect()
}

/// Profile of a lane over its runs (of one task, or all).
#[derive(Debug, Clone, Serialize)]
pub struct ProfileSummary {
    pub lane: String,
    /// `None`: every task.
    pub task: Option<String>,
    pub runs: usize,
    /// Mean frontier requests per run.
    pub turns: f64,
    /// Context per turn over every turn of these runs (pooled).
    pub context_mean: Option<f64>,
    pub context_p90: Option<f64>,
    /// Mean per run of the context summed over its turns.
    pub request_tokens: f64,
    /// Share of all context read from the provider's cache.
    pub cached_share: Option<f64>,
    /// Mean output tokens per run.
    pub output_tokens: f64,
    /// Mean turns per run by cause, over the runs with a transcript.
    pub causes: Option<Causes>,
    pub runs_with_causes: usize,
}

/// Summarizes `profiles` (one lane, and one task or all).
pub fn summarize(lane: &str, task: Option<&str>, profiles: &[&RunProfile]) -> ProfileSummary {
    let n = profiles.len().max(1) as f64;
    let contexts: Vec<f64> = profiles
        .iter()
        .flat_map(|p| p.turns.iter().map(|t| t.context as f64))
        .collect();
    let mut total = Usage::default();
    for p in profiles {
        total.add(p.total());
    }
    let context = context_of(&total);
    let with_causes: Vec<&Causes> = profiles.iter().filter_map(|p| p.causes.as_ref()).collect();
    let causes = (!with_causes.is_empty()).then(|| {
        let mut m = no_causes();
        for c in &with_causes {
            for (k, v) in *c {
                *m.entry(*k).or_default() += v;
            }
        }
        for v in m.values_mut() {
            *v /= with_causes.len() as f64;
        }
        m
    });
    ProfileSummary {
        lane: lane.to_owned(),
        task: task.map(str::to_owned),
        runs: profiles.len(),
        turns: profiles.iter().map(|p| p.requests as f64).sum::<f64>() / n,
        context_mean: (!contexts.is_empty())
            .then(|| contexts.iter().sum::<f64>() / contexts.len() as f64),
        context_p90: stats::percentile(&contexts, 0.9),
        request_tokens: context as f64 / n,
        cached_share: (context > 0).then(|| total.cache_read as f64 / context as f64),
        output_tokens: total.output as f64 / n,
        causes,
        runs_with_causes: with_causes.len(),
    }
}

/// Every lane over all its tasks, then each (lane, task), sorted by name.
pub fn summarize_all(profiles: &[RunProfile]) -> Vec<ProfileSummary> {
    let mut by_lane: BTreeMap<&str, BTreeMap<&str, Vec<&RunProfile>>> = BTreeMap::new();
    for p in profiles {
        by_lane
            .entry(&p.lane)
            .or_default()
            .entry(&p.task)
            .or_default()
            .push(p);
    }
    let mut out = Vec::new();
    for (lane, tasks) in by_lane {
        let all: Vec<&RunProfile> = tasks.values().flatten().copied().collect();
        out.push(summarize(lane, None, &all));
        for (task, ps) in tasks {
            out.push(summarize(lane, Some(task), &ps));
        }
    }
    out
}

/// Tokens in thousands, or millions from a million on.
fn kilo(x: f64) -> String {
    if x >= 1e6 {
        format!("{:.2}M", x / 1e6)
    } else {
        format!("{:.1}K", x / 1000.0)
    }
}

fn percent(x: Option<f64>) -> String {
    x.map_or("—".into(), |v| format!("{:.0}%", 100.0 * v))
}

/// The token profile section of a batch report.
pub fn render_profile(summaries: &[ProfileSummary]) -> String {
    let mut s = String::from(
        "\n## Token profile\n\nPer run means. Turns are frontier requests; the context of a turn is \
         what it sent (uncached input + cache reads + cache writes, from the provider's usage in the \
         proxy capture), its mean and 90th percentile over every turn of the runs. Request tokens \
         are the context summed over a run's turns. Turns by cause come from Declass's transcript \
         (sub-agents included): a turn with k tool calls counts 1/k toward each call's cause \
         (reading: read_file, read_raw, list_files, search, diff, git history, web, code_nav; \
         editing: edit_file, write_file, edit_protected, rename, git_commit; commands: run_command; \
         other: finish, delegate, MCP tools, no tool call).\n\n",
    );
    s.push_str(
        "| Lane | Task | Runs | Turns | Context/turn | p90 | Request tokens | Cached | Output |",
    );
    for c in Cause::ALL {
        let _ = write!(s, " {} |", c.label());
    }
    s.push_str("\n|---|---|---|---|---|---|---|---|---|");
    s.push_str(&"---|".repeat(Cause::ALL.len()));
    s.push('\n');
    for p in summaries {
        let _ = write!(
            s,
            "| {} | {} | {} | {:.1} | {} | {} | {} | {} | {} |",
            p.lane,
            p.task.as_deref().unwrap_or("**all**"),
            p.runs,
            p.turns,
            p.context_mean.map_or("—".into(), kilo),
            p.context_p90.map_or("—".into(), kilo),
            kilo(p.request_tokens),
            percent(p.cached_share),
            kilo(p.output_tokens),
        );
        for c in Cause::ALL {
            let _ = write!(
                s,
                " {} |",
                p.causes.as_ref().map_or("—".into(), |m| format!(
                    "{:.1}",
                    m.get(&c).copied().unwrap_or(0.0)
                ))
            );
        }
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn u(uncached: u64, read: u64, write: u64, output: u64) -> Usage {
        Usage {
            uncached_input: uncached,
            cache_read: read,
            cache_write: write,
            output,
        }
    }

    fn record(lane: &str, task: &str, seed: u64, usage: Usage) -> RunRecord {
        serde_json::from_value(json!({
            "task": task, "lane": lane, "lane_kind": "declass", "seed": seed,
            "run_id": format!("{task}-{lane}-s{seed}"), "exit_code": 0, "timed_out": false,
            "wall_seconds": 1.0, "grade": null, "leaks": [], "frontier_requests": 2,
            "usage_by_model": {"m1": usage}, "unreported_requests": 0, "error": null
        }))
        .unwrap()
    }

    fn requests(turns: &[Usage]) -> Vec<RequestUsage> {
        turns
            .iter()
            .map(|t| RequestUsage {
                model: "m1".into(),
                usage: Some(*t),
            })
            .collect()
    }

    #[test]
    fn token_counts_read_as_thousands_or_millions() {
        assert_eq!(kilo(12_345.0), "12.3K");
        assert_eq!(kilo(11_960_400.0), "11.96M");
    }

    #[test]
    fn tools_map_to_causes() {
        for (tool, cause) in [
            ("read_file", Cause::Reading),
            ("git_log", Cause::Reading),
            ("web_fetch", Cause::Reading),
            ("edit_file", Cause::Editing),
            ("edit_protected", Cause::Editing),
            ("run_command", Cause::Commands),
            ("ask_local", Cause::AskLocal),
            ("finish", Cause::Other),
            ("delegate", Cause::Other),
            ("mcp__fs__read_file", Cause::Other),
        ] {
            assert_eq!(Cause::of_tool(tool), cause, "{tool}");
        }
    }

    #[test]
    fn a_turn_is_split_between_the_causes_of_its_calls() {
        let assistant = |tools: &[&str]| {
            let calls: Vec<Value> = tools
                .iter()
                .map(|t| json!({"id": "c", "name": t, "arguments": {}}))
                .collect();
            json!({"kind": "item", "item": {"type": "assistant", "text": "", "tool_calls": calls}})
        };
        let lines = [
            json!({"kind": "start", "objective": "x", "mode": "hybrid", "frontier_model": "m"}),
            json!({"kind": "usage", "turn": 1, "usage": {}, "interventions": []}),
            assistant(&["read_file", "read_file", "ask_local", "run_command"]),
            json!({"kind": "item", "item": {"type": "tool_result", "call_id": "c", "content": "x"}}),
            assistant(&["edit_file"]),
            // A sub-agent's turn is nested under its id.
            json!({"kind": "subagent", "child": "a1", "entry": assistant(&["search"])}),
            assistant(&[]),
            "not json".into(),
        ];
        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        let c = causes_from_transcript(&text);
        assert!((c[&Cause::Reading] - 1.5).abs() < 1e-12, "{c:?}");
        assert!((c[&Cause::AskLocal] - 0.25).abs() < 1e-12);
        assert!((c[&Cause::Commands] - 0.25).abs() < 1e-12);
        assert!((c[&Cause::Editing] - 1.0).abs() < 1e-12);
        assert!((c[&Cause::Other] - 1.0).abs() < 1e-12);
        // Four turns in all.
        assert!((c.values().sum::<f64>() - 4.0).abs() < 1e-12);
    }

    #[test]
    fn per_turn_context_is_pooled_across_runs() {
        // Run 1: turns of 1000 and 3000 context; run 2: one of 6000 and one unreported.
        let a = build(
            &record("hy", "S1", 1, u(1000, 3000, 0, 300)),
            &requests(&[u(1000, 0, 0, 100), u(0, 3000, 0, 200)]),
            None,
        );
        let mut r2 = record("hy", "S1", 2, u(2000, 4000, 0, 100));
        r2.frontier_requests = 2;
        let mut req2 = requests(&[u(2000, 4000, 0, 100)]);
        req2.push(RequestUsage {
            model: "m1".into(),
            usage: None,
        });
        let b = build(&r2, &req2, Some(""));
        assert_eq!(context_of(&a.total()), 4000);
        assert_eq!(a.turns[0].context, 1000);
        let s = summarize("hy", None, &[&a, &b]);
        assert_eq!(s.runs, 2);
        assert!((s.turns - 2.0).abs() < 1e-12);
        // Contexts 1000, 3000, 6000: mean 3333.3, p90 between 3000 and 6000.
        assert!((s.context_mean.unwrap() - 10_000.0 / 3.0).abs() < 1e-9);
        assert!((s.context_p90.unwrap() - 5400.0).abs() < 1e-9);
        assert!((s.request_tokens - 5000.0).abs() < 1e-12);
        assert!((s.cached_share.unwrap() - 0.7).abs() < 1e-12);
        assert!((s.output_tokens - 200.0).abs() < 1e-12);
        // Only run 2 has a transcript (an empty one: no turns by cause).
        assert_eq!(s.runs_with_causes, 1);
        assert_eq!(s.causes.unwrap()[&Cause::Reading], 0.0);
    }

    #[test]
    fn a_run_without_a_capture_keeps_its_recorded_tokens() {
        let mut r = record("hy", "S1", 1, u(1000, 0, 0, 10));
        r.usage_by_model = [("other".to_owned(), u(1000, 0, 0, 10))].into();
        let prof = build(&r, &[], None);
        let s = summarize("hy", Some("S1"), &[&prof]);
        assert!((s.request_tokens - 1000.0).abs() < 1e-12);
        assert_eq!(s.context_mean, None, "no capture, no per-turn context");
    }

    #[test]
    fn summaries_cover_each_lane_then_each_task() {
        let ps: Vec<RunProfile> = [("b", "S1"), ("a", "S2"), ("a", "S1"), ("a", "S1")]
            .iter()
            .enumerate()
            .map(|(i, (lane, task))| {
                build(&record(lane, task, i as u64, u(10, 0, 0, 1)), &[], None)
            })
            .collect();
        let keys: Vec<(String, Option<String>, usize)> = summarize_all(&ps)
            .into_iter()
            .map(|s| (s.lane, s.task, s.runs))
            .collect();
        assert_eq!(
            keys,
            [
                ("a".into(), None, 3),
                ("a".into(), Some("S1".into()), 2),
                ("a".into(), Some("S2".into()), 1),
                ("b".into(), None, 1),
                ("b".into(), Some("S1".into()), 1),
            ]
        );
    }

    #[test]
    fn a_run_directory_loads_from_its_capture_and_transcript() {
        let d = tempfile::tempdir().unwrap();
        let run = d.path().join("S1-hy-s1");
        let proxy = run.join("proxy");
        fs::create_dir_all(proxy.join("requests")).unwrap();
        fs::create_dir_all(proxy.join("responses")).unwrap();
        let mut log = String::new();
        let bodies = [
            // A stream with usage; a stream cut short (no usage).
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5000,\"completion_tokens\":40,\
             \"prompt_tokens_details\":{\"cached_tokens\":4000}}}\n\ndata: [DONE]\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"par\"}}]}\n\n",
        ];
        for (i, body) in bodies.iter().enumerate() {
            let seq = i + 1;
            log.push_str(
                &json!({"seq": seq, "unix_ms": 1, "method": "POST", "path": "/chat/completions",
                        "bytes": 10, "sha256": "x", "status": 200, "leaked": []})
                .to_string(),
            );
            log.push('\n');
            fs::write(
                proxy.join(format!("requests/{seq:05}.body")),
                json!({"model": "m1", "messages": [{"role": "user", "content": "hi"}]}).to_string(),
            )
            .unwrap();
            fs::write(proxy.join(format!("responses/{seq:05}.body")), body).unwrap();
        }
        fs::write(proxy.join("requests.jsonl"), log).unwrap();
        let declass_run = run.join("workspace/.declass/runs/20260926-1");
        fs::create_dir_all(&declass_run).unwrap();
        fs::write(declass_run.join("summary.json"), "{}").unwrap();
        fs::write(
            declass_run.join("transcript.jsonl"),
            json!({"kind": "item", "item": {"type": "assistant", "text": "",
                   "tool_calls": [{"id": "c", "name": "run_command", "arguments": {}}]}})
            .to_string(),
        )
        .unwrap();
        let rec = record("hy", "S1", 1, u(1000, 4000, 0, 40));
        let prof = load(&run, &rec).unwrap();
        assert_eq!(prof.turns.len(), 1, "the cut stream reported nothing");
        assert_eq!(prof.turns[0].usage, u(1000, 4000, 0, 40));
        assert_eq!(prof.turns[0].model, "m1");
        assert_eq!(prof.causes.as_ref().unwrap()[&Cause::Commands], 1.0);
        // Without a capture or a transcript the profile keeps the recorded totals.
        let bare = load(&d.path().join("gone"), &rec).unwrap();
        assert!(bare.turns.is_empty() && bare.causes.is_none());
        assert_eq!(context_of(&bare.total()), 5000);
    }

    #[test]
    fn the_profile_table_shows_all_then_each_task() {
        let a = build(
            &record("hy", "S1", 1, u(1000, 3000, 0, 300)),
            &requests(&[u(1000, 0, 0, 100), u(0, 3000, 0, 200)]),
            Some(
                &[
                    json!({"kind": "item", "item": {"type": "assistant", "text": "",
                          "tool_calls": [{"id": "c", "name": "ask_local", "arguments": {}}]}})
                    .to_string(),
                ]
                .join("\n"),
            ),
        );
        let md = render_profile(&summarize_all(&[a]));
        assert!(md.contains("## Token profile"), "{md}");
        assert!(
            md.contains("| hy | **all** | 1 | 2.0 | 2.0K | 2.8K | 4.0K | 75% | 0.3K | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 |"),
            "{md}"
        );
        assert!(md.contains("| hy | S1 | 1 |"), "{md}");
    }
}
