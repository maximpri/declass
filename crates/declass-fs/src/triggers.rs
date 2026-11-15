// SPDX-License-Identifier: GPL-3.0-or-later
//! Files that another tool runs or loads later, when the operator opens the
//! folder, builds, tests or commits: an editor's tasks, a directory hook,
//! another coding agent's settings and instructions, git and build hooks.
//! A change the agent makes to one of them does not stay inside the run.
//! The list names other tools' configuration places only to recognise
//! writes to them; it is a list of well-known places, not a guarantee.

use std::path::Path;

/// When what the file says runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// When the operator next builds, tests, commits or pushes.
    OnUse,
    /// Without any further step: opening the folder, entering the
    /// directory, the next session of another agent.
    Autorun,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::OnUse => "on_use",
            Tier::Autorun => "autorun",
        }
    }
}

/// One kind of file that runs later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trigger {
    /// `dir/**` (anything under a directory at the workspace root),
    /// `**/path` (that file name or path ending at any depth), `*.ext` (any
    /// file with that extension), or an exact workspace-relative path.
    pub pattern: &'static str,
    /// What runs it, in words for the operator.
    pub runner: &'static str,
    pub tier: Tier,
}

const fn t(pattern: &'static str, runner: &'static str, tier: Tier) -> Trigger {
    Trigger {
        pattern,
        runner,
        tier,
    }
}

/// The catalogue, most specific first.
pub const TRIGGERS: &[Trigger] = &[
    // Editors: tasks that run when the folder opens, executables named in settings.
    t(
        ".vscode/tasks.json",
        "the editor (tasks can run when the folder opens)",
        Tier::Autorun,
    ),
    t(
        ".vscode/settings.json",
        "the editor (executable paths, agent auto-approval)",
        Tier::Autorun,
    ),
    t(".vscode/launch.json", "the editor's debugger", Tier::OnUse),
    t(
        "*.code-workspace",
        "the editor (workspace settings and tasks)",
        Tier::Autorun,
    ),
    t(
        ".idea/workspace.xml",
        "the IDE (run configurations)",
        Tier::Autorun,
    ),
    t(
        ".devcontainer/**",
        "the dev container (commands at create and start)",
        Tier::Autorun,
    ),
    // Shell environments.
    t(
        "**/.envrc",
        "direnv (when the shell enters the directory)",
        Tier::Autorun,
    ),
    // Other coding agents: their settings, hooks, servers, rules and skills.
    t(
        ".mcp.json",
        "another coding agent (MCP servers it starts)",
        Tier::Autorun,
    ),
    t(
        ".claude/**",
        "another coding agent (settings, hooks, skills)",
        Tier::Autorun,
    ),
    t(
        ".cursor/**",
        "another coding agent (settings, rules, MCP servers)",
        Tier::Autorun,
    ),
    t(
        ".gemini/**",
        "another coding agent (settings, extensions)",
        Tier::Autorun,
    ),
    t(
        ".codex/**",
        "another coding agent (configuration, MCP servers)",
        Tier::Autorun,
    ),
    t(
        ".opencode/**",
        "another coding agent (configuration, skills)",
        Tier::Autorun,
    ),
    t(
        ".agents/**",
        "coding agents (skills, plugins)",
        Tier::Autorun,
    ),
    t(
        ".github/hooks/**",
        "another coding agent (hooks)",
        Tier::Autorun,
    ),
    t(
        ".github/copilot-instructions.md",
        "another coding agent (instructions)",
        Tier::Autorun,
    ),
    t(
        "**/AGENTS.md",
        "coding agents, Declass too (instructions)",
        Tier::Autorun,
    ),
    t(
        "**/AGENTS.override.md",
        "coding agents (instructions)",
        Tier::Autorun,
    ),
    t(
        "**/CLAUDE.md",
        "another coding agent (instructions)",
        Tier::Autorun,
    ),
    t(
        "**/GEMINI.md",
        "another coding agent (instructions)",
        Tier::Autorun,
    ),
    t("**/DECLASS.md", "Declass (instructions)", Tier::Autorun),
    // git and commit hooks.
    t(".husky/**", "git hooks (husky)", Tier::OnUse),
    t(
        ".pre-commit-config.yaml",
        "git hooks (pre-commit)",
        Tier::OnUse,
    ),
    t("lefthook.yml", "git hooks (lefthook)", Tier::OnUse),
    t(".githooks/**", "git hooks (a hooks directory)", Tier::OnUse),
    t(
        ".gitattributes",
        "git (filters and diff drivers)",
        Tier::OnUse,
    ),
    t(
        ".gitmodules",
        "git (submodule URLs and commands)",
        Tier::OnUse,
    ),
    // CI.
    t(".github/workflows/**", "CI (GitHub Actions)", Tier::OnUse),
    t(".gitlab-ci.yml", "CI (GitLab)", Tier::OnUse),
    // Builds, tests and package managers.
    t(
        "**/package.json",
        "the package manager (scripts, install hooks)",
        Tier::OnUse,
    ),
    t(
        "**/.npmrc",
        "the package manager (script shell, registry)",
        Tier::OnUse,
    ),
    t(
        "**/.yarnrc.yml",
        "yarn (its own path, plugins)",
        Tier::OnUse,
    ),
    t("**/Makefile", "make", Tier::OnUse),
    t("**/justfile", "just", Tier::OnUse),
    t("**/Taskfile.yml", "task", Tier::OnUse),
    t(
        "**/.cargo/config.toml",
        "cargo (runners, wrappers, aliases)",
        Tier::OnUse,
    ),
    t("**/build.rs", "cargo (runs at build)", Tier::OnUse),
    t(
        "**/setup.py",
        "Python packaging (runs at install)",
        Tier::OnUse,
    ),
    t("**/conftest.py", "pytest (runs before tests)", Tier::OnUse),
    t("**/noxfile.py", "nox", Tier::OnUse),
    t("**/tasks.py", "invoke", Tier::OnUse),
    t(
        "**/sitecustomize.py",
        "Python (runs at every start)",
        Tier::OnUse,
    ),
    t(
        "*.pth",
        "Python (lines starting with import run at every start)",
        Tier::OnUse,
    ),
];

fn matches(pattern: &str, rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if let Some(dir) = pattern.strip_suffix("/**") {
        rel.strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
    } else if let Some(tail) = pattern.strip_prefix("**/") {
        // A file name, or a path ending, at any depth.
        rel == tail || rel.ends_with(&format!("/{tail}"))
    } else if let Some(ext) = pattern.strip_prefix('*') {
        name.ends_with(ext) && name.len() > ext.len()
    } else {
        rel == pattern
    }
}

/// The trigger `rel` (relative to the workspace) is, if any. Names are
/// compared folded ([`crate::fold_name`]): on a case-insensitive file system
/// a new `.VSCODE/tasks.json` is what the editor opens as
/// `.vscode/tasks.json`.
pub fn classify(rel: &Path) -> Option<&'static Trigger> {
    let rel = crate::fold_name(rel.to_str()?);
    let rel = rel.trim_start_matches("./");
    TRIGGERS
        .iter()
        .find(|t| matches(&crate::fold_name(t.pattern), rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(path: &str) -> Option<Tier> {
        classify(Path::new(path)).map(|t| t.tier)
    }

    #[test]
    fn files_that_run_later_are_recognised_by_when_they_run() {
        for path in [
            ".vscode/tasks.json",
            "app.code-workspace",
            ".envrc",
            "services/api/.envrc",
            ".mcp.json",
            ".claude/settings.json",
            ".cursor/rules/style.mdc",
            ".agents/skills/review/SKILL.md",
            "src/AGENTS.md",
            ".devcontainer/devcontainer.json",
        ] {
            assert_eq!(tier(path), Some(Tier::Autorun), "{path}");
        }
        for path in [
            ".husky/pre-commit",
            ".pre-commit-config.yaml",
            ".github/workflows/ci.yml",
            "package.json",
            "web/package.json",
            "Makefile",
            "build.rs",
            "crates/x/build.rs",
            "tests/conftest.py",
            "lib/site-packages/evil.pth",
            ".cargo/config.toml",
        ] {
            assert_eq!(tier(path), Some(Tier::OnUse), "{path}");
        }
        for path in [
            "src/main.rs",
            "README.md",
            ".vscode/extensions.json",
            "docs/agents-guide.md",
            "my.pth.txt",
            ".pth",
            "vscode/tasks.json",
        ] {
            assert_eq!(tier(path), None, "{path}");
        }
    }

    #[test]
    fn other_spellings_of_a_trigger_are_the_trigger() {
        // On macOS's default volumes these open the files the other tools
        // read: a new `.VSCODE/tasks.json` is the editor's tasks file.
        for path in [
            ".VSCODE/tasks.json",
            ".VSCode/settings.json",
            "docs/agents.md",
            "SRC/Claude.md",
            ".DevContainer/devcontainer.json",
            ".mcp.JSON",
        ] {
            assert_eq!(tier(path), Some(Tier::Autorun), "{path}");
        }
        for path in [".HUSKY/pre-commit", ".GitHub/workflows/ci.yml", "makefile"] {
            assert_eq!(tier(path), Some(Tier::OnUse), "{path}");
        }
    }
}
