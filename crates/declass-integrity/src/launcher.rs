// SPDX-License-Identifier: GPL-3.0-or-later
//! Package launchers in an MCP server's command line (`npx`, `uvx`, `docker
//! run`, ...): which package they run, and whether its version is pinned.
//! A launcher without a pinned version runs whatever the registry serves at
//! that moment, so no pin of the command line or the launcher's own
//! executable says what code runs.

use crate::lock::Package;

/// What a command line launches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// The launcher as found in the command line (`npx`, `uvx`, ...).
    pub launcher: String,
    /// The package and the version asked for (MCP registry field names).
    pub package: Package,
    /// No exact version or digest: the registry decides what runs.
    pub floating: bool,
}

/// The program's name without its directory.
fn program(argv: &[String]) -> Option<&str> {
    argv.first().map(|p| p.rsplit('/').next().unwrap_or(p))
}

/// The first argument that is not an option (or an option's value, for the
/// options listed in `with_value`).
fn first_operand<'a>(args: &'a [String], with_value: &[&str]) -> Option<&'a str> {
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a == "--" {
            continue;
        }
        if let Some(name) = a.strip_prefix('-') {
            let name = name.trim_start_matches('-');
            let bare = name.split('=').next().unwrap_or(name);
            skip = !a.contains('=') && with_value.contains(&bare);
            continue;
        }
        return Some(a);
    }
    None
}

/// An npm package specifier: `name@version`, `@scope/name@version`.
fn npm(spec: &str) -> (String, Option<String>) {
    let (scope, rest) = match spec.strip_prefix('@') {
        Some(rest) => ("@", rest),
        None => ("", spec),
    };
    match rest.split_once('@') {
        Some((name, version)) if !version.is_empty() => {
            (format!("{scope}{name}"), Some(version.to_owned()))
        }
        _ => (spec.to_owned(), None),
    }
}

/// An exact npm version: no range, tag or wildcard.
fn exact_semver(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// A PyPI requirement pinned with `==` (or `@ version` as uvx spells it).
fn pypi(spec: &str) -> (String, Option<String>) {
    if let Some((name, version)) = spec.split_once("==") {
        return (name.trim().to_owned(), Some(version.trim().to_owned()));
    }
    if let Some((name, version)) = spec.split_once('@') {
        return (name.trim().to_owned(), Some(version.trim().to_owned()));
    }
    (spec.to_owned(), None)
}

/// Classifies `argv` (program first). `None` when it is not a launcher this
/// knows: a pin of the program and its install directory then says what runs.
pub fn classify(argv: &[String]) -> Option<Launch> {
    let name = program(argv)?;
    let args = &argv[1..];
    let launch = |launcher: &str,
                  registry: &str,
                  identifier: String,
                  version: Option<String>,
                  floating: bool| Launch {
        launcher: launcher.to_owned(),
        package: Package {
            registry_type: registry.to_owned(),
            identifier,
            version,
            file_sha256: None,
        },
        floating,
    };
    match name {
        "npx" | "bunx" => {
            let spec = first_operand(args, &["p", "package", "c", "call"])?;
            let (id, version) = npm(spec);
            let floating = !version.as_deref().is_some_and(exact_semver);
            Some(launch(name, "npm", id, version, floating))
        }
        "pnpm" | "yarn" if args.first().is_some_and(|a| a == "dlx") => {
            let spec = first_operand(&args[1..], &["p", "package"])?;
            let (id, version) = npm(spec);
            let floating = !version.as_deref().is_some_and(exact_semver);
            Some(launch(&format!("{name} dlx"), "npm", id, version, floating))
        }
        "uvx" => {
            let spec = first_operand(args, &["from", "python", "p", "with", "index-url"])?;
            let (id, version) = pypi(spec);
            let floating = version.is_none();
            Some(launch(name, "pypi", id, version, floating))
        }
        "pipx" if args.first().is_some_and(|a| a == "run") => {
            let spec = first_operand(&args[1..], &["spec", "python", "index-url"])?;
            let (id, version) = pypi(spec);
            let floating = version.is_none();
            Some(launch("pipx run", "pypi", id, version, floating))
        }
        "docker" | "podman" if args.first().is_some_and(|a| a == "run") => {
            let image = first_operand(
                &args[1..],
                &[
                    "e",
                    "env",
                    "v",
                    "volume",
                    "p",
                    "publish",
                    "name",
                    "network",
                    "u",
                    "user",
                    "w",
                    "workdir",
                    "entrypoint",
                    "env-file",
                    "mount",
                    "platform",
                    "pull",
                ],
            )?;
            let (id, digest) = match image.split_once("@sha256:") {
                Some((id, digest)) => (id.to_owned(), Some(format!("sha256:{digest}"))),
                None => (image.to_owned(), None),
            };
            let floating = digest.is_none();
            Some(launch(&format!("{name} run"), "oci", id, digest, floating))
        }
        "go" if args.first().is_some_and(|a| a == "run") => {
            let module = first_operand(&args[1..], &["exec", "tags", "C"])?;
            let (id, version) = match module.split_once('@') {
                Some((id, v)) => (id.to_owned(), Some(v.to_owned())),
                None => (module.to_owned(), None),
            };
            let floating = version
                .as_deref()
                .is_none_or(|v| v == "latest" || !v.starts_with('v'));
            Some(launch("go run", "go", id, version, floating))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    fn launched(line: &str) -> (String, String, Option<String>, bool) {
        let l = classify(&argv(line)).unwrap_or_else(|| panic!("not a launcher: {line}"));
        (
            l.package.registry_type,
            l.package.identifier,
            l.package.version,
            l.floating,
        )
    }

    #[test]
    fn launchers_are_recognized_with_their_package_and_pin() {
        let some = |s: &str| Some(s.to_owned());
        for (line, want) in [
            (
                "npx -y @acme/files-mcp@1.4.2",
                ("npm", "@acme/files-mcp", some("1.4.2"), false),
            ),
            (
                "npx -y @acme/files-mcp",
                ("npm", "@acme/files-mcp", None, true),
            ),
            (
                "npx @acme/files-mcp@latest",
                ("npm", "@acme/files-mcp", some("latest"), true),
            ),
            (
                "npx -y files-mcp@^1.2.0",
                ("npm", "files-mcp", some("^1.2.0"), true),
            ),
            (
                "/opt/homebrew/bin/npx --yes server-everything@2026.1.14",
                ("npm", "server-everything", some("2026.1.14"), false),
            ),
            (
                "bunx mcp-git@0.6.2",
                ("npm", "mcp-git", some("0.6.2"), false),
            ),
            (
                "pnpm dlx @acme/x@1.0.0-beta.2",
                ("npm", "@acme/x", some("1.0.0-beta.2"), false),
            ),
            (
                "uvx mcp-server-fetch",
                ("pypi", "mcp-server-fetch", None, true),
            ),
            (
                "uvx mcp-server-fetch==2025.4.7",
                ("pypi", "mcp-server-fetch", some("2025.4.7"), false),
            ),
            (
                "uvx --python 3.12 mcp-server-git@0.6.2",
                ("pypi", "mcp-server-git", some("0.6.2"), false),
            ),
            ("pipx run mcp-thing", ("pypi", "mcp-thing", None, true)),
            (
                "docker run -i --rm -e TOKEN mcp/github",
                ("oci", "mcp/github", None, true),
            ),
            (
                "docker run -i --rm mcp/github@sha256:0123abcd",
                ("oci", "mcp/github", some("sha256:0123abcd"), false),
            ),
            (
                "go run github.com/acme/mcp@v1.2.3",
                ("go", "github.com/acme/mcp", some("v1.2.3"), false),
            ),
            (
                "go run github.com/acme/mcp@latest",
                ("go", "github.com/acme/mcp", some("latest"), true),
            ),
        ] {
            let (r, i, v, f) = want;
            assert_eq!(launched(line), (r.to_owned(), i.to_owned(), v, f), "{line}");
        }
        for not in [
            "node server.js",
            "python3 -m server",
            "/usr/local/bin/files-mcp --stdio",
            "pnpm exec x",
        ] {
            assert_eq!(classify(&argv(not)), None, "{not}");
        }
    }
}
