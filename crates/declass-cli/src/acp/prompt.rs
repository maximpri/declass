// SPDX-License-Identifier: GPL-3.0-or-later
//! The operator's message from a prompt's content blocks.
//!
//! Text is the message. A file the operator @-mentioned (a resource link, or
//! an embedded resource carrying the file's text) becomes its workspace path
//! in the message, never its content: the frontier reads it with its tools,
//! through the boundary, so the file's classification applies (a `.env` or a
//! customer CSV is read by the local model only). What the editor embedded is
//! dropped. Text embedded under a URI that is not a file (a selection from an
//! unsaved buffer, a rule or a fetched page) is treated as text the operator
//! pasted: it is part of the message and sanitized with it. Files outside the
//! workspace, binary resources, images and audio are not used; the operator
//! is told so.

use super::schema::ContentBlock;
use std::path::{Component, Path, PathBuf};

/// Limits on text treated as pasted, as for text attachments.
const MAX_PASTED: usize = 512 * 1024;
const MAX_PASTED_TOTAL: usize = 2 * 1024 * 1024;

/// A prompt as Declass reads it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Composed {
    /// The operator's message (empty when nothing in the prompt can be used).
    pub message: String,
    /// What was not used, each with why, for the operator.
    pub declined: Vec<String>,
}

/// The message for `blocks`, in the workspace `ws` (canonical).
pub(crate) fn compose(blocks: &[ContentBlock], ws: &Path) -> Composed {
    let mut text = String::new();
    let mut paths: Vec<String> = Vec::new();
    let mut pasted: Vec<&str> = Vec::new();
    let mut pasted_bytes = 0;
    let mut declined = Vec::new();
    fn mention(text: &mut String, paths: &mut Vec<String>, found: Mention) {
        text.push_str(&format!("`{}`", found.path));
        let shown = match found.lines {
            Some(lines) => format!("{} (lines {lines})", found.path),
            None => found.path,
        };
        if !paths.contains(&shown) {
            paths.push(shown);
        }
    }
    for block in blocks {
        match block {
            ContentBlock::Text { text: t } => text.push_str(t),
            ContentBlock::ResourceLink { uri, name } => match workspace_path(uri, ws) {
                Some(found) => mention(&mut text, &mut paths, found),
                None => declined.push(format!(
                    "{}: {}",
                    name.as_deref().filter(|n| !n.is_empty()).unwrap_or(uri),
                    why_not(uri)
                )),
            },
            ContentBlock::Resource { resource } => {
                if let Some(found) = workspace_path(&resource.uri, ws) {
                    // The file's own path, never what the editor embedded.
                    mention(&mut text, &mut paths, found);
                } else if is_file(&resource.uri) {
                    declined.push(format!("{}: {}", resource.uri, why_not(&resource.uri)));
                } else {
                    match resource.text.as_deref() {
                        None => declined.push(format!(
                            "{}: binary content is not accepted from the editor",
                            resource.uri
                        )),
                        Some(t)
                            if t.len() > MAX_PASTED
                                || pasted_bytes + t.len() > MAX_PASTED_TOTAL =>
                        {
                            declined.push(format!(
                                "{}: attached text over 512 KiB (2 MiB in all)",
                                resource.uri
                            ))
                        }
                        Some(t) => {
                            pasted_bytes += t.len();
                            pasted.push(t);
                        }
                    }
                }
            }
            ContentBlock::Image => declined.push(
                "an image: images are not accepted from the editor yet (in a terminal session, /image attaches one)"
                    .to_owned(),
            ),
            ContentBlock::Audio => declined.push("audio: not accepted".to_owned()),
            ContentBlock::Unknown => {
                declined.push("content of a kind Declass does not read".to_owned())
            }
        }
    }
    let mut message = text.trim().to_owned();
    if !paths.is_empty() {
        if !message.is_empty() {
            message.push_str("\n\n");
        }
        message.push_str(&format!(
            "[declass] The operator referred to these workspace paths in the editor; their content \
was not attached (read them with your tools if you need them): {}",
            paths.join(", ")
        ));
    }
    for t in pasted {
        if !message.is_empty() {
            message.push_str("\n\n");
        }
        message.push_str(&format!(
            "Text the operator attached:\n<attached_text>\n{}\n</attached_text>",
            t.trim_end()
        ));
    }
    Composed { message, declined }
}

/// A workspace path a URI names, with the lines it points at.
#[derive(Debug, PartialEq, Eq)]
struct Mention {
    /// Relative to the workspace (`.` for the workspace itself); a
    /// directory ends with `/`.
    path: String,
    lines: Option<String>,
}

fn is_file(uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|u| u.scheme() == "file")
}

fn why_not(uri: &str) -> &'static str {
    if is_file(uri) {
        "outside the workspace; Declass reads only the workspace's files"
    } else {
        "not a workspace file; Declass does not fetch links from the editor"
    }
}

/// The workspace path a `file:` URI names, if it is in `ws`: symbolic links
/// are resolved for a path that exists, `..` lexically for one that does not
/// (it is only named in the message; the tools check it when it is read).
fn workspace_path(uri: &str, ws: &Path) -> Option<Mention> {
    let url = url::Url::parse(uri).ok()?;
    if url.scheme() != "file" || !matches!(url.host_str(), None | Some("" | "localhost")) {
        return None;
    }
    let path = url.to_file_path().ok()?;
    let resolved = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => lexical(&path)?,
    };
    let rel = resolved.strip_prefix(ws).ok()?;
    let mut shown = match rel.to_str()? {
        "" => ".".to_owned(),
        s => s.to_owned(),
    };
    if resolved.is_dir() && shown != "." {
        shown.push('/');
    }
    Some(Mention {
        path: shown,
        lines: url.fragment().and_then(lines),
    })
}

/// `path` with `.` and `..` removed, without the file system; `None` when it
/// climbs above the root.
fn lexical(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    Some(out)
}

/// The lines a fragment such as `L12`, `L12:20`, `L12-20` or `L12-L20` names.
fn lines(fragment: &str) -> Option<String> {
    let rest = fragment.strip_prefix('L')?;
    let (start, end) = match rest.split_once([':', '-']) {
        Some((a, b)) => (a, Some(b.trim_start_matches('L'))),
        None => (rest, None),
    };
    let start: u64 = start.parse().ok()?;
    match end.map(str::parse::<u64>) {
        None => Some(start.to_string()),
        Some(Ok(end)) if end > start => Some(format!("{start}-{end}")),
        Some(Ok(_)) => Some(start.to_string()),
        Some(Err(_)) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::schema::EmbeddedResource;

    const CANARY: &str = "pine-lantern-7731-canary";

    fn workspace() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ws/src")).unwrap();
        let ws = dir.path().join("ws").canonicalize().unwrap();
        std::fs::write(ws.join(".env"), format!("KEY={CANARY}\n")).unwrap();
        std::fs::write(ws.join("src/a.rs"), "fn a() {}\n").unwrap();
        (dir, ws)
    }

    fn uri(path: &Path) -> String {
        url::Url::from_file_path(path).unwrap().to_string()
    }

    fn text(t: &str) -> ContentBlock {
        ContentBlock::Text { text: t.into() }
    }

    fn embedded(uri: String, text: Option<&str>) -> ContentBlock {
        ContentBlock::Resource {
            resource: EmbeddedResource {
                uri,
                text: text.map(str::to_owned),
            },
        }
    }

    #[test]
    fn a_mentioned_file_is_named_and_its_embedded_text_never_used() {
        let (_d, ws) = workspace();
        let composed = compose(
            &[
                text("Why does "),
                embedded(uri(&ws.join(".env")), Some(&format!("KEY={CANARY}"))),
                text(" break "),
                ContentBlock::ResourceLink {
                    uri: format!("{}#L1:3", uri(&ws.join("src/a.rs"))),
                    name: Some("a.rs".into()),
                },
                text("?"),
            ],
            &ws,
        );
        assert!(composed.declined.is_empty(), "{composed:?}");
        assert!(!composed.message.contains(CANARY), "{}", composed.message);
        assert!(
            composed
                .message
                .starts_with("Why does `.env` break `src/a.rs`?"),
            "{}",
            composed.message
        );
        assert!(
            composed
                .message
                .contains("in the editor; their content was not attached"),
            "{}",
            composed.message
        );
        assert!(
            composed.message.contains(".env, src/a.rs (lines 1-3)"),
            "{}",
            composed.message
        );
    }

    #[test]
    fn files_outside_the_workspace_and_escapes_are_declined() {
        let (d, ws) = workspace();
        let outside = d.path().join("other.env");
        std::fs::write(&outside, CANARY).unwrap();
        let link = ws.join("link.env");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let escape = format!("{}/src/../../other.env", uri(&ws));
        for block in [
            embedded(uri(&outside), Some(CANARY)),
            embedded(uri(&link), Some(CANARY)),
            embedded(escape.clone(), Some(CANARY)),
            ContentBlock::ResourceLink {
                uri: uri(&outside),
                name: None,
            },
            ContentBlock::ResourceLink {
                uri: "https://example.org/x".into(),
                name: Some("x".into()),
            },
            embedded("file:///w/b.bin".into(), None),
            ContentBlock::Image,
            ContentBlock::Audio,
            ContentBlock::Unknown,
        ] {
            let composed = compose(&[text("look"), block], &ws);
            assert_eq!(composed.message, "look", "{composed:?}");
            assert_eq!(composed.declined.len(), 1, "{composed:?}");
            assert!(!format!("{composed:?}").contains(CANARY));
        }
        let composed = compose(&[embedded(escape, Some(CANARY))], &ws);
        assert!(composed.declined[0].contains("outside the workspace"));
    }

    #[test]
    fn text_embedded_under_another_uri_is_pasted_text() {
        let (_d, ws) = workspace();
        let composed = compose(
            &[
                text("Use this:"),
                embedded(
                    "zed:///agent/rule/7".into(),
                    Some("Prefer small commits.\n"),
                ),
            ],
            &ws,
        );
        assert!(composed.declined.is_empty());
        assert_eq!(
            composed.message,
            "Use this:\n\nText the operator attached:\n<attached_text>\nPrefer small commits.\n</attached_text>"
        );
        let big = "x".repeat(MAX_PASTED + 1);
        let composed = compose(&[embedded("untitled:1".into(), Some(&big))], &ws);
        assert!(composed.message.is_empty() && composed.declined.len() == 1);
    }

    #[test]
    fn directories_and_line_fragments_read_as_paths() {
        let (_d, ws) = workspace();
        let composed = compose(
            &[ContentBlock::ResourceLink {
                uri: uri(&ws.join("src")),
                name: Some("src".into()),
            }],
            &ws,
        );
        assert!(composed.message.contains("`src/`"), "{}", composed.message);
        assert_eq!(lines("L12"), Some("12".into()));
        assert_eq!(lines("L12:20"), Some("12-20".into()));
        assert_eq!(lines("L12-L20"), Some("12-20".into()));
        assert_eq!(lines("L5:5"), Some("5".into()));
        assert_eq!(lines("L1:x"), None);
        assert_eq!(lines("top"), None);
        assert_eq!(
            lexical(Path::new("/a/b/../c/./d")),
            Some(PathBuf::from("/a/c/d"))
        );
        assert_eq!(lexical(Path::new("/a/../..")), None);
    }
}
