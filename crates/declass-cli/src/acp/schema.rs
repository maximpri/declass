// SPDX-License-Identifier: GPL-3.0-or-later
//! The Agent Client Protocol messages `declass acp` reads and writes, from
//! the protocol's published version 1 schema. Only these: other fields a
//! client sends are ignored, and every field Declass writes is listed here.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The protocol version Declass speaks. A client asking for a later one is
/// answered with this one, and may disconnect.
pub(crate) const PROTOCOL_VERSION: u16 = 1;

/// `initialize`: only the version is read. The client's capabilities grant
/// nothing (Declass never calls the client's file system or terminals), and
/// its name is shown in the log only.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitializeParams {
    pub protocol_version: u64,
    #[serde(default)]
    pub client_info: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitializeResult {
    pub protocol_version: u16,
    pub agent_capabilities: AgentCapabilities,
    pub agent_info: Implementation,
    /// None: Declass uses the owner's own setup (`declass setup`).
    pub auth_methods: Vec<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentCapabilities {
    pub load_session: bool,
    pub prompt_capabilities: PromptCapabilities,
    pub mcp_capabilities: McpCapabilities,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PromptCapabilities {
    pub image: bool,
    pub audio: bool,
    pub embedded_context: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct McpCapabilities {
    pub http: bool,
    pub sse: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct Implementation {
    pub name: String,
    pub title: String,
    pub version: String,
}

/// `session/new`. The client's MCP servers are named in the log and never
/// started (see `acp.rs`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NewSessionParams {
    pub cwd: String,
    #[serde(default)]
    pub mcp_servers: Option<Vec<Value>>,
    #[serde(default)]
    pub additional_directories: Option<Vec<Value>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NewSessionResult {
    pub session_id: String,
}

/// `session/prompt`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PromptParams {
    pub session_id: String,
    pub prompt: Vec<ContentBlock>,
}

/// One block of a prompt. Images, audio and kinds this version does not know
/// are never decoded: their data is skipped as it is read.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ContentBlock {
    Text {
        text: String,
    },
    Image,
    Audio,
    ResourceLink {
        uri: String,
        #[serde(default)]
        name: Option<String>,
    },
    Resource {
        resource: EmbeddedResource,
    },
    #[serde(other)]
    Unknown,
}

/// An embedded resource: a text or a blob (never decoded) under a URI.
#[derive(Debug, Deserialize)]
pub(crate) struct EmbeddedResource {
    pub uri: String,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StopReason {
    EndTurn,
    MaxTurnRequests,
    Cancelled,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PromptResult {
    pub stop_reason: StopReason,
}

/// `session/update`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionNotification<'a> {
    pub session_id: &'a str,
    pub update: SessionUpdate,
}

#[derive(Debug, Serialize)]
#[serde(tag = "sessionUpdate", rename_all = "snake_case")]
pub(crate) enum SessionUpdate {
    AgentMessageChunk { content: Content },
    ToolCall(ToolCall),
    ToolCallUpdate(ToolCallUpdate),
}

/// A content block Declass writes: text (Markdown).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Content {
    Text { text: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ToolKind {
    Read,
    Edit,
    Search,
    Execute,
    Think,
    Fetch,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ToolStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// What a tool call shows: text, or an edit as a diff.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ToolContent {
    Content {
        content: Content,
    },
    Diff {
        path: String,
        #[serde(rename = "oldText")]
        old_text: Option<String>,
        #[serde(rename = "newText")]
        new_text: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Location {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToolCall {
    pub tool_call_id: String,
    pub title: String,
    pub name: String,
    pub kind: ToolKind,
    pub status: ToolStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<ToolContent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
}

/// A change to a tool call: `content` replaces what it showed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToolCallUpdate {
    pub tool_call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ToolStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<ToolContent>>,
}

/// `session/request_permission`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PermissionRequest<'a> {
    pub session_id: &'a str,
    pub tool_call: ToolCallUpdate,
    pub options: [PermissionOption; 2],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PermissionOption {
    pub option_id: &'static str,
    pub name: &'static str,
    pub kind: &'static str,
}

/// The one option that approves. Every other answer denies: rejection,
/// cancellation, an option Declass did not offer, an error, no answer.
pub(crate) const ALLOW: &str = "allow-once";

/// Allow once and reject: Declass remembers no decision.
pub(crate) fn permission_options() -> [PermissionOption; 2] {
    [
        PermissionOption {
            option_id: ALLOW,
            name: "Allow once",
            kind: "allow_once",
        },
        PermissionOption {
            option_id: "reject-once",
            name: "Reject",
            kind: "reject_once",
        },
    ]
}

/// Whether a `session/request_permission` result selected [`ALLOW`].
pub(crate) fn approved(result: &Value) -> bool {
    let outcome = &result["outcome"];
    outcome["outcome"].as_str() == Some("selected") && outcome["optionId"].as_str() == Some(ALLOW)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn prompt_blocks_read_known_kinds_and_skip_the_rest() {
        let params: PromptParams = serde_json::from_value(json!({
            "sessionId": "s1",
            "prompt": [
                {"type": "text", "text": "fix it", "annotations": {"priority": 1}},
                {"type": "resource_link", "uri": "file:///w/a.rs", "name": "a.rs", "size": 3},
                {"type": "resource", "resource": {"uri": "file:///w/.env", "text": "K=v", "mimeType": "text/plain"}},
                {"type": "resource", "resource": {"uri": "file:///w/b.bin", "blob": "AAAA"}},
                {"type": "image", "mimeType": "image/png", "data": "iVBORw0KGgo="},
                {"type": "audio", "mimeType": "audio/wav", "data": "UklGRg=="},
                {"type": "video", "data": "..."}
            ]
        }))
        .unwrap();
        assert_eq!(params.session_id, "s1");
        let kinds: Vec<String> = params
            .prompt
            .iter()
            .map(|b| {
                format!("{b:?}")
                    .split([' ', '{'])
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "Text",
                "ResourceLink",
                "Resource",
                "Resource",
                "Image",
                "Audio",
                "Unknown"
            ]
        );
        let ContentBlock::Resource { resource } = &params.prompt[3] else {
            unreachable!()
        };
        assert!(resource.text.is_none(), "a blob is never decoded");
    }

    #[test]
    fn updates_are_written_in_the_protocols_shape() {
        let update = SessionNotification {
            session_id: "s1",
            update: SessionUpdate::ToolCall(ToolCall {
                tool_call_id: "c1".into(),
                title: "edit src/a.rs".into(),
                name: "edit_file".into(),
                kind: ToolKind::Edit,
                status: ToolStatus::InProgress,
                content: vec![ToolContent::Diff {
                    path: "/w/src/a.rs".into(),
                    old_text: None,
                    new_text: "x".into(),
                }],
                locations: vec![Location {
                    path: "/w/src/a.rs".into(),
                    line: None,
                }],
            }),
        };
        assert_eq!(
            serde_json::to_value(&update).unwrap(),
            json!({"sessionId": "s1", "update": {"sessionUpdate": "tool_call",
                "toolCallId": "c1", "title": "edit src/a.rs", "name": "edit_file",
                "kind": "edit", "status": "in_progress",
                "content": [{"type": "diff", "path": "/w/src/a.rs", "oldText": null, "newText": "x"}],
                "locations": [{"path": "/w/src/a.rs"}]}})
        );
        let chunk = SessionUpdate::AgentMessageChunk {
            content: Content::Text { text: "hi".into() },
        };
        assert_eq!(
            serde_json::to_value(&chunk).unwrap(),
            json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "hi"}})
        );
        assert_eq!(
            serde_json::to_value(PromptResult {
                stop_reason: StopReason::MaxTurnRequests
            })
            .unwrap(),
            json!({"stopReason": "max_turn_requests"})
        );
    }

    #[test]
    fn only_the_offered_allow_option_approves() {
        assert!(approved(
            &json!({"outcome": {"outcome": "selected", "optionId": ALLOW}})
        ));
        for denied in [
            json!({"outcome": {"outcome": "selected", "optionId": "reject-once"}}),
            json!({"outcome": {"outcome": "selected", "optionId": "allow-always"}}),
            json!({"outcome": {"outcome": "cancelled"}}),
            json!({"outcome": {"outcome": "cancelled", "optionId": ALLOW}}),
            json!({"outcome": "selected"}),
            json!({}),
            json!(null),
        ] {
            assert!(!approved(&denied), "{denied}");
        }
    }
}
