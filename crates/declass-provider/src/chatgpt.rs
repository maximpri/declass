// SPDX-License-Identifier: GPL-3.0-or-later
//! ChatGPT plan usage: "Sign in with ChatGPT" for open-source apps, the route
//! OpenAI documents for using a ChatGPT subscription from a local tool
//! (developers.openai.com/siwc/token-sharing-open-source, 2026-10). Requests go
//! to the public Responses API at [`API_BASE`] with an OAuth access token,
//! never to ChatGPT's own backend.
//!
//! - Sign-in is OAuth 2.0 authorization code with PKCE in the system browser,
//!   returning to a loopback listener on `127.0.0.1`. The first sign-in
//!   registers Declass for the account (`client_id=dynamic_agent_client`);
//!   OpenAI returns an issued client id that every later sign-in and refresh
//!   uses. The ID token's signature, issuer, audience, expiry and nonce are
//!   verified before anything is saved.
//! - Plan usage needs the `chatgpt.tokens.use.direct` scope in the grant; a
//!   valid sign-in without it cannot make requests.
//! - Access tokens last an hour. [`PlanSession`] renews them shortly before
//!   expiry, under a file lock so two Declass processes never race a rotating
//!   refresh token, and again once when the API refuses one.
//! - Credentials are one JSON file, written atomically with mode 0600 in a
//!   directory the command sandbox denies (see `declass_config`).

use crate::client::{Role, TokenSource};
use crate::endpoint::ApprovedEndpoint;
use crate::error::{ErrorKind, ProviderError};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The OpenAI authorization server.
pub const ISSUER: &str = "https://auth.openai.com";
/// Where ChatGPT plan inference and the account's model list are served.
pub const API_BASE: &str = "https://api.openai.com/v1";
/// Where the user reviews and limits each app's use of their plan.
pub const USAGE_URL: &str = "https://chatgpt.com/settings/usage";
/// The scope that authorizes requests billed to the ChatGPT plan.
pub const PLAN_SCOPE: &str = "chatgpt.tokens.use.direct";
/// The app name shown when the user approves Declass, the same everywhere.
pub const AGENT_NAME: &str = "Declass";

const SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const REGISTRATION_CLIENT: &str = "dynamic_agent_client";
const CALLBACK_PATH: &str = "/auth/callback";
/// The callback port tried first; any free port works when it is taken.
const CALLBACK_PORT: u16 = 1455;
/// Renew an access token this long before it expires.
const RENEW_BEFORE: i64 = 300;
/// Clock skew tolerated when checking the ID token's expiry.
const CLOCK_SKEW: i64 = 120;
/// How long a refresh waits for another process holding the lock.
const LOCK_WAIT: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// OAuth error codes after which the refresh token can never work again.
const DEAD_REFRESH: &[&str] = &[
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
];

const SIGN_IN_AGAIN: &str = "run `declass login chatgpt`";

/// The authorization server's endpoints. Production uses [`Issuer::openai`];
/// tests point it at a loopback server.
#[derive(Debug, Clone)]
pub struct Issuer {
    base: String,
}

impl Issuer {
    pub fn openai() -> Self {
        Self {
            base: ISSUER.to_owned(),
        }
    }

    /// An issuer at `base`, for tests against a loopback server.
    #[cfg(any(test, feature = "test-support"))]
    pub fn at(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.base
    }

    fn authorize_url(&self) -> String {
        format!("{}/api/accounts/authorize", self.base)
    }

    fn token_url(&self) -> String {
        format!("{}/api/accounts/oauth/token", self.base)
    }

    fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.base)
    }

    fn client(&self) -> Result<crate::http::Client, ProviderError> {
        let endpoint = ApprovedEndpoint::new(&self.base, &Role::Frontier)?;
        crate::http::client(&endpoint, Duration::from_secs(10), Some(HTTP_TIMEOUT))
            .map_err(|e| ProviderError::new(ErrorKind::Transport, e.to_string()))
    }
}

/// One ChatGPT account's registration and tokens, as saved on disk. Debug
/// output never shows a token.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub issuer: String,
    /// The client id OpenAI issued at registration (`oaiapp_…`), kept after
    /// sign-out so a later sign-in reuses it.
    pub client_id: String,
    pub ext_agent_host_id: String,
    /// The verified ID token's subject: the account identity.
    pub subject: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix seconds when the access token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Unix seconds of the last sign-in or refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<i64>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let present = |t: &Option<String>| if t.is_some() { "<set>" } else { "<none>" };
        f.debug_struct("Account")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("subject", &self.subject)
            .field("email", &self.email)
            .field("id_token", &present(&self.id_token))
            .field("access_token", &present(&self.access_token))
            .field("refresh_token", &present(&self.refresh_token))
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl Account {
    /// Signed in: a refresh token is present.
    pub fn signed_in(&self) -> bool {
        self.refresh_token.is_some()
    }

    /// The grant allows requests billed to the ChatGPT plan.
    pub fn plan_enabled(&self) -> bool {
        self.scopes.iter().any(|s| s == PLAN_SCOPE)
    }

    /// Forgets the tokens and keeps the registration (issued client id, host
    /// and identity) for the next sign-in.
    fn clear_tokens(&mut self) {
        self.id_token = None;
        self.access_token = None;
        self.refresh_token = None;
        self.expires_at = None;
        self.scopes.clear();
    }

    fn label(&self) -> String {
        self.email.clone().unwrap_or_else(|| self.subject.clone())
    }
}

/// Where the ChatGPT credentials live: a directory of owner-only files.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct HostRecord {
    ext_agent_host_id: String,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    fn host_path(&self) -> PathBuf {
        self.dir.join("host.json")
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join("refresh.lock")
    }

    /// The saved account, if any.
    pub fn account(&self) -> Result<Option<Account>, ProviderError> {
        match std::fs::read(self.account_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
                ProviderError::new(
                    ErrorKind::Auth,
                    format!(
                        "{} is unreadable ({e}); run `declass logout chatgpt` and sign in again",
                        self.account_path().display()
                    ),
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(&self.account_path(), e)),
        }
    }

    fn save_account(&self, account: &Account) -> Result<(), ProviderError> {
        let bytes = serde_json::to_vec_pretty(account)
            .map_err(|e| ProviderError::new(ErrorKind::Malformed, e.to_string()))?;
        write_private(&self.dir, &self.account_path(), &bytes)
    }

    /// This installation's stable host id, created on first use.
    fn host_id(&self) -> Result<String, ProviderError> {
        if let Ok(bytes) = std::fs::read(self.host_path())
            && let Ok(record) = serde_json::from_slice::<HostRecord>(&bytes)
            && record.ext_agent_host_id.starts_with("urn:uuid:")
        {
            return Ok(record.ext_agent_host_id);
        }
        let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let bytes = serde_json::to_vec_pretty(&HostRecord {
            ext_agent_host_id: id.clone(),
        })
        .map_err(|e| ProviderError::new(ErrorKind::Malformed, e.to_string()))?;
        write_private(&self.dir, &self.host_path(), &bytes)?;
        Ok(id)
    }

    /// Holds the refresh lock until dropped, waiting for another process up to
    /// [`LOCK_WAIT`].
    async fn lock(&self) -> Result<std::fs::File, ProviderError> {
        ensure_private_dir(&self.dir)?;
        let path = self.lock_path();
        let file = declass_fs::private::open_lock(&path).map_err(fs_error)?;
        let started = std::time::Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < LOCK_WAIT => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(ProviderError::new(
                        ErrorKind::Transport,
                        "another Declass process held the ChatGPT refresh lock for 30 s",
                    ));
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(io_error(&path, e)),
            }
        }
    }
}

fn io_error(path: &Path, e: std::io::Error) -> ProviderError {
    ProviderError::new(ErrorKind::Auth, format!("{}: {e}", path.display()))
}

fn fs_error(e: declass_fs::FsError) -> ProviderError {
    ProviderError::new(ErrorKind::Auth, e.to_string())
}

fn ensure_private_dir(dir: &Path) -> Result<(), ProviderError> {
    declass_fs::private::ensure_private_dir(dir).map_err(fs_error)
}

/// Writes `bytes` to `path` atomically, owner-only (0600 in a 0700
/// directory), never through a symlink.
fn write_private(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), ProviderError> {
    ensure_private_dir(dir)?;
    declass_fs::private::write_private(path, bytes).map_err(fs_error)
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A random URL-safe value with at least 244 bits from the OS generator.
fn random_value() -> String {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The PKCE S256 challenge for `verifier` (RFC 7636).
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The outcome of a completed sign-in.
#[derive(Debug, Clone)]
pub struct SignedIn {
    pub account: Account,
    /// The first sign-in on this host for this account (Declass was
    /// registered with it).
    pub registered: bool,
}

/// A sign-in in progress: the loopback listener is bound and the browser
/// should be sent to [`Pending::url`].
pub struct Pending {
    store: Store,
    issuer: Issuer,
    listener: tokio::net::TcpListener,
    redirect_uri: String,
    state: String,
    nonce: String,
    verifier: String,
    /// The issued client id when signing in again; `None` registers.
    client_id: Option<String>,
    host_id: String,
    previous: Option<Account>,
    url: String,
    display_url: String,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("redirect_uri", &self.redirect_uri)
            .field("registering", &self.client_id.is_none())
            .finish_non_exhaustive()
    }
}

/// Starts a sign-in: binds the callback listener and builds the
/// authorization URL. A saved registration is reused (its issued client id,
/// with the old ID token as `id_token_hint` so no account picker appears).
pub async fn begin(store: &Store, issuer: &Issuer) -> Result<Pending, ProviderError> {
    let host_id = store.host_id()?;
    let previous = store.account()?.filter(|a| a.issuer == issuer.as_str());
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", CALLBACK_PORT)).await {
        Ok(l) => l,
        Err(_) => tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| {
                ProviderError::new(
                    ErrorKind::Transport,
                    format!("cannot listen on 127.0.0.1 for the sign-in callback: {e}"),
                )
            })?,
    };
    let port = listener
        .local_addr()
        .map_err(|e| ProviderError::new(ErrorKind::Transport, e.to_string()))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
    let (state, nonce, verifier) = (random_value(), random_value(), random_value());
    let client_id = previous
        .as_ref()
        .map(|a| a.client_id.clone())
        .filter(|c| !c.is_empty());
    let mut params: Vec<(&str, String)> = vec![(
        "client_id",
        client_id
            .clone()
            .unwrap_or_else(|| REGISTRATION_CLIENT.into()),
    )];
    if client_id.is_none() {
        params.push(("agent_name_hint", AGENT_NAME.into()));
    }
    params.extend([
        ("ext_agent_host_id", host_id.clone()),
        ("response_type", "code".into()),
        ("redirect_uri", redirect_uri.clone()),
        ("scope", SCOPES.into()),
        ("resource", API_BASE.into()),
        ("state", state.clone()),
        ("nonce", nonce.clone()),
        ("code_challenge_method", "S256".into()),
        ("code_challenge", pkce_challenge(&verifier)),
    ]);
    if let Some(prev) = &previous {
        if let Some(email) = &prev.email {
            params.push(("login_hint", email.clone()));
        }
        // An earlier grant without plan usage: ask for consent again.
        if prev.signed_in() && !prev.plan_enabled() {
            params.push(("prompt", "consent".into()));
        }
    }
    let display_url = url_with(&issuer.authorize_url(), &params)?;
    // The ID token is a credential-like hint: it goes only to the browser,
    // never into the printed URL.
    if let Some(hint) = previous.as_ref().and_then(|a| a.id_token.clone()) {
        params.push(("id_token_hint", hint));
    }
    let url = url_with(&issuer.authorize_url(), &params)?;
    Ok(Pending {
        store: store.clone(),
        issuer: issuer.clone(),
        listener,
        redirect_uri,
        state,
        nonce,
        verifier,
        client_id,
        host_id,
        previous,
        url,
        display_url,
    })
}

fn url_with(base: &str, params: &[(&str, String)]) -> Result<String, ProviderError> {
    let mut url = reqwest::Url::parse(base)
        .map_err(|e| ProviderError::new(ErrorKind::Malformed, e.to_string()))?;
    url.query_pairs_mut()
        .extend_pairs(params.iter().map(|(k, v)| (*k, v.as_str())));
    Ok(url.into())
}

/// What the browser brought back to the callback.
#[derive(Debug, PartialEq, Eq)]
enum Callback {
    Code {
        code: String,
        client_id: Option<String>,
    },
    Error {
        error: String,
        description: Option<String>,
    },
}

impl Pending {
    /// The URL to open in the browser.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The same URL without the `id_token_hint`, safe to print.
    pub fn display_url(&self) -> &str {
        &self.display_url
    }

    /// Whether this sign-in registers Declass with a new account.
    pub fn registering(&self) -> bool {
        self.client_id.is_none()
    }

    /// Waits for the browser's callback (up to `timeout`), exchanges the code,
    /// verifies the ID token and saves the credentials.
    pub async fn finish(self, timeout: Duration) -> Result<SignedIn, ProviderError> {
        let callback = tokio::time::timeout(timeout, self.wait_for_callback())
            .await
            .map_err(|_| {
                ProviderError::new(
                    ErrorKind::Timeout,
                    "no sign-in arrived from the browser in time; run `declass login chatgpt` again",
                )
            })??;
        let (code, returned_client) = match callback {
            Callback::Code { code, client_id } => (code, client_id),
            Callback::Error { error, description } => {
                let detail = description.map(|d| format!(": {d}")).unwrap_or_default();
                let message = if error == "access_denied" {
                    format!(
                        "ChatGPT plan use isn't enabled: the sign-in was declined{detail}. Run `declass login chatgpt` to allow it, or use an API key (`declass config preset openai`)"
                    )
                } else {
                    format!("ChatGPT sign-in failed ({error}){detail}")
                };
                return Err(ProviderError::new(ErrorKind::Auth, message));
            }
        };
        let client_id = match (&self.client_id, returned_client) {
            (Some(expected), Some(returned)) if *expected != returned => {
                return Err(ProviderError::new(
                    ErrorKind::Auth,
                    "the sign-in returned a different client id than this account's registration; nothing was saved",
                ));
            }
            (Some(expected), _) => expected.clone(),
            (None, Some(issued)) if issued != REGISTRATION_CLIENT && !issued.is_empty() => issued,
            (None, _) => {
                return Err(ProviderError::new(
                    ErrorKind::Auth,
                    "the sign-in did not return an issued client id; registration is incomplete, run `declass login chatgpt` again",
                ));
            }
        };
        let client = self.issuer.client()?;
        let tokens = token_request(
            &client,
            &self.issuer.token_url(),
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
                ("code", &code),
                ("code_verifier", &self.verifier),
                ("redirect_uri", &self.redirect_uri),
                ("resource", API_BASE),
            ],
        )
        .await
        .map_err(|e| match e {
            TokenError::OAuth { code, .. } if code == "invalid_grant" => ProviderError::new(
                ErrorKind::Auth,
                "the sign-in code was refused; run `declass login chatgpt` again",
            ),
            other => other.into_provider_error(),
        })?;
        let id_token = tokens.id_token.clone().ok_or_else(|| {
            ProviderError::new(ErrorKind::Auth, "the sign-in returned no ID token")
        })?;
        let discovery = Discovery::fetch(&self.issuer, &client).await?;
        let claims = verify_id_token(
            &id_token,
            &discovery.jwks(&client).await?,
            &IdExpectations {
                issuer: self.issuer.as_str(),
                client_id: &client_id,
                nonce: &self.nonce,
                now: now(),
            },
        )?;
        if let Some(prev) = &self.previous
            && !prev.subject.is_empty()
            && prev.subject != claims.sub
            && self.client_id.is_some()
        {
            return Err(ProviderError::new(
                ErrorKind::Auth,
                format!(
                    "signed in as a different ChatGPT account than {}; nothing was saved (run `declass logout chatgpt --forget` to switch accounts)",
                    prev.label()
                ),
            ));
        }
        let refresh_token = tokens.refresh_token.clone().ok_or_else(|| {
            ProviderError::new(
                ErrorKind::Auth,
                "the sign-in returned no refresh token (offline_access was not granted)",
            )
        })?;
        let account = Account {
            issuer: self.issuer.as_str().to_owned(),
            client_id,
            ext_agent_host_id: self.host_id,
            subject: claims.sub,
            email: claims.email,
            id_token: Some(id_token),
            access_token: Some(tokens.access_token),
            refresh_token: Some(refresh_token),
            expires_at: Some(now() + tokens.expires_in.unwrap_or(3600)),
            scopes: split_scopes(tokens.scope.as_deref()),
            saved_at: Some(now()),
        };
        self.store.save_account(&account)?;
        Ok(SignedIn {
            account,
            registered: self.client_id.is_none(),
        })
    }

    async fn wait_for_callback(&self) -> Result<Callback, ProviderError> {
        loop {
            let (mut stream, _) = self
                .listener
                .accept()
                .await
                .map_err(|e| ProviderError::new(ErrorKind::Transport, e.to_string()))?;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 2048];
            let read = tokio::time::timeout(Duration::from_secs(10), async {
                while buf.len() < 16 * 1024 && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
            })
            .await;
            if read.is_err() {
                continue;
            }
            let head = String::from_utf8_lossy(&buf);
            let target = head
                .lines()
                .next()
                .and_then(|line| line.strip_prefix("GET "))
                .and_then(|rest| rest.split(' ').next())
                .unwrap_or("");
            let Some(callback) = parse_callback(target, &self.state) else {
                respond(&mut stream, 404, "Not the Declass sign-in callback.").await;
                continue;
            };
            match &callback {
                Ok(Callback::Code { .. }) => {
                    respond(
                        &mut stream,
                        200,
                        "Signed in with ChatGPT. You can close this tab and return to Declass.",
                    )
                    .await;
                }
                Ok(Callback::Error { .. }) => {
                    respond(
                        &mut stream,
                        200,
                        "ChatGPT plan use wasn't enabled. You can close this tab; Declass explains what to do next.",
                    )
                    .await;
                }
                Err(_) => {
                    // A stale or forged callback: refuse it and keep waiting.
                    respond(
                        &mut stream,
                        400,
                        "This sign-in link has expired. Start again from Declass.",
                    )
                    .await;
                    continue;
                }
            }
            return callback;
        }
    }
}

/// Parses a request target. `None`: not the callback path; `Some(Err)`: the
/// state does not match this sign-in.
fn parse_callback(target: &str, state: &str) -> Option<Result<Callback, ProviderError>> {
    let url = reqwest::Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    if url.path() != CALLBACK_PATH {
        return None;
    }
    let get = |key: &str| {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    };
    if get("state").as_deref() != Some(state) {
        return Some(Err(ProviderError::new(
            ErrorKind::Auth,
            "the sign-in callback's state did not match",
        )));
    }
    if let Some(error) = get("error") {
        return Some(Ok(Callback::Error {
            error,
            description: get("error_description"),
        }));
    }
    Some(match get("code").filter(|c| !c.is_empty()) {
        Some(code) => Ok(Callback::Code {
            code,
            client_id: get("client_id"),
        }),
        None => Err(ProviderError::new(
            ErrorKind::Auth,
            "the sign-in callback carried no code",
        )),
    })
}

async fn respond(stream: &mut tokio::net::TcpStream, status: u16, message: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Declass</title><body style=\"font: 16px system-ui, sans-serif; margin: 15vh auto; max-width: 32em; padding: 0 16px\"><p>{}</p></body>",
        html_escape(message)
    );
    let reply = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn split_scopes(scope: Option<&str>) -> Vec<String> {
    let mut scopes: Vec<String> = scope
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug)]
enum TokenError {
    /// The server answered with an OAuth error code.
    OAuth { code: String, status: u16 },
    /// Anything else: the request failed or the answer was unusable.
    Other(ProviderError),
}

impl TokenError {
    fn into_provider_error(self) -> ProviderError {
        match self {
            TokenError::OAuth { code, status } => {
                let kind = if status >= 500 {
                    ErrorKind::Status(status)
                } else {
                    ErrorKind::Auth
                };
                let mut e = ProviderError::new(kind, format!("ChatGPT sign-in error: {code}"));
                e.http_status = Some(status);
                e
            }
            TokenError::Other(e) => e,
        }
    }
}

async fn token_request(
    client: &crate::http::Client,
    url: &str,
    form: &[(&str, &str)],
) -> Result<TokenResponse, TokenError> {
    let response = client
        .post(url)
        .map_err(TokenError::Other)?
        .form(form)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| TokenError::Other(ProviderError::new(ErrorKind::Transport, e.to_string())))?;
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .map_err(|e| TokenError::Other(ProviderError::new(ErrorKind::Transport, e.to_string())))?;
    if (200..300).contains(&status) {
        return serde_json::from_slice(&body).map_err(|e| {
            TokenError::Other(ProviderError::new(
                ErrorKind::Malformed,
                format!("unexpected token response: {e}"),
            ))
        });
    }
    let code = serde_json::from_slice::<Value>(&body).ok().and_then(|v| {
        v.get("error")
            .and_then(|e| e.as_str().or_else(|| e.get("code").and_then(Value::as_str)))
            .map(str::to_owned)
    });
    match code {
        Some(code) => Err(TokenError::OAuth { code, status }),
        None => {
            let kind = if status >= 500 || status == 429 {
                ErrorKind::Status(status)
            } else {
                ErrorKind::Auth
            };
            let mut e = ProviderError::new(
                kind,
                format!("ChatGPT token endpoint answered HTTP {status}"),
            );
            e.http_status = Some(status);
            Err(TokenError::Other(e))
        }
    }
}

/// The parts of the OpenID configuration Declass uses.
#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
}

impl Discovery {
    async fn fetch(issuer: &Issuer, client: &crate::http::Client) -> Result<Self, ProviderError> {
        let d: Discovery = get_json(client, &issuer.discovery_url()).await?;
        if d.issuer.trim_end_matches('/') != issuer.as_str() {
            return Err(ProviderError::new(
                ErrorKind::Auth,
                "the OpenID configuration names a different issuer",
            ));
        }
        Ok(d)
    }

    /// The signing keys. The JWKS must be served by the issuer's own origin;
    /// the pinned client refuses any other.
    async fn jwks(&self, client: &crate::http::Client) -> Result<Value, ProviderError> {
        get_json(client, &self.jwks_uri).await
    }
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &crate::http::Client,
    url: &str,
) -> Result<T, ProviderError> {
    let response = client
        .get(url)?
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| ProviderError::new(ErrorKind::Transport, e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let mut e = ProviderError::new(
            ErrorKind::Status(status),
            format!("GET {url}: HTTP {status}"),
        );
        e.http_status = Some(status);
        return Err(e);
    }
    response
        .json()
        .await
        .map_err(|e| ProviderError::new(ErrorKind::Malformed, format!("GET {url}: {e}")))
}

/// What a verified ID token must say.
pub struct IdExpectations<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// Unix seconds.
    pub now: i64,
}

/// The verified identity in an ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdClaims {
    pub sub: String,
    pub email: Option<String>,
}

fn bad_token(why: &str) -> ProviderError {
    ProviderError::new(
        ErrorKind::Auth,
        format!("the ChatGPT ID token was rejected: {why}"),
    )
}

/// Verifies an RS256 ID token against a JWKS and the expected issuer,
/// audience, nonce and lifetime.
pub fn verify_id_token(
    token: &str,
    jwks: &Value,
    expect: &IdExpectations<'_>,
) -> Result<IdClaims, ProviderError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad_token("not a JWT"));
    };
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| bad_token("bad encoding"))
    };
    let header: Value = serde_json::from_slice(&decode(h)?).map_err(|_| bad_token("bad header"))?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(bad_token("unsupported signature algorithm"));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| bad_token("no signing keys published"))?;
    let rsa: Vec<&Value> = keys
        .iter()
        .filter(|k| k.get("kty").and_then(Value::as_str) == Some("RSA"))
        .filter(|k| {
            k.get("use")
                .and_then(Value::as_str)
                .is_none_or(|u| u == "sig")
        })
        .collect();
    let key = match kid {
        Some(kid) => rsa
            .iter()
            .find(|k| k.get("kid").and_then(Value::as_str) == Some(kid)),
        None if rsa.len() == 1 => rsa.first(),
        None => None,
    }
    .ok_or_else(|| bad_token("signed with an unknown key"))?;
    let component = |name: &str| {
        key.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| bad_token("malformed signing key"))
            .and_then(decode)
    };
    let public = ring::signature::RsaPublicKeyComponents {
        n: component("n")?,
        e: component("e")?,
    };
    public
        .verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            format!("{h}.{p}").as_bytes(),
            &decode(s)?,
        )
        .map_err(|_| bad_token("the signature does not verify"))?;
    let claims: Value = serde_json::from_slice(&decode(p)?).map_err(|_| bad_token("bad claims"))?;
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("iss").map(|i| i.trim_end_matches('/')) != Some(expect.issuer.trim_end_matches('/')) {
        return Err(bad_token("wrong issuer"));
    }
    let audience_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == expect.client_id,
        Some(Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(expect.client_id)),
        _ => false,
    };
    if !audience_ok {
        return Err(bad_token("issued for a different client"));
    }
    match claims.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp + CLOCK_SKEW > expect.now => {}
        _ => return Err(bad_token("expired")),
    }
    if text("nonce") != Some(expect.nonce) {
        return Err(bad_token("nonce mismatch"));
    }
    let sub = text("sub")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad_token("no subject"))?;
    Ok(IdClaims {
        sub: sub.to_owned(),
        email: text("email").map(str::to_owned),
    })
}

/// The result of signing out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOut {
    /// The account that was signed in, if one was.
    pub account: Option<String>,
    /// OpenAI confirmed the refresh token is revoked.
    pub revoked: bool,
}

/// Signs out: revokes the renewable session at OpenAI, then clears the local
/// tokens. The registration is kept for the next sign-in unless `forget`.
pub async fn sign_out(
    store: &Store,
    issuer: &Issuer,
    forget: bool,
) -> Result<SignedOut, ProviderError> {
    let Some(mut account) = store.account()? else {
        return Ok(SignedOut {
            account: None,
            revoked: false,
        });
    };
    let label = account.signed_in().then(|| account.label());
    let mut revoked = false;
    if let Some(refresh) = account.refresh_token.clone() {
        revoked = revoke(issuer, &account.client_id, &refresh).await.is_ok();
    }
    let _lock = store.lock().await?;
    if forget {
        std::fs::remove_file(store.account_path())
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|e| io_error(&store.account_path(), e))?;
    } else {
        account.clear_tokens();
        store.save_account(&account)?;
    }
    Ok(SignedOut {
        account: label,
        revoked,
    })
}

async fn revoke(issuer: &Issuer, client_id: &str, refresh: &str) -> Result<(), ProviderError> {
    let client = issuer.client()?;
    let discovery = Discovery::fetch(issuer, &client).await?;
    let endpoint = discovery.revocation_endpoint.ok_or_else(|| {
        ProviderError::new(ErrorKind::Malformed, "no revocation endpoint published")
    })?;
    let mut last = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(500 * u64::from(attempt))).await;
        }
        let sent = client
            .post(&endpoint)?
            .form(&[
                ("token", refresh),
                ("token_type_hint", "refresh_token"),
                ("client_id", client_id),
            ])
            .send()
            .await;
        match sent {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) if r.status().is_server_error() => {
                last = Some(ProviderError::new(
                    ErrorKind::Status(r.status().as_u16()),
                    "revocation failed",
                ));
            }
            Ok(r) => {
                return Err(ProviderError::new(
                    ErrorKind::Status(r.status().as_u16()),
                    "revocation refused",
                ));
            }
            Err(e) => last = Some(ProviderError::new(ErrorKind::Transport, e.to_string())),
        }
    }
    Err(last.unwrap_or_else(|| ProviderError::new(ErrorKind::Transport, "revocation failed")))
}

/// The access token source for requests billed to the ChatGPT plan: reads the
/// saved account, renews the token before it expires and after a refusal.
#[derive(Debug)]
pub struct PlanSession {
    store: Store,
    issuer: Issuer,
    cached: tokio::sync::Mutex<Option<Account>>,
}

impl PlanSession {
    pub fn new(store: Store, issuer: Issuer) -> Self {
        Self {
            store,
            issuer,
            cached: tokio::sync::Mutex::new(None),
        }
    }

    async fn current(&self) -> Result<String, ProviderError> {
        let mut cached = self.cached.lock().await;
        if cached.is_none() {
            *cached = self.store.account()?;
        }
        let account = usable(cached.as_ref())?;
        if account.expires_at.unwrap_or(0) - RENEW_BEFORE > now()
            && let Some(token) = &account.access_token
        {
            return Ok(token.clone());
        }
        let renewed = self.renew(account).await?;
        let token = renewed.access_token.clone().unwrap_or_default();
        *cached = Some(renewed);
        Ok(token)
    }

    /// Renews the access token under the refresh lock. Another process may
    /// have renewed it already: the saved account is read again first.
    async fn renew(&self, ours: &Account) -> Result<Account, ProviderError> {
        let _lock = self.store.lock().await?;
        let mut account = self.store.account()?.unwrap_or_else(|| ours.clone());
        usable(Some(&account))?;
        if account.access_token != ours.access_token
            && account.expires_at.unwrap_or(0) - RENEW_BEFORE > now()
        {
            return Ok(account);
        }
        let refresh = account.refresh_token.clone().unwrap_or_default();
        let client = self.issuer.client()?;
        let result = token_request(
            &client,
            &self.issuer.token_url(),
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &account.client_id),
                ("refresh_token", &refresh),
                ("resource", API_BASE),
            ],
        )
        .await;
        match result {
            Ok(tokens) => {
                account.access_token = Some(tokens.access_token);
                if let Some(r) = tokens.refresh_token {
                    account.refresh_token = Some(r);
                }
                if let Some(id) = tokens.id_token {
                    account.id_token = Some(id);
                }
                account.expires_at = Some(now() + tokens.expires_in.unwrap_or(3600));
                if tokens.scope.is_some() {
                    account.scopes = split_scopes(tokens.scope.as_deref());
                }
                account.saved_at = Some(now());
                self.store.save_account(&account)?;
                usable(Some(&account))?;
                Ok(account)
            }
            Err(TokenError::OAuth { code, status }) if DEAD_REFRESH.contains(&code.as_str()) => {
                account.clear_tokens();
                self.store.save_account(&account)?;
                let mut e = ProviderError::new(
                    ErrorKind::Auth,
                    format!("the ChatGPT sign-in has ended ({code}); {SIGN_IN_AGAIN}"),
                );
                e.http_status = Some(status);
                Err(e)
            }
            Err(TokenError::OAuth { code, status }) if code == "invalid_client" => {
                let mut e = ProviderError::new(
                    ErrorKind::Auth,
                    "OpenAI no longer accepts this Declass registration (invalid_client); run `declass logout chatgpt --forget`, then `declass login chatgpt`",
                );
                e.http_status = Some(status);
                Err(e)
            }
            // Temporary failures keep the credentials (they are retried).
            Err(other) => Err(other.into_provider_error()),
        }
    }
}

/// The account, if it can make plan requests.
fn usable(account: Option<&Account>) -> Result<&Account, ProviderError> {
    let account = account.filter(|a| a.signed_in()).ok_or_else(|| {
        ProviderError::new(
            ErrorKind::Auth,
            format!("not signed in with ChatGPT; {SIGN_IN_AGAIN}"),
        )
    })?;
    if !account.plan_enabled() {
        return Err(ProviderError::new(
            ErrorKind::Auth,
            format!(
                "ChatGPT plan use isn't enabled for {}; {SIGN_IN_AGAIN} and allow it, or use an API key (`declass config preset openai`)",
                account.label()
            ),
        ));
    }
    Ok(account)
}

impl TokenSource for PlanSession {
    fn token(&self) -> BoxFuture<'_, Result<String, ProviderError>> {
        Box::pin(self.current())
    }

    fn refused(&self, token: &str) -> BoxFuture<'_, Result<(), ProviderError>> {
        let token = token.to_owned();
        Box::pin(async move {
            let mut cached = self.cached.lock().await;
            if let Some(account) = cached.as_mut()
                && account.access_token.as_deref() == Some(token.as_str())
            {
                // Renew on the next request even though it has not expired.
                account.expires_at = Some(0);
            }
            Ok(())
        })
    }
}

/// A model the signed-in account may use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanModel {
    pub slug: String,
    pub display_name: String,
}

/// The account's model choices (`GET /v1/models`, those meant for display),
/// in the server's order.
pub async fn list_models(token: &str, base: &str) -> Result<Vec<PlanModel>, ProviderError> {
    let endpoint = ApprovedEndpoint::new(base, &Role::Frontier)?;
    let client = crate::http::client(&endpoint, Duration::from_secs(10), Some(HTTP_TIMEOUT))
        .map_err(|e| ProviderError::new(ErrorKind::Transport, e.to_string()))?;
    let url = format!("{}/models", base.trim_end_matches('/'));
    let response = client
        .get(&url)?
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| ProviderError::new(ErrorKind::Transport, e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let kind = if matches!(status, 401 | 403) {
            ErrorKind::Auth
        } else {
            ErrorKind::Status(status)
        };
        let mut e = ProviderError::new(kind, format!("listing ChatGPT plan models: HTTP {status}"));
        e.http_status = Some(status);
        return Err(e);
    }
    let listing: Value = response
        .json()
        .await
        .map_err(|e| ProviderError::new(ErrorKind::Malformed, e.to_string()))?;
    Ok(plan_models(&listing))
}

/// The displayable models in a plan listing (`models[]` with `visibility`).
pub fn plan_models(listing: &Value) -> Vec<PlanModel> {
    listing
        .get("models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|m| m.get("visibility").and_then(Value::as_str) == Some("list"))
        .filter_map(|m| {
            let slug = m.get("slug").and_then(Value::as_str)?.to_owned();
            let display_name = m
                .get("display_name")
                .and_then(Value::as_str)
                .unwrap_or(&slug)
                .to_owned();
            Some(PlanModel { slug, display_name })
        })
        .collect()
}

#[cfg(test)]
mod tests;
