// SPDX-License-Identifier: GPL-3.0-or-later
//! HTTP client for every wire dialect: streaming, deadlines and retries.

use crate::dialect::Dialect;
use crate::endpoint::ApprovedEndpoint;
use crate::error::{ErrorKind, ProviderError, is_context_overflow};
use crate::live::{Differ, StreamEvent, StreamTap};
use crate::retry::{backoff, parse_retry_after};
use crate::sse::SseDecoder;
use crate::types::{AttemptUsage, Request, Response, Usage, UsageStatus, estimate_tokens};
use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::Instant;

/// The raw HTTP exchange, abstracted so tests can script provider behaviour.
pub struct HttpReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: BoxStream<'static, Result<Bytes, String>>,
}

pub trait Transport: Send + Sync {
    fn post(
        &self,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> BoxFuture<'static, Result<HttpReply, ProviderError>>;
}

pub struct ReqwestTransport {
    client: crate::http::Client,
}

impl ReqwestTransport {
    pub fn new(endpoint: ApprovedEndpoint, connect_timeout: Duration) -> Self {
        Self {
            client: crate::http::client(&endpoint, connect_timeout, None).expect("reqwest client"),
        }
    }
}

impl Transport for ReqwestTransport {
    fn post(
        &self,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> BoxFuture<'static, Result<HttpReply, ProviderError>> {
        let mut rb = match self.client.post(&url) {
            Ok(rb) => rb.body(body),
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        for (k, v) in headers {
            rb = rb.header(k, v);
        }
        Box::pin(async move {
            let resp = rb
                .send()
                .await
                .map_err(|e| ProviderError::new(ErrorKind::Transport, e.to_string()))?;
            let status = resp.status().as_u16();
            let headers = resp
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_owned(),
                        v.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect();
            let body = resp
                .bytes_stream()
                .map(|r| r.map_err(|e| e.to_string()))
                .boxed();
            Ok(HttpReply {
                status,
                headers,
                body,
            })
        })
    }
}

/// A bearer credential that can change while it is in use: an OAuth access
/// token that expires and is renewed (ChatGPT plan usage). The provider asks
/// for the token before every attempt, so a retry after expiry uses the
/// renewed one, and reports a token the server refused (HTTP 401) so the
/// source renews it before the next attempt.
pub trait TokenSource: Send + Sync + std::fmt::Debug {
    /// A token that is valid now, renewed first when it is about to expire.
    fn token(&self) -> BoxFuture<'_, Result<String, ProviderError>>;
    /// The server refused `token`; renew it if it is still the current one.
    fn refused(&self, token: &str) -> BoxFuture<'_, Result<(), ProviderError>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// Receives only gated, boundary-checked content.
    Frontier,
    /// Reads sensitive content; must be loopback or an owner-allowlisted host,
    /// and a remote host needs TLS unless the owner allows plain HTTP.
    Local {
        allowlist: Vec<String>,
        allow_plaintext: bool,
    },
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Endpoint base, e.g. `https://api.z.ai/api/coding/paas/v4` or `http://127.0.0.1:8080/v1`.
    pub base_url: String,
    pub model: String,
    /// The API the endpoint speaks (Chat Completions unless set).
    pub dialect: Dialect,
    /// Environment variable holding the bearer token (never the token itself).
    pub api_key_env: Option<String>,
    /// A renewable bearer token used instead of `api_key_env` (sign-in with a
    /// subscription).
    pub token: Option<Arc<dyn TokenSource>>,
    /// Requests are ChatGPT plan usage: the Responses body is adapted to that
    /// route's limits ([`crate::responses::for_chatgpt_plan`]).
    pub chatgpt_plan: bool,
    pub headers: Vec<(String, String)>,
    pub role: Role,
    /// Deadline for the first response byte (local prefill can be slow).
    pub first_byte_timeout: Duration,
    /// Deadline between stream chunks once output has started.
    pub idle_timeout: Duration,
    /// Attempts per request; `None` (the default) retries infrastructure
    /// failures in place until `deadline` or `cancel` stops them.
    pub max_attempts: Option<u32>,
    /// When retrying must stop: the run's wall-clock budget. A request still
    /// failing then ends with [`ErrorKind::Deadline`]; an attempt in flight is
    /// cut off at it.
    pub deadline: Option<Instant>,
    /// Set when the run is interrupted; retries stop with [`ErrorKind::Cancelled`].
    pub cancel: Option<Arc<AtomicBool>>,
    /// Multiplier on backoff delays (1.0 in production; 0.0 in tests).
    pub backoff_scale: f64,
    /// Recover a tool call written as text (useful for some local models).
    pub recover_text_tool_calls: bool,
}

impl ProviderConfig {
    pub fn new(base_url: &str, model: &str, role: Role) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            model: model.to_owned(),
            dialect: Dialect::Chat,
            api_key_env: None,
            token: None,
            chatgpt_plan: false,
            headers: Vec::new(),
            recover_text_tool_calls: matches!(role, Role::Local { .. }),
            role,
            first_byte_timeout: Duration::from_secs(600),
            idle_timeout: Duration::from_secs(180),
            max_attempts: None,
            deadline: None,
            cancel: None,
            backoff_scale: 1.0,
        }
    }
}

/// How often a retry wait looks at the cancel flag.
const CANCEL_POLL: Duration = Duration::from_millis(200);

/// A peer controls Retry-After. Bound extreme values before scaling or adding
/// them to an Instant so a rate-limit response cannot panic the client or
/// suspend an unbudgeted request indefinitely. Ordinary delays remain intact.
const MAX_SERVER_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

fn deadline_error(last: &str) -> ProviderError {
    ProviderError::new(
        ErrorKind::Deadline,
        format!("the run's wall-clock budget ended while retrying ({last})"),
    )
}

/// A model endpoint speaking one of the [`Dialect`]s (the name predates the
/// other dialects).
pub struct ChatProvider {
    config: ProviderConfig,
    transport: Box<dyn Transport>,
}

impl ChatProvider {
    pub fn new(
        config: ProviderConfig,
        transport: Box<dyn Transport>,
    ) -> Result<Self, ProviderError> {
        ApprovedEndpoint::new(&config.base_url, &config.role)?;
        Ok(Self { config, transport })
    }

    pub fn with_reqwest(config: ProviderConfig) -> Result<Self, ProviderError> {
        let endpoint = ApprovedEndpoint::new(&config.base_url, &config.role)?;
        Self::new(
            config,
            Box::new(ReqwestTransport::new(endpoint, Duration::from_secs(20))),
        )
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    /// The request body exactly as [`ChatProvider::create`] sends it, for the
    /// outbound gate to check and audit.
    pub fn body(&self, req: &Request) -> Value {
        let mut body = self
            .config
            .dialect
            .build_body(&self.config.model, req, true);
        if self.config.chatgpt_plan && self.config.dialect == Dialect::Responses {
            crate::responses::for_chatgpt_plan(&mut body);
        }
        body
    }

    /// The request headers and the bearer token they carry, if it came from
    /// the [`TokenSource`].
    async fn headers(&self) -> Result<(Vec<(String, String)>, Option<String>), ProviderError> {
        let dialect = self.config.dialect;
        let mut h = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("accept".to_owned(), "text/event-stream".to_owned()),
        ];
        h.extend(dialect.fixed_headers());
        let mut token = None;
        if let Some(source) = &self.config.token {
            let t = source.token().await?;
            h.extend(dialect.auth_headers(&t));
            token = Some(t);
        } else if let Some(var) = &self.config.api_key_env {
            let key = std::env::var(var)
                .map_err(|_| ProviderError::new(ErrorKind::Auth, format!("{var} is not set")))?;
            h.extend(dialect.auth_headers(&key));
        }
        h.extend(self.config.headers.iter().cloned());
        Ok((h, token))
    }

    /// Sends `req`, retrying transient failures in place. Only the deadline,
    /// the cancel flag or `max_attempts` end the retries; errors a fresh attempt
    /// cannot fix (credentials, an invalid request) are returned at once.
    ///
    /// Estimated usage of attempts that failed after output started is kept
    /// apart from the billed usage: in `Response::attempts` on success, and in
    /// `ProviderError::failed_usage` when the request fails in the end.
    pub async fn create(&self, req: &Request) -> Result<Response, ProviderError> {
        self.create_with(req, None).await
    }

    /// [`ChatProvider::create`], with `tap` watching each attempt's stream as
    /// it arrives (see [`crate::live`]). The request and the response are the
    /// same as without it.
    pub async fn create_with(
        &self,
        req: &Request,
        tap: Option<&dyn StreamTap>,
    ) -> Result<Response, ProviderError> {
        let mut attempts = AttemptUsage::default();
        let mut in_flight = false;
        self.retrying(req, &mut attempts, &mut in_flight, tap)
            .await
            .map_err(|mut e| {
                e.failed_usage = attempts.estimated_failed;
                e
            })
    }

    async fn retrying(
        &self,
        req: &Request,
        attempts: &mut AttemptUsage,
        in_flight: &mut bool,
        tap: Option<&dyn StreamTap>,
    ) -> Result<Response, ProviderError> {
        let body = serde_json::to_vec(&self.body(req))
            .map_err(|e| ProviderError::new(ErrorKind::Malformed, e.to_string()))?;
        let url = format!("{}{}", self.config.base_url, self.config.dialect.path());
        let started = Instant::now();
        // A refused renewable token is renewed once per request.
        let mut renewed = false;
        let mut token_failures = 0u32;
        loop {
            if self.cancelled() {
                return Err(ProviderError::new(ErrorKind::Cancelled, "interrupted"));
            }
            let (headers, token) = match self.headers().await {
                Ok(h) => h,
                // Renewing a token can fail for the same transient reasons
                // as a request (the auth server unreachable or overloaded).
                Err(err) if err.is_retryable() => {
                    token_failures += 1;
                    if self
                        .config
                        .max_attempts
                        .is_some_and(|max| token_failures >= max)
                    {
                        return Err(err);
                    }
                    let jitter = f64::from(started.elapsed().subsec_nanos() % 1000) / 1000.0;
                    let delay =
                        backoff(token_failures - 1, jitter).mul_f64(self.config.backoff_scale);
                    self.pause(delay, &err).await?;
                    continue;
                }
                Err(err) => return Err(err),
            };
            attempts.attempts += 1;
            if let Some(tap) = tap {
                tap.event(StreamEvent::Attempt(attempts.attempts));
            }
            let attempt = self.attempt(&url, &headers, &body, req, tap);
            *in_flight = true;
            let result = match self.config.deadline {
                Some(at) => match tokio::time::timeout_at(at, attempt).await {
                    Ok(r) => r,
                    Err(_) => return Err(deadline_error("the request was still in flight")),
                },
                None => attempt.await,
            };
            *in_flight = false;
            match result {
                Ok(mut response) => {
                    attempts.billed = response.usage;
                    response.attempts = *attempts;
                    return Ok(response);
                }
                Err(err) => {
                    if let (Some(source), Some(token)) = (&self.config.token, &token)
                        && err.http_status == Some(401)
                        && !renewed
                    {
                        renewed = true;
                        source.refused(token).await?;
                        continue;
                    }
                    if err.output_started {
                        // The prompt was processed and some output generated.
                        let failed = &mut attempts.estimated_failed;
                        failed.input += estimate_tokens(body.len());
                        failed.output += estimate_tokens(err.partial_output_bytes);
                        failed.status = UsageStatus::Estimated;
                    }
                    let capped = self
                        .config
                        .max_attempts
                        .is_some_and(|max| attempts.attempts >= max);
                    if !err.is_retryable() || capped {
                        return Err(err);
                    }
                    let jitter = f64::from(started.elapsed().subsec_nanos() % 1000) / 1000.0;
                    let delay = err
                        .retry_after
                        .map(|delay| delay.min(MAX_SERVER_RETRY_AFTER))
                        .unwrap_or_else(|| backoff(attempts.attempts - 1, jitter))
                        .mul_f64(self.config.backoff_scale);
                    self.pause(delay, &err).await?;
                }
            }
        }
    }

    fn cancelled(&self) -> bool {
        self.config
            .cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::SeqCst))
    }

    /// Waits `delay` before the next attempt, watching the cancel flag; fails
    /// when the deadline comes first.
    async fn pause(&self, delay: Duration, last: &ProviderError) -> Result<(), ProviderError> {
        let wake = Instant::now() + delay;
        if let Some(at) = self.config.deadline
            && wake >= at
        {
            tokio::time::sleep_until(at).await;
            return Err(deadline_error(&last.to_string()));
        }
        loop {
            if self.cancelled() {
                return Err(ProviderError::new(ErrorKind::Cancelled, "interrupted"));
            }
            let now = Instant::now();
            if now >= wake {
                return Ok(());
            }
            let step = if self.config.cancel.is_some() {
                (wake - now).min(CANCEL_POLL)
            } else {
                wake - now
            };
            tokio::time::sleep(step).await;
        }
    }

    async fn attempt(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        req: &Request,
        tap: Option<&dyn StreamTap>,
    ) -> Result<Response, ProviderError> {
        let result = self.streamed(url, headers, body, req, tap).await;
        if let Some(tap) = tap {
            tap.event(StreamEvent::End);
        }
        result
    }

    async fn streamed(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        req: &Request,
        tap: Option<&dyn StreamTap>,
    ) -> Result<Response, ProviderError> {
        let reply = tokio::time::timeout(
            self.config.first_byte_timeout,
            self.transport
                .post(url.to_owned(), headers.to_vec(), body.to_vec()),
        )
        .await
        .map_err(|_| {
            ProviderError::new(
                ErrorKind::Timeout,
                "no response headers before the first-byte deadline",
            )
        })??;
        let mut stream = reply.body;
        if !(200..300).contains(&reply.status) {
            let mut text = Vec::new();
            while let Ok(Some(Ok(chunk))) =
                tokio::time::timeout(self.config.idle_timeout, stream.next()).await
            {
                text.extend_from_slice(&chunk);
                if text.len() > 64 * 1024 {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&text).into_owned();
            let plan = serde_json::from_str::<Value>(&text)
                .ok()
                .as_ref()
                .and_then(crate::responses::error_code)
                .and_then(crate::responses::plan_error_kind);
            let from_plan = plan.is_some();
            let kind = match (plan, reply.status) {
                (Some(kind), _) => kind,
                (None, 401 | 403) => ErrorKind::Auth,
                (None, 400 | 413) if is_context_overflow(&text) => ErrorKind::ContextOverflow,
                (None, code) => ErrorKind::Status(code),
            };
            let message = match crate::responses::plan_error_hint(&kind).filter(|_| from_plan) {
                Some(hint) => format!("{text} ({hint})"),
                None => text,
            };
            let mut e = ProviderError::new(kind, message);
            e.http_status = Some(reply.status);
            e.retry_after = reply
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))
                .and_then(|(_, v)| parse_retry_after(v, time::OffsetDateTime::now_utc()));
            return Err(e);
        }
        let mut decoder = SseDecoder::default();
        let mut assembler = self.config.dialect.assembler();
        let mut differ = Differ::default();
        let mut first = true;
        loop {
            let deadline = if first {
                self.config.first_byte_timeout
            } else {
                self.config.idle_timeout
            };
            let next = tokio::time::timeout(deadline, stream.next()).await;
            let chunk = match next {
                Err(_) => {
                    let mut e = ProviderError::new(ErrorKind::Timeout, "stream stalled");
                    e.output_started = assembler.output_bytes() > 0;
                    e.partial_output_bytes = assembler.output_bytes();
                    return Err(e);
                }
                Ok(None) => break,
                Ok(Some(Err(msg))) => {
                    let mut e = ProviderError::new(ErrorKind::Transport, msg);
                    e.output_started = assembler.output_bytes() > 0;
                    e.partial_output_bytes = assembler.output_bytes();
                    return Err(e);
                }
                Ok(Some(Ok(bytes))) => bytes,
            };
            first = false;
            for event in decoder.push(&chunk) {
                assembler.apply(&event.data)?;
            }
            if let Some(tap) = tap {
                differ.diff(&assembler.view(), tap);
            }
        }
        for event in decoder.finish() {
            assembler.apply(&event.data)?;
        }
        if let Some(tap) = tap {
            differ.finish(&assembler.view(), tap);
        }
        let recover = self
            .config
            .recover_text_tool_calls
            .then_some(req.tools.as_slice());
        assembler.finish(&self.config.model, recover)
    }
}

/// Sum of billed usage across responses, for ledgers.
pub fn sum_usage<'a>(responses: impl IntoIterator<Item = &'a Usage>) -> Usage {
    responses.into_iter().fold(Usage::default(), |mut acc, u| {
        acc.input += u.input;
        acc.cache_read += u.cache_read;
        acc.cache_write += u.cache_write;
        acc.output += u.output;
        acc.reasoning += u.reasoning;
        acc
    })
}
