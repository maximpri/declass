// SPDX-License-Identifier: GPL-3.0-or-later
//! Sign in with ChatGPT against a scripted authorization server: registration,
//! ID-token checks, renewal, reauthorization and sign-out.

use super::*;
use serde_json::json;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::net::{TcpListener, TcpStream};

/// A 2048-bit RSA signing key generated once per test run, so no private key
/// is committed.
fn keypair() -> &'static ring::signature::RsaKeyPair {
    static KEY: OnceLock<ring::signature::RsaKeyPair> = OnceLock::new();
    KEY.get_or_init(generate_rsa_2048)
}

fn generate_rsa_2048() -> ring::signature::RsaKeyPair {
    use num_bigint::BigUint;
    let e = BigUint::from(65_537u32);
    let one = BigUint::from(1u32);
    loop {
        let (a, b) = (random_prime(1024), random_prime(1024));
        // ring wants q < p.
        let (p, q) = match a.cmp(&b) {
            std::cmp::Ordering::Greater => (a, b),
            std::cmp::Ordering::Less => (b, a),
            std::cmp::Ordering::Equal => continue,
        };
        let n = &p * &q;
        let (p1, q1) = (&p - &one, &q - &one);
        let Some(d) = e.modinv(&(&p1 * &q1)) else {
            continue;
        };
        let components = ring::rsa::KeyPairComponents {
            public_key: ring::rsa::PublicKeyComponents {
                n: n.to_bytes_be(),
                e: e.to_bytes_be(),
            },
            dP: (&d % &p1).to_bytes_be(),
            dQ: (&d % &q1).to_bytes_be(),
            qInv: q.modinv(&p).unwrap().to_bytes_be(),
            d: d.to_bytes_be(),
            p: p.to_bytes_be(),
            q: q.to_bytes_be(),
        };
        return ring::signature::RsaKeyPair::from_components(&components).unwrap();
    }
}

/// A random prime of exactly `bits` bits (top two bits set, so the product of
/// two is exactly twice as long) with `p - 1` coprime to 65537.
fn random_prime(bits: usize) -> num_bigint::BigUint {
    use ring::rand::SecureRandom;
    let small: Vec<u32> = (3..2000u32)
        .filter(|n| (2..*n).take_while(|d| d * d <= *n).all(|d| n % d != 0))
        .collect();
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = vec![0u8; bits / 8];
    loop {
        rng.fill(&mut bytes).unwrap();
        bytes[0] |= 0xC0;
        bytes[bits / 8 - 1] |= 1;
        let c = num_bigint::BigUint::from_bytes_be(&bytes);
        let zero = num_bigint::BigUint::ZERO;
        if small.iter().any(|s| &c % *s == zero) || (&c - 1u32) % 65_537u32 == zero {
            continue;
        }
        if probably_prime(&c) {
            return c;
        }
    }
}

/// Miller-Rabin over the first prime bases; ample for random candidates.
fn probably_prime(n: &num_bigint::BigUint) -> bool {
    use num_bigint::BigUint;
    let one = BigUint::from(1u32);
    let n1 = n - &one;
    let s = n1.trailing_zeros().unwrap();
    let d = &n1 >> s;
    'bases: for a in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29] {
        let mut x = BigUint::from(a).modpow(&d, n);
        if x == one || x == n1 {
            continue;
        }
        for _ in 1..s {
            x = &x * &x % n;
            if x == n1 {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

fn jwks() -> Value {
    let public = ring::signature::RsaPublicKeyComponents::<Vec<u8>>::from(keypair().public());
    json!({"keys": [
        {"kty": "EC", "kid": "other", "crv": "P-256", "x": "AA", "y": "AA"},
        {"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
         "n": URL_SAFE_NO_PAD.encode(&public.n), "e": URL_SAFE_NO_PAD.encode(&public.e)}
    ]})
}

fn sign_jwt(header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let key = keypair();
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

fn id_token(issuer: &str, nonce: &str, sub: &str) -> String {
    sign_jwt(
        &json!({"alg": "RS256", "kid": "test", "typ": "JWT"}),
        &json!({"iss": issuer, "aud": "oaiapp_test", "sub": sub, "email": "dev@example.com",
                "nonce": nonce, "exp": now() + 3600, "iat": now()}),
    )
}

fn expect<'a>(nonce: &'a str) -> IdExpectations<'a> {
    IdExpectations {
        issuer: "https://auth.example",
        client_id: "oaiapp_test",
        nonce,
        now: now(),
    }
}

#[test]
fn pkce_matches_the_rfc_7636_example() {
    assert_eq!(
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let (a, b) = (random_value(), random_value());
    assert_ne!(a, b);
    assert!(
        a.len() >= 43
            && a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    );
}

#[test]
fn a_valid_id_token_verifies_and_every_mismatch_is_refused() {
    let good = id_token("https://auth.example", "n1", "user-1");
    let claims = verify_id_token(&good, &jwks(), &expect("n1")).unwrap();
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.email.as_deref(), Some("dev@example.com"));

    let refused = |token: &str, e: IdExpectations<'_>, why: &str| {
        let err = verify_id_token(token, &jwks(), &e).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Auth);
        assert!(err.message.contains(why), "{why}: {}", err.message);
    };
    refused(&good, expect("n2"), "nonce");
    refused(
        &good,
        IdExpectations {
            client_id: "oaiapp_other",
            ..expect("n1")
        },
        "different client",
    );
    refused(
        &good,
        IdExpectations {
            issuer: "https://evil.example",
            ..expect("n1")
        },
        "issuer",
    );
    refused(
        &good,
        IdExpectations {
            now: now() + 7200,
            ..expect("n1")
        },
        "expired",
    );
    // A changed payload under the original signature.
    let mut parts: Vec<&str> = good.split('.').collect();
    let forged = URL_SAFE_NO_PAD.encode(
        json!({"iss": "https://auth.example", "aud": "oaiapp_test", "sub": "admin",
               "nonce": "n1", "exp": now() + 3600})
        .to_string(),
    );
    parts[1] = &forged;
    refused(&parts.join("."), expect("n1"), "signature");
    // "none" and HMAC tokens are never accepted.
    let none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        good.split('.').nth(1).unwrap()
    );
    refused(&none, expect("n1"), "algorithm");
    let unknown_key = sign_jwt(
        &json!({"alg": "RS256", "kid": "rotated"}),
        &json!({"iss": "https://auth.example", "aud": "oaiapp_test", "sub": "u", "nonce": "n1", "exp": now() + 60}),
    );
    refused(&unknown_key, expect("n1"), "unknown key");
    // An audience list naming the client is accepted.
    let listed = sign_jwt(
        &json!({"alg": "RS256", "kid": "test"}),
        &json!({"iss": "https://auth.example", "aud": ["x", "oaiapp_test"], "sub": "u", "nonce": "n1", "exp": now() + 60}),
    );
    assert!(verify_id_token(&listed, &jwks(), &expect("n1")).is_ok());
}

#[test]
fn callbacks_are_matched_by_path_and_state() {
    assert!(parse_callback("/favicon.ico", "s").is_none());
    assert!(parse_callback("/callback?code=c&state=s", "s").is_none());
    assert!(
        parse_callback("/auth/callback?code=c&state=other", "s")
            .unwrap()
            .is_err()
    );
    assert!(
        parse_callback("/auth/callback?state=s", "s")
            .unwrap()
            .is_err()
    );
    assert_eq!(
        parse_callback("/auth/callback?code=c%2B1&state=s&client_id=oaiapp_x", "s")
            .unwrap()
            .unwrap(),
        Callback::Code {
            code: "c+1".into(),
            client_id: Some("oaiapp_x".into())
        }
    );
    assert_eq!(
        parse_callback("/auth/callback?error=access_denied&state=s", "s")
            .unwrap()
            .unwrap(),
        Callback::Error {
            error: "access_denied".into(),
            description: None
        }
    );
}

#[test]
fn only_listed_models_are_offered() {
    let listing = json!({"models": [
        {"slug": "gpt-6.1-sol", "display_name": "GPT-6.1 Sol", "visibility": "list"},
        {"slug": "internal", "display_name": "Hidden", "visibility": "hide"},
        {"slug": "gpt-6-luna", "visibility": "list"}
    ]});
    assert_eq!(
        plan_models(&listing),
        vec![
            PlanModel {
                slug: "gpt-6.1-sol".into(),
                display_name: "GPT-6.1 Sol".into()
            },
            PlanModel {
                slug: "gpt-6-luna".into(),
                display_name: "gpt-6-luna".into()
            },
        ]
    );
}

#[test]
fn debug_output_never_shows_tokens() {
    let account = Account {
        access_token: Some("secret-access".into()),
        refresh_token: Some("secret-refresh".into()),
        id_token: Some("secret-id".into()),
        ..Account::default()
    };
    let shown = format!("{account:?}");
    assert!(!shown.contains("secret"), "{shown}");
}

type Handler = dyn Fn(&str, &str, &str) -> (u16, String) + Send + Sync;

/// A scripted authorization server on loopback.
struct AuthServer {
    base: String,
    requests: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl AuthServer {
    async fn start(handler: Arc<Handler>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (handler, seen) = (handler.clone(), seen.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head, body) = loop {
                        let n = stream.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).into_owned();
                        if let Some(end) = text.find("\r\n\r\n") {
                            let head = text[..end].to_owned();
                            let length: usize = head
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if buf.len() >= end + 4 + length {
                                break (head, text[end + 4..end + 4 + length].to_owned());
                            }
                        }
                    };
                    let mut words = head.split_whitespace();
                    let (method, path) = (
                        words.next().unwrap_or("").to_owned(),
                        words.next().unwrap_or("").to_owned(),
                    );
                    seen.lock()
                        .unwrap()
                        .push((method.clone(), path.clone(), body.clone()));
                    let (status, reply) = handler(&method, &path, &body);
                    let out = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                    let _ = stream.write_all(out.as_bytes()).await;
                });
            }
        });
        Self { base, requests }
    }

    fn token_requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path, _)| path == "/api/accounts/oauth/token")
            .map(|(_, _, body)| body.clone())
            .collect()
    }
}

fn form(body: &str) -> std::collections::HashMap<String, String> {
    reqwest::Url::parse(&format!("http://x/?{body}"))
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The authorization server's behaviour; `nonce` is set once a sign-in starts.
fn openai_like(
    base: Arc<Mutex<String>>,
    nonce: Arc<Mutex<String>>,
    sub: &'static str,
) -> Arc<Handler> {
    Arc::new(move |method, path, body| {
        let base = base.lock().unwrap().clone();
        match (method, path) {
            ("GET", "/.well-known/openid-configuration") => (
                200,
                json!({
                "issuer": base, "jwks_uri": format!("{base}/jwks"),
                "revocation_endpoint": format!("{base}/oauth/revoke")})
                .to_string(),
            ),
            ("GET", "/jwks") => (200, jwks().to_string()),
            ("POST", "/oauth/revoke") => (200, String::new()),
            ("POST", "/api/accounts/oauth/token") => {
                let f = form(body);
                match f.get("grant_type").map(String::as_str) {
                    Some("authorization_code") if f["client_id"] == "oaiapp_test"
                        && f["code"] == "code-1" && f.contains_key("code_verifier")
                        && f["resource"] == API_BASE =>
                    {
                        (200, json!({"access_token": "at-1", "refresh_token": "rt-1",
                            "id_token": id_token(&base, &nonce.lock().unwrap(), sub),
                            "token_type": "Bearer", "expires_in": 3600,
                            "scope": "chatgpt.tokens.use.direct email offline_access openid profile resource.invoke"}).to_string())
                    }
                    Some("refresh_token") if f["refresh_token"] == "rt-1" && f["client_id"] == "oaiapp_test" => {
                        (200, json!({"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 3600,
                            "scope": "chatgpt.tokens.use.direct email offline_access openid profile resource.invoke"}).to_string())
                    }
                    _ => (400, json!({"error": "invalid_grant"}).to_string()),
                }
            }
            _ => (404, "{}".into()),
        }
    })
}

/// Plays the browser: requests the callback URL and returns the page status.
async fn browser(redirect_uri: &str, query: &str) -> u16 {
    let url = reqwest::Url::parse(redirect_uri).unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", url.port().unwrap()))
        .await
        .unwrap();
    let request = format!(
        "GET {}?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        url.path()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply).await;
    reply
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn temp_store() -> (Store, PathBuf) {
    let root =
        std::env::temp_dir().join(format!("declass-chatgpt-{}", uuid::Uuid::new_v4().simple()));
    (Store::new(root.join("credentials").join("chatgpt")), root)
}

fn query(url: &str) -> std::collections::HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[tokio::test]
async fn sign_in_registers_renews_reauthorizes_and_signs_out() {
    use std::os::unix::fs::PermissionsExt;
    let (base, nonce) = (
        Arc::new(Mutex::new(String::new())),
        Arc::new(Mutex::new(String::new())),
    );
    let server = AuthServer::start(openai_like(base.clone(), nonce.clone(), "user-1")).await;
    *base.lock().unwrap() = server.base.clone();
    let issuer = Issuer::at(&server.base);
    let (store, root) = temp_store();

    // First sign-in registers Declass.
    let pending = begin(&store, &issuer).await.unwrap();
    assert!(pending.registering());
    let q = query(pending.url());
    assert_eq!(q["client_id"], "dynamic_agent_client");
    assert_eq!(q["agent_name_hint"], "Declass");
    assert!(q["ext_agent_host_id"].starts_with("urn:uuid:"));
    assert!(
        q["redirect_uri"].starts_with("http://127.0.0.1:")
            && q["redirect_uri"].ends_with("/auth/callback")
    );
    assert_eq!(q["scope"], SCOPES);
    assert_eq!(q["resource"], API_BASE);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["code_challenge"], pkce_challenge(&pending.verifier));
    assert!(!q.contains_key("id_token_hint"));
    *nonce.lock().unwrap() = pending.nonce.clone();
    let (redirect, state) = (pending.redirect_uri.clone(), pending.state.clone());
    let browse = tokio::spawn(async move {
        // A stale tab is refused; the real callback completes the sign-in.
        assert_eq!(browser(&redirect, "code=old&state=stale").await, 400);
        assert_eq!(
            browser(
                &redirect,
                &format!("code=code-1&state={state}&client_id=oaiapp_test")
            )
            .await,
            200
        );
    });
    let signed = pending.finish(Duration::from_secs(10)).await.unwrap();
    browse.await.unwrap();
    assert!(signed.registered);
    assert_eq!(signed.account.client_id, "oaiapp_test");
    assert_eq!(signed.account.subject, "user-1");
    assert_eq!(signed.account.email.as_deref(), Some("dev@example.com"));
    assert!(signed.account.plan_enabled());
    let file = store.dir().join("account.json");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!format!("{:?}", signed.account).contains("rt-1"));

    // The token is used until it is refused, then renewed once.
    let session = PlanSession::new(store.clone(), issuer.clone());
    assert_eq!(session.token().await.unwrap(), "at-1");
    session.refused("at-1").await.unwrap();
    assert_eq!(session.token().await.unwrap(), "at-2");
    let saved = store.account().unwrap().unwrap();
    assert_eq!(saved.refresh_token.as_deref(), Some("rt-2"));
    let refreshes: Vec<_> = server
        .token_requests()
        .into_iter()
        .filter(|b| b.contains("refresh_token"))
        .collect();
    assert_eq!(refreshes.len(), 1);
    assert!(!refreshes[0].contains("dynamic_agent_client") && !refreshes[0].contains("scope="));
    // Another session reads the renewed token from disk instead of refreshing.
    let other = PlanSession::new(store.clone(), issuer.clone());
    assert_eq!(other.token().await.unwrap(), "at-2");
    assert_eq!(server.token_requests().len(), 2);

    // Signing in again reuses the registration.
    let again = begin(&store, &issuer).await.unwrap();
    assert!(!again.registering());
    let q = query(again.url());
    assert_eq!(q["client_id"], "oaiapp_test");
    assert!(!q.contains_key("agent_name_hint"));
    assert_eq!(q["login_hint"], "dev@example.com");
    assert!(q.contains_key("id_token_hint"));
    assert!(!query(again.display_url()).contains_key("id_token_hint"));
    assert_eq!(q["ext_agent_host_id"], signed.account.ext_agent_host_id);
    drop(again);

    // Signing out revokes, clears the tokens and keeps the registration.
    let out = sign_out(&store, &issuer, false).await.unwrap();
    assert_eq!(
        out,
        SignedOut {
            account: Some("dev@example.com".into()),
            revoked: true
        }
    );
    let kept = store.account().unwrap().unwrap();
    assert!(!kept.signed_in() && kept.id_token.is_none());
    assert_eq!(kept.client_id, "oaiapp_test");
    let err = PlanSession::new(store.clone(), issuer.clone())
        .token()
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Auth);
    assert!(err.message.contains("declass login chatgpt"));
    let revoke = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .find(|(_, p, _)| p == "/oauth/revoke")
        .cloned()
        .unwrap();
    let f = form(&revoke.2);
    assert_eq!(
        (
            f["token"].as_str(),
            f["token_type_hint"].as_str(),
            f["client_id"].as_str()
        ),
        ("rt-2", "refresh_token", "oaiapp_test")
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_declined_sign_in_saves_nothing() {
    let (base, nonce) = (
        Arc::new(Mutex::new(String::new())),
        Arc::new(Mutex::new(String::new())),
    );
    let server = AuthServer::start(openai_like(base.clone(), nonce, "user-1")).await;
    *base.lock().unwrap() = server.base.clone();
    let (store, root) = temp_store();
    let pending = begin(&store, &Issuer::at(&server.base)).await.unwrap();
    let (redirect, state) = (pending.redirect_uri.clone(), pending.state.clone());
    tokio::spawn(
        async move { browser(&redirect, &format!("error=access_denied&state={state}")).await },
    );
    let err = pending.finish(Duration::from_secs(10)).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Auth);
    assert!(err.message.contains("isn't enabled"), "{}", err.message);
    assert!(store.account().unwrap().is_none());
    assert!(server.token_requests().is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_registration_without_an_issued_client_is_incomplete() {
    let (base, nonce) = (
        Arc::new(Mutex::new(String::new())),
        Arc::new(Mutex::new(String::new())),
    );
    let server = AuthServer::start(openai_like(base.clone(), nonce, "user-1")).await;
    *base.lock().unwrap() = server.base.clone();
    let (store, root) = temp_store();
    let pending = begin(&store, &Issuer::at(&server.base)).await.unwrap();
    let (redirect, state) = (pending.redirect_uri.clone(), pending.state.clone());
    tokio::spawn(async move { browser(&redirect, &format!("code=code-1&state={state}")).await });
    let err = pending.finish(Duration::from_secs(10)).await.unwrap_err();
    assert!(err.message.contains("issued client id"), "{}", err.message);
    assert!(server.token_requests().is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_dead_refresh_token_ends_the_sign_in_and_a_missing_scope_blocks_use() {
    let (base, nonce) = (
        Arc::new(Mutex::new(String::new())),
        Arc::new(Mutex::new(String::new())),
    );
    let server = AuthServer::start(openai_like(base.clone(), nonce, "user-1")).await;
    *base.lock().unwrap() = server.base.clone();
    let issuer = Issuer::at(&server.base);
    let (store, root) = temp_store();
    let expired = Account {
        issuer: server.base.clone(),
        client_id: "oaiapp_test".into(),
        ext_agent_host_id: "urn:uuid:1".into(),
        subject: "user-1".into(),
        email: Some("dev@example.com".into()),
        id_token: Some("id".into()),
        access_token: Some("at-old".into()),
        refresh_token: Some("rt-revoked".into()),
        expires_at: Some(now() - 10),
        scopes: vec![PLAN_SCOPE.into()],
        saved_at: Some(now() - 4000),
    };
    store.save_account(&expired).unwrap();
    let err = PlanSession::new(store.clone(), issuer.clone())
        .token()
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Auth);
    assert!(err.message.contains("invalid_grant") && err.message.contains("declass login chatgpt"));
    let kept = store.account().unwrap().unwrap();
    assert!(!kept.signed_in());
    assert_eq!(kept.client_id, "oaiapp_test");

    let no_plan = Account {
        expires_at: Some(now() + 3600),
        refresh_token: Some("rt-1".into()),
        scopes: vec!["openid".into(), "email".into()],
        ..expired
    };
    store.save_account(&no_plan).unwrap();
    let err = PlanSession::new(store.clone(), issuer.clone())
        .token()
        .await
        .unwrap_err();
    assert!(err.message.contains("isn't enabled"), "{}", err.message);
    // Signing in again asks for consent to plan usage.
    let pending = begin(&store, &issuer).await.unwrap();
    assert_eq!(query(pending.url())["prompt"], "consent");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_temporary_refresh_failure_keeps_the_credentials() {
    let server = AuthServer::start(Arc::new(|_: &str, _: &str, _: &str| {
        (503, "{}".to_string())
    }))
    .await;
    let issuer = Issuer::at(&server.base);
    let (store, root) = temp_store();
    let account = Account {
        issuer: server.base.clone(),
        client_id: "oaiapp_test".into(),
        subject: "user-1".into(),
        refresh_token: Some("rt-1".into()),
        access_token: Some("at-1".into()),
        expires_at: Some(now() - 1),
        scopes: vec![PLAN_SCOPE.into()],
        ..Account::default()
    };
    store.save_account(&account).unwrap();
    let err = PlanSession::new(store.clone(), issuer)
        .token()
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err:?}");
    assert_eq!(store.account().unwrap().unwrap(), account);
    let _ = std::fs::remove_dir_all(root);
}
