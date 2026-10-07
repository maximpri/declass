// SPDX-License-Identifier: GPL-3.0-or-later
//! `declass login` / `declass logout`: subscription sign-in for the frontier.
//! ChatGPT plans sign in through OpenAI's "Sign in with ChatGPT" for
//! open-source apps (see `declass_provider::chatgpt`). Other providers'
//! subscriptions are not offered: their terms reserve them for the vendor's
//! own apps, so they are used through API keys.

use crate::chatgpt_plan;
use anyhow::Result;
use clap::ValueEnum;
use declass_config::Config;
use declass_provider::chatgpt::{self, Account, Issuer};
use std::time::Duration;

/// A subscription Declass can sign in with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Subscription {
    /// A ChatGPT Plus or Pro plan (Sign in with ChatGPT).
    Chatgpt,
}

/// How long the browser has to complete the sign-in.
pub(crate) const SIGN_IN_WAIT: Duration = Duration::from_secs(300);

/// `declass login chatgpt`: signs in, or with `status` shows the sign-in.
pub async fn login(cfg: &Config, _: Subscription, no_browser: bool, status: bool) -> Result<i32> {
    let store = crate::chatgpt_store();
    if status {
        return show_status(cfg, store.account()?.as_ref());
    }
    let pending = chatgpt::begin(&store, &Issuer::openai()).await?;
    println!("Continue with ChatGPT: sign in to let Declass use your ChatGPT plan.");
    if pending.registering() {
        println!(
            "OpenAI will ask you to approve \"{}\" and its use of your plan; you can limit it at {} at any time.",
            chatgpt::AGENT_NAME,
            chatgpt::USAGE_URL
        );
    }
    let opened = !no_browser && open_browser(pending.url());
    if opened {
        println!("Your browser should open. If it does not, open this address:");
    } else {
        println!("Open this address in a browser on this computer:");
    }
    println!("\n  {}\n", pending.display_url());
    println!("Waiting for the sign-in (up to 5 minutes; Ctrl-C to cancel)…");
    let signed = pending.finish(SIGN_IN_WAIT).await?;
    let who = signed
        .account
        .email
        .clone()
        .unwrap_or_else(|| signed.account.subject.clone());
    if !signed.account.plan_enabled() {
        println!(
            "Signed in as {who}, but ChatGPT plan use isn't enabled for Declass.\n\
Run `declass login chatgpt` again and allow it, or pay per token with an API key: `declass config preset openai --confirm`."
        );
        return Ok(1);
    }
    println!("Using ChatGPT plan as {who}.");
    println!("Manage usage: {}", chatgpt::USAGE_URL);
    if !chatgpt_plan(cfg)? {
        println!(
            "\nThe frontier does not use it yet. Switch with:\n  declass config preset chatgpt --confirm"
        );
    }
    Ok(0)
}

/// `declass logout chatgpt`: revokes the sign-in at OpenAI and deletes the
/// tokens; `forget` also drops the registration (to switch accounts).
pub async fn logout(cfg: &Config, _: Subscription, forget: bool) -> Result<i32> {
    let out = chatgpt::sign_out(&crate::chatgpt_store(), &Issuer::openai(), forget).await?;
    match (&out.account, out.revoked) {
        (None, _) => println!("Not signed in with ChatGPT."),
        (Some(who), true) => println!("Signed out {who}; OpenAI revoked the sign-in."),
        (Some(who), false) => println!(
            "Signed out {who} on this computer, but OpenAI did not confirm the revocation.\n\
To be sure, disconnect Declass in ChatGPT settings: {}",
            chatgpt::USAGE_URL
        ),
    }
    if forget {
        println!(
            "Declass's registration with that account was removed; the next sign-in registers it again."
        );
    }
    if chatgpt_plan(cfg)? {
        println!(
            "frontier.auth is still \"chatgpt\": runs need `declass login chatgpt`, or switch to a key with `declass config preset openai --confirm`."
        );
    }
    Ok(0)
}

fn show_status(cfg: &Config, account: Option<&Account>) -> Result<i32> {
    let in_use = chatgpt_plan(cfg)?;
    let Some(account) = account.filter(|a| a.signed_in()) else {
        println!("ChatGPT plan: not signed in. Sign in with `declass login chatgpt`.");
        return Ok(if in_use { 1 } else { 0 });
    };
    let who = account.email.as_deref().unwrap_or(&account.subject);
    println!("ChatGPT plan: signed in as {who}");
    if account.plan_enabled() {
        println!("  plan usage: allowed");
    } else {
        println!("  plan usage: not allowed; run `declass login chatgpt` and allow it");
    }
    println!(
        "  access token: renewed automatically (hourly; the sign-in lasts while Declass is used at least every 30 days)"
    );
    if in_use {
        println!("  frontier: uses this plan (frontier.auth = \"chatgpt\")");
    } else {
        println!(
            "  frontier: not using it (switch with `declass config preset chatgpt --confirm`)"
        );
    }
    println!("  manage usage: {}", chatgpt::USAGE_URL);
    println!("  credentials: {}", crate::chatgpt_store().dir().display());
    Ok(if account.plan_enabled() { 0 } else { 1 })
}

/// Opens `url` in the default browser; false when that is not possible.
pub(crate) fn open_browser(url: &str) -> bool {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(program)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}
