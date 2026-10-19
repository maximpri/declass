// SPDX-License-Identifier: GPL-3.0-or-later
//! Tries to get out of its sandbox and says how each attempt went: one JSON
//! line per attempt, `{"probe", "target", "outcome", "detail"}`, `outcome`
//! being `escaped` (it worked) or `blocked`. The containment tests run it
//! once outside the sandbox (what works on this machine at all) and once
//! inside. Never part of a release: tools/release.sh builds only `declass`.
//!
//! declass-probe [--read PATH]... [--write PATH]... [--tcp HOST:PORT]...
//!               [--resolve NAME]... [--unix PATH]... [--exec PROGRAM]...

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::time::Duration;

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn report(probe: &str, target: &str, result: Result<String, String>) {
    let (outcome, detail) = match result {
        Ok(d) => ("escaped", d),
        Err(d) => ("blocked", d),
    };
    println!(
        "{{\"probe\":{},\"target\":{},\"outcome\":\"{outcome}\",\"detail\":{}}}",
        json_string(probe),
        json_string(target),
        json_string(&detail)
    );
}

fn read(path: &str) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 64];
    let n = f.read(&mut buf).map_err(|e| e.to_string())?;
    Ok(format!("read {n} bytes"))
}

fn write(path: &str) -> Result<String, String> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(b"# declass-probe\n")
        .map_err(|e| e.to_string())?;
    Ok("appended".into())
}

fn tcp(target: &str) -> Result<String, String> {
    let addr = target
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("no address")?;
    std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map(|_| "connected".to_owned())
        .map_err(|e| e.to_string())
}

fn resolve(name: &str) -> Result<String, String> {
    (name, 443)
        .to_socket_addrs()
        .map_err(|e| e.to_string())
        .and_then(|mut a| {
            a.next()
                .map(|a| a.ip().to_string())
                .ok_or("no address".into())
        })
}

fn unix(path: &str) -> Result<String, String> {
    std::os::unix::net::UnixStream::connect(path)
        .map(|_| "connected".to_owned())
        .map_err(|e| e.to_string())
}

fn exec(program: &str) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(format!("exited 0, {} bytes", out.stdout.len()))
    } else {
        Err(format!(
            "{}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.chunks(2);
    for pair in &mut it {
        let [flag, target] = pair else {
            eprintln!(
                "usage: declass-probe [--read|--write|--tcp|--resolve|--unix|--exec VALUE]..."
            );
            std::process::exit(2);
        };
        let (probe, result) = match flag.as_str() {
            "--read" => ("read", read(target)),
            "--write" => ("write", write(target)),
            "--tcp" => ("tcp", tcp(target)),
            "--resolve" => ("resolve", resolve(target)),
            "--unix" => ("unix", unix(target)),
            "--exec" => ("exec", exec(target)),
            other => {
                eprintln!("unknown probe {other}");
                std::process::exit(2);
            }
        };
        report(probe, target, result);
    }
}
