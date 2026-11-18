//! `paseka`: one static binary for every role of the gate.
//!
//! Subcommands: `serve` (gate daemon), `mcp` (agent mailbox over stdio), `init` (first-run
//! ceremony), `conformance` (local attack suite), `version`. Invoked through a link named
//! `paseka-<role>`, the binary runs that role.

use std::io::Write as _;
use std::process::ExitCode;

use paseka_conformance::Outcome;

const USAGE: &str = "usage: paseka <serve|mcp|init|conformance|version>";

fn main() -> ExitCode {
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_default();
    let role = std::path::Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("paseka-"))
        .map(str::to_owned);
    let Some(cmd) = role.or_else(|| args.next()) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match cmd.as_str() {
        "version" | "--version" | "-V" => version(),
        "conformance" => conformance(),
        "serve" | "mcp" | "init" => {
            eprintln!("paseka {cmd}: not implemented");
            ExitCode::from(70)
        }
        "help" | "--help" | "-h" => {
            eprintln!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("paseka: unknown command {other:?}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn version() -> ExitCode {
    let commit = option_env!("PASEKA_BUILD_COMMIT").unwrap_or("unknown");
    let mut out = std::io::stdout().lock();
    match writeln!(
        out,
        "paseka {} (commit {commit})",
        env!("CARGO_PKG_VERSION")
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

/// Runs every attack; exit status 1 if any attack got through.
fn conformance() -> ExitCode {
    let mut out = std::io::stdout().lock();
    let (mut pass, mut fail, mut pending) = (0, 0, 0);
    for (attack, outcome) in paseka_conformance::run_all() {
        let line = match &outcome {
            Outcome::Pass => {
                pass += 1;
                format!("PASS     {}", attack.id)
            }
            Outcome::Fail(why) => {
                fail += 1;
                format!("FAIL     {}: {} ({why})", attack.id, attack.title)
            }
            Outcome::Pending(needs) => {
                pending += 1;
                format!("PENDING  {}: needs {needs}", attack.id)
            }
        };
        if writeln!(out, "{line}").is_err() {
            return ExitCode::FAILURE;
        }
    }
    if writeln!(out, "{pass} passed, {fail} failed, {pending} pending").is_err() || fail > 0 {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
