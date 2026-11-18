//! The binary's observable contract: exit codes and output of each subcommand.

use std::process::Command;

fn paseka(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_paseka"))
        .args(args)
        .output()
        .expect("paseka binary runs")
}

#[test]
fn version_prints_name_and_version() {
    let out = paseka(&["version"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with(&format!("paseka {} (commit ", env!("CARGO_PKG_VERSION"))),
        "{text}"
    );
}

#[test]
fn conformance_passes_with_no_failures() {
    let out = paseka(&["conformance"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{text}");
    assert!(text.lines().last().unwrap().contains(" 0 failed"), "{text}");
}

#[test]
fn unimplemented_roles_fail_loudly() {
    for role in ["serve", "mcp", "init"] {
        let out = paseka(&[role]);
        assert_eq!(out.status.code(), Some(70), "{role}");
    }
}

#[test]
fn unknown_or_missing_command_is_a_usage_error() {
    assert_eq!(paseka(&["approve"]).status.code(), Some(2));
    assert_eq!(paseka(&[]).status.code(), Some(2));
}
