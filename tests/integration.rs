use std::path::PathBuf;
use std::process::Command;

fn poe_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.push("poe");
    if !path.exists() {
        path = PathBuf::from("target/release/poe");
    }
    path
}

#[test]
fn run_captures_nonzero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(poe_binary())
        .args([
            "run",
            "--output",
            dir.path().to_str().unwrap(),
            "--",
            "false",
        ])
        .output()
        .expect("failed to run poe");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("poe debug packet"));
    assert!(stderr.contains(".poepack"));

    let packs: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "poepack")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(packs.len(), 1);
}

#[test]
fn run_no_pack_on_success() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(poe_binary())
        .args([
            "run",
            "--output",
            dir.path().to_str().unwrap(),
            "--",
            "true",
        ])
        .output()
        .expect("failed to run poe");

    assert_eq!(output.status.code(), Some(0));
    let packs: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "poepack")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(packs.len(), 0);
}

#[test]
fn run_always_captures_success() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(poe_binary())
        .args([
            "run",
            "--always",
            "--output",
            dir.path().to_str().unwrap(),
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("failed to run poe");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"));

    let packs: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "poepack")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(packs.len(), 1);
}

#[test]
fn explain_produces_output() {
    let dir = tempfile::tempdir().unwrap();
    Command::new(poe_binary())
        .args([
            "run",
            "--output",
            dir.path().to_str().unwrap(),
            "--",
            "false",
        ])
        .output()
        .expect("failed to run poe");

    let pack = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.path()
                .extension()
                .map(|x| x == "poepack")
                .unwrap_or(false)
        })
        .expect("no pack found");

    let output = Command::new(poe_binary())
        .args(["explain", pack.path().to_str().unwrap()])
        .output()
        .expect("failed to run explain");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("poe explain"));
    assert!(stdout.contains("process tree"));
}

#[test]
fn explain_json_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    Command::new(poe_binary())
        .args([
            "run",
            "--output",
            dir.path().to_str().unwrap(),
            "--",
            "false",
        ])
        .output()
        .expect("failed to run poe");

    let pack = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.path()
                .extension()
                .map(|x| x == "poepack")
                .unwrap_or(false)
        })
        .expect("no pack found");

    let output = Command::new(poe_binary())
        .args(["explain", "--json", pack.path().to_str().unwrap()])
        .output()
        .expect("failed to run explain");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("explain --json did not produce valid JSON");
    assert!(parsed.get("failure").is_some());
    assert!(parsed.get("process_tree").is_some());
    assert!(parsed.get("timeline").is_some());
}

#[test]
fn query_stats_returns_json() {
    let dir = tempfile::tempdir().unwrap();
    Command::new(poe_binary())
        .args([
            "run",
            "--output",
            dir.path().to_str().unwrap(),
            "--",
            "false",
        ])
        .output()
        .expect("failed to run poe");

    let pack = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.path()
                .extension()
                .map(|x| x == "poepack")
                .unwrap_or(false)
        })
        .expect("no pack found");

    let output = Command::new(poe_binary())
        .args(["query", pack.path().to_str().unwrap(), "stats"])
        .output()
        .expect("failed to run query");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("query stats did not produce valid JSON");
    assert!(parsed.get("process_count").is_some());
}

#[test]
fn doctor_succeeds() {
    let output = Command::new(poe_binary())
        .args(["doctor"])
        .output()
        .expect("failed to run doctor");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ok") || stdout.contains("OK"));
}

#[test]
fn crash_signal_captured() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(poe_binary())
        .args([
            "run",
            "--output",
            dir.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "kill -SEGV $$",
        ])
        .output()
        .expect("failed to run poe");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CRASH") || stderr.contains("SIGSEGV"));

    let packs: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "poepack")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(packs.len(), 1);
}
