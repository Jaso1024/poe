use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::pack::reader::PackReader;
use crate::pack::summary::PackSummary;
use crate::trace::db::*;
use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainOutput {
    pub failure: Option<FailureExplanation>,
    pub timeline: TimelineExplanation,
    pub hotspots: Vec<Hotspot>,
    pub file_activity: FileActivitySummary,
    pub net_activity: NetActivitySummary,
    pub process_tree: Vec<ProcessNode>,
    pub error_patterns: Vec<ErrorPattern>,
    pub stderr_tail: Option<String>,
    pub stdout_tail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureExplanation {
    pub kind: String,
    pub primary_location: Option<LocationInfo>,
    pub description: String,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationInfo {
    pub file: Option<String>,
    pub line: Option<u32>,
    pub function: Option<String>,
    pub module: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineExplanation {
    pub merged: Vec<TimelineEntry>,
    pub last_file_ops: Vec<TimelineEntry>,
    pub last_net_ops: Vec<TimelineEntry>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub ts_ms: f64,
    pub proc_id: i32,
    pub kind: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hotspot {
    pub location: String,
    pub count: u64,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileActivitySummary {
    pub total_ops: i64,
    pub unique_paths: usize,
    pub most_accessed: Vec<(String, u64)>,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub failed_opens: Vec<FailedFileOp>,
    pub permission_errors: Vec<FailedFileOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedFileOp {
    pub path: String,
    pub op: String,
    pub errno: i64,
    pub errno_name: String,
    pub ts_ms: f64,
    pub pid: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetActivitySummary {
    pub total_ops: i64,
    pub connections: Vec<ConnectionInfo>,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub failed_connections: Vec<FailedConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub addr: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedConnection {
    pub addr: String,
    pub errno: i64,
    pub errno_name: String,
    pub ts_ms: f64,
    pub pid: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: i32,
    pub parent_pid: Option<i32>,
    pub command: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPattern {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub count: usize,
    pub examples: Vec<String>,
}

pub fn analyze(pack: &PackReader) -> Result<ExplainOutput> {
    let summary = pack.summary();
    let db = pack.db();

    let failure = build_failure_explanation(summary);
    let process_tree = build_process_tree(db)?;
    let timeline = build_timeline(db, summary.duration_ms)?;
    let hotspots = build_hotspots(db)?;
    let file_activity = build_file_activity(db)?;
    let net_activity = build_net_activity(db)?;

    let stderr_tail = pack.stderr().ok().and_then(|data| {
        let s = String::from_utf8_lossy(&data);
        let lines: Vec<&str> = s.lines().collect();
        let tail: Vec<&str> = lines.iter().rev().take(50).rev().copied().collect();
        if tail.is_empty() {
            None
        } else {
            Some(tail.join("\n"))
        }
    });

    let stdout_tail = pack.stdout().ok().and_then(|data| {
        let s = String::from_utf8_lossy(&data);
        let lines: Vec<&str> = s.lines().collect();
        let tail: Vec<&str> = lines.iter().rev().take(20).rev().copied().collect();
        if tail.is_empty() {
            None
        } else {
            Some(tail.join("\n"))
        }
    });

    let error_patterns = detect_error_patterns(
        &failure,
        &file_activity,
        &net_activity,
        &process_tree,
        &stderr_tail,
    );

    Ok(ExplainOutput {
        failure,
        timeline,
        hotspots,
        file_activity,
        net_activity,
        process_tree,
        error_patterns,
        stderr_tail,
        stdout_tail,
    })
}

fn build_failure_explanation(summary: &PackSummary) -> Option<FailureExplanation> {
    let failure_info = summary.failure.as_ref()?;

    Some(FailureExplanation {
        kind: failure_info.kind.clone(),
        primary_location: None,
        description: failure_info.description.clone(),
        exit_code: summary.exit_code,
        signal: summary.signal_name.clone(),
    })
}

fn build_process_tree(db: &TraceDb) -> Result<Vec<ProcessNode>> {
    let processes = db.query_processes()?;

    Ok(processes
        .iter()
        .map(|p| {
            let command = p
                .argv
                .as_ref()
                .and_then(|a| serde_json::from_str::<Vec<String>>(a).ok())
                .map(|args| args.join(" "))
                .unwrap_or_else(|| format!("pid:{}", p.proc_id));

            let duration_ms = match (p.end_ts, p.start_ts) {
                (Some(end), start) if end > start => {
                    Some((end - start) as f64 / 1_000_000.0)
                }
                _ => None,
            };

            ProcessNode {
                pid: p.proc_id,
                parent_pid: p.parent_proc_id,
                command,
                exit_code: p.exit_code,
                signal: p.signal,
                duration_ms,
            }
        })
        .collect())
}

fn build_timeline(db: &TraceDb, duration_ms: u64) -> Result<TimelineExplanation> {
    let last_events = db.query_last_events(50)?;
    let file_events = db.query_file_events()?;
    let net_events = db.query_net_events()?;

    let mut merged: Vec<TimelineEntry> = Vec::new();

    for e in last_events.iter().rev() {
        merged.push(TimelineEntry {
            ts_ms: e.ts as f64 / 1_000_000.0,
            proc_id: e.proc_id,
            kind: "event".into(),
            description: format!(
                "[{}] {}",
                e.kind,
                e.detail.as_deref().unwrap_or("")
            ),
        });
    }

    let file_tail: Vec<&FileQueryResult> = file_events.iter().rev().take(30).collect();
    for f in file_tail.iter().rev() {
        if is_noise_path(f.path.as_deref()) {
            continue;
        }
        let result_str = match f.result {
            Some(r) if r < 0 => format!(" err={}", errno_name(-r)),
            Some(r) => format!(" -> {}", r),
            None => String::new(),
        };
        let bytes_str = f.bytes.map(|b| format!(" ({} bytes)", b)).unwrap_or_default();
        let desc = format!(
            "{}{}{}{}",
            f.op,
            f.path.as_ref().map(|p| format!(" {}", p)).unwrap_or_default(),
            bytes_str,
            result_str,
        );
        merged.push(TimelineEntry {
            ts_ms: f.ts as f64 / 1_000_000.0,
            proc_id: f.proc_id,
            kind: "file".into(),
            description: desc,
        });
    }

    let net_tail: Vec<&NetQueryResult> = net_events.iter().rev().take(20).collect();
    for n in net_tail.iter().rev() {
        let result_str = match n.result {
            Some(r) if r < 0 && r != -115 => format!(" err={}", errno_name(-r)),
            Some(-115) => " (in progress)".into(),
            Some(r) => format!(" -> {}", r),
            None => String::new(),
        };
        let bytes_str = n.bytes.map(|b| format!(" ({} bytes)", b)).unwrap_or_default();
        let desc = format!(
            "{}{}{}{}",
            n.op,
            n.dst.as_ref().map(|d| format!(" {}", d)).unwrap_or_default(),
            bytes_str,
            result_str,
        );
        merged.push(TimelineEntry {
            ts_ms: n.ts as f64 / 1_000_000.0,
            proc_id: n.proc_id,
            kind: "net".into(),
            description: desc,
        });
    }

    merged.sort_by(|a, b| a.ts_ms.partial_cmp(&b.ts_ms).unwrap_or(std::cmp::Ordering::Equal));
    merged.truncate(50);

    let file_entries: Vec<TimelineEntry> = file_events
        .iter()
        .rev()
        .take(20)
        .rev()
        .filter(|f| !is_noise_path(f.path.as_deref()))
        .map(|f| {
            let result_str = match f.result {
                Some(r) if r < 0 => format!(" err={}", errno_name(-r)),
                Some(r) => format!(" -> {}", r),
                None => String::new(),
            };
            let bytes_str = f.bytes.map(|b| format!(" ({} bytes)", b)).unwrap_or_default();
            TimelineEntry {
                ts_ms: f.ts as f64 / 1_000_000.0,
                proc_id: f.proc_id,
                kind: "file".into(),
                description: format!(
                    "{}{}{}{}",
                    f.op,
                    f.path.as_ref().map(|p| format!(" {}", p)).unwrap_or_default(),
                    bytes_str,
                    result_str,
                ),
            }
        })
        .collect();

    let net_entries: Vec<TimelineEntry> = net_events
        .iter()
        .rev()
        .take(20)
        .rev()
        .map(|n| {
            let result_str = match n.result {
                Some(r) if r < 0 && r != -115 => format!(" err={}", errno_name(-r)),
                Some(-115) => " (in progress)".into(),
                Some(r) => format!(" -> {}", r),
                None => String::new(),
            };
            let bytes_str = n.bytes.map(|b| format!(" ({} bytes)", b)).unwrap_or_default();
            TimelineEntry {
                ts_ms: n.ts as f64 / 1_000_000.0,
                proc_id: n.proc_id,
                kind: "net".into(),
                description: format!(
                    "{}{}{}{}",
                    n.op,
                    n.dst.as_ref().map(|d| format!(" {}", d)).unwrap_or_default(),
                    bytes_str,
                    result_str,
                ),
            }
        })
        .collect();

    Ok(TimelineExplanation {
        merged,
        last_file_ops: file_entries,
        last_net_ops: net_entries,
        duration_ms,
    })
}

fn build_hotspots(db: &TraceDb) -> Result<Vec<Hotspot>> {
    let stacks = db.query_stacks()?;

    if stacks.is_empty() {
        return Ok(Vec::new());
    }

    let mut frame_counts: HashMap<String, u64> = HashMap::new();
    let mut total_samples = 0u64;

    for stack in &stacks {
        let frames: Vec<u64> = serde_json::from_str(&stack.frames).unwrap_or_default();
        let weight = stack.weight.unwrap_or(1) as u64;
        total_samples += weight;

        if let Some(&top_frame) = frames.first() {
            let key = format!("{:#x}", top_frame);
            *frame_counts.entry(key).or_insert(0) += weight;
        }
    }

    if total_samples == 0 {
        return Ok(Vec::new());
    }

    let mut hotspots: Vec<Hotspot> = frame_counts
        .into_iter()
        .map(|(location, count)| Hotspot {
            location,
            count,
            percentage: (count as f64 / total_samples as f64) * 100.0,
        })
        .collect();

    hotspots.sort_by(|a, b| b.count.cmp(&a.count));
    hotspots.truncate(20);

    Ok(hotspots)
}

fn build_file_activity(db: &TraceDb) -> Result<FileActivitySummary> {
    let events = db.query_file_events()?;

    let mut path_counts: HashMap<String, u64> = HashMap::new();
    let mut total_read = 0u64;
    let mut total_written = 0u64;
    let mut failed_opens = Vec::new();
    let mut permission_errors = Vec::new();

    for ev in &events {
        if let Some(path) = &ev.path {
            if !is_noise_path(Some(path.as_str())) {
                *path_counts.entry(path.clone()).or_insert(0) += 1;
            }
        }

        if let Some(bytes) = ev.bytes {
            let bytes = bytes as u64;
            match ev.op.as_str() {
                "read" => total_read += bytes,
                "write" => total_written += bytes,
                _ => {}
            }
        }

        if let (Some(result), Some(path)) = (ev.result, &ev.path) {
            if is_noise_path(Some(path.as_str())) {
                continue;
            }

            let neg = -result;
            if neg == libc::ENOENT as i64 && (ev.op == "open" || ev.op == "stat") {
                failed_opens.push(FailedFileOp {
                    path: path.clone(),
                    op: ev.op.clone(),
                    errno: neg,
                    errno_name: errno_name(neg),
                    ts_ms: ev.ts as f64 / 1_000_000.0,
                    pid: ev.proc_id,
                });
            } else if neg == libc::EACCES as i64 || neg == libc::EPERM as i64 {
                permission_errors.push(FailedFileOp {
                    path: path.clone(),
                    op: ev.op.clone(),
                    errno: neg,
                    errno_name: errno_name(neg),
                    ts_ms: ev.ts as f64 / 1_000_000.0,
                    pid: ev.proc_id,
                });
            }
        }
    }

    failed_opens.dedup_by(|a, b| a.path == b.path);
    permission_errors.dedup_by(|a, b| a.path == b.path);

    let unique_paths = path_counts.len();
    let mut most_accessed: Vec<(String, u64)> = path_counts.into_iter().collect();
    most_accessed.sort_by(|a, b| b.1.cmp(&a.1));
    most_accessed.truncate(10);

    Ok(FileActivitySummary {
        total_ops: events.len() as i64,
        unique_paths,
        most_accessed,
        total_bytes_read: total_read,
        total_bytes_written: total_written,
        failed_opens,
        permission_errors,
    })
}

fn build_net_activity(db: &TraceDb) -> Result<NetActivitySummary> {
    let events = db.query_net_events()?;

    let mut connections = Vec::new();
    let mut failed_connections = Vec::new();
    let mut total_sent = 0u64;
    let mut total_received = 0u64;

    for ev in &events {
        match ev.op.as_str() {
            "connect" => {
                if let Some(dst) = &ev.dst {
                    if is_noise_addr(dst) {
                        continue;
                    }
                    let result = ev.result.unwrap_or(0);
                    if result >= 0 || result == -115 {
                        connections.push(ConnectionInfo {
                            addr: dst.clone(),
                            result: if result == -115 {
                                "async".into()
                            } else {
                                "ok".into()
                            },
                        });
                    } else {
                        failed_connections.push(FailedConnection {
                            addr: dst.clone(),
                            errno: -result,
                            errno_name: errno_name(-result),
                            ts_ms: ev.ts as f64 / 1_000_000.0,
                            pid: ev.proc_id,
                        });
                    }
                }
            }
            "send" | "sendto" | "sendmsg" => {
                if let Some(bytes) = ev.bytes {
                    total_sent += bytes as u64;
                }
            }
            "recv" | "recvfrom" | "recvmsg" => {
                if let Some(bytes) = ev.bytes {
                    total_received += bytes as u64;
                }
            }
            _ => {}
        }
    }

    connections.dedup_by(|a, b| a.addr == b.addr);

    Ok(NetActivitySummary {
        total_ops: events.len() as i64,
        connections,
        total_bytes_sent: total_sent,
        total_bytes_received: total_received,
        failed_connections,
    })
}

fn detect_error_patterns(
    failure: &Option<FailureExplanation>,
    file_activity: &FileActivitySummary,
    net_activity: &NetActivitySummary,
    process_tree: &[ProcessNode],
    stderr_tail: &Option<String>,
) -> Vec<ErrorPattern> {
    let mut patterns = Vec::new();

    if let Some(f) = failure {
        if f.signal.as_deref() == Some("SIGSEGV") {
            patterns.push(ErrorPattern {
                category: "crash".into(),
                severity: "critical".into(),
                description: "Segmentation fault - the process accessed invalid memory".into(),
                count: 1,
                examples: vec!["Process received SIGSEGV".into()],
            });
        } else if f.signal.as_deref() == Some("SIGABRT") {
            patterns.push(ErrorPattern {
                category: "crash".into(),
                severity: "critical".into(),
                description: "Process aborted - likely an assertion failure or double-free".into(),
                count: 1,
                examples: vec!["Process received SIGABRT".into()],
            });
        } else if f.signal.as_deref() == Some("SIGBUS") {
            patterns.push(ErrorPattern {
                category: "crash".into(),
                severity: "critical".into(),
                description: "Bus error - misaligned memory access or mmap beyond file".into(),
                count: 1,
                examples: vec!["Process received SIGBUS".into()],
            });
        } else if f.signal.as_deref() == Some("SIGFPE") {
            patterns.push(ErrorPattern {
                category: "crash".into(),
                severity: "critical".into(),
                description: "Floating point exception - likely division by zero".into(),
                count: 1,
                examples: vec!["Process received SIGFPE".into()],
            });
        }
    }

    if !file_activity.permission_errors.is_empty() {
        let examples: Vec<String> = file_activity
            .permission_errors
            .iter()
            .take(5)
            .map(|e| format!("{} {} -> {}", e.op, e.path, e.errno_name))
            .collect();
        patterns.push(ErrorPattern {
            category: "permission".into(),
            severity: "error".into(),
            description: format!(
                "{} file operation(s) failed with permission denied",
                file_activity.permission_errors.len()
            ),
            count: file_activity.permission_errors.len(),
            examples,
        });
    }

    let significant_missing: Vec<&FailedFileOp> = file_activity
        .failed_opens
        .iter()
        .filter(|f| is_significant_missing_file(&f.path))
        .collect();
    if !significant_missing.is_empty() {
        let examples: Vec<String> = significant_missing
            .iter()
            .take(5)
            .map(|e| format!("{} {}", e.op, e.path))
            .collect();
        patterns.push(ErrorPattern {
            category: "missing_file".into(),
            severity: "warning".into(),
            description: format!(
                "{} file(s) not found that may be significant",
                significant_missing.len()
            ),
            count: significant_missing.len(),
            examples,
        });
    }

    if !net_activity.failed_connections.is_empty() {
        let examples: Vec<String> = net_activity
            .failed_connections
            .iter()
            .take(5)
            .map(|e| format!("connect {} -> {}", e.addr, e.errno_name))
            .collect();
        patterns.push(ErrorPattern {
            category: "network".into(),
            severity: "error".into(),
            description: format!(
                "{} network connection(s) failed",
                net_activity.failed_connections.len()
            ),
            count: net_activity.failed_connections.len(),
            examples,
        });
    }

    let killed_procs: Vec<&ProcessNode> = process_tree
        .iter()
        .filter(|p| p.signal.is_some())
        .collect();
    if killed_procs.len() > 1 {
        let examples: Vec<String> = killed_procs
            .iter()
            .take(5)
            .map(|p| {
                format!(
                    "pid {} ({}) killed by {}",
                    p.pid,
                    &p.command[..p.command.len().min(40)],
                    p.signal.map(util::signal_name).unwrap_or_default()
                )
            })
            .collect();
        patterns.push(ErrorPattern {
            category: "multi_crash".into(),
            severity: "critical".into(),
            description: format!(
                "{} processes were killed by signals",
                killed_procs.len()
            ),
            count: killed_procs.len(),
            examples,
        });
    }

    if let Some(stderr) = stderr_tail {
        detect_stderr_patterns(stderr, &mut patterns);
    }

    patterns
}

fn detect_stderr_patterns(stderr: &str, patterns: &mut Vec<ErrorPattern>) {
    let stderr_lower = stderr.to_lowercase();

    let oom_keywords = ["out of memory", "oom", "cannot allocate memory", "alloc failed"];
    if oom_keywords.iter().any(|k| stderr_lower.contains(k)) {
        let example_line = stderr
            .lines()
            .find(|l| {
                let ll = l.to_lowercase();
                oom_keywords.iter().any(|k| ll.contains(k))
            })
            .unwrap_or("out of memory");
        patterns.push(ErrorPattern {
            category: "oom".into(),
            severity: "critical".into(),
            description: "Out of memory condition detected in stderr".into(),
            count: 1,
            examples: vec![example_line.to_string()],
        });
    }

    let timeout_keywords = ["timeout", "timed out", "deadline exceeded"];
    if timeout_keywords.iter().any(|k| stderr_lower.contains(k)) {
        let example_line = stderr
            .lines()
            .find(|l| {
                let ll = l.to_lowercase();
                timeout_keywords.iter().any(|k| ll.contains(k))
            })
            .unwrap_or("timeout");
        patterns.push(ErrorPattern {
            category: "timeout".into(),
            severity: "error".into(),
            description: "Timeout detected in stderr".into(),
            count: 1,
            examples: vec![example_line.to_string()],
        });
    }

    let panic_indicators = [
        "panic:", "panicked at", "traceback (most recent",
        "unhandled exception", "fatal error", "segmentation fault",
        "stack overflow", "uncaught exception",
    ];
    let found_panic = panic_indicators
        .iter()
        .find(|k| stderr_lower.contains(*k));
    if let Some(keyword) = found_panic {
        let example_lines: Vec<String> = stderr
            .lines()
            .filter(|l| l.to_lowercase().contains(keyword))
            .take(3)
            .map(|s| s.to_string())
            .collect();
        if !example_lines.is_empty() {
            patterns.push(ErrorPattern {
                category: "exception".into(),
                severity: "critical".into(),
                description: "Exception or panic detected in stderr".into(),
                count: 1,
                examples: example_lines,
            });
        }
    }
}

pub fn is_noise_path_pub(path: Option<&str>) -> bool {
    is_noise_path(path)
}

fn is_noise_path(path: Option<&str>) -> bool {
    let path = match path {
        Some(p) => p,
        None => return false,
    };

    let noise_prefixes = [
        "/proc/self/",
        "/proc/thread-self/",
        "/etc/ld.so",
        "/etc/ld-nix.so",
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
    ];

    let noise_suffixes = [
        "ld.so.cache",
        "ld.so.preload",
        "ld-nix.so.preload",
    ];

    let noise_contains = [
        "gconv-modules",
        "locale-archive",
        "nsswitch.conf",
        "/nss_",
        "libnss_",
        "glibc-hwcaps",
        "tls/haswell",
        "tls/x86_64",
    ];

    // Shared library loads are noise
    if path.ends_with(".so") || path.contains(".so.") {
        return true;
    }

    for prefix in &noise_prefixes {
        if path.starts_with(prefix) {
            return true;
        }
    }

    for suffix in &noise_suffixes {
        if path.ends_with(suffix) {
            return true;
        }
    }

    for substr in &noise_contains {
        if path.contains(substr) {
            return true;
        }
    }

    false
}

fn is_noise_addr(addr: &str) -> bool {
    addr.starts_with("family=") || addr.contains("nscd")
}

fn is_significant_missing_file(path: &str) -> bool {
    if is_noise_path(Some(path)) {
        return false;
    }

    let insignificant_patterns = [
        ".pyc",
        "__pycache__",
        "pyvenv.cfg",
        ".pth",
        "RECORD",
        "METADATA",
        "top_level.txt",
        "INSTALLER",
        "WHEEL",
        "site-packages",
        "/bin/",
        "/sbin/",
    ];

    for pat in &insignificant_patterns {
        if path.contains(pat) {
            return false;
        }
    }

    // PATH search for executables is noise
    let path_search_dirs = [
        "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
        ".cargo/bin/", ".nix-profile/bin/", "/nix/profile/",
        "/run/wrappers/bin/", "/run/current-system/sw/bin/",
        "/home/", // home dir searches for executables
    ];
    for dir in &path_search_dirs {
        if path.contains(dir) && !path.contains('.') {
            return false;
        }
    }

    // Config file probes are often noise
    if path.ends_with(".cfg") || path.ends_with(".conf") {
        return false;
    }

    true
}

fn errno_name(errno: i64) -> String {
    match errno {
        1 => "EPERM".into(),
        2 => "ENOENT".into(),
        3 => "ESRCH".into(),
        4 => "EINTR".into(),
        5 => "EIO".into(),
        6 => "ENXIO".into(),
        9 => "EBADF".into(),
        11 => "EAGAIN".into(),
        12 => "ENOMEM".into(),
        13 => "EACCES".into(),
        14 => "EFAULT".into(),
        17 => "EEXIST".into(),
        20 => "ENOTDIR".into(),
        21 => "EISDIR".into(),
        22 => "EINVAL".into(),
        23 => "ENFILE".into(),
        24 => "EMFILE".into(),
        28 => "ENOSPC".into(),
        30 => "EROFS".into(),
        32 => "EPIPE".into(),
        36 => "ENAMETOOLONG".into(),
        38 => "ENOSYS".into(),
        39 => "ENOTEMPTY".into(),
        40 => "ELOOP".into(),
        61 => "ENODATA".into(),
        98 => "EADDRINUSE".into(),
        99 => "EADDRNOTAVAIL".into(),
        100 => "ENETDOWN".into(),
        101 => "ENETUNREACH".into(),
        104 => "ECONNRESET".into(),
        110 => "ETIMEDOUT".into(),
        111 => "ECONNREFUSED".into(),
        112 => "EHOSTDOWN".into(),
        113 => "EHOSTUNREACH".into(),
        115 => "EINPROGRESS".into(),
        _ => format!("errno({})", errno),
    }
}
