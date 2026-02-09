use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::pack::reader::PackReader;
use crate::pack::summary::PackSummary;
use crate::trace::db::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainOutput {
    pub failure: Option<FailureExplanation>,
    pub timeline: TimelineExplanation,
    pub hotspots: Vec<Hotspot>,
    pub file_activity: FileActivitySummary,
    pub net_activity: NetActivitySummary,
    pub process_tree: Vec<ProcessNode>,
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
    pub last_events: Vec<TimelineEntry>,
    pub last_file_ops: Vec<TimelineEntry>,
    pub last_net_ops: Vec<TimelineEntry>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub ts_ms: f64,
    pub proc_id: i32,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetActivitySummary {
    pub total_ops: i64,
    pub connections: Vec<String>,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
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

    Ok(ExplainOutput {
        failure,
        timeline,
        hotspots,
        file_activity,
        net_activity,
        process_tree,
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
    let last_events = db.query_last_events(30)?;
    let file_events = db.query_file_events()?;
    let net_events = db.query_net_events()?;

    let event_entries: Vec<TimelineEntry> = last_events
        .iter()
        .rev()
        .map(|e| TimelineEntry {
            ts_ms: e.ts as f64 / 1_000_000.0,
            proc_id: e.proc_id,
            description: format!(
                "[{}] {}",
                e.kind,
                e.detail.as_deref().unwrap_or("")
            ),
        })
        .collect();

    let file_entries: Vec<TimelineEntry> = file_events
        .iter()
        .rev()
        .take(20)
        .rev()
        .map(|f| {
            let desc = format!(
                "{} {} fd={} result={}",
                f.op,
                f.path.as_deref().unwrap_or(""),
                f.fd.map(|fd| fd.to_string()).unwrap_or_default(),
                f.result.map(|r| r.to_string()).unwrap_or_default(),
            );
            TimelineEntry {
                ts_ms: f.ts as f64 / 1_000_000.0,
                proc_id: f.proc_id,
                description: desc,
            }
        })
        .collect();

    let net_entries: Vec<TimelineEntry> = net_events
        .iter()
        .rev()
        .take(20)
        .rev()
        .map(|n| {
            let desc = format!(
                "{} {} -> {} bytes={} result={}",
                n.op,
                n.src.as_deref().unwrap_or(""),
                n.dst.as_deref().unwrap_or(""),
                n.bytes.map(|b| b.to_string()).unwrap_or_default(),
                n.result.map(|r| r.to_string()).unwrap_or_default(),
            );
            TimelineEntry {
                ts_ms: n.ts as f64 / 1_000_000.0,
                proc_id: n.proc_id,
                description: desc,
            }
        })
        .collect();

    Ok(TimelineExplanation {
        last_events: event_entries,
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

    for ev in &events {
        if let Some(path) = &ev.path {
            *path_counts.entry(path.clone()).or_insert(0) += 1;
        }

        if let Some(bytes) = ev.bytes {
            let bytes = bytes as u64;
            match ev.op.as_str() {
                "read" => total_read += bytes,
                "write" => total_written += bytes,
                _ => {}
            }
        }
    }

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
    })
}

fn build_net_activity(db: &TraceDb) -> Result<NetActivitySummary> {
    let events = db.query_net_events()?;

    let mut connections = Vec::new();
    let mut total_sent = 0u64;
    let mut total_received = 0u64;

    for ev in &events {
        match ev.op.as_str() {
            "connect" => {
                if let Some(dst) = &ev.dst {
                    if ev.result.map(|r| r >= 0).unwrap_or(false) || ev.result == Some(-115) {
                        connections.push(dst.clone());
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

    connections.sort();
    connections.dedup();

    Ok(NetActivitySummary {
        total_ops: events.len() as i64,
        connections,
        total_bytes_sent: total_sent,
        total_bytes_received: total_received,
    })
}
