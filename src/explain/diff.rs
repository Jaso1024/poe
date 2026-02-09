use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::pack::reader::PackReader;
use crate::trace::db::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffOutput {
    pub baseline_id: String,
    pub candidate_id: String,
    pub exit_code_diff: Option<ExitCodeDiff>,
    pub signal_diff: Option<SignalDiff>,
    pub duration_diff: DurationDiff,
    pub process_diff: ProcessDiff,
    pub file_diff: FileDiff,
    pub net_diff: NetDiff,
    pub stderr_diff: Option<StderrDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitCodeDiff {
    pub baseline: Option<i32>,
    pub candidate: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalDiff {
    pub baseline: Option<String>,
    pub candidate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurationDiff {
    pub baseline_ms: u64,
    pub candidate_ms: u64,
    pub delta_ms: i64,
    pub delta_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDiff {
    pub baseline_count: usize,
    pub candidate_count: usize,
    pub new_processes: Vec<String>,
    pub missing_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiff {
    pub baseline_ops: i64,
    pub candidate_ops: i64,
    pub new_paths: Vec<String>,
    pub missing_paths: Vec<String>,
    pub baseline_bytes_read: u64,
    pub candidate_bytes_read: u64,
    pub baseline_bytes_written: u64,
    pub candidate_bytes_written: u64,
    pub new_errors: Vec<FileErrorDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileErrorDiff {
    pub path: String,
    pub op: String,
    pub result: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetDiff {
    pub baseline_ops: i64,
    pub candidate_ops: i64,
    pub new_connections: Vec<String>,
    pub missing_connections: Vec<String>,
    pub baseline_bytes_sent: u64,
    pub candidate_bytes_sent: u64,
    pub baseline_bytes_recv: u64,
    pub candidate_bytes_recv: u64,
    pub new_errors: Vec<NetErrorDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetErrorDiff {
    pub addr: String,
    pub op: String,
    pub result: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StderrDiff {
    pub baseline_lines: Vec<String>,
    pub candidate_lines: Vec<String>,
    pub new_lines: Vec<String>,
}

pub fn diff_packs(baseline_path: &Path, candidate_path: &Path) -> Result<DiffOutput> {
    let baseline = PackReader::open(baseline_path)?;
    let candidate = PackReader::open(candidate_path)?;

    let bs = baseline.summary();
    let cs = candidate.summary();
    let bdb = baseline.db();
    let cdb = candidate.db();

    let exit_code_diff = if bs.exit_code != cs.exit_code {
        Some(ExitCodeDiff {
            baseline: bs.exit_code,
            candidate: cs.exit_code,
        })
    } else {
        None
    };

    let signal_diff = if bs.signal_name != cs.signal_name {
        Some(SignalDiff {
            baseline: bs.signal_name.clone(),
            candidate: cs.signal_name.clone(),
        })
    } else {
        None
    };

    let duration_diff = {
        let delta = cs.duration_ms as i64 - bs.duration_ms as i64;
        let pct = if bs.duration_ms > 0 {
            (delta as f64 / bs.duration_ms as f64) * 100.0
        } else {
            0.0
        };
        DurationDiff {
            baseline_ms: bs.duration_ms,
            candidate_ms: cs.duration_ms,
            delta_ms: delta,
            delta_pct: pct,
        }
    };

    let process_diff = diff_processes(bdb, cdb)?;
    let file_diff = diff_files(bdb, cdb)?;
    let net_diff = diff_net(bdb, cdb)?;
    let stderr_diff = diff_stderr(&baseline, &candidate);

    Ok(DiffOutput {
        baseline_id: bs.run_id.clone(),
        candidate_id: cs.run_id.clone(),
        exit_code_diff,
        signal_diff,
        duration_diff,
        process_diff,
        file_diff,
        net_diff,
        stderr_diff,
    })
}

fn diff_processes(bdb: &TraceDb, cdb: &TraceDb) -> Result<ProcessDiff> {
    let bp = bdb.query_processes()?;
    let cp = cdb.query_processes()?;

    let b_cmds: HashSet<String> = bp
        .iter()
        .filter_map(|p| {
            p.argv.as_ref().and_then(|a| {
                serde_json::from_str::<Vec<String>>(a)
                    .ok()
                    .map(|v| v.join(" "))
            })
        })
        .collect();

    let c_cmds: HashSet<String> = cp
        .iter()
        .filter_map(|p| {
            p.argv.as_ref().and_then(|a| {
                serde_json::from_str::<Vec<String>>(a)
                    .ok()
                    .map(|v| v.join(" "))
            })
        })
        .collect();

    let new_processes: Vec<String> = c_cmds.difference(&b_cmds).cloned().collect();
    let missing_processes: Vec<String> = b_cmds.difference(&c_cmds).cloned().collect();

    Ok(ProcessDiff {
        baseline_count: bp.len(),
        candidate_count: cp.len(),
        new_processes,
        missing_processes,
    })
}

fn diff_files(bdb: &TraceDb, cdb: &TraceDb) -> Result<FileDiff> {
    let bf = bdb.query_file_events()?;
    let cf = cdb.query_file_events()?;

    let b_paths: HashSet<String> = bf.iter().filter_map(|f| f.path.clone()).collect();
    let c_paths: HashSet<String> = cf.iter().filter_map(|f| f.path.clone()).collect();

    let new_paths: Vec<String> = c_paths
        .difference(&b_paths)
        .filter(|p| !super::analyzer::is_noise_path_pub(Some(p.as_str())))
        .cloned()
        .collect();
    let missing_paths: Vec<String> = b_paths
        .difference(&c_paths)
        .filter(|p| !super::analyzer::is_noise_path_pub(Some(p.as_str())))
        .cloned()
        .collect();

    let (b_read, b_written) = sum_file_bytes(&bf);
    let (c_read, c_written) = sum_file_bytes(&cf);

    let b_errors: HashSet<String> = bf
        .iter()
        .filter(|f| f.result.map(|r| r < 0).unwrap_or(false))
        .filter_map(|f| f.path.clone())
        .collect();

    let new_errors: Vec<FileErrorDiff> = cf
        .iter()
        .filter(|f| {
            f.result.map(|r| r < 0).unwrap_or(false)
                && f.path
                    .as_ref()
                    .map(|p| !b_errors.contains(p))
                    .unwrap_or(false)
                && !super::analyzer::is_noise_path_pub(f.path.as_deref())
        })
        .map(|f| FileErrorDiff {
            path: f.path.clone().unwrap_or_default(),
            op: f.op.clone(),
            result: f.result.unwrap_or(0),
        })
        .collect();

    Ok(FileDiff {
        baseline_ops: bf.len() as i64,
        candidate_ops: cf.len() as i64,
        new_paths,
        missing_paths,
        baseline_bytes_read: b_read,
        candidate_bytes_read: c_read,
        baseline_bytes_written: b_written,
        candidate_bytes_written: c_written,
        new_errors,
    })
}

fn sum_file_bytes(events: &[FileQueryResult]) -> (u64, u64) {
    let mut read = 0u64;
    let mut written = 0u64;
    for ev in events {
        if let Some(bytes) = ev.bytes {
            match ev.op.as_str() {
                "read" => read += bytes as u64,
                "write" => written += bytes as u64,
                _ => {}
            }
        }
    }
    (read, written)
}

fn diff_net(bdb: &TraceDb, cdb: &TraceDb) -> Result<NetDiff> {
    let bn = bdb.query_net_events()?;
    let cn = cdb.query_net_events()?;

    let b_conns: HashSet<String> = bn
        .iter()
        .filter(|n| n.op == "connect")
        .filter_map(|n| n.dst.clone())
        .collect();
    let c_conns: HashSet<String> = cn
        .iter()
        .filter(|n| n.op == "connect")
        .filter_map(|n| n.dst.clone())
        .collect();

    let new_connections: Vec<String> = c_conns.difference(&b_conns).cloned().collect();
    let missing_connections: Vec<String> = b_conns.difference(&c_conns).cloned().collect();

    let (b_sent, b_recv) = sum_net_bytes(&bn);
    let (c_sent, c_recv) = sum_net_bytes(&cn);

    let b_err_addrs: HashSet<String> = bn
        .iter()
        .filter(|n| n.result.map(|r| r < 0 && r != -115).unwrap_or(false))
        .filter_map(|n| n.dst.clone())
        .collect();

    let new_errors: Vec<NetErrorDiff> = cn
        .iter()
        .filter(|n| {
            n.result.map(|r| r < 0 && r != -115).unwrap_or(false)
                && n.dst
                    .as_ref()
                    .map(|d| !b_err_addrs.contains(d))
                    .unwrap_or(false)
        })
        .map(|n| NetErrorDiff {
            addr: n.dst.clone().unwrap_or_default(),
            op: n.op.clone(),
            result: n.result.unwrap_or(0),
        })
        .collect();

    Ok(NetDiff {
        baseline_ops: bn.len() as i64,
        candidate_ops: cn.len() as i64,
        new_connections,
        missing_connections,
        baseline_bytes_sent: b_sent,
        candidate_bytes_sent: c_sent,
        baseline_bytes_recv: b_recv,
        candidate_bytes_recv: c_recv,
        new_errors,
    })
}

fn sum_net_bytes(events: &[NetQueryResult]) -> (u64, u64) {
    let mut sent = 0u64;
    let mut recv = 0u64;
    for ev in events {
        if let Some(bytes) = ev.bytes {
            match ev.op.as_str() {
                "send" | "sendto" | "sendmsg" => sent += bytes as u64,
                "recv" | "recvfrom" | "recvmsg" => recv += bytes as u64,
                _ => {}
            }
        }
    }
    (sent, recv)
}

fn diff_stderr(baseline: &PackReader, candidate: &PackReader) -> Option<StderrDiff> {
    let b_stderr = baseline.stderr().ok()?;
    let c_stderr = candidate.stderr().ok()?;

    let b_text = String::from_utf8_lossy(&b_stderr);
    let c_text = String::from_utf8_lossy(&c_stderr);

    let b_lines: Vec<String> = b_text.lines().map(|s| s.to_string()).collect();
    let c_lines: Vec<String> = c_text.lines().map(|s| s.to_string()).collect();

    let b_set: HashSet<&str> = b_text.lines().collect();
    let new_lines: Vec<String> = c_text
        .lines()
        .filter(|l| !b_set.contains(l) && !l.is_empty())
        .map(|s| s.to_string())
        .collect();

    if b_lines == c_lines {
        return None;
    }

    Some(StderrDiff {
        baseline_lines: b_lines.into_iter().rev().take(10).rev().collect(),
        candidate_lines: c_lines.into_iter().rev().take(10).rev().collect(),
        new_lines,
    })
}
