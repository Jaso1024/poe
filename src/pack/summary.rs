use serde::{Deserialize, Serialize};

use crate::events::types::*;
use crate::trace::db::TraceDb;
use crate::util;

use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackSummary {
    pub version: String,
    pub run_id: String,
    pub timestamp: String,
    pub command: Vec<String>,
    pub working_dir: String,
    pub hostname: String,
    pub git_sha: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub signal_name: Option<String>,
    pub trigger_reason: Option<String>,
    pub duration_ms: u64,
    pub failure: Option<FailureSummary>,
    pub stats: StatsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureSummary {
    pub kind: String,
    pub description: String,
    pub primary_pid: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSummary {
    pub process_count: i64,
    pub event_count: i64,
    pub file_ops: i64,
    pub net_ops: i64,
    pub stack_samples: i64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn generate_summary(
    db: &TraceDb,
    run_info: &RunInfo,
    exit_code: Option<i32>,
    signal: Option<i32>,
    trigger: Option<TriggerReason>,
    duration_ms: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
) -> Result<PackSummary> {
    let failure = match trigger {
        Some(TriggerReason::Crash) => {
            let sig_name = signal.map(|s| util::signal_name(s).to_string());
            Some(FailureSummary {
                kind: "crash".into(),
                description: format!(
                    "Process crashed with signal {}",
                    sig_name.as_deref().unwrap_or("unknown")
                ),
                primary_pid: None,
            })
        }
        Some(TriggerReason::Signal) => {
            let sig_name = signal.map(|s| util::signal_name(s).to_string());
            Some(FailureSummary {
                kind: "signal".into(),
                description: format!(
                    "Process killed by signal {}",
                    sig_name.as_deref().unwrap_or("unknown")
                ),
                primary_pid: None,
            })
        }
        Some(TriggerReason::NonZeroExit) => Some(FailureSummary {
            kind: "non_zero_exit".into(),
            description: format!("Process exited with code {}", exit_code.unwrap_or(-1)),
            primary_pid: None,
        }),
        Some(TriggerReason::Always) => {
            if exit_code == Some(0) && signal.is_none() {
                None
            } else {
                Some(FailureSummary {
                    kind: "non_zero_exit".into(),
                    description: format!("Process exited with code {}", exit_code.unwrap_or(-1)),
                    primary_pid: None,
                })
            }
        }
        _ => None,
    };

    let stats = StatsSummary {
        process_count: db.process_count().unwrap_or(0),
        event_count: db.event_count().unwrap_or(0),
        file_ops: db.file_event_count().unwrap_or(0),
        net_ops: db.net_event_count().unwrap_or(0),
        stack_samples: db.stack_count().unwrap_or(0),
        stdout_bytes,
        stderr_bytes,
    };

    Ok(PackSummary {
        version: env!("CARGO_PKG_VERSION").to_string(),
        run_id: run_info.run_id.clone(),
        timestamp: run_info.start_time.to_rfc3339(),
        command: run_info.command.clone(),
        working_dir: run_info.working_dir.clone(),
        hostname: run_info.hostname.clone(),
        git_sha: run_info.git_sha.clone(),
        exit_code,
        signal,
        signal_name: signal.map(|s| util::signal_name(s).to_string()),
        trigger_reason: trigger.map(|t| t.as_str().to_string()),
        duration_ms,
        failure,
        stats,
    })
}
