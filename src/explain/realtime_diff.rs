use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::events::types::*;
use crate::pack::reader::PackReader;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Divergence {
    pub ts_ms: f64,
    pub kind: DivergenceKind,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DivergenceKind {
    NewFilePath,
    MissingFilePath,
    NewFileError,
    NewNetConnection,
    FailedNetConnection,
    NewProcess,
    UnexpectedSignal,
    ExtraStderr,
}

pub struct RealtimeDiffState {
    baseline_file_paths: HashSet<String>,
    baseline_net_addrs: HashSet<String>,
    baseline_file_errors: HashSet<String>,
    baseline_processes: HashSet<String>,
    baseline_stderr_lines: HashSet<String>,
    divergences: Vec<Divergence>,
}

impl RealtimeDiffState {
    pub fn from_baseline(baseline_path: &Path) -> Result<Self> {
        let pack = PackReader::open(baseline_path)?;
        let db = pack.db();

        let file_events = db.query_file_events()?;
        let net_events = db.query_net_events()?;
        let processes = db.query_processes()?;

        let baseline_file_paths: HashSet<String> =
            file_events.iter().filter_map(|f| f.path.clone()).collect();

        let baseline_net_addrs: HashSet<String> = net_events
            .iter()
            .filter(|n| n.op == "connect")
            .filter_map(|n| n.dst.clone())
            .collect();

        let baseline_file_errors: HashSet<String> = file_events
            .iter()
            .filter(|f| f.result.map(|r| r < 0).unwrap_or(false))
            .filter_map(|f| f.path.clone())
            .collect();

        let baseline_processes: HashSet<String> = processes
            .iter()
            .filter_map(|p| {
                p.argv.as_ref().and_then(|a| {
                    serde_json::from_str::<Vec<String>>(a)
                        .ok()
                        .map(|v| v.join(" "))
                })
            })
            .collect();

        let baseline_stderr_lines: HashSet<String> = pack
            .stderr()
            .ok()
            .map(|d| {
                String::from_utf8_lossy(&d)
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(|l| l.to_string())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            baseline_file_paths,
            baseline_net_addrs,
            baseline_file_errors,
            baseline_processes,
            baseline_stderr_lines,
            divergences: Vec::new(),
        })
    }

    pub fn check_event(&mut self, event: &TraceEvent) {
        match event {
            TraceEvent::File(f) => {
                if let Some(ref path) = f.path {
                    if !self.baseline_file_paths.contains(path)
                        && !crate::explain::analyzer::is_noise_path_pub(Some(path.as_str()))
                        && !path.contains("poe-pyhook")
                        && !path.contains("poe-rt-")
                        && !path.contains("poe-build-")
                    {
                        self.divergences.push(Divergence {
                            ts_ms: f.ts as f64 / 1_000_000.0,
                            kind: DivergenceKind::NewFilePath,
                            description: format!("new file access: {} {}", f.op.as_str(), path),
                        });
                    }

                    if let Some(result) = f.result {
                        if result < 0
                            && !self.baseline_file_errors.contains(path)
                            && !crate::explain::analyzer::is_noise_path_pub(Some(path.as_str()))
                            && !path.contains("poe-pyhook")
                            && !path.contains("poe-rt-")
                            && !path.contains("poe-build-")
                        {
                            self.divergences.push(Divergence {
                                ts_ms: f.ts as f64 / 1_000_000.0,
                                kind: DivergenceKind::NewFileError,
                                description: format!(
                                    "new file error: {} {} -> {}",
                                    f.op.as_str(),
                                    path,
                                    result
                                ),
                            });
                        }
                    }
                }
            }
            TraceEvent::Net(n) => {
                if n.op == NetOpKind::Connect {
                    if let Some(ref dst) = n.dst {
                        if !self.baseline_net_addrs.contains(dst) {
                            self.divergences.push(Divergence {
                                ts_ms: n.ts as f64 / 1_000_000.0,
                                kind: DivergenceKind::NewNetConnection,
                                description: format!("new network connection: {}", dst),
                            });
                        }

                        if let Some(result) = n.result {
                            if result < 0 && result != -115 {
                                self.divergences.push(Divergence {
                                    ts_ms: n.ts as f64 / 1_000_000.0,
                                    kind: DivergenceKind::FailedNetConnection,
                                    description: format!(
                                        "failed connection: {} -> {}",
                                        dst, result
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            TraceEvent::Process(p) => {
                let cmd = p.argv.join(" ");
                if !self.baseline_processes.contains(&cmd) {
                    self.divergences.push(Divergence {
                        ts_ms: p.start_ts as f64 / 1_000_000.0,
                        kind: DivergenceKind::NewProcess,
                        description: format!("new process: {}", cmd),
                    });
                }
            }
            TraceEvent::Stdio(chunk) => {
                if chunk.stream == StdioStream::Stderr {
                    let text = String::from_utf8_lossy(&chunk.data);
                    for line in text.lines() {
                        if !line.is_empty() && !self.baseline_stderr_lines.contains(line) {
                            self.divergences.push(Divergence {
                                ts_ms: chunk.ts as f64 / 1_000_000.0,
                                kind: DivergenceKind::ExtraStderr,
                                description: format!(
                                    "new stderr: {}",
                                    &line[..line.len().min(120)]
                                ),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    pub fn divergences(&self) -> &[Divergence] {
        &self.divergences
    }

    pub fn first_divergence(&self) -> Option<&Divergence> {
        self.divergences.first()
    }

    pub fn has_diverged(&self) -> bool {
        !self.divergences.is_empty()
    }
}

pub struct RealtimeDiffMonitor {
    state: Arc<Mutex<RealtimeDiffState>>,
}

impl RealtimeDiffMonitor {
    pub fn new(baseline_path: &Path) -> Result<Self> {
        let state = RealtimeDiffState::from_baseline(baseline_path)?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn check(&self, event: &TraceEvent) {
        if let Ok(mut state) = self.state.lock() {
            state.check_event(event);
        }
    }

    pub fn take_divergences(&self) -> Vec<Divergence> {
        if let Ok(mut state) = self.state.lock() {
            std::mem::take(&mut state.divergences)
        } else {
            Vec::new()
        }
    }

    pub fn has_diverged(&self) -> bool {
        self.state.lock().map(|s| s.has_diverged()).unwrap_or(false)
    }
}
