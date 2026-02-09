use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use anyhow::Result;

use crate::build::instrument;
use crate::capture::stacks::StackSampler;
use crate::capture::stdio::{self, StdioCapture};
use crate::capture::tracer::{Tracer, TracerConfig};
use crate::distributed::trace_context::TraceContext;
use crate::events::types::*;
use crate::explain::realtime_diff::RealtimeDiffMonitor;
use crate::hooks::adapter::AdapterManager;
use crate::hooks::rust as rust_hooks;
use crate::trace::TraceDb;
use crate::util;

pub struct RunConfig {
    pub command: Vec<String>,
    pub capture_mode: CaptureMode,
    pub always_emit: bool,
    pub output_dir: PathBuf,
    pub ring_buffer_size: usize,
    pub sample_freq: u64,
    pub batch_size: usize,
    pub diff_baseline: Option<std::path::PathBuf>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            capture_mode: CaptureMode::Lite,
            always_emit: false,
            output_dir: PathBuf::from("."),
            ring_buffer_size: 1024 * 1024,
            sample_freq: 99,
            batch_size: 1024,
            diff_baseline: None,
        }
    }
}

pub struct RunResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub trigger: Option<TriggerReason>,
    pub pack_path: Option<PathBuf>,
    pub run_id: String,
    pub duration_ms: u64,
    pub realtime_divergences: Vec<crate::explain::realtime_diff::Divergence>,
}

pub fn execute_run(config: RunConfig) -> Result<RunResult> {
    let run_id = uuid::Uuid::new_v4().to_string();
    let start_time = chrono::Utc::now();
    let start_mono = util::timestamp_ns();

    let work_dir = std::env::temp_dir().join(format!("poe-{}", &run_id[..8]));
    std::fs::create_dir_all(&work_dir)?;

    let db_path = work_dir.join("trace.sqlite");
    {
        let db = TraceDb::create(&db_path)?;
        drop(db);
    }

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let env_hash = {
        let env: std::collections::HashMap<String, String> = std::env::vars().collect();
        util::hash_env(&env)
    };

    let git_sha = util::procfs::git_sha(Path::new(&cwd));
    let hostname = util::procfs::hostname();

    let run_info = RunInfo {
        run_id: run_id.clone(),
        command: config.command.clone(),
        working_dir: cwd.clone(),
        env_hash,
        start_time,
        git_sha,
        hostname,
    };

    {
        let db = TraceDb::open(&db_path)?;
        db.insert_run(&run_info)?;
    }

    let pipes = stdio::create_pipes()?;

    let mut adapter_manager = AdapterManager::new();
    adapter_manager.detect_and_register(&config.command);

    let (event_tx, event_rx) = mpsc::channel::<TraceEvent>();

    let diff_monitor: Option<Arc<RealtimeDiffMonitor>> =
        config
            .diff_baseline
            .as_ref()
            .and_then(|path| match RealtimeDiffMonitor::new(path) {
                Ok(m) => {
                    eprintln!("poe: realtime diff monitor active against baseline");
                    Some(Arc::new(m))
                }
                Err(e) => {
                    eprintln!("poe: failed to load diff baseline: {:#}", e);
                    None
                }
            });

    let batch_size = config.batch_size;
    let db_writer_handle = {
        let db_path = db_path.clone();
        let diff_mon = diff_monitor.clone();
        thread::Builder::new()
            .name("poe-db-writer".into())
            .spawn(move || -> Result<()> {
                let db = TraceDb::open(&db_path)?;
                let mut batch = Vec::with_capacity(batch_size);

                loop {
                    match event_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(event) => {
                            if let Some(ref mon) = diff_mon {
                                mon.check(&event);
                            }
                            batch.push(event);
                            while let Ok(event) = event_rx.try_recv() {
                                if let Some(ref mon) = diff_mon {
                                    mon.check(&event);
                                }
                                batch.push(event);
                                if batch.len() >= batch_size {
                                    break;
                                }
                            }
                            if batch.len() >= batch_size {
                                db.batch_insert_events(&batch)?;
                                batch.clear();
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if !batch.is_empty() {
                                db.batch_insert_events(&batch)?;
                                batch.clear();
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            if !batch.is_empty() {
                                db.batch_insert_events(&batch)?;
                            }
                            break;
                        }
                    }
                }
                Ok(())
            })?
    };

    let mut env_overrides = std::collections::HashMap::new();
    let mut clear_cloexec_fds = Vec::new();

    adapter_manager.on_load(&mut env_overrides, &mut clear_cloexec_fds)?;

    rust_hooks::apply_rust_env(&mut env_overrides);

    let trace_ctx = TraceContext::from_env_or_new();
    trace_ctx.inject_env(&mut env_overrides);

    let tracer_config = TracerConfig {
        capture_mode: config.capture_mode,
        stdout_fd: Some(pipes.child_stdout_write),
        stderr_fd: Some(pipes.child_stderr_write),
        env_overrides,
        clear_cloexec_fds,
    };

    let mut tracer = Tracer::new(tracer_config, event_tx.clone());
    let root_pid = tracer.spawn_and_trace(&config.command)?;
    let base_ts = tracer.base_ts();

    let stdio_capture = StdioCapture::start(
        &pipes,
        root_pid,
        event_tx.clone(),
        base_ts,
        config.ring_buffer_size,
    )?;

    adapter_manager.on_start(event_tx.clone(), root_pid)?;

    let mut stack_sampler = StackSampler::new(base_ts, config.sample_freq);
    stack_sampler.add_process(root_pid)?;

    let (exit_code, signal) = tracer.run_event_loop()?;

    stack_sampler.drain_samples(&event_tx);
    stack_sampler.stop();

    drop(event_tx);
    drop(tracer);

    adapter_manager.on_exit()?;

    let rt_trace_path = std::path::PathBuf::from(format!("/tmp/poe-rt-{}.bin", root_pid));
    let (native_trace_entries, rt_start_ns) = if rt_trace_path.exists() {
        match instrument::read_runtime_trace(&rt_trace_path) {
            Ok((entries, start_ns)) => {
                eprintln!(
                    "poe: captured {} native function trace entries",
                    entries.len()
                );
                let _ = std::fs::remove_file(&rt_trace_path);
                (entries, start_ns)
            }
            Err(e) => {
                eprintln!("poe: failed to read runtime trace: {:#}", e);
                (Vec::new(), base_ts)
            }
        }
    } else {
        (Vec::new(), base_ts)
    };

    let (stdout_ring, stderr_ring) = stdio_capture.finish();

    match db_writer_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("poe: db writer error: {:#}", e),
        Err(e) => eprintln!("poe: db writer thread panicked: {:?}", e),
    }

    let end_time = chrono::Utc::now();
    let duration_ns = util::timestamp_ns().saturating_sub(start_mono);
    let duration_ms = duration_ns / 1_000_000;

    let trigger = determine_trigger(exit_code, signal, config.always_emit);

    if !native_trace_entries.is_empty() {
        let db = TraceDb::open(&db_path)?;
        let binary_path = &config.command[0];
        let resolved_addrs = resolve_native_addrs(
            binary_path,
            &native_trace_entries
                .iter()
                .map(|e| e.func_addr)
                .collect::<Vec<_>>(),
        );
        for entry in &native_trace_entries {
            let symbol = resolved_addrs
                .get(&entry.func_addr)
                .cloned()
                .unwrap_or_else(|| format!("0x{:x}", entry.func_addr));
            let call_site = resolved_addrs
                .get(&entry.call_site)
                .cloned()
                .unwrap_or_else(|| format!("0x{:x}", entry.call_site));
            let detail = serde_json::json!({
                "func": symbol,
                "call_site": call_site,
                "depth": entry.depth,
                "tid": entry.tid,
                "func_addr": format!("0x{:x}", entry.func_addr),
            });
            let kind = if entry.event_type == 0 {
                crate::events::types::EventKind::NativeTraceEnter
            } else {
                crate::events::types::EventKind::NativeTraceExit
            };
            let event = crate::events::types::Event {
                ts: rt_start_ns.saturating_sub(base_ts) + entry.ts_ns,
                proc_id: root_pid,
                kind,
                detail: detail.to_string(),
            };
            db.insert_event(&event)?;
        }
    }

    {
        let db = TraceDb::open(&db_path)?;
        db.update_run_end(&run_id, &end_time, exit_code, signal, trigger)?;
    }

    let pack_path = if trigger.is_some() {
        let pack_name = format!("poe-{}.poepack", &run_id[..8]);
        let pack_path = config.output_dir.join(&pack_name);

        let db = TraceDb::open(&db_path)?;
        db.checkpoint()?;
        crate::pack::writer::write_pack(
            &pack_path,
            &db,
            &run_info,
            exit_code,
            signal,
            trigger,
            duration_ms,
            &stdout_ring,
            &stderr_ring,
        )?;

        Some(pack_path)
    } else {
        None
    };

    if let Err(e) = std::fs::remove_dir_all(&work_dir) {
        eprintln!("poe: failed to clean up work dir: {}", e);
    }

    let realtime_divergences = diff_monitor
        .as_ref()
        .map(|m| m.take_divergences())
        .unwrap_or_default();

    Ok(RunResult {
        exit_code,
        signal,
        trigger,
        pack_path,
        run_id,
        duration_ms,
        realtime_divergences,
    })
}

fn determine_trigger(
    exit_code: Option<i32>,
    signal: Option<i32>,
    always: bool,
) -> Option<TriggerReason> {
    if always {
        return Some(TriggerReason::Always);
    }

    if let Some(sig) = signal {
        match sig {
            libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGFPE | libc::SIGABRT => {
                return Some(TriggerReason::Crash);
            }
            _ => return Some(TriggerReason::Signal),
        }
    }

    if let Some(code) = exit_code {
        if code != 0 {
            return Some(TriggerReason::NonZeroExit);
        }
    }

    None
}

fn resolve_native_addrs(binary: &str, addrs: &[u64]) -> std::collections::HashMap<u64, String> {
    use std::collections::HashMap;

    let mut result = HashMap::new();

    let Ok(output) = std::process::Command::new("nm")
        .arg("-C")
        .arg(binary)
        .output()
    else {
        return result;
    };

    if !output.status.success() {
        return result;
    }

    let nm_output = String::from_utf8_lossy(&output.stdout);
    let mut sym_map: Vec<(u64, String)> = Vec::new();

    for line in nm_output.lines() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() == 3 {
            if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                sym_map.push((addr, parts[2].to_string()));
            }
        }
    }

    sym_map.sort_by_key(|&(a, _)| a);

    let elf_main = sym_map
        .iter()
        .find(|(_, name)| name == "main")
        .map(|&(a, _)| a);

    let load_offset = if let Some(elf_m) = elf_main {
        let page_offset = elf_m & 0xFFF;
        addrs
            .iter()
            .find(|&&a| (a & 0xFFF) == page_offset)
            .map(|&a| a - elf_m)
            .unwrap_or(0)
    } else {
        0
    };

    for &addr in addrs {
        let file_addr = addr.wrapping_sub(load_offset);
        let idx = sym_map.partition_point(|&(sa, _)| sa <= file_addr);
        if idx > 0 {
            let (sym_addr, ref sym_name) = sym_map[idx - 1];
            let offset = file_addr - sym_addr;
            if offset < 0x10000 {
                if offset == 0 {
                    result.insert(addr, sym_name.clone());
                } else {
                    result.insert(addr, format!("{}+0x{:x}", sym_name, offset));
                }
            }
        }
    }

    result
}
