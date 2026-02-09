use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::Result;

use crate::capture::stacks::StackSampler;
use crate::capture::stdio::{self, StdioCapture};
use crate::capture::tracer::{Tracer, TracerConfig};
use crate::events::types::*;
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

    let (event_tx, event_rx) = mpsc::channel::<TraceEvent>();

    let batch_size = config.batch_size;
    let db_writer_handle = {
        let db_path = db_path.clone();
        thread::Builder::new()
            .name("poe-db-writer".into())
            .spawn(move || -> Result<()> {
                let db = TraceDb::open(&db_path)?;
                let mut batch = Vec::with_capacity(batch_size);

                loop {
                    match event_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(event) => {
                            batch.push(event);
                            while let Ok(event) = event_rx.try_recv() {
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

    let tracer_config = TracerConfig {
        capture_mode: config.capture_mode,
        stdout_fd: Some(pipes.child_stdout_write),
        stderr_fd: Some(pipes.child_stderr_write),
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

    let mut stack_sampler = StackSampler::new(base_ts, config.sample_freq);
    stack_sampler.add_process(root_pid)?;

    let (exit_code, signal) = tracer.run_event_loop()?;

    stack_sampler.drain_samples(&event_tx);
    stack_sampler.stop();

    drop(event_tx);
    drop(tracer);

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

    {
        let db = TraceDb::open(&db_path)?;
        db.update_run_end(
            &run_id,
            &end_time,
            exit_code,
            signal,
            trigger,
        )?;
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

    Ok(RunResult {
        exit_code,
        signal,
        trigger,
        pack_path,
        run_id,
        duration_ms,
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
