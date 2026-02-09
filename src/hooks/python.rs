use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::events::types::*;

const SITECUSTOMIZE_PY: &str = include_str!("sitecustomize.py");

pub fn is_python_command(argv: &[String]) -> bool {
    if argv.is_empty() {
        return false;
    }

    let cmd = Path::new(&argv[0])
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();

    cmd == "python"
        || cmd == "python3"
        || cmd.starts_with("python3.")
        || cmd == "python2"
        || cmd.starts_with("python2.")
}

pub struct PythonHookSetup {
    hook_dir: PathBuf,
    read_fd: RawFd,
    write_fd: RawFd,
}

impl PythonHookSetup {
    pub fn prepare(run_id: &str) -> Result<Self> {
        let hook_dir = std::env::temp_dir().join(format!("poe-pyhook-{}", &run_id[..8]));
        fs::create_dir_all(&hook_dir)?;

        let site_path = hook_dir.join("sitecustomize.py");
        fs::write(&site_path, SITECUSTOMIZE_PY)?;

        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret != 0 {
            anyhow::bail!(
                "pipe2 for python hook fd failed: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(Self {
            hook_dir,
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    pub fn write_fd(&self) -> RawFd {
        self.write_fd
    }

    pub fn apply_env(&self, env: &mut HashMap<String, String>) {
        let hook_dir_str = self.hook_dir.to_string_lossy().into_owned();

        let existing = env.get("PYTHONPATH").cloned().unwrap_or_default();
        if existing.is_empty() {
            env.insert("PYTHONPATH".into(), hook_dir_str);
        } else {
            env.insert(
                "PYTHONPATH".into(),
                format!("{}:{}", hook_dir_str, existing),
            );
        }

        env.insert("_POE_HOOK_FD".into(), self.write_fd.to_string());
        env.insert("_POE_TRACE_CALLS".into(), "1".into());
    }

    pub fn clear_cloexec_on_write_fd(&self) {
        unsafe {
            let flags = libc::fcntl(self.write_fd, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(self.write_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
        }
    }

    pub fn start_reader(
        self,
        event_tx: mpsc::Sender<TraceEvent>,
        root_pid: i32,
    ) -> PythonHookReader {
        nix::unistd::close(self.write_fd).ok();

        let read_fd = self.read_fd;
        let hook_dir = self.hook_dir.clone();

        let handle = thread::Builder::new()
            .name("poe-python-hook".into())
            .spawn(move || {
                let file = unsafe { std::fs::File::from_raw_fd(read_fd) };
                let reader = BufReader::new(file);

                for line in reader.lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => break,
                    };

                    if line.is_empty() {
                        continue;
                    }

                    if let Ok(record) = serde_json::from_str::<PythonEvent>(&line) {
                        let trace_event = convert_python_event(record, root_pid);
                        let _ = event_tx.send(trace_event);
                    }
                }

                let _ = fs::remove_dir_all(&hook_dir);
            })
            .expect("failed to spawn python hook reader thread");

        PythonHookReader {
            handle: Some(handle),
        }
    }
}

pub struct PythonHookReader {
    handle: Option<thread::JoinHandle<()>>,
}

impl PythonHookReader {
    pub fn finish(mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum PythonEvent {
    #[serde(rename = "call")]
    Call {
        ts: u64,
        tid: u64,
        func: String,
        file: String,
        line: u32,
        depth: u32,
    },
    #[serde(rename = "return")]
    Return {
        ts: u64,
        tid: u64,
        func: String,
        file: String,
        line: u32,
        depth: u32,
        retval: Option<String>,
    },
    #[serde(rename = "exception")]
    Exception {
        ts: u64,
        tid: u64,
        func: String,
        file: String,
        line: u32,
        exc_type: String,
        exc_msg: String,
        locals: Option<HashMap<String, String>>,
    },
    #[serde(rename = "unhandled_exception")]
    UnhandledException {
        ts: u64,
        tid: u64,
        exc_type: String,
        exc_msg: String,
        traceback: Vec<PythonFrame>,
        chain: Vec<PythonExcChain>,
        formatted: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct PythonFrame {
    file: String,
    line: u32,
    func: String,
    locals: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PythonExcChain {
    #[serde(rename = "type")]
    exc_type: String,
    msg: String,
    cause: Option<String>,
}

fn convert_python_event(event: PythonEvent, root_pid: i32) -> TraceEvent {
    match event {
        PythonEvent::Call {
            ts,
            tid: _,
            func,
            file,
            line,
            depth,
        } => TraceEvent::Generic(Event {
            ts,
            proc_id: root_pid,
            kind: EventKind::PythonCall,
            detail: serde_json::json!({
                "func": func,
                "file": file,
                "line": line,
                "depth": depth,
            })
            .to_string(),
        }),
        PythonEvent::Return {
            ts,
            tid: _,
            func,
            file,
            line,
            depth,
            retval,
        } => TraceEvent::Generic(Event {
            ts,
            proc_id: root_pid,
            kind: EventKind::PythonReturn,
            detail: serde_json::json!({
                "func": func,
                "file": file,
                "line": line,
                "depth": depth,
                "retval": retval,
            })
            .to_string(),
        }),
        PythonEvent::Exception {
            ts,
            tid: _,
            func,
            file,
            line,
            exc_type,
            exc_msg,
            locals,
        } => TraceEvent::Generic(Event {
            ts,
            proc_id: root_pid,
            kind: EventKind::PythonException,
            detail: serde_json::json!({
                "func": func,
                "file": file,
                "line": line,
                "exc_type": exc_type,
                "exc_msg": exc_msg,
                "locals": locals,
            })
            .to_string(),
        }),
        PythonEvent::UnhandledException {
            ts,
            tid: _,
            exc_type,
            exc_msg,
            traceback,
            chain,
            formatted,
        } => TraceEvent::Generic(Event {
            ts,
            proc_id: root_pid,
            kind: EventKind::PythonUnhandledException,
            detail: serde_json::json!({
                "exc_type": exc_type,
                "exc_msg": exc_msg,
                "traceback": traceback,
                "chain": chain,
                "formatted": formatted,
            })
            .to_string(),
        }),
    }
}
