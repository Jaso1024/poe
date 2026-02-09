use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::mpsc;
use std::thread;

use anyhow::Result;

use crate::events::types::*;
use crate::util;
use crate::util::ringbuf::ByteRing;

pub struct StdioPipes {
    pub child_stdout_write: RawFd,
    pub child_stderr_write: RawFd,
    pub parent_stdout_read: RawFd,
    pub parent_stderr_read: RawFd,
}

pub fn create_pipes() -> Result<StdioPipes> {
    let stdout_pipe = unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            anyhow::bail!("pipe2 failed: {}", std::io::Error::last_os_error());
        }
        fds
    };
    let stderr_pipe = unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            anyhow::bail!("pipe2 failed: {}", std::io::Error::last_os_error());
        }
        fds
    };

    Ok(StdioPipes {
        parent_stdout_read: stdout_pipe[0],
        child_stdout_write: stdout_pipe[1],
        parent_stderr_read: stderr_pipe[0],
        child_stderr_write: stderr_pipe[1],
    })
}

pub struct StdioCapture {
    stdout_handle: Option<thread::JoinHandle<ByteRing>>,
    stderr_handle: Option<thread::JoinHandle<ByteRing>>,
}

impl StdioCapture {
    pub fn start(
        pipes: &StdioPipes,
        root_pid: i32,
        event_tx: mpsc::Sender<TraceEvent>,
        base_ts: u64,
        ring_capacity: usize,
    ) -> Result<Self> {
        nix::unistd::close(pipes.child_stdout_write).ok();
        nix::unistd::close(pipes.child_stderr_write).ok();

        let stdout_read = pipes.parent_stdout_read;
        let stderr_read = pipes.parent_stderr_read;

        let stdout_tx = event_tx.clone();
        let stderr_tx = event_tx;

        let stdout_handle = thread::Builder::new()
            .name("poe-stdout-relay".into())
            .spawn(move || {
                relay_stream(
                    stdout_read,
                    std::io::stdout(),
                    StdioStream::Stdout,
                    root_pid,
                    stdout_tx,
                    base_ts,
                    ring_capacity,
                )
            })?;

        let stderr_handle = thread::Builder::new()
            .name("poe-stderr-relay".into())
            .spawn(move || {
                relay_stream(
                    stderr_read,
                    std::io::stderr(),
                    StdioStream::Stderr,
                    root_pid,
                    stderr_tx,
                    base_ts,
                    ring_capacity,
                )
            })?;

        Ok(Self {
            stdout_handle: Some(stdout_handle),
            stderr_handle: Some(stderr_handle),
        })
    }

    pub fn finish(mut self) -> (ByteRing, ByteRing) {
        let stdout_ring = self
            .stdout_handle
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_else(|| ByteRing::new(0));

        let stderr_ring = self
            .stderr_handle
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_else(|| ByteRing::new(0));

        (stdout_ring, stderr_ring)
    }
}

fn relay_stream<W: Write>(
    read_fd: RawFd,
    mut output: W,
    stream: StdioStream,
    root_pid: i32,
    event_tx: mpsc::Sender<TraceEvent>,
    base_ts: u64,
    ring_capacity: usize,
) -> ByteRing {
    let mut ring = ByteRing::new(ring_capacity);
    let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let mut buf = [0u8; 8192];

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = &buf[..n];
                ring.write(chunk);
                let _ = output.write_all(chunk);
                let _ = output.flush();

                let ts = util::timestamp_ns().saturating_sub(base_ts);
                let _ = event_tx.send(TraceEvent::Stdio(StdioChunk {
                    ts,
                    proc_id: root_pid,
                    stream,
                    data: chunk.to_vec(),
                }));
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
        }
    }

    ring
}
