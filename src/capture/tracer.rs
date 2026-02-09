use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::mpsc;

use anyhow::{bail, Context, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use crate::capture::syscalls::*;
use crate::events::types::*;
use crate::util;

struct TracedProcess {
    pid: Pid,
    pending_syscall: Option<PendingSyscall>,
    alive: bool,
}

struct PendingSyscall {
    nr: u64,
    args: [u64; 6],
    entry_info: SyscallEntryInfo,
}

pub struct TracerConfig {
    pub capture_mode: CaptureMode,
    pub stdout_fd: Option<RawFd>,
    pub stderr_fd: Option<RawFd>,
    pub env_overrides: HashMap<String, String>,
    pub clear_cloexec_fds: Vec<RawFd>,
}

pub struct Tracer {
    config: TracerConfig,
    processes: HashMap<i32, TracedProcess>,
    root_pid: Option<Pid>,
    event_tx: mpsc::Sender<TraceEvent>,
    decoder: SyscallDecoder,
    base_ts: u64,
}

impl Tracer {
    pub fn new(config: TracerConfig, event_tx: mpsc::Sender<TraceEvent>) -> Self {
        let base_ts = util::timestamp_ns();
        Self {
            config,
            processes: HashMap::new(),
            root_pid: None,
            event_tx,
            decoder: SyscallDecoder::new(),
            base_ts,
        }
    }

    pub fn spawn_and_trace(&mut self, argv: &[String]) -> Result<i32> {
        if argv.is_empty() {
            bail!("empty command");
        }

        let program = CString::new(argv[0].as_str())
            .with_context(|| format!("invalid program name: {}", argv[0]))?;

        let c_args: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(a.as_str()).unwrap())
            .collect();

        let stdout_fd = self.config.stdout_fd;
        let stderr_fd = self.config.stderr_fd;
        let env_overrides = self.config.env_overrides.clone();
        let clear_cloexec_fds = self.config.clear_cloexec_fds.clone();

        let fork_result = unsafe { nix::unistd::fork() }?;

        match fork_result {
            nix::unistd::ForkResult::Child => {
                if let Some(fd) = stdout_fd {
                    nix::unistd::dup2(fd, 1).ok();
                    nix::unistd::close(fd).ok();
                }
                if let Some(fd) = stderr_fd {
                    nix::unistd::dup2(fd, 2).ok();
                    nix::unistd::close(fd).ok();
                }

                for fd in &clear_cloexec_fds {
                    unsafe {
                        let flags = libc::fcntl(*fd, libc::F_GETFD);
                        if flags >= 0 {
                            libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                        }
                    }
                }

                for (key, val) in &env_overrides {
                    std::env::set_var(key, val);
                }

                ptrace::traceme().expect("PTRACE_TRACEME failed");

                unsafe { libc::raise(libc::SIGSTOP) };

                let err = nix::unistd::execvp(&program, &c_args).unwrap_err();
                eprintln!("poe: execvp failed: {}", err);
                std::process::exit(127);
            }
            nix::unistd::ForkResult::Parent { child } => {
                let raw_pid = child.as_raw();
                self.root_pid = Some(child);

                let status = waitpid(child, Some(WaitPidFlag::__WALL))?;
                match status {
                    WaitStatus::Stopped(_, Signal::SIGSTOP) => {}
                    other => bail!("unexpected initial wait status: {:?}", other),
                }

                let opts = ptrace::Options::PTRACE_O_TRACESYSGOOD
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORK
                    | ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEEXEC
                    | ptrace::Options::PTRACE_O_TRACEEXIT;
                ptrace::setoptions(child, opts)?;

                let cwd = util::procfs::read_cwd(raw_pid).unwrap_or_default();

                let proc_info = ProcessInfo {
                    proc_id: raw_pid,
                    parent_proc_id: None,
                    argv: argv.to_vec(),
                    cwd,
                    start_ts: 0,
                };

                self.processes.insert(
                    raw_pid,
                    TracedProcess {
                        pid: child,
                        pending_syscall: None,
                        alive: true,
                    },
                );

                let _ = self.event_tx.send(TraceEvent::Process(proc_info));

                ptrace::syscall(child, None)?;

                Ok(raw_pid)
            }
        }
    }

    pub fn run_event_loop(&mut self) -> Result<(Option<i32>, Option<i32>)> {
        let root_pid = self
            .root_pid
            .ok_or_else(|| anyhow::anyhow!("no root process"))?;
        let mut root_exit_code: Option<i32> = None;
        let mut root_signal: Option<i32> = None;

        loop {
            let status = match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
                Ok(s) => s,
                Err(nix::errno::Errno::ECHILD) => break,
                Err(e) => return Err(e.into()),
            };

            match status {
                WaitStatus::PtraceSyscall(pid) => {
                    self.handle_syscall(pid)?;
                    if ptrace::syscall(pid, None).is_err() {
                        self.mark_dead(pid.as_raw());
                    }
                }

                WaitStatus::PtraceEvent(pid, _sig, event) => {
                    self.handle_ptrace_event(pid, event)?;
                    if ptrace::syscall(pid, None).is_err() {
                        self.mark_dead(pid.as_raw());
                    }
                }

                WaitStatus::Exited(pid, code) => {
                    let ts = self.relative_ts();
                    let _ = self.event_tx.send(TraceEvent::ProcessExit(ProcessExit {
                        proc_id: pid.as_raw(),
                        end_ts: ts,
                        exit_code: Some(code),
                        signal: None,
                    }));
                    self.mark_dead(pid.as_raw());

                    if pid == root_pid {
                        root_exit_code = Some(code);
                    }
                    if self.all_dead() {
                        break;
                    }
                }

                WaitStatus::Signaled(pid, sig, _core) => {
                    let ts = self.relative_ts();
                    let sig_num = sig as i32;

                    let _ = self.event_tx.send(TraceEvent::ProcessExit(ProcessExit {
                        proc_id: pid.as_raw(),
                        end_ts: ts,
                        exit_code: None,
                        signal: Some(sig_num),
                    }));

                    let _ = self.event_tx.send(TraceEvent::Generic(Event {
                        ts,
                        proc_id: pid.as_raw(),
                        kind: EventKind::Signal,
                        detail: format!("killed by {} ({})", util::signal_name(sig_num), sig_num),
                    }));

                    self.mark_dead(pid.as_raw());

                    if pid == root_pid {
                        root_signal = Some(sig_num);
                    }
                    if self.all_dead() {
                        break;
                    }
                }

                WaitStatus::Stopped(pid, sig) => {
                    let deliver = match sig {
                        Signal::SIGSTOP | Signal::SIGTRAP => None,
                        _ => {
                            let ts = self.relative_ts();
                            let sig_num = sig as i32;
                            let is_crash = matches!(
                                sig,
                                Signal::SIGSEGV
                                    | Signal::SIGBUS
                                    | Signal::SIGILL
                                    | Signal::SIGFPE
                                    | Signal::SIGABRT
                            );

                            let mut detail =
                                format!("received {} ({})", util::signal_name(sig_num), sig_num);

                            if is_crash {
                                if let Ok(regs) = ptrace::getregs(pid) {
                                    detail.push_str(&format!(
                                        " rip={:#x} rsp={:#x} rbp={:#x} rax={:#x} rdi={:#x} rsi={:#x}",
                                        regs.rip, regs.rsp, regs.rbp, regs.rax, regs.rdi, regs.rsi,
                                    ));
                                }

                                if let Ok(siginfo) = ptrace::getsiginfo(pid) {
                                    let fault_addr = unsafe { siginfo.si_addr() } as u64;
                                    if fault_addr != 0 {
                                        detail.push_str(&format!(" fault_addr={:#x}", fault_addr));
                                    }
                                    detail.push_str(&format!(" si_code={}", siginfo.si_code));
                                }

                                if let Ok(maps) = util::procfs::read_maps(pid.as_raw()) {
                                    detail.push_str(&format!(" maps=[{}]", maps.len()));
                                }
                            }

                            let _ = self.event_tx.send(TraceEvent::Generic(Event {
                                ts,
                                proc_id: pid.as_raw(),
                                kind: EventKind::Signal,
                                detail,
                            }));
                            Some(sig)
                        }
                    };
                    if ptrace::syscall(pid, deliver).is_err() {
                        self.mark_dead(pid.as_raw());
                    }
                }

                WaitStatus::Continued(_) => {}

                WaitStatus::StillAlive => {}
            }
        }

        Ok((root_exit_code, root_signal))
    }

    fn handle_syscall(&mut self, pid: Pid) -> Result<()> {
        let raw = pid.as_raw();

        let regs = match ptrace::getregs(pid) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        let nr = regs.orig_rax;
        let rax = regs.rax as i64;

        // On x86_64, at syscall entry the kernel sets rax = -ENOSYS (-38).
        // At syscall exit, rax contains the return value.
        // We use this to determine entry vs exit without fragile toggling.
        let is_entry = rax == -38;

        if is_entry {
            let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];

            if is_interesting_syscall(nr) {
                let path_reader =
                    |addr: u64| -> Option<String> { read_string_from_process(pid, addr, 4096) };
                let addr_reader = |addr: u64, len: usize| -> Option<Vec<u8>> {
                    read_bytes_from_process(pid, addr, len)
                };

                let ts = self.relative_ts();
                let entry_info =
                    self.decoder
                        .decode_entry(raw, ts, nr, args, &path_reader, &addr_reader);

                if let Some(proc) = self.processes.get_mut(&raw) {
                    proc.pending_syscall = Some(PendingSyscall {
                        nr,
                        args,
                        entry_info,
                    });
                }
            }
        } else {
            let ret = rax;

            if let Some(proc) = self.processes.get_mut(&raw) {
                if let Some(pending) = proc.pending_syscall.take() {
                    match &pending.entry_info {
                        SyscallEntryInfo::File { .. } => {
                            if let Some(file_event) = self.decoder.finalize_file_event(
                                raw,
                                &pending.entry_info,
                                ret,
                                pending.nr,
                            ) {
                                let _ = self.event_tx.send(TraceEvent::File(file_event));
                            }
                        }
                        SyscallEntryInfo::Net { .. } => {
                            if let Some(net_event) = self.decoder.finalize_net_event(
                                raw,
                                &pending.entry_info,
                                ret,
                                pending.nr,
                                pending.args,
                            ) {
                                let _ = self.event_tx.send(TraceEvent::Net(net_event));
                            }
                        }
                        SyscallEntryInfo::Ignored => {}
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_ptrace_event(&mut self, pid: Pid, event: i32) -> Result<()> {
        let ts = self.relative_ts();

        match event {
            libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                let new_pid_raw = ptrace::getevent(pid)? as i32;
                let new_pid = Pid::from_raw(new_pid_raw);

                let _ = waitpid(new_pid, Some(WaitPidFlag::__WALL));

                let opts = ptrace::Options::PTRACE_O_TRACESYSGOOD
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORK
                    | ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEEXEC
                    | ptrace::Options::PTRACE_O_TRACEEXIT;

                let _ = ptrace::setoptions(new_pid, opts);

                let cwd = util::procfs::read_cwd(new_pid_raw).unwrap_or_default();
                let cmdline = util::procfs::read_cmdline(new_pid_raw).unwrap_or_default();

                self.processes.insert(
                    new_pid_raw,
                    TracedProcess {
                        pid: new_pid,
                        pending_syscall: None,
                        alive: true,
                    },
                );

                let _ = self.event_tx.send(TraceEvent::Process(ProcessInfo {
                    proc_id: new_pid_raw,
                    parent_proc_id: Some(pid.as_raw()),
                    argv: cmdline,
                    cwd,
                    start_ts: ts,
                }));

                let _ = ptrace::syscall(new_pid, None);
            }

            libc::PTRACE_EVENT_EXEC => {
                let raw = pid.as_raw();
                let cmdline = util::procfs::read_cmdline(raw).unwrap_or_default();

                let _ = self.event_tx.send(TraceEvent::Generic(Event {
                    ts,
                    proc_id: raw,
                    kind: EventKind::ProcessExec,
                    detail: serde_json::to_string(&cmdline).unwrap_or_default(),
                }));

                if let Some(proc) = self.processes.get_mut(&raw) {
                    proc.pending_syscall = None;
                }
            }

            libc::PTRACE_EVENT_EXIT => {
                let exit_status = ptrace::getevent(pid)? as i32;
                let code = if libc::WIFEXITED(exit_status) {
                    Some(libc::WEXITSTATUS(exit_status))
                } else {
                    None
                };
                let sig = if libc::WIFSIGNALED(exit_status) {
                    Some(libc::WTERMSIG(exit_status))
                } else {
                    None
                };

                let _ = self.event_tx.send(TraceEvent::Generic(Event {
                    ts,
                    proc_id: pid.as_raw(),
                    kind: EventKind::ProcessExit,
                    detail: format!("exit_code={:?} signal={:?}", code, sig),
                }));
            }

            _ => {}
        }

        Ok(())
    }

    fn mark_dead(&mut self, raw_pid: i32) {
        if let Some(proc) = self.processes.get_mut(&raw_pid) {
            proc.alive = false;
        }
    }

    fn all_dead(&self) -> bool {
        self.processes.values().all(|p| !p.alive)
    }

    fn relative_ts(&self) -> u64 {
        util::timestamp_ns().saturating_sub(self.base_ts)
    }

    pub fn root_pid(&self) -> Option<i32> {
        self.root_pid.map(|p| p.as_raw())
    }

    pub fn base_ts(&self) -> u64 {
        self.base_ts
    }
}

fn read_string_from_process(pid: Pid, addr: u64, max_len: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }

    let mut buf = vec![0u8; max_len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: max_len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: max_len,
    };

    let n = unsafe { libc::process_vm_readv(pid.as_raw(), &local_iov, 1, &remote_iov, 1, 0) };

    if n <= 0 {
        return read_string_ptrace(pid, addr, max_len.min(256));
    }

    let n = n as usize;
    let nul_pos = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Some(String::from_utf8_lossy(&buf[..nul_pos]).into_owned())
}

fn read_string_ptrace(pid: Pid, addr: u64, max_len: usize) -> Option<String> {
    let mut result = Vec::new();
    let word_size = std::mem::size_of::<libc::c_long>();
    let mut current_addr = addr;

    for _ in 0..(max_len / word_size + 1) {
        let word = ptrace::read(pid, current_addr as *mut libc::c_void).ok()?;
        let bytes = word.to_ne_bytes();

        for &b in &bytes {
            if b == 0 {
                return Some(String::from_utf8_lossy(&result).into_owned());
            }
            result.push(b);
            if result.len() >= max_len {
                return Some(String::from_utf8_lossy(&result).into_owned());
            }
        }

        current_addr += word_size as u64;
    }

    Some(String::from_utf8_lossy(&result).into_owned())
}

fn read_bytes_from_process(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
    if addr == 0 || len == 0 {
        return None;
    }

    let mut buf = vec![0u8; len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };

    let n = unsafe { libc::process_vm_readv(pid.as_raw(), &local_iov, 1, &remote_iov, 1, 0) };

    if n <= 0 {
        return read_bytes_ptrace(pid, addr, len);
    }

    buf.truncate(n as usize);
    Some(buf)
}

fn read_bytes_ptrace(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
    let word_size = std::mem::size_of::<libc::c_long>();
    let mut result = Vec::with_capacity(len);
    let mut current_addr = addr;

    while result.len() < len {
        let word = ptrace::read(pid, current_addr as *mut libc::c_void).ok()?;
        let bytes = word.to_ne_bytes();
        let remaining = len - result.len();
        let take = remaining.min(word_size);
        result.extend_from_slice(&bytes[..take]);
        current_addr += word_size as u64;
    }

    Some(result)
}
