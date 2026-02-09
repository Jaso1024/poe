use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    pub run_id: String,
    pub command: Vec<String>,
    pub working_dir: String,
    pub env_hash: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub git_sha: Option<String>,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub proc_id: i32,
    pub parent_proc_id: Option<i32>,
    pub argv: Vec<String>,
    pub cwd: String,
    pub start_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExit {
    pub proc_id: i32,
    pub end_ts: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    ProcessStart,
    ProcessExit,
    ProcessExec,
    SyscallEntry,
    SyscallExit,
    Signal,
    FileOp,
    NetOp,
    StackSample,
    StdoutData,
    StderrData,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessStart => "process_start",
            Self::ProcessExit => "process_exit",
            Self::ProcessExec => "process_exec",
            Self::SyscallEntry => "syscall_entry",
            Self::SyscallExit => "syscall_exit",
            Self::Signal => "signal",
            Self::FileOp => "file_op",
            Self::NetOp => "net_op",
            Self::StackSample => "stack_sample",
            Self::StdoutData => "stdout_data",
            Self::StderrData => "stderr_data",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: u64,
    pub proc_id: i32,
    pub kind: EventKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOpKind {
    Open,
    Close,
    Read,
    Write,
    Rename,
    Unlink,
    Mkdir,
    Stat,
    Chmod,
    Chown,
    Link,
    Symlink,
    Readlink,
    Truncate,
    Access,
}

impl FileOpKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Close => "close",
            Self::Read => "read",
            Self::Write => "write",
            Self::Rename => "rename",
            Self::Unlink => "unlink",
            Self::Mkdir => "mkdir",
            Self::Stat => "stat",
            Self::Chmod => "chmod",
            Self::Chown => "chown",
            Self::Link => "link",
            Self::Symlink => "symlink",
            Self::Readlink => "readlink",
            Self::Truncate => "truncate",
            Self::Access => "access",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub ts: u64,
    pub proc_id: i32,
    pub op: FileOpKind,
    pub path: Option<String>,
    pub fd: Option<i32>,
    pub bytes: Option<u64>,
    pub flags: Option<i32>,
    pub result: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetOpKind {
    Socket,
    Connect,
    Bind,
    Listen,
    Accept,
    Send,
    Recv,
    Shutdown,
    GetSockName,
    GetPeerName,
}

impl NetOpKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Connect => "connect",
            Self::Bind => "bind",
            Self::Listen => "listen",
            Self::Accept => "accept",
            Self::Send => "send",
            Self::Recv => "recv",
            Self::Shutdown => "shutdown",
            Self::GetSockName => "getsockname",
            Self::GetPeerName => "getpeername",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEvent {
    pub ts: u64,
    pub proc_id: i32,
    pub op: NetOpKind,
    pub proto: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub bytes: Option<u64>,
    pub fd: Option<i32>,
    pub result: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSample {
    pub ts: u64,
    pub proc_id: i32,
    pub frames: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioChunk {
    pub ts: u64,
    pub proc_id: i32,
    pub stream: StdioStream,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StdioStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceEvent {
    Process(ProcessInfo),
    ProcessExit(ProcessExit),
    File(FileEvent),
    Net(NetEvent),
    Stack(StackSample),
    Stdio(StdioChunk),
    Generic(Event),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerReason {
    NonZeroExit,
    Signal,
    Crash,
    Explicit,
    Always,
}

impl TriggerReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NonZeroExit => "non_zero_exit",
            Self::Signal => "signal",
            Self::Crash => "crash",
            Self::Explicit => "explicit",
            Self::Always => "always",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureMode {
    Lite,
    Full,
}
