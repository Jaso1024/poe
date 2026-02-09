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
    PythonCall,
    PythonReturn,
    PythonException,
    PythonUnhandledException,
    NativeTraceEnter,
    NativeTraceExit,
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
            Self::PythonCall => "python_call",
            Self::PythonReturn => "python_return",
            Self::PythonException => "python_exception",
            Self::PythonUnhandledException => "python_unhandled_exception",
            Self::NativeTraceEnter => "native_trace_enter",
            Self::NativeTraceExit => "native_trace_exit",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kind_round_trip() {
        let kinds = [
            EventKind::ProcessStart,
            EventKind::ProcessExit,
            EventKind::ProcessExec,
            EventKind::SyscallEntry,
            EventKind::SyscallExit,
            EventKind::Signal,
            EventKind::FileOp,
            EventKind::NetOp,
            EventKind::StackSample,
            EventKind::StdoutData,
            EventKind::StderrData,
            EventKind::PythonCall,
            EventKind::PythonReturn,
            EventKind::PythonException,
            EventKind::PythonUnhandledException,
            EventKind::NativeTraceEnter,
            EventKind::NativeTraceExit,
        ];

        for kind in &kinds {
            let s = kind.as_str();
            assert!(!s.is_empty(), "EventKind {:?} has empty as_str", kind);
        }
    }

    #[test]
    fn file_op_kind_as_str() {
        assert_eq!(FileOpKind::Open.as_str(), "open");
        assert_eq!(FileOpKind::Read.as_str(), "read");
        assert_eq!(FileOpKind::Write.as_str(), "write");
        assert_eq!(FileOpKind::Close.as_str(), "close");
    }

    #[test]
    fn net_op_kind_as_str() {
        assert_eq!(NetOpKind::Connect.as_str(), "connect");
        assert_eq!(NetOpKind::Send.as_str(), "send");
        assert_eq!(NetOpKind::Recv.as_str(), "recv");
    }

    #[test]
    fn trigger_reason_as_str() {
        assert_eq!(TriggerReason::Crash.as_str(), "crash");
        assert_eq!(TriggerReason::Signal.as_str(), "signal");
        assert_eq!(TriggerReason::NonZeroExit.as_str(), "non_zero_exit");
        assert_eq!(TriggerReason::Always.as_str(), "always");
    }

    #[test]
    fn process_info_fields() {
        let pi = ProcessInfo {
            proc_id: 1234,
            parent_proc_id: Some(1),
            argv: vec!["test".into(), "--flag".into()],
            cwd: "/tmp".into(),
            start_ts: 1000,
        };
        assert_eq!(pi.proc_id, 1234);
        assert_eq!(pi.argv.len(), 2);
    }
}
