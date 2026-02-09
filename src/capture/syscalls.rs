use crate::events::types::*;

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_PIPE: u64 = 22;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_SENDMSG: u64 = 46;
pub const SYS_RECVMSG: u64 = 47;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SOCKETPAIR: u64 = 53;
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_CREAT: u64 = 85;
pub const SYS_LINK: u64 = 86;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_SYMLINK: u64 = 88;
pub const SYS_READLINK: u64 = 89;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_FCHMODAT: u64 = 268;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_ACCEPT4: u64 = 288;
pub const SYS_RENAMEAT2: u64 = 316;
pub const SYS_EXECVEAT: u64 = 322;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_PIPE2: u64 = 293;

pub fn syscall_name(nr: u64) -> &'static str {
    match nr {
        SYS_READ => "read",
        SYS_WRITE => "write",
        SYS_OPEN => "open",
        SYS_CLOSE => "close",
        SYS_STAT => "stat",
        SYS_FSTAT => "fstat",
        SYS_LSTAT => "lstat",
        SYS_PREAD64 => "pread64",
        SYS_PWRITE64 => "pwrite64",
        SYS_READV => "readv",
        SYS_WRITEV => "writev",
        SYS_PIPE => "pipe",
        SYS_DUP => "dup",
        SYS_DUP2 => "dup2",
        SYS_SOCKET => "socket",
        SYS_CONNECT => "connect",
        SYS_ACCEPT => "accept",
        SYS_SENDTO => "sendto",
        SYS_RECVFROM => "recvfrom",
        SYS_SENDMSG => "sendmsg",
        SYS_RECVMSG => "recvmsg",
        SYS_SHUTDOWN => "shutdown",
        SYS_BIND => "bind",
        SYS_LISTEN => "listen",
        SYS_GETSOCKNAME => "getsockname",
        SYS_GETPEERNAME => "getpeername",
        SYS_SOCKETPAIR => "socketpair",
        SYS_CLONE => "clone",
        SYS_FORK => "fork",
        SYS_VFORK => "vfork",
        SYS_EXECVE => "execve",
        SYS_EXIT => "exit",
        SYS_FCNTL => "fcntl",
        SYS_TRUNCATE => "truncate",
        SYS_FTRUNCATE => "ftruncate",
        SYS_CHDIR => "chdir",
        SYS_RENAME => "rename",
        SYS_MKDIR => "mkdir",
        SYS_RMDIR => "rmdir",
        SYS_CREAT => "creat",
        SYS_LINK => "link",
        SYS_UNLINK => "unlink",
        SYS_SYMLINK => "symlink",
        SYS_READLINK => "readlink",
        SYS_CHMOD => "chmod",
        SYS_CHOWN => "chown",
        SYS_OPENAT => "openat",
        SYS_MKDIRAT => "mkdirat",
        SYS_UNLINKAT => "unlinkat",
        SYS_RENAMEAT => "renameat",
        SYS_FCHMODAT => "fchmodat",
        SYS_FACCESSAT => "faccessat",
        SYS_ACCEPT4 => "accept4",
        SYS_RENAMEAT2 => "renameat2",
        SYS_EXECVEAT => "execveat",
        SYS_EXIT_GROUP => "exit_group",
        SYS_NEWFSTATAT => "newfstatat",
        SYS_PIPE2 => "pipe2",
        _ => "unknown",
    }
}

pub fn is_file_syscall(nr: u64) -> bool {
    matches!(
        nr,
        SYS_READ
            | SYS_WRITE
            | SYS_OPEN
            | SYS_CLOSE
            | SYS_STAT
            | SYS_FSTAT
            | SYS_LSTAT
            | SYS_PREAD64
            | SYS_PWRITE64
            | SYS_READV
            | SYS_WRITEV
            | SYS_TRUNCATE
            | SYS_FTRUNCATE
            | SYS_RENAME
            | SYS_MKDIR
            | SYS_RMDIR
            | SYS_CREAT
            | SYS_LINK
            | SYS_UNLINK
            | SYS_SYMLINK
            | SYS_READLINK
            | SYS_CHMOD
            | SYS_CHOWN
            | SYS_OPENAT
            | SYS_MKDIRAT
            | SYS_UNLINKAT
            | SYS_RENAMEAT
            | SYS_FCHMODAT
            | SYS_FACCESSAT
            | SYS_RENAMEAT2
            | SYS_NEWFSTATAT
    )
}

pub fn is_net_syscall(nr: u64) -> bool {
    matches!(
        nr,
        SYS_SOCKET
            | SYS_CONNECT
            | SYS_ACCEPT
            | SYS_SENDTO
            | SYS_RECVFROM
            | SYS_SENDMSG
            | SYS_RECVMSG
            | SYS_SHUTDOWN
            | SYS_BIND
            | SYS_LISTEN
            | SYS_GETSOCKNAME
            | SYS_GETPEERNAME
            | SYS_SOCKETPAIR
            | SYS_ACCEPT4
    )
}

pub fn is_interesting_syscall(nr: u64) -> bool {
    is_file_syscall(nr) || is_net_syscall(nr) || is_process_syscall(nr)
}

pub fn is_process_syscall(nr: u64) -> bool {
    matches!(
        nr,
        SYS_CLONE | SYS_FORK | SYS_VFORK | SYS_EXECVE | SYS_EXIT | SYS_EXIT_GROUP | SYS_EXECVEAT
    )
}

#[derive(Debug, Clone)]
pub struct SyscallInfo {
    pub nr: u64,
    pub args: [u64; 6],
    pub ret: Option<i64>,
}

#[derive(Debug, Clone)]
pub enum DecodedSyscall {
    File(FileEvent),
    Net(NetEvent),
    Process(String),
    Ignored,
}

pub struct SyscallDecoder;

impl Default for SyscallDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallDecoder {
    pub fn new() -> Self {
        Self
    }

    pub fn decode_entry(
        &self,
        _pid: i32,
        ts: u64,
        nr: u64,
        args: [u64; 6],
        path_reader: &dyn Fn(u64) -> Option<String>,
        addr_reader: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    ) -> SyscallEntryInfo {
        let rel_ts = ts;

        match nr {
            SYS_OPEN | SYS_CREAT => {
                let path = path_reader(args[0]);
                SyscallEntryInfo::File {
                    op: FileOpKind::Open,
                    path,
                    fd: None,
                    flags: Some(args[1] as i32),
                    ts: rel_ts,
                }
            }
            SYS_OPENAT => {
                let path = path_reader(args[1]);
                SyscallEntryInfo::File {
                    op: FileOpKind::Open,
                    path,
                    fd: Some(args[0] as i32),
                    flags: Some(args[2] as i32),
                    ts: rel_ts,
                }
            }
            SYS_CLOSE => SyscallEntryInfo::File {
                op: FileOpKind::Close,
                path: None,
                fd: Some(args[0] as i32),
                flags: None,
                ts: rel_ts,
            },
            SYS_READ | SYS_PREAD64 => SyscallEntryInfo::File {
                op: FileOpKind::Read,
                path: None,
                fd: Some(args[0] as i32),
                flags: None,
                ts: rel_ts,
            },
            SYS_WRITE | SYS_PWRITE64 => SyscallEntryInfo::File {
                op: FileOpKind::Write,
                path: None,
                fd: Some(args[0] as i32),
                flags: None,
                ts: rel_ts,
            },
            SYS_READV => SyscallEntryInfo::File {
                op: FileOpKind::Read,
                path: None,
                fd: Some(args[0] as i32),
                flags: None,
                ts: rel_ts,
            },
            SYS_WRITEV => SyscallEntryInfo::File {
                op: FileOpKind::Write,
                path: None,
                fd: Some(args[0] as i32),
                flags: None,
                ts: rel_ts,
            },
            SYS_RENAME => {
                let old = path_reader(args[0]);
                let new = path_reader(args[1]);
                let path = match (old, new) {
                    (Some(o), Some(n)) => Some(format!("{} -> {}", o, n)),
                    (Some(o), None) => Some(o),
                    _ => None,
                };
                SyscallEntryInfo::File {
                    op: FileOpKind::Rename,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_RENAMEAT | SYS_RENAMEAT2 => {
                let old = path_reader(args[1]);
                let new = path_reader(args[3]);
                let path = match (old, new) {
                    (Some(o), Some(n)) => Some(format!("{} -> {}", o, n)),
                    (Some(o), None) => Some(o),
                    _ => None,
                };
                SyscallEntryInfo::File {
                    op: FileOpKind::Rename,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_UNLINK => {
                let path = path_reader(args[0]);
                SyscallEntryInfo::File {
                    op: FileOpKind::Unlink,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_UNLINKAT => {
                let path = path_reader(args[1]);
                SyscallEntryInfo::File {
                    op: FileOpKind::Unlink,
                    path,
                    fd: Some(args[0] as i32),
                    flags: Some(args[2] as i32),
                    ts: rel_ts,
                }
            }
            SYS_MKDIR | SYS_MKDIRAT => {
                let path = if nr == SYS_MKDIR {
                    path_reader(args[0])
                } else {
                    path_reader(args[1])
                };
                SyscallEntryInfo::File {
                    op: FileOpKind::Mkdir,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_STAT | SYS_LSTAT | SYS_NEWFSTATAT => {
                let path = if nr == SYS_NEWFSTATAT {
                    path_reader(args[1])
                } else {
                    path_reader(args[0])
                };
                SyscallEntryInfo::File {
                    op: FileOpKind::Stat,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_FSTAT => SyscallEntryInfo::File {
                op: FileOpKind::Stat,
                path: None,
                fd: Some(args[0] as i32),
                flags: None,
                ts: rel_ts,
            },
            SYS_CHMOD | SYS_FCHMODAT => {
                let path = if nr == SYS_FCHMODAT {
                    path_reader(args[1])
                } else {
                    path_reader(args[0])
                };
                SyscallEntryInfo::File {
                    op: FileOpKind::Chmod,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_CHOWN => {
                let path = path_reader(args[0]);
                SyscallEntryInfo::File {
                    op: FileOpKind::Chown,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_LINK => {
                let old = path_reader(args[0]);
                let new = path_reader(args[1]);
                let path = match (old, new) {
                    (Some(o), Some(n)) => Some(format!("{} -> {}", o, n)),
                    (Some(o), None) => Some(o),
                    _ => None,
                };
                SyscallEntryInfo::File {
                    op: FileOpKind::Link,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_SYMLINK => {
                let target = path_reader(args[0]);
                let linkpath = path_reader(args[1]);
                let path = match (target, linkpath) {
                    (Some(t), Some(l)) => Some(format!("{} -> {}", l, t)),
                    (_, Some(l)) => Some(l),
                    _ => None,
                };
                SyscallEntryInfo::File {
                    op: FileOpKind::Symlink,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_READLINK => {
                let path = path_reader(args[0]);
                SyscallEntryInfo::File {
                    op: FileOpKind::Readlink,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_TRUNCATE => {
                let path = path_reader(args[0]);
                SyscallEntryInfo::File {
                    op: FileOpKind::Truncate,
                    path,
                    fd: None,
                    flags: None,
                    ts: rel_ts,
                }
            }
            SYS_FTRUNCATE => SyscallEntryInfo::File {
                op: FileOpKind::Truncate,
                path: None,
                fd: Some(args[0] as i32),
                flags: None,
                ts: rel_ts,
            },
            SYS_FACCESSAT => {
                let path = path_reader(args[1]);
                SyscallEntryInfo::File {
                    op: FileOpKind::Access,
                    path,
                    fd: Some(args[0] as i32),
                    flags: Some(args[2] as i32),
                    ts: rel_ts,
                }
            }

            SYS_SOCKET => {
                let proto = decode_socket_domain(args[0] as i32);
                SyscallEntryInfo::Net {
                    op: NetOpKind::Socket,
                    proto: Some(proto),
                    addr: None,
                    ts: rel_ts,
                }
            }
            SYS_CONNECT => {
                let addr = decode_sockaddr(args[1], args[2] as usize, addr_reader);
                SyscallEntryInfo::Net {
                    op: NetOpKind::Connect,
                    proto: None,
                    addr,
                    ts: rel_ts,
                }
            }
            SYS_BIND => {
                let addr = decode_sockaddr(args[1], args[2] as usize, addr_reader);
                SyscallEntryInfo::Net {
                    op: NetOpKind::Bind,
                    proto: None,
                    addr,
                    ts: rel_ts,
                }
            }
            SYS_LISTEN => SyscallEntryInfo::Net {
                op: NetOpKind::Listen,
                proto: None,
                addr: None,
                ts: rel_ts,
            },
            SYS_ACCEPT | SYS_ACCEPT4 => SyscallEntryInfo::Net {
                op: NetOpKind::Accept,
                proto: None,
                addr: None,
                ts: rel_ts,
            },
            SYS_SENDTO => SyscallEntryInfo::Net {
                op: NetOpKind::Send,
                proto: None,
                addr: decode_sockaddr(args[4], args[5] as usize, addr_reader),
                ts: rel_ts,
            },
            SYS_RECVFROM => SyscallEntryInfo::Net {
                op: NetOpKind::Recv,
                proto: None,
                addr: None,
                ts: rel_ts,
            },
            SYS_SENDMSG => SyscallEntryInfo::Net {
                op: NetOpKind::Send,
                proto: None,
                addr: None,
                ts: rel_ts,
            },
            SYS_RECVMSG => SyscallEntryInfo::Net {
                op: NetOpKind::Recv,
                proto: None,
                addr: None,
                ts: rel_ts,
            },
            SYS_SHUTDOWN => SyscallEntryInfo::Net {
                op: NetOpKind::Shutdown,
                proto: None,
                addr: None,
                ts: rel_ts,
            },

            _ => SyscallEntryInfo::Ignored,
        }
    }

    pub fn finalize_file_event(
        &self,
        pid: i32,
        entry: &SyscallEntryInfo,
        ret: i64,
        nr: u64,
    ) -> Option<FileEvent> {
        if let SyscallEntryInfo::File {
            op,
            path,
            fd,
            flags,
            ts,
        } = entry
        {
            let bytes = match nr {
                SYS_READ | SYS_PREAD64 | SYS_READV | SYS_WRITE | SYS_PWRITE64 | SYS_WRITEV => {
                    if ret >= 0 {
                        Some(ret as u64)
                    } else {
                        None
                    }
                }
                _ => None,
            };

            Some(FileEvent {
                ts: *ts,
                proc_id: pid,
                op: *op,
                path: path.clone(),
                fd: match nr {
                    SYS_OPEN | SYS_OPENAT | SYS_CREAT => {
                        if ret >= 0 {
                            Some(ret as i32)
                        } else {
                            *fd
                        }
                    }
                    _ => *fd,
                },
                bytes,
                flags: *flags,
                result: Some(ret),
            })
        } else {
            None
        }
    }

    pub fn finalize_net_event(
        &self,
        pid: i32,
        entry: &SyscallEntryInfo,
        ret: i64,
        nr: u64,
        args: [u64; 6],
    ) -> Option<NetEvent> {
        if let SyscallEntryInfo::Net {
            op,
            proto,
            addr,
            ts,
        } = entry
        {
            let bytes = match nr {
                SYS_SENDTO | SYS_SENDMSG => {
                    if ret >= 0 {
                        Some(ret as u64)
                    } else {
                        None
                    }
                }
                SYS_RECVFROM | SYS_RECVMSG => {
                    if ret >= 0 {
                        Some(ret as u64)
                    } else {
                        None
                    }
                }
                _ => None,
            };

            let fd = match nr {
                SYS_SOCKET => {
                    if ret >= 0 {
                        Some(ret as i32)
                    } else {
                        None
                    }
                }
                SYS_ACCEPT | SYS_ACCEPT4 => {
                    if ret >= 0 {
                        Some(ret as i32)
                    } else {
                        None
                    }
                }
                SYS_CONNECT | SYS_BIND | SYS_LISTEN | SYS_SHUTDOWN | SYS_SENDTO | SYS_RECVFROM
                | SYS_SENDMSG | SYS_RECVMSG => Some(args[0] as i32),
                _ => None,
            };

            Some(NetEvent {
                ts: *ts,
                proc_id: pid,
                op: *op,
                proto: proto.clone(),
                src: None,
                dst: addr.clone(),
                bytes,
                fd,
                result: Some(ret),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub enum SyscallEntryInfo {
    File {
        op: FileOpKind,
        path: Option<String>,
        fd: Option<i32>,
        flags: Option<i32>,
        ts: u64,
    },
    Net {
        op: NetOpKind,
        proto: Option<String>,
        addr: Option<String>,
        ts: u64,
    },
    Ignored,
}

fn decode_socket_domain(domain: i32) -> String {
    match domain {
        libc::AF_UNIX => "unix".into(),
        libc::AF_INET => "ipv4".into(),
        libc::AF_INET6 => "ipv6".into(),
        libc::AF_NETLINK => "netlink".into(),
        other => format!("af_{}", other),
    }
}

fn decode_sockaddr(
    addr_ptr: u64,
    addr_len: usize,
    reader: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
) -> Option<String> {
    if addr_ptr == 0 || addr_len < 2 {
        return None;
    }

    let data = reader(addr_ptr, addr_len.min(128))?;
    if data.len() < 2 {
        return None;
    }

    let family = u16::from_ne_bytes([data[0], data[1]]) as i32;

    match family {
        libc::AF_INET => {
            if data.len() < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            let port = u16::from_be_bytes([data[2], data[3]]);
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(format!("{}:{}", ip, port))
        }
        libc::AF_INET6 => {
            if data.len() < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            let port = u16::from_be_bytes([data[2], data[3]]);
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&data[8..24]);
            let ip = std::net::Ipv6Addr::from(addr_bytes);
            Some(format!("[{}]:{}", ip, port))
        }
        libc::AF_UNIX => {
            if data.len() > 2 {
                let path_bytes = &data[2..];
                let end = path_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(path_bytes.len());
                if end > 0 && path_bytes[0] == 0 {
                    Some(format!("@{}", String::from_utf8_lossy(&path_bytes[1..end])))
                } else {
                    Some(String::from_utf8_lossy(&path_bytes[..end]).into_owned())
                }
            } else {
                Some("unix".into())
            }
        }
        _ => Some(format!("family={}", family)),
    }
}
