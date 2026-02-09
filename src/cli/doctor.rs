use anyhow::Result;
use colored::Colorize;

struct Check {
    name: &'static str,
    status: CheckStatus,
    detail: String,
}

enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

pub fn execute() -> Result<()> {
    println!();
    println!("{}", "=== poe doctor ===".cyan().bold());
    println!();

    let checks = vec![
        check_kernel(),
        check_ptrace(),
        check_perf(),
        check_proc_filesystem(),
        check_process_vm_readv(),
    ];

    let mut ok_count = 0;
    let mut warn_count = 0;
    let mut fail_count = 0;

    for check in &checks {
        let (icon, color_fn): (&str, fn(&str) -> colored::ColoredString) = match check.status {
            CheckStatus::Ok => {
                ok_count += 1;
                ("OK", |s: &str| s.green())
            }
            CheckStatus::Warn => {
                warn_count += 1;
                ("WARN", |s: &str| s.yellow())
            }
            CheckStatus::Fail => {
                fail_count += 1;
                ("FAIL", |s: &str| s.red())
            }
        };

        println!(
            "  [{}] {}: {}",
            color_fn(icon),
            check.name,
            check.detail
        );
    }

    println!();
    println!(
        "  {} ok, {} warnings, {} failures",
        ok_count.to_string().green(),
        warn_count.to_string().yellow(),
        fail_count.to_string().red()
    );
    println!();

    if fail_count > 0 {
        println!(
            "  {}",
            "Some checks failed. poe may not work correctly on this system."
                .red()
                .bold()
        );
    } else if warn_count > 0 {
        println!(
            "  {}",
            "Some optional features are unavailable. Core functionality should work."
                .yellow()
        );
    } else {
        println!(
            "  {}",
            "All checks passed. poe is ready to use.".green().bold()
        );
    }

    println!();

    Ok(())
}

fn check_kernel() -> Check {
    let version = std::fs::read_to_string("/proc/version").unwrap_or_default();
    let version_short = version
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string();

    let parts: Vec<&str> = version_short.split('.').collect();
    let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    if major >= 5 || (major == 4 && minor >= 8) {
        Check {
            name: "kernel version",
            status: CheckStatus::Ok,
            detail: format!("{} (>= 4.8 required for full ptrace support)", version_short),
        }
    } else {
        Check {
            name: "kernel version",
            status: CheckStatus::Warn,
            detail: format!("{} (4.8+ recommended)", version_short),
        }
    }
}

fn check_ptrace() -> Check {
    let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .unwrap_or_else(|_| "N/A".into())
        .trim()
        .to_string();

    match scope.as_str() {
        "0" => Check {
            name: "ptrace scope",
            status: CheckStatus::Ok,
            detail: "0 (classic ptrace permissions - unrestricted for child processes)".into(),
        },
        "1" => Check {
            name: "ptrace scope",
            status: CheckStatus::Ok,
            detail: "1 (restricted - child processes only, sufficient for poe)".into(),
        },
        "2" => Check {
            name: "ptrace scope",
            status: CheckStatus::Warn,
            detail: "2 (admin only - may need CAP_SYS_PTRACE)".into(),
        },
        "3" => Check {
            name: "ptrace scope",
            status: CheckStatus::Fail,
            detail: "3 (no ptrace allowed - poe cannot function)".into(),
        },
        "N/A" => Check {
            name: "ptrace scope",
            status: CheckStatus::Ok,
            detail: "YAMA not present (ptrace unrestricted)".into(),
        },
        _ => Check {
            name: "ptrace scope",
            status: CheckStatus::Warn,
            detail: format!("unknown scope: {}", scope),
        },
    }
}

fn check_perf() -> Check {
    let paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .unwrap_or_else(|_| "N/A".into())
        .trim()
        .to_string();

    match paranoid.as_str() {
        "-1" => Check {
            name: "perf_event_paranoid",
            status: CheckStatus::Ok,
            detail: "-1 (no restrictions on perf events)".into(),
        },
        "0" | "1" => Check {
            name: "perf_event_paranoid",
            status: CheckStatus::Ok,
            detail: format!(
                "{} (sufficient for user-space stack sampling)",
                paranoid
            ),
        },
        "2" => Check {
            name: "perf_event_paranoid",
            status: CheckStatus::Warn,
            detail: "2 (stack sampling may require CAP_PERFMON)".into(),
        },
        "3" | "4" => Check {
            name: "perf_event_paranoid",
            status: CheckStatus::Warn,
            detail: format!(
                "{} (stack sampling disabled without CAP_PERFMON)",
                paranoid
            ),
        },
        "N/A" => Check {
            name: "perf_event_paranoid",
            status: CheckStatus::Warn,
            detail: "unable to read perf_event_paranoid".into(),
        },
        _ => Check {
            name: "perf_event_paranoid",
            status: CheckStatus::Warn,
            detail: format!("unknown value: {}", paranoid),
        },
    }
}

fn check_proc_filesystem() -> Check {
    if std::path::Path::new("/proc/self/maps").exists() {
        Check {
            name: "/proc filesystem",
            status: CheckStatus::Ok,
            detail: "available (required for memory map reading)".into(),
        }
    } else {
        Check {
            name: "/proc filesystem",
            status: CheckStatus::Fail,
            detail: "/proc not mounted or not accessible".into(),
        }
    }
}

fn check_process_vm_readv() -> Check {
    let local_iov = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    };
    let remote_iov = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    };

    let ret = unsafe {
        libc::process_vm_readv(std::process::id() as i32, &local_iov, 1, &remote_iov, 1, 0)
    };

    let err = std::io::Error::last_os_error();
    if ret == 0 || err.raw_os_error() != Some(libc::ENOSYS) {
        Check {
            name: "process_vm_readv",
            status: CheckStatus::Ok,
            detail: "available (efficient cross-process memory reading)".into(),
        }
    } else {
        Check {
            name: "process_vm_readv",
            status: CheckStatus::Warn,
            detail: "unavailable (will fall back to ptrace PEEKDATA, slower)".into(),
        }
    }
}
