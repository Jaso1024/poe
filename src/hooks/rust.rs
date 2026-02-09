use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::explain::analyzer::ErrorPattern;

pub fn is_rust_command(argv: &[String]) -> bool {
    if argv.is_empty() {
        return false;
    }

    let cmd = std::path::Path::new(&argv[0])
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();

    if cmd == "cargo" {
        if let Some(sub) = argv.get(1) {
            return matches!(sub.as_str(), "run" | "test" | "bench");
        }
        return false;
    }

    false
}

pub fn is_likely_rust_binary(argv: &[String]) -> bool {
    if argv.is_empty() {
        return false;
    }

    let path = &argv[0];

    if path.contains("/target/debug/") || path.contains("/target/release/") {
        return true;
    }

    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.is_file() {
            if let Ok(data) = std::fs::read(path) {
                if data.len() > 100 {
                    let haystack = &data[..data.len().min(1024 * 1024)];
                    return haystack.windows(12).any(|w| {
                        w == b"rust_begin_" || w == b"rust_panic" || w == b"__rust_alloc"
                    });
                }
            }
        }
    }

    false
}

pub fn apply_rust_env(env: &mut HashMap<String, String>) {
    if !env.contains_key("RUST_BACKTRACE") {
        env.insert("RUST_BACKTRACE".into(), "full".into());
    }
    if !env.contains_key("RUST_LIB_BACKTRACE") {
        env.insert("RUST_LIB_BACKTRACE".into(), "1".into());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustPanicInfo {
    pub message: String,
    pub location: Option<PanicLocation>,
    pub thread: Option<String>,
    pub backtrace: Vec<RustBacktraceFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanicLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustBacktraceFrame {
    pub index: u32,
    pub symbol: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub addr: Option<String>,
}

pub fn parse_rust_panic(stderr: &str) -> Option<RustPanicInfo> {
    let mut thread_name = None;
    let mut panic_msg = None;
    let mut panic_location = None;
    let mut backtrace_frames = Vec::new();

    let lines: Vec<&str> = stderr.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if line.contains("panicked at") {
            if let Some(info) = parse_panic_line(line) {
                thread_name = info.0;
                panic_location = info.2;
                if info.1.is_empty() {
                    if let Some(next_line) = lines.get(i + 1) {
                        let msg = next_line.trim().to_string();
                        if !msg.is_empty()
                            && !msg.starts_with("note:")
                            && !msg.starts_with("stack backtrace:")
                        {
                            panic_msg = Some(msg);
                        }
                    }
                } else {
                    panic_msg = Some(info.1);
                }
            }
        }

        if line.trim().starts_with("thread '") && line.contains("panicked") {
            let start = line.find("thread '").unwrap() + 8;
            if let Some(end) = line[start..].find('\'') {
                thread_name = Some(line[start..start + end].to_string());
            }
        }

        if let Some(frame) = parse_backtrace_frame(line) {
            backtrace_frames.push(frame);
        }

        if line.trim().starts_with("at ") && !backtrace_frames.is_empty() {
            if let Some(loc) = parse_at_location(line.trim()) {
                if let Some(last) = backtrace_frames.last_mut() {
                    last.file = Some(loc.0);
                    last.line = Some(loc.1);
                }
            }
        }
    }

    panic_msg.map(|message| RustPanicInfo {
        message,
        location: panic_location,
        thread: thread_name,
        backtrace: backtrace_frames,
    })
}

fn parse_panic_line(line: &str) -> Option<(Option<String>, String, Option<PanicLocation>)> {
    let thread_name = if line.contains("thread '") {
        let start = line.find("thread '")? + 8;
        let end = start + line[start..].find('\'')?;
        Some(line[start..end].to_string())
    } else {
        None
    };

    let panic_at_idx = line.find("panicked at ")?;
    let after_panic = &line[panic_at_idx + 12..];

    if after_panic.starts_with('\'') {
        let msg_start = 1;
        let msg_end = after_panic[msg_start..].find('\'')?;
        let msg = after_panic[msg_start..msg_start + msg_end].to_string();

        let rest = &after_panic[msg_start + msg_end + 1..];
        let location = if rest.contains(", ") {
            parse_panic_location(rest.trim_start_matches(", ").trim())
        } else {
            None
        };

        Some((thread_name, msg, location))
    } else {
        let trimmed = after_panic.trim().trim_end_matches(':');
        if let Some(loc) = parse_panic_location(trimmed) {
            Some((thread_name, String::new(), Some(loc)))
        } else {
            Some((thread_name, trimmed.to_string(), None))
        }
    }
}

fn parse_panic_location(s: &str) -> Option<PanicLocation> {
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    if parts.len() >= 2 {
        let line_str = parts[0].trim();
        let col_and_file: (Option<u32>, String) = if parts.len() == 3 {
            (parts[1].trim().parse::<u32>().ok(), parts[2].to_string())
        } else {
            (None, parts[1].to_string())
        };

        let line: Option<u32> = if col_and_file.0.is_some() {
            parts[1].trim().parse::<u32>().ok()
        } else {
            line_str.parse::<u32>().ok()
        };

        line.map(|l| PanicLocation {
            file: col_and_file.1,
            line: l,
            column: if col_and_file.0.is_some() {
                line_str.parse::<u32>().ok()
            } else {
                None
            },
        })
    } else {
        None
    }
}

fn parse_backtrace_frame(line: &str) -> Option<RustBacktraceFrame> {
    let trimmed = line.trim();

    if !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }

    let colon_pos = trimmed.find(':')?;
    let index: u32 = trimmed[..colon_pos].trim().parse().ok()?;
    let rest = trimmed[colon_pos + 1..].trim();

    let (addr, symbol) = if rest.starts_with("0x") {
        let dash_pos = rest.find(" - ");
        match dash_pos {
            Some(dp) => {
                let addr = rest[..dp].trim().to_string();
                let sym = rest[dp + 3..].trim().to_string();
                (Some(addr), if sym.is_empty() { None } else { Some(sym) })
            }
            None => {
                let space = rest.find(' ').unwrap_or(rest.len());
                (Some(rest[..space].to_string()), None)
            }
        }
    } else {
        (
            None,
            if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            },
        )
    };

    Some(RustBacktraceFrame {
        index,
        symbol,
        file: None,
        line: None,
        addr,
    })
}

fn parse_at_location(line: &str) -> Option<(String, u32)> {
    let s = line.strip_prefix("at ")?;
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    match parts.len() {
        3 => {
            let line_num: u32 = parts[1].trim().parse().ok()?;
            Some((parts[2].to_string(), line_num))
        }
        2 => {
            let line_num: u32 = parts[0].trim().parse().ok()?;
            Some((parts[1].to_string(), line_num))
        }
        _ => None,
    }
}

pub fn detect_rust_patterns(stderr: &str) -> Vec<ErrorPattern> {
    let mut patterns = Vec::new();

    if let Some(panic_info) = parse_rust_panic(stderr) {
        let location_str = panic_info
            .location
            .as_ref()
            .map(|l| format!(" at {}:{}", l.file, l.line))
            .unwrap_or_default();

        let thread_str = panic_info
            .thread
            .as_ref()
            .map(|t| format!(" in thread '{}'", t))
            .unwrap_or_default();

        let mut examples = vec![format!(
            "panic: {}{}{}",
            panic_info.message, location_str, thread_str
        )];

        let user_frames: Vec<&RustBacktraceFrame> = panic_info
            .backtrace
            .iter()
            .filter(|f| {
                f.symbol
                    .as_ref()
                    .map(|s| {
                        !s.contains("std::")
                            && !s.contains("core::")
                            && !s.contains("__rust_")
                            && !s.contains("rust_begin_")
                            && !s.contains("backtrace::")
                            && !s.contains("panic_unwind")
                    })
                    .unwrap_or(false)
            })
            .take(5)
            .collect();

        for frame in &user_frames {
            let loc = match (&frame.file, frame.line) {
                (Some(f), Some(l)) => format!(" at {}:{}", f, l),
                _ => String::new(),
            };
            examples.push(format!(
                "  #{}: {}{}",
                frame.index,
                frame.symbol.as_deref().unwrap_or("???"),
                loc,
            ));
        }

        patterns.push(ErrorPattern {
            category: "rust_panic".into(),
            severity: "critical".into(),
            description: format!(
                "Rust panic: {}{}",
                &panic_info.message[..panic_info.message.len().min(120)],
                location_str,
            ),
            count: 1,
            examples,
        });
    }

    if stderr.contains("memory allocation of") && stderr.contains("failed") {
        patterns.push(ErrorPattern {
            category: "rust_oom".into(),
            severity: "critical".into(),
            description: "Rust memory allocation failure".into(),
            count: 1,
            examples: vec![stderr
                .lines()
                .find(|l| l.contains("memory allocation"))
                .unwrap_or("allocation failed")
                .to_string()],
        });
    }

    if stderr.contains("stack overflow") {
        patterns.push(ErrorPattern {
            category: "rust_stack_overflow".into(),
            severity: "critical".into(),
            description: "Rust stack overflow detected".into(),
            count: 1,
            examples: vec!["thread caused a stack overflow".into()],
        });
    }

    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_format_panic() {
        let stderr = r#"thread 'main' panicked at src/main.rs:4:5:
index out of bounds: the len is 3 but the index is 20
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"#;

        let info = parse_rust_panic(stderr).unwrap();
        assert_eq!(
            info.message,
            "index out of bounds: the len is 3 but the index is 20"
        );
        assert_eq!(info.thread.as_deref(), Some("main"));
        let loc = info.location.as_ref().unwrap();
        assert_eq!(loc.file, "src/main.rs");
        assert_eq!(loc.line, 4);
        assert_eq!(loc.column, Some(5));
    }

    #[test]
    fn parse_new_format_with_pid() {
        let stderr = r#"thread 'main' (12345) panicked at main.rs:4:5:
index out of bounds: the len is 3 but the index is 20"#;

        let info = parse_rust_panic(stderr).unwrap();
        assert_eq!(
            info.message,
            "index out of bounds: the len is 3 but the index is 20"
        );
        assert_eq!(info.thread.as_deref(), Some("main"));
        let loc = info.location.as_ref().unwrap();
        assert_eq!(loc.file, "main.rs");
        assert_eq!(loc.line, 4);
    }

    #[test]
    fn parse_old_format_panic() {
        let stderr = r#"thread 'main' panicked at 'attempt to divide by zero', src/main.rs:10:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"#;

        let info = parse_rust_panic(stderr).unwrap();
        assert_eq!(info.message, "attempt to divide by zero");
        assert_eq!(info.thread.as_deref(), Some("main"));
        let loc = info.location.as_ref().unwrap();
        assert_eq!(loc.file, "src/main.rs");
        assert_eq!(loc.line, 10);
    }

    #[test]
    fn parse_backtrace_frames() {
        let stderr = r#"thread 'main' panicked at src/main.rs:4:5:
something went wrong
stack backtrace:
   0:     0x55fb1c2af592 - std::backtrace_rs::backtrace::libunwind::trace::h123
                               at /rustc/abc123/library/std/src/backtrace.rs:117:9
   1:     0x55fb1c281051 - main::process_data::h123
                               at /home/user/project/src/main.rs:4:5
   2:     0x55fb1c281136 - main::main::h456
                               at /home/user/project/src/main.rs:9:18"#;

        let info = parse_rust_panic(stderr).unwrap();
        assert_eq!(info.backtrace.len(), 3);
        assert_eq!(info.backtrace[0].index, 0);
        assert!(info.backtrace[0]
            .symbol
            .as_ref()
            .unwrap()
            .contains("backtrace"));
        assert_eq!(info.backtrace[1].index, 1);
        assert!(info.backtrace[1]
            .symbol
            .as_ref()
            .unwrap()
            .contains("process_data"));
        assert_eq!(
            info.backtrace[1].file.as_deref(),
            Some("/home/user/project/src/main.rs")
        );
        assert_eq!(info.backtrace[1].line, Some(4));
    }

    #[test]
    fn parse_named_thread() {
        let stderr = "thread 'worker-3' panicked at src/worker.rs:42:10:\ncustom error";
        let info = parse_rust_panic(stderr).unwrap();
        assert_eq!(info.thread.as_deref(), Some("worker-3"));
        assert_eq!(info.message, "custom error");
    }

    #[test]
    fn detect_oom_pattern() {
        let stderr = "memory allocation of 1073741824 bytes failed";
        let patterns = detect_rust_patterns(stderr);
        assert!(patterns.iter().any(|p| p.category == "rust_oom"));
    }

    #[test]
    fn detect_stack_overflow() {
        let stderr = "thread 'main' has overflowed its stack\nfatal runtime error: stack overflow";
        let patterns = detect_rust_patterns(stderr);
        assert!(patterns.iter().any(|p| p.category == "rust_stack_overflow"));
    }

    #[test]
    fn no_panic_returns_none() {
        let stderr = "some normal output\nno panics here";
        assert!(parse_rust_panic(stderr).is_none());
    }

    #[test]
    fn parse_location_file_line_col() {
        let loc = parse_panic_location("src/main.rs:42:10").unwrap();
        assert_eq!(loc.file, "src/main.rs");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.column, Some(10));
    }

    #[test]
    fn parse_location_file_line() {
        let loc = parse_panic_location("src/main.rs:42").unwrap();
        assert_eq!(loc.file, "src/main.rs");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.column, None);
    }
}
