use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct MemoryMapping {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub path: Option<String>,
}

pub fn read_maps(pid: i32) -> Result<Vec<MemoryMapping>> {
    let path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path))?;

    let mut mappings = Vec::new();
    for line in content.lines() {
        if let Some(mapping) = parse_maps_line(line) {
            mappings.push(mapping);
        }
    }
    Ok(mappings)
}

fn parse_maps_line(line: &str) -> Option<MemoryMapping> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let permissions = parts.next()?.to_string();
    let offset_str = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    let path = parts.next().map(|s| s.to_string());

    let (start_str, end_str) = range.split_once('-')?;
    let start = u64::from_str_radix(start_str, 16).ok()?;
    let end = u64::from_str_radix(end_str, 16).ok()?;
    let offset = u64::from_str_radix(offset_str, 16).ok()?;

    Some(MemoryMapping {
        start,
        end,
        permissions,
        offset,
        path,
    })
}

pub fn read_cmdline(pid: i32) -> Result<Vec<String>> {
    let path = format!("/proc/{}/cmdline", pid);
    let content = fs::read(&path)
        .with_context(|| format!("failed to read {}", path))?;

    Ok(content
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

pub fn read_cwd(pid: i32) -> Result<String> {
    let path = format!("/proc/{}/cwd", pid);
    let target = fs::read_link(&path)
        .with_context(|| format!("failed to readlink {}", path))?;
    Ok(target.to_string_lossy().into_owned())
}

pub fn read_environ(pid: i32) -> Result<HashMap<String, String>> {
    let path = format!("/proc/{}/environ", pid);
    let content = fs::read(&path)
        .with_context(|| format!("failed to read {}", path))?;

    let mut env = HashMap::new();
    for entry in content.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(entry);
        if let Some((key, value)) = s.split_once('=') {
            env.insert(key.to_string(), value.to_string());
        }
    }
    Ok(env)
}

pub fn read_exe(pid: i32) -> Result<String> {
    let path = format!("/proc/{}/exe", pid);
    let target = fs::read_link(&path)
        .with_context(|| format!("failed to readlink {}", path))?;
    Ok(target.to_string_lossy().into_owned())
}

pub fn read_status_field(pid: i32, field: &str) -> Result<String> {
    let path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path))?;

    for line in content.lines() {
        if let Some(value) = line.strip_prefix(field) {
            if let Some(value) = value.strip_prefix(':') {
                return Ok(value.trim().to_string());
            }
        }
    }
    anyhow::bail!("field {} not found in {}", field, path)
}

pub fn git_sha(dir: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    let res = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if res == 0 {
        let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..nul]).into_owned()
    } else {
        "unknown".into()
    }
}
