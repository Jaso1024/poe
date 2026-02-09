use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

const POE_RT_C: &str = include_str!("../../runtime/poe_rt.c");

pub struct InstrumentConfig {
    pub build_command: Vec<String>,
    pub _output_dir: PathBuf,
}

pub fn execute_instrumented_build(config: InstrumentConfig) -> Result<PathBuf> {
    let work_dir = std::env::temp_dir().join(format!(
        "poe-build-{}",
        &uuid::Uuid::new_v4().to_string()[..8]
    ));
    fs::create_dir_all(&work_dir)?;

    let rt_path = compile_runtime(&work_dir)?;

    let wrapper_dir = work_dir.join("wrappers");
    fs::create_dir_all(&wrapper_dir)?;

    for compiler in ["cc", "gcc", "g++", "clang", "clang++", "c++"] {
        if find_real_compiler(compiler).is_ok() {
            create_compiler_wrapper(&wrapper_dir, compiler, &rt_path)?;
        }
    }

    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", wrapper_dir.display(), current_path);

    if config.build_command.is_empty() {
        bail!("no build command specified");
    }

    eprintln!("poe build: compiling runtime library...");
    eprintln!("poe build: injecting -finstrument-functions via compiler wrappers");
    eprintln!("poe build: running: {}", config.build_command.join(" "));

    let status = Command::new(&config.build_command[0])
        .args(&config.build_command[1..])
        .env("PATH", &new_path)
        .env("POE_RT_LIB", rt_path.to_string_lossy().as_ref())
        .status()
        .with_context(|| format!("failed to run: {}", config.build_command[0]))?;

    if !status.success() {
        bail!("build command failed with exit code: {:?}", status.code());
    }

    eprintln!("poe build: done. Run the instrumented binary under 'poe run' to capture traces.");
    eprintln!("poe build: runtime library: {}", rt_path.display());

    Ok(rt_path)
}

fn compile_runtime(work_dir: &Path) -> Result<PathBuf> {
    let src_path = work_dir.join("poe_rt.c");
    fs::write(&src_path, POE_RT_C)?;

    let lib_path = work_dir.join("libpoe_rt.so");

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());

    let status = Command::new(&cc)
        .args([
            "-shared",
            "-fPIC",
            "-O2",
            "-o",
            lib_path.to_str().unwrap(),
            src_path.to_str().unwrap(),
            "-lpthread",
            "-fno-instrument-functions",
        ])
        .status()
        .with_context(|| format!("failed to compile poe runtime with {}", cc))?;

    if !status.success() {
        bail!("failed to compile poe runtime library");
    }

    Ok(lib_path)
}

fn create_compiler_wrapper(dir: &Path, name: &str, rt_lib: &Path) -> Result<()> {
    let real_compiler = find_real_compiler(name)?;

    let wrapper_path = dir.join(name);
    let script = format!(
        r#"#!/bin/sh
LINKING=0
for arg in "$@"; do
    case "$arg" in
        -c|-S|-E) ;;
        *.c|*.cc|*.cpp|*.cxx) ;;
        -o) LINKING=1 ;;
    esac
done

has_dash_c=0
for arg in "$@"; do
    case "$arg" in
        -c) has_dash_c=1 ;;
    esac
done

if [ "$has_dash_c" = "1" ]; then
    exec "{real}" -finstrument-functions "$@"
else
    exec "{real}" -finstrument-functions "$@" -L"{rt_dir}" -lpoe_rt -Wl,-rpath,"{rt_dir}"
fi
"#,
        real = real_compiler,
        rt_dir = rt_lib.parent().unwrap().display(),
    );

    fs::write(&wrapper_path, script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wrapper_path, fs::Permissions::from_mode(0o755))?;
    }

    Ok(())
}

fn find_real_compiler(name: &str) -> Result<String> {
    let output = Command::new("which")
        .arg(name)
        .output()
        .with_context(|| format!("failed to find compiler: {}", name))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        bail!("compiler '{}' not found in PATH", name);
    }
}

pub fn read_runtime_trace(path: &Path) -> Result<(Vec<RuntimeEntry>, u64)> {
    let data = fs::read(path)
        .with_context(|| format!("failed to read runtime trace: {}", path.display()))?;

    if data.len() < 64 {
        bail!("runtime trace file too small");
    }

    let magic = u32::from_le_bytes(data[0..4].try_into()?);
    if magic != 0x504F4552 {
        bail!("invalid runtime trace magic: {:#x}", magic);
    }

    let capacity = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    let write_pos = u64::from_le_bytes(data[16..24].try_into()?) as usize;
    let start_ns = u64::from_le_bytes(data[24..32].try_into()?);

    let header_size = 64;
    let entry_size = 32;
    let total_entries = write_pos.min(capacity);

    let start_idx = if write_pos > capacity {
        write_pos % capacity
    } else {
        0
    };

    let mut entries = Vec::with_capacity(total_entries);

    for i in 0..total_entries {
        let idx = (start_idx + i) % capacity;
        let offset = header_size + idx * entry_size;
        if offset + entry_size > data.len() {
            break;
        }

        let e = &data[offset..offset + entry_size];
        entries.push(RuntimeEntry {
            ts_ns: u64::from_le_bytes(e[0..8].try_into()?),
            func_addr: u64::from_le_bytes(e[8..16].try_into()?),
            call_site: u64::from_le_bytes(e[16..24].try_into()?),
            tid: u32::from_le_bytes(e[24..28].try_into()?),
            event_type: e[28],
            depth: e[29],
        });
    }

    entries.sort_by_key(|e| e.ts_ns);

    Ok((entries, start_ns))
}

#[derive(Debug, Clone)]
pub struct RuntimeEntry {
    pub ts_ns: u64,
    pub func_addr: u64,
    pub call_site: u64,
    pub tid: u32,
    pub event_type: u8,
    pub depth: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_trace(capacity: u32, entries: &[(u64, u64, u64, u32, u8, u8)]) -> Vec<u8> {
        let header_size = 64;
        let entry_size = 32;
        let file_size = header_size + (capacity as usize) * entry_size;
        let mut data = vec![0u8; file_size];

        data[0..4].copy_from_slice(&0x504F4552u32.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&capacity.to_le_bytes());
        data[16..24].copy_from_slice(&(entries.len() as u64).to_le_bytes());
        data[24..32].copy_from_slice(&1000u64.to_le_bytes());

        for (i, &(ts, func, call_site, tid, etype, depth)) in entries.iter().enumerate() {
            let offset = header_size + i * entry_size;
            data[offset..offset + 8].copy_from_slice(&ts.to_le_bytes());
            data[offset + 8..offset + 16].copy_from_slice(&func.to_le_bytes());
            data[offset + 16..offset + 24].copy_from_slice(&call_site.to_le_bytes());
            data[offset + 24..offset + 28].copy_from_slice(&tid.to_le_bytes());
            data[offset + 28] = etype;
            data[offset + 29] = depth;
        }

        data
    }

    #[test]
    fn read_empty_trace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.bin");
        let data = make_test_trace(16, &[]);
        std::fs::write(&path, data).unwrap();

        let (entries, start_ns) = read_runtime_trace(&path).unwrap();
        assert_eq!(entries.len(), 0);
        assert_eq!(start_ns, 1000);
    }

    #[test]
    fn read_basic_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.bin");
        let data = make_test_trace(
            16,
            &[
                (100, 0x1000, 0x2000, 1, 0, 0),
                (200, 0x1100, 0x1050, 1, 0, 1),
                (300, 0x1100, 0x1050, 1, 1, 1),
                (400, 0x1000, 0x2000, 1, 1, 0),
            ],
        );
        std::fs::write(&path, data).unwrap();

        let (entries, start_ns) = read_runtime_trace(&path).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(start_ns, 1000);

        assert_eq!(entries[0].ts_ns, 100);
        assert_eq!(entries[0].func_addr, 0x1000);
        assert_eq!(entries[0].event_type, 0);
        assert_eq!(entries[0].depth, 0);

        assert_eq!(entries[1].func_addr, 0x1100);
        assert_eq!(entries[1].event_type, 0);
        assert_eq!(entries[1].depth, 1);

        assert_eq!(entries[2].event_type, 1);
        assert_eq!(entries[3].event_type, 1);
        assert_eq!(entries[3].depth, 0);
    }

    #[test]
    fn entries_sorted_by_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.bin");
        let data = make_test_trace(
            16,
            &[
                (300, 0x1000, 0x2000, 1, 0, 0),
                (100, 0x1100, 0x2000, 1, 0, 1),
                (200, 0x1200, 0x2000, 1, 1, 1),
            ],
        );
        std::fs::write(&path, data).unwrap();

        let (entries, _) = read_runtime_trace(&path).unwrap();
        assert!(entries[0].ts_ns <= entries[1].ts_ns);
        assert!(entries[1].ts_ns <= entries[2].ts_ns);
    }

    #[test]
    fn invalid_magic_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.bin");
        let mut data = make_test_trace(16, &[]);
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        std::fs::write(&path, data).unwrap();

        assert!(read_runtime_trace(&path).is_err());
    }

    #[test]
    fn too_small_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.bin");
        std::fs::write(&path, b"too small").unwrap();

        assert!(read_runtime_trace(&path).is_err());
    }

    #[test]
    fn multi_thread_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.bin");
        let data = make_test_trace(
            16,
            &[
                (100, 0x1000, 0x2000, 1, 0, 0),
                (150, 0x1000, 0x2000, 2, 0, 0),
                (200, 0x1000, 0x2000, 1, 1, 0),
                (250, 0x1000, 0x2000, 2, 1, 0),
            ],
        );
        std::fs::write(&path, data).unwrap();

        let (entries, _) = read_runtime_trace(&path).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].tid, 1);
        assert_eq!(entries[1].tid, 2);
    }
}
