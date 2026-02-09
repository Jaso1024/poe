use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::events::types::*;
use crate::pack::summary;
use crate::trace::db::TraceDb;
use crate::util::ringbuf::ByteRing;

#[allow(clippy::too_many_arguments)]
pub fn write_pack(
    output_path: &Path,
    db: &TraceDb,
    run_info: &RunInfo,
    exit_code: Option<i32>,
    signal: Option<i32>,
    trigger: Option<TriggerReason>,
    duration_ms: u64,
    stdout_ring: &ByteRing,
    stderr_ring: &ByteRing,
) -> Result<()> {
    let file = File::create(output_path)
        .with_context(|| format!("failed to create pack file: {}", output_path.display()))?;

    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let pack_summary = summary::generate_summary(
        db,
        run_info,
        exit_code,
        signal,
        trigger,
        duration_ms,
        stdout_ring.total_written(),
        stderr_ring.total_written(),
    )?;

    let summary_json = serde_json::to_string_pretty(&pack_summary)?;
    zip.start_file("summary.json", options)?;
    zip.write_all(summary_json.as_bytes())?;

    let db_path = db.path()?;
    if !db_path.is_empty() && Path::new(&db_path).exists() {
        let db_bytes =
            fs::read(&db_path).with_context(|| format!("failed to read trace db: {}", db_path))?;
        zip.start_file("trace.sqlite", options)?;
        zip.write_all(&db_bytes)?;
    }

    let stdout_data = stdout_ring.contents();
    if !stdout_data.is_empty() {
        zip.start_file("artifacts/stdout.log", options)?;
        zip.write_all(&stdout_data)?;
    }

    let stderr_data = stderr_ring.contents();
    if !stderr_data.is_empty() {
        zip.start_file("artifacts/stderr.log", options)?;
        zip.write_all(&stderr_data)?;
    }

    let env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let redactor = crate::redact::Redactor::new();
    let redacted_env = redactor.redact_env(&env);

    let trace_ctx = crate::distributed::trace_context::TraceContext::from_env_or_new();

    let meta = serde_json::json!({
        "run_id": run_info.run_id,
        "git_sha": run_info.git_sha,
        "hostname": run_info.hostname,
        "poe_version": env!("CARGO_PKG_VERSION"),
        "kernel": get_kernel_version(),
        "arch": std::env::consts::ARCH,
        "environment": redacted_env,
        "trace_context": {
            "trace_id": trace_ctx.trace_id,
            "span_id": trace_ctx.span_id,
            "parent_span_id": trace_ctx.parent_span_id,
            "origin_host": trace_ctx.origin_host,
        },
    });

    let meta_json = serde_json::to_string_pretty(&meta)?;
    zip.start_file("meta/environment.json", options)?;
    zip.write_all(meta_json.as_bytes())?;

    zip.finish()?;

    Ok(())
}

fn get_kernel_version() -> String {
    fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .trim()
        .to_string()
}
