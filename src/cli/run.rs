use std::path::PathBuf;
use std::process;

use anyhow::Result;
use colored::Colorize;

use crate::capture::runner::{self, RunConfig};
use crate::events::types::CaptureMode;
use crate::explain;
use crate::util;

pub fn execute(
    command: Vec<String>,
    always: bool,
    mode: Option<String>,
    output_dir: Option<PathBuf>,
    diff_baseline: Option<PathBuf>,
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    let capture_mode = match mode.as_deref() {
        Some("full") => CaptureMode::Full,
        _ => CaptureMode::Lite,
    };

    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));

    let force_always = always || diff_baseline.is_some();

    let config = RunConfig {
        command: command.clone(),
        capture_mode,
        always_emit: force_always,
        output_dir,
        ..Default::default()
    };

    let result = runner::execute_run(config)?;

    if let Some(ref pack_path) = result.pack_path {
        eprintln!();
        eprintln!("{}", "--- poe debug packet ---".yellow().bold());

        if let Some(sig) = result.signal {
            eprintln!(
                "  {} process killed by {} ({})",
                "CRASH".red().bold(),
                util::signal_name(sig).red(),
                sig
            );
        } else if let Some(code) = result.exit_code {
            if code != 0 {
                eprintln!(
                    "  {} process exited with code {}",
                    "FAIL".red().bold(),
                    code.to_string().red()
                );
            }
        }

        eprintln!(
            "  {} {}",
            "packet:".dimmed(),
            pack_path.display().to_string().cyan()
        );
        eprintln!(
            "  {} {}ms",
            "duration:".dimmed(),
            result.duration_ms
        );
        eprintln!(
            "  {} poe explain {}",
            "run:".dimmed(),
            pack_path.display()
        );
        eprintln!("{}", "------------------------".yellow().bold());

        if let Some(ref baseline_path) = diff_baseline {
            eprintln!();
            let diff_result = explain::diff::diff_packs(baseline_path, pack_path)?;
            crate::cli::diff::print_diff(&diff_result);
        }
    }

    let exit_code = result.exit_code.unwrap_or(if result.signal.is_some() { 128 + result.signal.unwrap_or(0) } else { 1 });
    process::exit(exit_code);
}
