use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;

use crate::explain::diff;

pub fn execute(baseline: PathBuf, candidate: PathBuf, json: bool) -> Result<()> {
    let output = diff::diff_packs(&baseline, &candidate)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    print_diff(&output);
    Ok(())
}

pub fn print_diff(output: &diff::DiffOutput) {
    println!();
    println!("{}", "=== poe diff ===".cyan().bold());
    println!();

    println!(
        "{} {} vs {}",
        "comparing:".dimmed(),
        output.baseline_id[..8].yellow(),
        output.candidate_id[..8].yellow(),
    );
    println!();

    if let Some(ref ec) = output.exit_code_diff {
        println!("{}", "--- exit code changed ---".red().bold());
        println!(
            "  baseline: {}  candidate: {}",
            ec.baseline
                .map(|c| c.to_string())
                .unwrap_or("none".into()),
            ec.candidate
                .map(|c| c.to_string())
                .unwrap_or("none".into()),
        );
        println!();
    }

    if let Some(ref sig) = output.signal_diff {
        println!("{}", "--- signal changed ---".red().bold());
        println!(
            "  baseline: {}  candidate: {}",
            sig.baseline.as_deref().unwrap_or("none"),
            sig.candidate.as_deref().unwrap_or("none"),
        );
        println!();
    }

    {
        let d = &output.duration_diff;
        let delta_str = if d.delta_ms >= 0 {
            format!("+{}ms ({:+.1}%)", d.delta_ms, d.delta_pct)
        } else {
            format!("{}ms ({:+.1}%)", d.delta_ms, d.delta_pct)
        };
        let delta_colored = if d.delta_pct.abs() > 20.0 {
            delta_str.red().to_string()
        } else if d.delta_pct.abs() > 5.0 {
            delta_str.yellow().to_string()
        } else {
            delta_str.dimmed().to_string()
        };
        println!(
            "{} {}ms -> {}ms {}",
            "duration:".dimmed(),
            d.baseline_ms,
            d.candidate_ms,
            delta_colored,
        );
        println!();
    }

    {
        let p = &output.process_diff;
        if p.baseline_count != p.candidate_count
            || !p.new_processes.is_empty()
            || !p.missing_processes.is_empty()
        {
            println!("{}", "--- process changes ---".yellow().bold());
            println!(
                "  {} -> {} processes",
                p.baseline_count, p.candidate_count
            );
            for proc in &p.new_processes {
                println!("  {} {}", "+".green(), proc);
            }
            for proc in &p.missing_processes {
                println!("  {} {}", "-".red(), proc);
            }
            println!();
        }
    }

    {
        let f = &output.file_diff;
        let has_changes = !f.new_paths.is_empty()
            || !f.missing_paths.is_empty()
            || !f.new_errors.is_empty()
            || f.baseline_ops != f.candidate_ops;

        if has_changes {
            println!("{}", "--- file changes ---".yellow().bold());
            println!(
                "  {} -> {} ops, read: {} -> {}, written: {} -> {}",
                f.baseline_ops,
                f.candidate_ops,
                format_bytes(f.baseline_bytes_read),
                format_bytes(f.candidate_bytes_read),
                format_bytes(f.baseline_bytes_written),
                format_bytes(f.candidate_bytes_written),
            );
            if !f.new_paths.is_empty() {
                println!("  {}", "new paths:".dimmed());
                for path in f.new_paths.iter().take(10) {
                    println!("    {} {}", "+".green(), path);
                }
                if f.new_paths.len() > 10 {
                    println!(
                        "    {} ...and {} more",
                        "+".green(),
                        f.new_paths.len() - 10
                    );
                }
            }
            if !f.missing_paths.is_empty() {
                println!("  {}", "missing paths:".dimmed());
                for path in f.missing_paths.iter().take(10) {
                    println!("    {} {}", "-".red(), path);
                }
                if f.missing_paths.len() > 10 {
                    println!(
                        "    {} ...and {} more",
                        "-".red(),
                        f.missing_paths.len() - 10
                    );
                }
            }
            if !f.new_errors.is_empty() {
                println!("  {}", "new file errors:".red());
                for err in f.new_errors.iter().take(10) {
                    println!("    {} {} -> {}", err.op, err.path, err.result);
                }
            }
            println!();
        }
    }

    {
        let n = &output.net_diff;
        let has_changes = !n.new_connections.is_empty()
            || !n.missing_connections.is_empty()
            || !n.new_errors.is_empty()
            || n.baseline_ops != n.candidate_ops;

        if has_changes {
            println!("{}", "--- network changes ---".yellow().bold());
            println!(
                "  {} -> {} ops, sent: {} -> {}, recv: {} -> {}",
                n.baseline_ops,
                n.candidate_ops,
                format_bytes(n.baseline_bytes_sent),
                format_bytes(n.candidate_bytes_sent),
                format_bytes(n.baseline_bytes_recv),
                format_bytes(n.candidate_bytes_recv),
            );
            if !n.new_connections.is_empty() {
                println!("  {}", "new connections:".dimmed());
                for conn in &n.new_connections {
                    println!("    {} {}", "+".green(), conn);
                }
            }
            if !n.missing_connections.is_empty() {
                println!("  {}", "missing connections:".dimmed());
                for conn in &n.missing_connections {
                    println!("    {} {}", "-".red(), conn);
                }
            }
            if !n.new_errors.is_empty() {
                println!("  {}", "new connection errors:".red());
                for err in &n.new_errors {
                    println!("    {} {} -> {}", err.op, err.addr, err.result);
                }
            }
            println!();
        }
    }

    if let Some(ref sd) = output.stderr_diff {
        if !sd.new_lines.is_empty() {
            println!("{}", "--- new stderr lines ---".yellow().bold());
            for line in sd.new_lines.iter().take(20) {
                println!("  {} {}", "+".green(), line);
            }
            println!();
        }
    }

    if output.exit_code_diff.is_none()
        && output.signal_diff.is_none()
        && output.process_diff.new_processes.is_empty()
        && output.process_diff.missing_processes.is_empty()
        && output.file_diff.new_errors.is_empty()
        && output.net_diff.new_errors.is_empty()
    {
        println!("{}", "No significant behavioral divergence detected.".green());
        println!();
    }

    println!("{}", "===================".cyan().bold());
    println!();
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        "0 B".into()
    } else if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
