use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;

use crate::explain::analyzer;
use crate::pack::reader::PackReader;
use crate::util;

pub fn execute(pack_path: PathBuf, json: bool) -> Result<()> {
    let pack = PackReader::open(&pack_path)?;
    let output = analyzer::analyze(&pack)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let summary = pack.summary();

    println!();
    println!("{}", "=== poe explain ===".cyan().bold());
    println!();

    println!("{} {}", "run_id:".dimmed(), summary.run_id);
    println!("{} {}", "command:".dimmed(), summary.command.join(" "));
    println!("{} {}", "time:".dimmed(), summary.timestamp);
    println!("{} {}ms", "duration:".dimmed(), summary.duration_ms);
    if let Some(ref sha) = summary.git_sha {
        println!("{} {}", "git:".dimmed(), sha);
    }
    println!();

    if let Some(ref failure) = output.failure {
        println!("{}", "--- failure ---".red().bold());
        println!("  {} {}", "kind:".dimmed(), failure.kind.red());
        println!("  {} {}", "description:".dimmed(), failure.description);
        if let Some(code) = failure.exit_code {
            println!("  {} {}", "exit_code:".dimmed(), code);
        }
        if let Some(ref sig) = failure.signal {
            println!("  {} {}", "signal:".dimmed(), sig.as_str().red());
        }
        if let Some(ref loc) = failure.primary_location {
            if let Some(ref func) = loc.function {
                print!("  {} {}", "location:".dimmed(), func);
                if let Some(ref file) = loc.file {
                    print!(" at {}", file);
                    if let Some(line) = loc.line {
                        print!(":{}", line);
                    }
                }
                println!();
            }
        }
        println!();
    } else {
        println!("{}", "--- no failure detected ---".green().bold());
        println!();
    }

    if !output.process_tree.is_empty() {
        println!("{}", "--- process tree ---".yellow().bold());
        for proc in &output.process_tree {
            let status = if let Some(sig) = proc.signal {
                format!("killed by {}", util::signal_name(sig)).red().to_string()
            } else if let Some(code) = proc.exit_code {
                if code == 0 {
                    "ok".green().to_string()
                } else {
                    format!("exit {}", code).red().to_string()
                }
            } else {
                "?".dimmed().to_string()
            };

            let duration = proc
                .duration_ms
                .map(|d| format!(" ({:.1}ms)", d))
                .unwrap_or_default();

            println!(
                "  [{}] {}{} -> {}",
                proc.pid, proc.command, duration, status
            );
        }
        println!();
    }

    if !output.hotspots.is_empty() {
        println!("{}", "--- stack hotspots ---".yellow().bold());
        for hs in &output.hotspots {
            println!(
                "  {:5.1}% ({:>5}) {}",
                hs.percentage, hs.count, hs.location
            );
        }
        println!();
    }

    println!("{}", "--- file activity ---".yellow().bold());
    println!(
        "  {} total ops, {} unique paths",
        output.file_activity.total_ops, output.file_activity.unique_paths
    );
    println!(
        "  {} bytes read, {} bytes written",
        output.file_activity.total_bytes_read, output.file_activity.total_bytes_written
    );
    if !output.file_activity.most_accessed.is_empty() {
        println!("  most accessed:");
        for (path, count) in &output.file_activity.most_accessed {
            println!("    {:>5}x {}", count, path);
        }
    }
    println!();

    println!("{}", "--- network activity ---".yellow().bold());
    println!("  {} total ops", output.net_activity.total_ops);
    println!(
        "  {} bytes sent, {} bytes received",
        output.net_activity.total_bytes_sent, output.net_activity.total_bytes_received
    );
    if !output.net_activity.connections.is_empty() {
        println!("  connections:");
        for conn in &output.net_activity.connections {
            println!("    {}", conn);
        }
    }
    println!();

    if !output.timeline.last_events.is_empty() {
        println!("{}", "--- last events ---".yellow().bold());
        for entry in &output.timeline.last_events {
            println!(
                "  {:>10.2}ms [pid:{}] {}",
                entry.ts_ms, entry.proc_id, entry.description
            );
        }
        println!();
    }

    if let Some(ref stderr_tail) = output.stderr_tail {
        println!("{}", "--- stderr (tail) ---".yellow().bold());
        for line in stderr_tail.lines().take(30) {
            println!("  {}", Colorize::dimmed(line));
        }
        println!();
    }

    println!("{}", "===================".cyan().bold());
    println!();

    Ok(())
}
