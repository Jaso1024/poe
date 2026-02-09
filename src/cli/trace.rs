use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;

use crate::distributed::trace_context;

pub fn execute(packs: Vec<PathBuf>, json: bool) -> Result<()> {
    let traces = trace_context::correlate_packs(&packs)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&traces)?);
        return Ok(());
    }

    for trace in &traces {
        println!();
        println!(
            "{} {}",
            "=== distributed trace ===".cyan().bold(),
            &trace.trace_id[..8].yellow()
        );
        println!();

        for span in &trace.spans {
            let is_root = span.parent_span_id.is_none();
            let indent = if is_root { "  " } else { "    " };
            let prefix = if is_root { "root" } else { "child" };

            let status = if let Some(sig) = span.signal {
                format!("signal {}", crate::util::signal_name(sig))
                    .red()
                    .to_string()
            } else if let Some(code) = span.exit_code {
                if code == 0 {
                    "ok".green().to_string()
                } else {
                    format!("exit {}", code).red().to_string()
                }
            } else {
                "?".dimmed().to_string()
            };

            println!(
                "{}[{}] {} @ {} ({}ms) -> {}",
                indent,
                prefix.cyan(),
                span.command.join(" "),
                span.hostname.dimmed(),
                span.duration_ms,
                status,
            );

            if let Some(ref path) = span.pack_path {
                println!("{}  {} {}", indent, "pack:".dimmed(), path);
            }
        }

        println!();
        println!("{}", "=========================".cyan().bold());
    }

    Ok(())
}
