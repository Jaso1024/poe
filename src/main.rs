#![allow(dead_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod capture;
mod cli;
mod events;
mod explain;
mod pack;
mod redact;
mod symbols;
mod trace;
mod util;

#[derive(Parser)]
#[command(
    name = "poe",
    about = "Auto-annotating debug packets for AI-native debugging",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command with debug capture
    Run {
        /// Always emit a debug packet, even on success
        #[arg(long)]
        always: bool,

        /// Capture mode: lite (default) or full
        #[arg(long)]
        mode: Option<String>,

        /// Output directory for the .poepack file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Baseline .poepack to diff against after run
        #[arg(long)]
        diff: Option<PathBuf>,

        /// The command to run (after --)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Analyze a debug packet and explain what happened
    Explain {
        /// Path to the .poepack file
        #[arg(required = true)]
        packet: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Compare two debug packets to find divergences
    Diff {
        /// Baseline .poepack file
        #[arg(required = true)]
        baseline: PathBuf,

        /// Candidate .poepack file
        #[arg(required = true)]
        candidate: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Query a debug packet for specific data
    Query {
        /// Path to the .poepack file
        #[arg(required = true)]
        packet: PathBuf,

        /// Query to run (summary, processes, events, files, net, stacks, stdout, stderr, stats, files:<pattern>, net:<pattern>, sql:<query>)
        #[arg(required = true)]
        query: String,
    },

    /// Check system capabilities for poe
    Doctor,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Run {
            always,
            mode,
            output,
            diff,
            command,
        } => cli::run::execute(command, always, mode, output, diff),

        Commands::Explain { packet, json } => cli::explain::execute(packet, json),

        Commands::Diff {
            baseline,
            candidate,
            json,
        } => cli::diff::execute(baseline, candidate, json),

        Commands::Query { packet, query } => cli::query::execute(packet, query),

        Commands::Doctor => cli::doctor::execute(),
    };

    if let Err(e) = result {
        eprintln!("poe: error: {:#}", e);
        std::process::exit(1);
    }
}
