use std::path::PathBuf;

use anyhow::Result;

use crate::build::instrument::{self, InstrumentConfig};

pub fn execute(command: Vec<String>, output: Option<PathBuf>) -> Result<()> {
    let config = InstrumentConfig {
        build_command: command,
        _output_dir: output.unwrap_or_else(|| PathBuf::from(".")),
    };

    instrument::execute_instrumented_build(config)?;

    Ok(())
}
