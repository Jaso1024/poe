use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use zip::ZipArchive;

use crate::pack::summary::PackSummary;
use crate::trace::db::TraceDb;

pub struct PackReader {
    work_dir: std::path::PathBuf,
    summary: PackSummary,
    db: TraceDb,
}

impl PackReader {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open pack: {}", path.display()))?;

        let mut archive = ZipArchive::new(file)?;

        let work_dir = std::env::temp_dir().join(format!(
            "poe-read-{}",
            &uuid::Uuid::new_v4().to_string()[..8]
        ));
        fs::create_dir_all(&work_dir)?;

        let summary = {
            let mut entry = archive.by_name("summary.json")
                .context("pack missing summary.json")?;
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            serde_json::from_str::<PackSummary>(&content)
                .context("invalid summary.json")?
        };

        let db_path = work_dir.join("trace.sqlite");
        {
            let mut entry = archive.by_name("trace.sqlite")
                .context("pack missing trace.sqlite")?;
            let mut db_file = File::create(&db_path)?;
            std::io::copy(&mut entry, &mut db_file)?;
        }

        let db = TraceDb::open(&db_path)?;

        for name in ["artifacts/stdout.log", "artifacts/stderr.log", "meta/environment.json"] {
            if let Ok(mut entry) = archive.by_name(name) {
                let out_path = work_dir.join(name);
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut out_file = File::create(&out_path)?;
                std::io::copy(&mut entry, &mut out_file)?;
            }
        }

        Ok(Self {
            work_dir,
            summary,
            db,
        })
    }

    pub fn summary(&self) -> &PackSummary {
        &self.summary
    }

    pub fn db(&self) -> &TraceDb {
        &self.db
    }

    pub fn read_artifact(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.work_dir.join(format!("artifacts/{}", name));
        fs::read(&path).with_context(|| format!("artifact not found: {}", name))
    }

    pub fn read_meta(&self, name: &str) -> Result<String> {
        let path = self.work_dir.join(format!("meta/{}", name));
        fs::read_to_string(&path).with_context(|| format!("meta not found: {}", name))
    }

    pub fn stdout(&self) -> Result<Vec<u8>> {
        self.read_artifact("stdout.log")
    }

    pub fn stderr(&self) -> Result<Vec<u8>> {
        self.read_artifact("stderr.log")
    }
}

impl Drop for PackReader {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.work_dir);
    }
}
