use std::collections::HashMap;

use serde::{Deserialize, Serialize};

const POE_TRACE_ID_ENV: &str = "POE_TRACE_ID";
const POE_PARENT_SPAN_ENV: &str = "POE_PARENT_SPAN_ID";
const POE_TRACE_ORIGIN_ENV: &str = "POE_TRACE_ORIGIN";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub origin_host: String,
}

impl TraceContext {
    pub fn new_root() -> Self {
        Self {
            trace_id: uuid::Uuid::new_v4().to_string(),
            span_id: uuid::Uuid::new_v4().to_string()[..16].to_string(),
            parent_span_id: None,
            origin_host: crate::util::procfs::hostname(),
        }
    }

    pub fn from_env() -> Option<Self> {
        let trace_id = std::env::var(POE_TRACE_ID_ENV).ok()?;
        let parent_span = std::env::var(POE_PARENT_SPAN_ENV).ok();

        Some(Self {
            trace_id,
            span_id: uuid::Uuid::new_v4().to_string()[..16].to_string(),
            parent_span_id: parent_span,
            origin_host: crate::util::procfs::hostname(),
        })
    }

    pub fn from_env_or_new() -> Self {
        Self::from_env().unwrap_or_else(Self::new_root)
    }

    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: uuid::Uuid::new_v4().to_string()[..16].to_string(),
            parent_span_id: Some(self.span_id.clone()),
            origin_host: crate::util::procfs::hostname(),
        }
    }

    pub fn inject_env(&self, env: &mut HashMap<String, String>) {
        env.insert(POE_TRACE_ID_ENV.into(), self.trace_id.clone());
        env.insert(POE_PARENT_SPAN_ENV.into(), self.span_id.clone());
        env.insert(POE_TRACE_ORIGIN_ENV.into(), self.origin_host.clone());
    }

    pub fn is_distributed(&self) -> bool {
        self.parent_span_id.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedTrace {
    pub trace_id: String,
    pub spans: Vec<TraceSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub run_id: String,
    pub command: Vec<String>,
    pub hostname: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub pack_path: Option<String>,
}

pub fn correlate_packs(pack_paths: &[std::path::PathBuf]) -> anyhow::Result<Vec<DistributedTrace>> {
    let mut traces: HashMap<String, Vec<TraceSpan>> = HashMap::new();

    for path in pack_paths {
        let pack = crate::pack::reader::PackReader::open(path)?;
        let summary = pack.summary();

        let meta_str = pack.read_meta("environment.json").ok();
        let meta_val: Option<serde_json::Value> =
            meta_str.as_ref().and_then(|m| serde_json::from_str(m).ok());

        let trace_id = meta_val
            .as_ref()
            .and_then(|v| {
                v.get("trace_context")?
                    .get("trace_id")?
                    .as_str()
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                meta_val.as_ref().and_then(|v| {
                    v.get("environment")?
                        .get(POE_TRACE_ID_ENV)?
                        .as_str()
                        .map(|s| s.to_string())
                })
            })
            .unwrap_or_else(|| summary.run_id.clone());

        let span_id = meta_val
            .as_ref()
            .and_then(|v| {
                v.get("trace_context")?
                    .get("span_id")?
                    .as_str()
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| summary.run_id[..16].to_string());

        let parent_span = meta_val.as_ref().and_then(|v| {
            v.get("trace_context")?
                .get("parent_span_id")?
                .as_str()
                .map(|s| s.to_string())
        });

        let span = TraceSpan {
            span_id,
            parent_span_id: parent_span,
            run_id: summary.run_id.clone(),
            command: summary.command.clone(),
            hostname: summary.hostname.clone(),
            exit_code: summary.exit_code,
            signal: summary.signal,
            duration_ms: summary.duration_ms,
            pack_path: Some(path.to_string_lossy().into_owned()),
        };

        traces.entry(trace_id).or_default().push(span);
    }

    Ok(traces
        .into_iter()
        .map(|(trace_id, mut spans)| {
            spans.sort_by_key(|s| s.parent_span_id.is_some());
            DistributedTrace { trace_id, spans }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_root_context() {
        let ctx = TraceContext::new_root();
        assert!(!ctx.trace_id.is_empty());
        assert!(!ctx.span_id.is_empty());
        assert!(ctx.parent_span_id.is_none());
        assert!(!ctx.is_distributed());
    }

    #[test]
    fn child_context() {
        let root = TraceContext::new_root();
        let child = root.child();
        assert_eq!(child.trace_id, root.trace_id);
        assert_ne!(child.span_id, root.span_id);
        assert_eq!(child.parent_span_id.as_deref(), Some(root.span_id.as_str()));
        assert!(child.is_distributed());
    }

    #[test]
    fn inject_and_read_env() {
        let ctx = TraceContext::new_root();
        let mut env = std::collections::HashMap::new();
        ctx.inject_env(&mut env);

        assert_eq!(env.get("POE_TRACE_ID").unwrap(), &ctx.trace_id);
        assert_eq!(env.get("POE_PARENT_SPAN_ID").unwrap(), &ctx.span_id);
    }

    #[test]
    fn from_env_returns_none_without_vars() {
        std::env::remove_var("POE_TRACE_ID");
        assert!(TraceContext::from_env().is_none());
    }
}
