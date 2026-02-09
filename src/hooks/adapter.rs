use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::mpsc;

use anyhow::Result;

use crate::events::types::TraceEvent;

pub trait LanguageAdapter: Send {
    fn name(&self) -> &str;

    fn on_load(
        &mut self,
        env: &mut HashMap<String, String>,
        clear_cloexec_fds: &mut Vec<RawFd>,
    ) -> Result<()>;

    fn on_start(&mut self, event_tx: mpsc::Sender<TraceEvent>, root_pid: i32) -> Result<()>;

    fn on_exit(&mut self) -> Result<()>;
}

pub struct AdapterManager {
    adapters: Vec<Box<dyn LanguageAdapter>>,
}

impl Default for AdapterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterManager {
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    pub fn detect_and_register(&mut self, argv: &[String]) {
        if super::python::is_python_command(argv) {
            if let Ok(adapter) = PythonAdapter::new() {
                self.adapters.push(Box::new(adapter));
            }
        }
    }

    pub fn on_load(
        &mut self,
        env: &mut HashMap<String, String>,
        clear_cloexec_fds: &mut Vec<RawFd>,
    ) -> Result<()> {
        for adapter in &mut self.adapters {
            adapter.on_load(env, clear_cloexec_fds)?;
        }
        Ok(())
    }

    pub fn on_start(&mut self, event_tx: mpsc::Sender<TraceEvent>, root_pid: i32) -> Result<()> {
        for adapter in &mut self.adapters {
            adapter.on_start(event_tx.clone(), root_pid)?;
        }
        Ok(())
    }

    pub fn on_exit(&mut self) -> Result<()> {
        for adapter in &mut self.adapters {
            adapter.on_exit()?;
        }
        Ok(())
    }

    pub fn adapter_names(&self) -> Vec<&str> {
        self.adapters.iter().map(|a| a.name()).collect()
    }

    pub fn has_adapters(&self) -> bool {
        !self.adapters.is_empty()
    }
}

struct PythonAdapter {
    hook: Option<super::python::PythonHookSetup>,
    reader: Option<super::python::PythonHookReader>,
}

impl PythonAdapter {
    fn new() -> Result<Self> {
        Ok(Self {
            hook: None,
            reader: None,
        })
    }
}

impl LanguageAdapter for PythonAdapter {
    fn name(&self) -> &str {
        "python"
    }

    fn on_load(
        &mut self,
        env: &mut HashMap<String, String>,
        clear_cloexec_fds: &mut Vec<RawFd>,
    ) -> Result<()> {
        let run_id = uuid::Uuid::new_v4().to_string();
        let hook = super::python::PythonHookSetup::prepare(&run_id)?;
        hook.apply_env(env);
        clear_cloexec_fds.push(hook.write_fd());
        self.hook = Some(hook);
        Ok(())
    }

    fn on_start(&mut self, event_tx: mpsc::Sender<TraceEvent>, root_pid: i32) -> Result<()> {
        if let Some(hook) = self.hook.take() {
            self.reader = Some(hook.start_reader(event_tx, root_pid));
        }
        Ok(())
    }

    fn on_exit(&mut self) -> Result<()> {
        if let Some(reader) = self.reader.take() {
            reader.finish();
        }
        Ok(())
    }
}
