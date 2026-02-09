use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

use crate::events::types::*;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS run (
    run_id TEXT PRIMARY KEY,
    command TEXT NOT NULL,
    working_dir TEXT NOT NULL,
    env_hash TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    git_sha TEXT,
    hostname TEXT,
    exit_code INTEGER,
    signal INTEGER,
    trigger_reason TEXT
);

CREATE TABLE IF NOT EXISTS processes (
    proc_id INTEGER PRIMARY KEY,
    parent_proc_id INTEGER,
    argv TEXT,
    cwd TEXT,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER,
    exit_code INTEGER,
    signal INTEGER,
    FOREIGN KEY (parent_proc_id) REFERENCES processes(proc_id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    proc_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    proc_id INTEGER NOT NULL,
    op TEXT NOT NULL,
    path TEXT,
    fd INTEGER,
    bytes INTEGER,
    flags INTEGER,
    result INTEGER,
    FOREIGN KEY (proc_id) REFERENCES processes(proc_id)
);

CREATE TABLE IF NOT EXISTS net (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    proc_id INTEGER NOT NULL,
    op TEXT NOT NULL,
    proto TEXT,
    src TEXT,
    dst TEXT,
    bytes INTEGER,
    fd INTEGER,
    result INTEGER,
    FOREIGN KEY (proc_id) REFERENCES processes(proc_id)
);

CREATE TABLE IF NOT EXISTS stacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    proc_id INTEGER NOT NULL,
    frames TEXT NOT NULL,
    weight INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    content_hash TEXT,
    size INTEGER
);

CREATE TABLE IF NOT EXISTS spans (
    span_id TEXT PRIMARY KEY,
    proc_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER,
    attrs TEXT,
    FOREIGN KEY (proc_id) REFERENCES processes(proc_id)
);

CREATE TABLE IF NOT EXISTS effects (
    effect_id TEXT PRIMARY KEY,
    proc_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    attrs TEXT,
    idempotency_key TEXT,
    FOREIGN KEY (proc_id) REFERENCES processes(proc_id)
);

CREATE TABLE IF NOT EXISTS stdio (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    proc_id INTEGER NOT NULL,
    stream TEXT NOT NULL,
    data BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_proc ON events(proc_id);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_files_ts ON files(ts);
CREATE INDEX IF NOT EXISTS idx_files_proc ON files(proc_id);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_net_ts ON net(ts);
CREATE INDEX IF NOT EXISTS idx_net_proc ON net(proc_id);
CREATE INDEX IF NOT EXISTS idx_stacks_ts ON stacks(ts);
CREATE INDEX IF NOT EXISTS idx_stacks_proc ON stacks(proc_id);
CREATE INDEX IF NOT EXISTS idx_stdio_proc ON stdio(proc_id);
"#;

pub struct TraceDb {
    conn: Mutex<Connection>,
}

impl TraceDb {
    pub fn create(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to create trace db at {}", path.display()))?;

        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch("PRAGMA cache_size=-64000;")?;
        conn.execute_batch("PRAGMA temp_store=MEMORY;")?;
        conn.execute_batch(SCHEMA)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open trace db at {}", path.display()))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert_run(&self, info: &RunInfo) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO run (run_id, command, working_dir, env_hash, start_time, git_sha, hostname)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                info.run_id,
                serde_json::to_string(&info.command)?,
                info.working_dir,
                info.env_hash,
                info.start_time.to_rfc3339(),
                info.git_sha,
                info.hostname,
            ],
        )?;
        Ok(())
    }

    pub fn update_run_end(
        &self,
        run_id: &str,
        end_time: &chrono::DateTime<chrono::Utc>,
        exit_code: Option<i32>,
        signal: Option<i32>,
        trigger: Option<TriggerReason>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE run SET end_time = ?1, exit_code = ?2, signal = ?3, trigger_reason = ?4
             WHERE run_id = ?5",
            params![
                end_time.to_rfc3339(),
                exit_code,
                signal,
                trigger.map(|t| t.as_str()),
                run_id,
            ],
        )?;
        Ok(())
    }

    pub fn insert_process(&self, info: &ProcessInfo) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO processes (proc_id, parent_proc_id, argv, cwd, start_ts)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                info.proc_id,
                info.parent_proc_id,
                serde_json::to_string(&info.argv)?,
                info.cwd,
                info.start_ts as i64,
            ],
        )?;
        Ok(())
    }

    pub fn update_process_exit(&self, exit: &ProcessExit) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE processes SET end_ts = ?1, exit_code = ?2, signal = ?3
             WHERE proc_id = ?4",
            params![
                exit.end_ts as i64,
                exit.exit_code,
                exit.signal,
                exit.proc_id,
            ],
        )?;
        Ok(())
    }

    pub fn insert_event(&self, event: &Event) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events (ts, proc_id, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![
                event.ts as i64,
                event.proc_id,
                event.kind.as_str(),
                event.detail,
            ],
        )?;
        Ok(())
    }

    pub fn insert_file_event(&self, event: &FileEvent) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO files (ts, proc_id, op, path, fd, bytes, flags, result)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.ts as i64,
                event.proc_id,
                event.op.as_str(),
                event.path,
                event.fd,
                event.bytes.map(|b| b as i64),
                event.flags,
                event.result,
            ],
        )?;
        Ok(())
    }

    pub fn insert_net_event(&self, event: &NetEvent) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO net (ts, proc_id, op, proto, src, dst, bytes, fd, result)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.ts as i64,
                event.proc_id,
                event.op.as_str(),
                event.proto,
                event.src,
                event.dst,
                event.bytes.map(|b| b as i64),
                event.fd,
                event.result,
            ],
        )?;
        Ok(())
    }

    pub fn insert_stack(&self, sample: &StackSample) -> Result<()> {
        let frames_json = serde_json::to_string(&sample.frames)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO stacks (ts, proc_id, frames) VALUES (?1, ?2, ?3)",
            params![sample.ts as i64, sample.proc_id, frames_json],
        )?;
        Ok(())
    }

    pub fn insert_stdio(&self, chunk: &StdioChunk) -> Result<()> {
        let stream_str = match chunk.stream {
            StdioStream::Stdout => "stdout",
            StdioStream::Stderr => "stderr",
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO stdio (ts, proc_id, stream, data) VALUES (?1, ?2, ?3, ?4)",
            params![chunk.ts as i64, chunk.proc_id, stream_str, chunk.data],
        )?;
        Ok(())
    }

    pub fn insert_artifact(
        &self,
        id: &str,
        kind: &str,
        path: &str,
        hash: Option<&str>,
        size: Option<u64>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO artifacts (artifact_id, kind, path, content_hash, size)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, kind, path, hash, size.map(|s| s as i64)],
        )?;
        Ok(())
    }

    pub fn batch_insert_events(&self, events: &[TraceEvent]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        for event in events {
            match event {
                TraceEvent::Process(info) => {
                    tx.execute(
                        "INSERT OR REPLACE INTO processes (proc_id, parent_proc_id, argv, cwd, start_ts)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            info.proc_id,
                            info.parent_proc_id,
                            serde_json::to_string(&info.argv)?,
                            info.cwd,
                            info.start_ts as i64,
                        ],
                    )?;
                }
                TraceEvent::ProcessExit(exit) => {
                    tx.execute(
                        "UPDATE processes SET end_ts = ?1, exit_code = ?2, signal = ?3
                         WHERE proc_id = ?4",
                        params![
                            exit.end_ts as i64,
                            exit.exit_code,
                            exit.signal,
                            exit.proc_id
                        ],
                    )?;
                }
                TraceEvent::File(f) => {
                    tx.execute(
                        "INSERT INTO files (ts, proc_id, op, path, fd, bytes, flags, result)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            f.ts as i64,
                            f.proc_id,
                            f.op.as_str(),
                            f.path,
                            f.fd,
                            f.bytes.map(|b| b as i64),
                            f.flags,
                            f.result,
                        ],
                    )?;
                }
                TraceEvent::Net(n) => {
                    tx.execute(
                        "INSERT INTO net (ts, proc_id, op, proto, src, dst, bytes, fd, result)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            n.ts as i64,
                            n.proc_id,
                            n.op.as_str(),
                            n.proto,
                            n.src,
                            n.dst,
                            n.bytes.map(|b| b as i64),
                            n.fd,
                            n.result,
                        ],
                    )?;
                }
                TraceEvent::Stack(s) => {
                    tx.execute(
                        "INSERT INTO stacks (ts, proc_id, frames) VALUES (?1, ?2, ?3)",
                        params![s.ts as i64, s.proc_id, serde_json::to_string(&s.frames)?],
                    )?;
                }
                TraceEvent::Stdio(c) => {
                    let stream_str = match c.stream {
                        StdioStream::Stdout => "stdout",
                        StdioStream::Stderr => "stderr",
                    };
                    tx.execute(
                        "INSERT INTO stdio (ts, proc_id, stream, data) VALUES (?1, ?2, ?3, ?4)",
                        params![c.ts as i64, c.proc_id, stream_str, c.data],
                    )?;
                }
                TraceEvent::Generic(e) => {
                    tx.execute(
                        "INSERT INTO events (ts, proc_id, kind, detail) VALUES (?1, ?2, ?3, ?4)",
                        params![e.ts as i64, e.proc_id, e.kind.as_str(), e.detail],
                    )?;
                }
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn query_run(&self) -> Result<Option<RunQueryResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT run_id, command, working_dir, env_hash, start_time, end_time,
                    git_sha, hostname, exit_code, signal, trigger_reason
             FROM run LIMIT 1",
        )?;

        let result = stmt
            .query_row([], |row| {
                Ok(RunQueryResult {
                    run_id: row.get(0)?,
                    command: row.get(1)?,
                    working_dir: row.get(2)?,
                    env_hash: row.get(3)?,
                    start_time: row.get(4)?,
                    end_time: row.get(5)?,
                    git_sha: row.get(6)?,
                    hostname: row.get(7)?,
                    exit_code: row.get(8)?,
                    signal: row.get(9)?,
                    trigger_reason: row.get(10)?,
                })
            })
            .optional()?;

        Ok(result)
    }

    pub fn query_processes(&self) -> Result<Vec<ProcessQueryResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT proc_id, parent_proc_id, argv, cwd, start_ts, end_ts, exit_code, signal
             FROM processes ORDER BY start_ts",
        )?;

        let results = stmt
            .query_map([], |row| {
                Ok(ProcessQueryResult {
                    proc_id: row.get(0)?,
                    parent_proc_id: row.get(1)?,
                    argv: row.get(2)?,
                    cwd: row.get(3)?,
                    start_ts: row.get(4)?,
                    end_ts: row.get(5)?,
                    exit_code: row.get(6)?,
                    signal: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    pub fn query_last_events(&self, limit: usize) -> Result<Vec<EventQueryResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT ts, proc_id, kind, detail FROM events ORDER BY ts DESC LIMIT ?1")?;

        let results = stmt
            .query_map(params![limit as i64], |row| {
                Ok(EventQueryResult {
                    ts: row.get(0)?,
                    proc_id: row.get(1)?,
                    kind: row.get(2)?,
                    detail: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    pub fn query_file_events(&self) -> Result<Vec<FileQueryResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ts, proc_id, op, path, fd, bytes, flags, result
             FROM files ORDER BY ts",
        )?;

        let results = stmt
            .query_map([], |row| {
                Ok(FileQueryResult {
                    ts: row.get(0)?,
                    proc_id: row.get(1)?,
                    op: row.get(2)?,
                    path: row.get(3)?,
                    fd: row.get(4)?,
                    bytes: row.get(5)?,
                    flags: row.get(6)?,
                    result: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    pub fn query_net_events(&self) -> Result<Vec<NetQueryResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ts, proc_id, op, proto, src, dst, bytes, fd, result
             FROM net ORDER BY ts",
        )?;

        let results = stmt
            .query_map([], |row| {
                Ok(NetQueryResult {
                    ts: row.get(0)?,
                    proc_id: row.get(1)?,
                    op: row.get(2)?,
                    proto: row.get(3)?,
                    src: row.get(4)?,
                    dst: row.get(5)?,
                    bytes: row.get(6)?,
                    fd: row.get(7)?,
                    result: row.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    pub fn query_stacks(&self) -> Result<Vec<StackQueryResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT ts, proc_id, frames, weight FROM stacks ORDER BY ts")?;

        let results = stmt
            .query_map([], |row| {
                Ok(StackQueryResult {
                    ts: row.get(0)?,
                    proc_id: row.get(1)?,
                    frames: row.get(2)?,
                    weight: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    pub fn query_stdio(&self, stream: &str) -> Result<Vec<u8>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT data FROM stdio WHERE stream = ?1 ORDER BY ts")?;

        let mut all_data = Vec::new();
        let rows = stmt.query_map(params![stream], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        for row in rows {
            all_data.extend(row?);
        }
        Ok(all_data)
    }

    pub fn event_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn file_event_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn net_event_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM net", [], |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn stack_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM stacks", [], |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn process_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM processes", [], |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn raw_query(&self, sql: &str) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(sql)?;
        let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();

        let rows = stmt.query_map([], |row| {
            let mut map = serde_json::Map::new();
            for (i, name) in column_names.iter().enumerate() {
                let val: rusqlite::Result<rusqlite::types::Value> = row.get(i);
                let json_val = match val {
                    Ok(rusqlite::types::Value::Null) => serde_json::Value::Null,
                    Ok(rusqlite::types::Value::Integer(n)) => serde_json::json!(n),
                    Ok(rusqlite::types::Value::Real(f)) => serde_json::json!(f),
                    Ok(rusqlite::types::Value::Text(s)) => serde_json::json!(s),
                    Ok(rusqlite::types::Value::Blob(b)) => {
                        serde_json::json!(format!("<blob {} bytes>", b.len()))
                    }
                    Err(_) => serde_json::Value::Null,
                };
                map.insert(name.clone(), json_val);
            }
            Ok(serde_json::Value::Object(map))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn query_python_events(&self, kind: &str) -> Result<Vec<EventQueryResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT ts, proc_id, kind, detail FROM events WHERE kind = ?1 ORDER BY ts")?;

        let results = stmt
            .query_map(params![kind], |row| {
                Ok(EventQueryResult {
                    ts: row.get(0)?,
                    proc_id: row.get(1)?,
                    kind: row.get(2)?,
                    detail: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(results)
    }

    pub fn query_python_unhandled_exceptions(&self) -> Result<Vec<EventQueryResult>> {
        self.query_python_events("python_unhandled_exception")
    }

    pub fn query_python_exceptions(&self) -> Result<Vec<EventQueryResult>> {
        self.query_python_events("python_exception")
    }

    pub fn has_python_events(&self) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM events WHERE kind LIKE 'python_%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
            > 0
    }

    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    pub fn path(&self) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.path().unwrap_or("").to_string())
    }
}

use rusqlite::OptionalExtension;

#[derive(Debug, Clone)]
pub struct RunQueryResult {
    pub run_id: String,
    pub command: String,
    pub working_dir: String,
    pub env_hash: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub git_sha: Option<String>,
    pub hostname: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub trigger_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProcessQueryResult {
    pub proc_id: i32,
    pub parent_proc_id: Option<i32>,
    pub argv: Option<String>,
    pub cwd: Option<String>,
    pub start_ts: i64,
    pub end_ts: Option<i64>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct EventQueryResult {
    pub ts: i64,
    pub proc_id: i32,
    pub kind: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FileQueryResult {
    pub ts: i64,
    pub proc_id: i32,
    pub op: String,
    pub path: Option<String>,
    pub fd: Option<i32>,
    pub bytes: Option<i64>,
    pub flags: Option<i32>,
    pub result: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NetQueryResult {
    pub ts: i64,
    pub proc_id: i32,
    pub op: String,
    pub proto: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub bytes: Option<i64>,
    pub fd: Option<i32>,
    pub result: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StackQueryResult {
    pub ts: i64,
    pub proc_id: i32,
    pub frames: String,
    pub weight: Option<i32>,
}
