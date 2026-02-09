use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::explain::analyzer;
use crate::pack::reader::PackReader;

struct PackStore {
    dir: PathBuf,
    index: HashMap<String, PackMeta>,
}

#[derive(Clone, serde::Serialize)]
struct PackMeta {
    id: String,
    filename: String,
    uploaded_at: String,
    command: Vec<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    duration_ms: u64,
}

impl PackStore {
    fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let mut store = Self {
            dir: dir.to_path_buf(),
            index: HashMap::new(),
        };
        store.scan_existing()?;
        Ok(store)
    }

    fn scan_existing(&mut self) -> Result<()> {
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "poepack").unwrap_or(false) {
                if let Ok(pack) = PackReader::open(&path) {
                    let summary = pack.summary();
                    let meta = PackMeta {
                        id: summary.run_id.clone(),
                        filename: path.file_name().unwrap().to_string_lossy().into_owned(),
                        uploaded_at: summary.timestamp.clone(),
                        command: summary.command.clone(),
                        exit_code: summary.exit_code,
                        signal: summary.signal,
                        duration_ms: summary.duration_ms,
                    };
                    self.index.insert(summary.run_id.clone(), meta);
                }
            }
        }
        Ok(())
    }

    fn store_pack(&mut self, data: &[u8]) -> Result<String> {
        let temp_path = self
            .dir
            .join(format!("temp-{}.poepack", uuid::Uuid::new_v4()));
        fs::write(&temp_path, data)?;

        let pack = PackReader::open(&temp_path).context("invalid .poepack file")?;
        let summary = pack.summary();
        let id = summary.run_id.clone();

        let final_name = format!("poe-{}.poepack", &id[..8]);
        let final_path = self.dir.join(&final_name);
        fs::rename(&temp_path, &final_path)?;

        let meta = PackMeta {
            id: id.clone(),
            filename: final_name,
            uploaded_at: summary.timestamp.clone(),
            command: summary.command.clone(),
            exit_code: summary.exit_code,
            signal: summary.signal,
            duration_ms: summary.duration_ms,
        };
        self.index.insert(id.clone(), meta);

        Ok(id)
    }

    fn get_path(&self, id: &str) -> Option<PathBuf> {
        self.index.get(id).map(|m| self.dir.join(&m.filename))
    }

    fn list(&self) -> Vec<&PackMeta> {
        let mut metas: Vec<_> = self.index.values().collect();
        metas.sort_by(|a, b| b.uploaded_at.cmp(&a.uploaded_at));
        metas
    }
}

pub fn start(bind: &str, store_dir: &Path) -> Result<()> {
    let server =
        Server::http(bind).map_err(|e| anyhow::anyhow!("failed to bind {}: {}", bind, e))?;

    eprintln!("poe serve: listening on http://{}", bind);
    eprintln!("poe serve: pack store: {}", store_dir.display());
    eprintln!();
    eprintln!("  POST   /api/packs           upload a .poepack");
    eprintln!("  GET    /api/packs           list all packs");
    eprintln!("  GET    /api/packs/:id       get pack summary");
    eprintln!("  GET    /api/packs/:id/explain   analyze pack");
    eprintln!("  GET    /api/packs/:id/query/:q  query pack data");
    eprintln!();

    let store = Arc::new(Mutex::new(PackStore::new(store_dir)?));

    for request in server.incoming_requests() {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            if let Err(e) = handle_request(request, store) {
                eprintln!("poe serve: request error: {:#}", e);
            }
        });
    }

    Ok(())
}

fn handle_request(mut request: Request, store: Arc<Mutex<PackStore>>) -> Result<()> {
    let url = request.url().to_string();
    let method = request.method().clone();

    let segments: Vec<&str> = url.trim_start_matches('/').split('/').collect();

    let (status, body) = route(&method, &segments, &mut request, &store)?;

    let response = Response::from_string(&body)
        .with_status_code(StatusCode(status))
        .with_header(
            Header::from_bytes(
                "Content-Type",
                if status == 200 && url == "/" {
                    "text/html"
                } else {
                    "application/json"
                },
            )
            .unwrap(),
        );
    request.respond(response)?;
    Ok(())
}

fn route(
    method: &Method,
    segments: &[&str],
    request: &mut Request,
    store: &Arc<Mutex<PackStore>>,
) -> Result<(u16, String)> {
    match (method, segments) {
        (Method::Get, ["api", "packs"]) => {
            let store = store.lock().unwrap();
            let packs = store.list();
            Ok((200, serde_json::to_string_pretty(&packs)?))
        }

        (Method::Post, ["api", "packs"]) => {
            let mut body = Vec::new();
            request.as_reader().read_to_end(&mut body)?;

            let mut store = store.lock().unwrap();
            match store.store_pack(&body) {
                Ok(id) => Ok((
                    200,
                    serde_json::json!({"id": id, "status": "ok"}).to_string(),
                )),
                Err(e) => Ok((
                    400,
                    serde_json::json!({"error": format!("{:#}", e)}).to_string(),
                )),
            }
        }

        (Method::Get, ["api", "packs", id]) => {
            let store = store.lock().unwrap();
            if let Some(path) = store.get_path(id) {
                let pack = PackReader::open(&path)?;
                Ok((200, serde_json::to_string_pretty(pack.summary())?))
            } else {
                Ok((
                    404,
                    serde_json::json!({"error": "pack not found"}).to_string(),
                ))
            }
        }

        (Method::Get, ["api", "packs", id, "explain"]) => {
            let store = store.lock().unwrap();
            if let Some(path) = store.get_path(id) {
                let pack = PackReader::open(&path)?;
                let output = analyzer::analyze(&pack)?;
                Ok((200, serde_json::to_string_pretty(&output)?))
            } else {
                Ok((
                    404,
                    serde_json::json!({"error": "pack not found"}).to_string(),
                ))
            }
        }

        (Method::Get, ["api", "packs", id, "query", query]) => {
            let store = store.lock().unwrap();
            if let Some(path) = store.get_path(id) {
                let pack = PackReader::open(&path)?;
                let db = pack.db();

                let result: serde_json::Value = match *query {
                    "processes" | "procs" => {
                        let procs = db.query_processes()?;
                        serde_json::to_value(
                            procs
                                .iter()
                                .map(|p| {
                                    serde_json::json!({
                                        "pid": p.proc_id,
                                        "parent_pid": p.parent_proc_id,
                                        "argv": p.argv,
                                        "exit_code": p.exit_code,
                                        "signal": p.signal,
                                    })
                                })
                                .collect::<Vec<_>>(),
                        )?
                    }
                    "files" => {
                        let files = db.query_file_events()?;
                        serde_json::to_value(
                            files
                                .iter()
                                .take(500)
                                .map(|f| {
                                    serde_json::json!({
                                        "ts_ms": f.ts as f64 / 1_000_000.0,
                                        "op": f.op,
                                        "path": f.path,
                                        "bytes": f.bytes,
                                        "result": f.result,
                                    })
                                })
                                .collect::<Vec<_>>(),
                        )?
                    }
                    "net" | "network" => {
                        let net = db.query_net_events()?;
                        serde_json::to_value(
                            net.iter()
                                .map(|n| {
                                    serde_json::json!({
                                        "ts_ms": n.ts as f64 / 1_000_000.0,
                                        "op": n.op,
                                        "dst": n.dst,
                                        "bytes": n.bytes,
                                        "result": n.result,
                                    })
                                })
                                .collect::<Vec<_>>(),
                        )?
                    }
                    "stats" => {
                        serde_json::json!({
                            "events": db.event_count()?,
                            "files": db.file_event_count()?,
                            "net": db.net_event_count()?,
                            "stacks": db.stack_count()?,
                            "processes": db.process_count()?,
                        })
                    }
                    _ => serde_json::json!({"error": format!("unknown query: {}", query)}),
                };

                Ok((200, serde_json::to_string_pretty(&result)?))
            } else {
                Ok((
                    404,
                    serde_json::json!({"error": "pack not found"}).to_string(),
                ))
            }
        }

        (Method::Get, [""]) | (Method::Get, &[]) => {
            let html = "<!DOCTYPE html><html><head><title>poe serve</title></head><body><h1>poe serve</h1><p>See /api/packs</p></body></html>";
            Ok((200, html.to_string()))
        }

        _ => Ok((404, serde_json::json!({"error": "not found"}).to_string())),
    }
}
