use std::path::PathBuf;

use anyhow::Result;

use crate::pack::reader::PackReader;

pub fn execute(pack_path: PathBuf, query: String) -> Result<()> {
    let pack = PackReader::open(&pack_path)?;
    let db = pack.db();

    let query_lower = query.to_lowercase();

    match query_lower.as_str() {
        "summary" => {
            println!("{}", serde_json::to_string_pretty(pack.summary())?);
        }

        "processes" | "procs" => {
            let procs = db.query_processes()?;
            let results: Vec<serde_json::Value> = procs
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "pid": p.proc_id,
                        "parent_pid": p.parent_proc_id,
                        "argv": p.argv.as_ref().and_then(|a| serde_json::from_str::<Vec<String>>(a).ok()),
                        "start_ts_ms": p.start_ts as f64 / 1_000_000.0,
                        "end_ts_ms": p.end_ts.map(|t| t as f64 / 1_000_000.0),
                        "exit_code": p.exit_code,
                        "signal": p.signal,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&results)?);
        }

        "events" => {
            let events = db.query_last_events(100)?;
            let results: Vec<serde_json::Value> = events
                .iter()
                .rev()
                .map(|e| {
                    serde_json::json!({
                        "ts_ms": e.ts as f64 / 1_000_000.0,
                        "pid": e.proc_id,
                        "kind": e.kind,
                        "detail": e.detail,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&results)?);
        }

        "files" => {
            let files = db.query_file_events()?;
            let results: Vec<serde_json::Value> = files
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "ts_ms": f.ts as f64 / 1_000_000.0,
                        "pid": f.proc_id,
                        "op": f.op,
                        "path": f.path,
                        "fd": f.fd,
                        "bytes": f.bytes,
                        "result": f.result,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&results)?);
        }

        "net" | "network" => {
            let net = db.query_net_events()?;
            let results: Vec<serde_json::Value> = net
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "ts_ms": n.ts as f64 / 1_000_000.0,
                        "pid": n.proc_id,
                        "op": n.op,
                        "src": n.src,
                        "dst": n.dst,
                        "bytes": n.bytes,
                        "fd": n.fd,
                        "result": n.result,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&results)?);
        }

        "stacks" => {
            let stacks = db.query_stacks()?;
            let results: Vec<serde_json::Value> = stacks
                .iter()
                .map(|s| {
                    let frames: Vec<u64> = serde_json::from_str(&s.frames).unwrap_or_default();
                    serde_json::json!({
                        "ts_ms": s.ts as f64 / 1_000_000.0,
                        "pid": s.proc_id,
                        "frames": frames.iter().map(|f| format!("{:#x}", f)).collect::<Vec<_>>(),
                        "weight": s.weight,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&results)?);
        }

        "stdout" => match pack.stdout() {
            Ok(data) => {
                std::io::Write::write_all(&mut std::io::stdout(), &data)?;
            }
            Err(_) => {
                eprintln!("no stdout captured");
            }
        },

        "stderr" => match pack.stderr() {
            Ok(data) => {
                std::io::Write::write_all(&mut std::io::stdout(), &data)?;
            }
            Err(_) => {
                eprintln!("no stderr captured");
            }
        },

        "stats" => {
            let summary = pack.summary();
            println!("{}", serde_json::to_string_pretty(&summary.stats)?);
        }

        _ => {
            if query_lower.starts_with("sql:") {
                let sql = &query[4..].trim();
                execute_raw_sql(db, sql)?;
            } else if query_lower.starts_with("files:") {
                let pattern = &query[6..].trim();
                search_files(db, pattern)?;
            } else if query_lower.starts_with("net:") {
                let pattern = &query[4..].trim();
                search_net(db, pattern)?;
            } else {
                eprintln!("Unknown query: {}", query);
                eprintln!();
                eprintln!("Available queries:");
                eprintln!("  summary        - Full summary JSON");
                eprintln!("  processes      - Process tree");
                eprintln!("  events         - Last 100 events");
                eprintln!("  files          - All file operations");
                eprintln!("  net            - All network operations");
                eprintln!("  stacks         - Stack samples");
                eprintln!("  stdout         - Captured stdout");
                eprintln!("  stderr         - Captured stderr");
                eprintln!("  stats          - Statistics");
                eprintln!("  files:<path>   - Search file ops by path pattern");
                eprintln!("  net:<addr>     - Search net ops by address pattern");
                eprintln!("  sql:<query>    - Raw SQL against trace.sqlite");
            }
        }
    }

    Ok(())
}

fn execute_raw_sql(db: &crate::trace::db::TraceDb, sql: &str) -> Result<()> {
    let results = db.raw_query(sql)?;
    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

fn search_files(db: &crate::trace::db::TraceDb, pattern: &str) -> Result<()> {
    let files = db.query_file_events()?;
    let results: Vec<serde_json::Value> = files
        .iter()
        .filter(|f| {
            f.path
                .as_ref()
                .map(|p| p.contains(pattern))
                .unwrap_or(false)
        })
        .map(|f| {
            serde_json::json!({
                "ts_ms": f.ts as f64 / 1_000_000.0,
                "pid": f.proc_id,
                "op": f.op,
                "path": f.path,
                "bytes": f.bytes,
                "result": f.result,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

fn search_net(db: &crate::trace::db::TraceDb, pattern: &str) -> Result<()> {
    let net = db.query_net_events()?;
    let results: Vec<serde_json::Value> = net
        .iter()
        .filter(|n| {
            n.dst.as_ref().map(|d| d.contains(pattern)).unwrap_or(false)
                || n.src.as_ref().map(|s| s.contains(pattern)).unwrap_or(false)
        })
        .map(|n| {
            serde_json::json!({
                "ts_ms": n.ts as f64 / 1_000_000.0,
                "pid": n.proc_id,
                "op": n.op,
                "dst": n.dst,
                "bytes": n.bytes,
                "result": n.result,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}
