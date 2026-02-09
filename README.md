# poe

Auto-annotating debugger for AI-native debugging. Captures everything a program
does at runtime and packages it into a `.poepack` file for post-mortem analysis.

Zero-code adoption: no source annotations, no recompilation, no config files.

```
poe run -- ./your-program --arg1 --arg2
```

When the program crashes or exits non-zero, poe emits a `.poepack` containing
the full execution record: processes, files, network, signals, stdio, stack
samples, and language-level traces for Python, Rust, and instrumented C/C++.

## Install

### From source (requires Rust toolchain)

```
cargo build --release
cp target/release/poe ~/.local/bin/
```

### With Nix

```
nix develop   # enters dev shell with all dependencies
cargo build --release
```

## Quick Start

### Capture a crash

```
$ poe run -- python3 my_script.py
Traceback (most recent call last):
  File "my_script.py", line 10, in main
    process(data)
ValueError: invalid input

--- poe debug packet ---
  FAIL process exited with code 1
  packet: ./poe-a1b2c3d4.poepack
  duration: 234ms
  run: poe explain ./poe-a1b2c3d4.poepack
------------------------
```

### Analyze it

```
$ poe explain ./poe-a1b2c3d4.poepack

=== poe explain ===

run_id: a1b2c3d4-...
command: python3 my_script.py
duration: 234ms

--- diagnosis ---
  [critical] python_exception 1 unhandled Python exception(s)
    ValueError: invalid input at my_script.py:10 in process

--- python exceptions ---
  >>> ValueError: invalid input
  traceback:
    > my_script.py:15 in <module>
    > my_script.py:10 in process
      data = [1, 2, 3]
      result = None

--- timeline ---
    5.2ms -> <module>() at my_script.py:0
    5.4ms   -> process() at my_script.py:8
    6.1ms   !! ValueError: invalid input in process()
    6.3ms   <- process() = None
```

### Compare two runs

```
$ poe run --diff baseline.poepack -- python3 my_script.py

--- realtime divergence detected ---
  12.3ms NewFilePath: new file access: open /tmp/output.dat
  ^^ this is the first behavioral divergence from baseline
------------------------------------

=== poe diff ===
--- exit code changed ---
  baseline: 0  candidate: 1
--- file changes ---
  new paths: + /tmp/output.dat
```

## Commands

### `poe run [OPTIONS] -- <command>`

Run a command under poe supervision. Captures syscalls, file I/O, network
activity, process tree, stdio, and language-level traces.

A `.poepack` is emitted when the program crashes (SIGSEGV, SIGABRT, etc.),
exits non-zero, or is killed by a signal. Use `--always` to emit on clean
exit too.

```
poe run -- ./my-program           # capture on failure
poe run --always -- make test     # always capture
poe run --mode full -- ./server   # full capture mode
poe run --diff baseline.poepack -- ./my-program   # diff against baseline
```

Options:
- `--always` -- emit pack even on success
- `--mode lite|full` -- capture detail level
- `--diff <baseline.poepack>` -- realtime divergence detection + post-hoc diff
- `--output <dir>` -- output directory for pack

### `poe explain <pack> [--json]`

Analyze a pack and produce a structured failure explanation:

- **Diagnosis**: error patterns with severity (crash signals, missing files,
  failed connections, panics, exceptions)
- **Process tree**: PIDs, commands, durations, exit status
- **Python exceptions**: full tracebacks with local variables at every frame
- **Rust panics**: parsed panic message, location, backtrace with user frames highlighted
- **Native traces**: C/C++ function call chains from instrumented builds
- **File/network activity**: most accessed paths, bytes, errors
- **Timeline**: chronological interleaved view of all events

### `poe diff <baseline> <candidate> [--json]`

Compare two packs: exit code, duration, process tree, file paths, network
connections, byte counts, stderr content.

### `poe query <pack> <query>`

Query pack data directly. Query types:
- `summary` -- run metadata
- `processes` -- process tree
- `events` -- generic events
- `files` -- file operations
- `net` -- network operations
- `stacks` -- stack samples
- `stdout` / `stderr` -- captured output
- `stats` -- event counts
- `files:<pattern>` -- file ops matching pattern
- `net:<pattern>` -- net ops matching pattern
- `sql:<query>` -- raw SQL against trace.sqlite

### `poe build [OPTIONS] -- <build-command>`

Wrap a build system to inject `-finstrument-functions` into C/C++ code. Links
a crash-safe runtime library that records function entry/exit to a mmap'd ring
buffer. After the instrumented binary runs under `poe run`, the call chain
appears in the timeline.

```
poe build -- make
poe run -- ./my-instrumented-binary
poe explain ./poe-*.poepack
# timeline shows: -> main() -> process() -> compute() -> SIGFPE
```

### `poe serve [OPTIONS]`

HTTP API server for `.poepack` analysis. Upload packs, list them, get
explanations and query results via JSON API.

```
poe serve --bind 0.0.0.0:3000 --store ./packs

# Upload
curl -X POST --data-binary @debug.poepack http://localhost:3000/api/packs

# Analyze
curl http://localhost:3000/api/packs/<id>/explain
```

Endpoints:
- `POST /api/packs` -- upload
- `GET /api/packs` -- list
- `GET /api/packs/:id` -- summary
- `GET /api/packs/:id/explain` -- full analysis
- `GET /api/packs/:id/query/:q` -- query data

### `poe trace <pack1> <pack2> ... [--json]`

Correlate packs from distributed executions. Poe propagates trace IDs via
environment variables (`POE_TRACE_ID`, `POE_PARENT_SPAN_ID`) so captures
across processes and machines can be linked.

```
$ poe trace service-a.poepack service-b.poepack

=== distributed trace === a1b2c3d4
  [root] ./service-a @ host1 (1200ms) -> exit 1
  [child] ./service-b @ host2 (800ms) -> ok
```

### `poe doctor`

Check system capabilities: kernel version, ptrace scope, perf paranoid level,
/proc availability, process_vm_readv support.

## Language Support

### Python

Automatic. When poe detects a Python command, it injects a `sitecustomize.py`
hook that captures:
- Function calls and returns with file/line
- Exception chains with full tracebacks
- Local variables at every frame

No changes to your Python code needed.

### Rust

Automatic. Poe sets `RUST_BACKTRACE=full` for all programs. When a Rust
program panics, poe parses the panic output to extract:
- Panic message and location
- Full backtrace with user frames highlighted
- Thread name

### C/C++

Use `poe build` to compile with instrumentation:
```
poe build -- make
poe run -- ./my-program
```

The runtime library uses a mmap'd ring buffer that survives crashes, so you
get the full call chain even when the program segfaults.

## .poepack Format

A `.poepack` is a deflate-compressed zip containing:
- `summary.json` -- quick preview metadata
- `trace.sqlite` -- full indexed event database
- `artifacts/stdout.log`, `artifacts/stderr.log` -- captured output
- `meta/environment.json` -- redacted env vars, trace context, system info

## Security

Environment variables are redacted before storage. 35+ patterns of sensitive
keys (AWS_SECRET_ACCESS_KEY, API_KEY, DATABASE_URL, etc.) are scrubbed.
Bearer tokens in captured data are also redacted.

## Requirements

- Linux x86_64
- Kernel with ptrace support (ptrace_scope <= 1)
- Optional: perf_event_paranoid <= 1 for stack sampling

## Architecture

See [DESIGN.md](DESIGN.md) for full architecture documentation, module map,
SQLite schema, and technical details.
