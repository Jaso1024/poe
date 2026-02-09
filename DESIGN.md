# poe -- Auto-annotating Debugger for AI-native Debugging

## What It Is

poe is a debugging tool that captures everything a program does at runtime -- processes, files, network, signals, stacks, stdio -- and packages it into a single `.poepack` file that an AI (or a human) can analyze after the fact. The core idea: instead of adding print statements, breakpoints, or logging to your code, you just run it under poe and get a complete execution record when something goes wrong.

Zero-code adoption. No source annotations, no recompilation, no config files. Wrap your command with `poe run --` and you're done.

## Why It Exists

Debugging with AI assistants today is a loop of "paste your error" / "what does your code look like" / "add a print statement here" / "paste the output." That loop is slow because the AI has almost no execution context. It sees a stack trace and maybe a few lines of stderr. It doesn't know what files the program touched, what network calls it made, what other processes it spawned, whether the failure is a regression from a previous run, or what the program was doing in the seconds before it crashed.

poe gives the AI all of that context in one shot. A `.poepack` is a self-contained artifact that tells the full story of what happened during a program's execution. Feed it to an AI and you skip the entire "gather more context" loop.

## Design Principles

**Flight recorder model.** Capture is always-on and cheap. Data flows into ring buffers and gets flushed to a SQLite database on a background thread. When the program exits abnormally (crash, non-zero exit, signal), poe packages everything into a `.poepack`. When the program exits cleanly, nothing is emitted (unless `--always` is set). The overhead is the cost of ptrace syscall interception, which is meaningful but acceptable for debugging runs.

**Safe by default.** Environment variables are redacted before being written to the pack. 35+ patterns of sensitive keys (AWS_SECRET_ACCESS_KEY, DATABASE_URL, API_KEY, etc.) are scrubbed. Bearer tokens in captured data are redacted. There's an allowlist/denylist system for fine-grained control.

**Zero-code adoption.** poe doesn't require any changes to the program being debugged. No annotations, no libraries, no build system integration. It works by sitting between the kernel and the program using ptrace, intercepting every syscall to observe what the program does without modifying how it does it.

**Structured output for machines.** The `.poepack` is a zip file containing a `summary.json` (fast preview), `trace.sqlite` (full indexed event database), captured stdio, and environment metadata. Every piece of data is queryable. The explain output is designed to be consumed by AI systems as much as by humans.

## Architecture

```
poe run -- <cmd>
    |
    v
+-- fork() --+
|             |
| parent:     | child:
| ptrace      | PTRACE_TRACEME
| event loop  | raise(SIGSTOP)
|             | execvp(cmd)
|             |
| intercepts every syscall entry/exit
| decodes file ops, net ops, process ops
|     |
|     v
|  mpsc channel --> db writer thread --> trace.sqlite (WAL mode)
|                                           |
|  stdio pipes --> relay threads            |
|  (forward to terminal + capture to ring)  |
|                                           |
|  perf_event_open --> stack sampler        |
|  (99Hz sampling when kernel allows)       |
|                                           |
+--- on exit: determine trigger -----+------+
                                     |
                                     v
                              pack writer
                              (zip: summary.json + trace.sqlite + artifacts/)
                                     |
                                     v
                              .poepack file
```

### Module Map

```
src/
  main.rs              CLI entry point (clap)
  lib.rs               Module declarations

  capture/
    tracer.rs          ptrace event loop, fork/exec, syscall interception
    syscalls.rs        x86_64 syscall number table, entry/exit decoding,
                       sockaddr parsing, file/net/process classification
    stdio.rs           pipe2(O_CLOEXEC), relay threads, ring buffer capture
    stacks.rs          perf_event_open, mmap ring buffer, sample parsing
    runner.rs          orchestrates tracer + stdio + stacks + db writer

  trace/
    db.rs              SQLite schema, batch insert, query methods, WAL/checkpoint

  events/
    types.rs           RunInfo, ProcessInfo, FileEvent, NetEvent, StackSample,
                       StdioChunk, TraceEvent enum, CaptureMode, TriggerReason

  pack/
    writer.rs          zip creation: summary.json + trace.sqlite + artifacts/
    reader.rs          zip extraction, PackReader API
    summary.rs         summary.json generation with failure classification

  explain/
    analyzer.rs        failure explanation, error pattern detection, timeline
                       construction, file/net activity summary, crash analysis
    diff.rs            two-pack comparison: exit code, duration, process tree,
                       file paths, network connections, byte counts, stderr

  cli/
    run.rs             poe run [--always] [--diff baseline] -- <cmd>
    explain.rs         poe explain <packet> [--json]
    diff.rs            poe diff <baseline> <candidate> [--json]
    query.rs           poe query <packet> <query>
    doctor.rs          poe doctor

  redact/
    patterns.rs        sensitive env key detection, bearer token scrubbing,
                       allowlist/denylist

  symbols/
    resolver.rs        ELF symtab/dynsym parsing, /proc/PID/maps reading

  util/
    mod.rs             timestamp_ns, hash_env, signal_name
    ringbuf.rs         ByteRing (fixed-size circular buffer), EventRing
    procfs.rs          /proc/<pid>/{maps,cmdline,cwd,environ,exe,status},
                       git_sha, hostname
```

## .poepack Format

A `.poepack` is a deflate-compressed zip file:

```
summary.json              quick preview: run_id, command, exit_code, signal,
                          duration, failure info, stats (event counts, byte counts)

trace.sqlite              full event database (see schema below)

artifacts/
  stdout.log              captured stdout (ring buffer, last N bytes)
  stderr.log              captured stderr

meta/
  environment.json        redacted environment variables, git sha, kernel version,
                          architecture, poe version
```

### SQLite Schema

```sql
run           run_id, command, working_dir, env_hash, start_time, end_time,
              git_sha, hostname, exit_code, signal, trigger_reason

processes     proc_id, parent_proc_id, argv, cwd, start_ts, end_ts,
              exit_code, signal

events        ts, proc_id, kind, detail

files         ts, proc_id, op, path, fd, bytes, flags, result

net           ts, proc_id, op, proto, src, dst, bytes, fd, result

stacks        ts, proc_id, frames (JSON array of u64 addresses), weight

stdio         ts, proc_id, stream, data (blob)

artifacts     artifact_id, kind, path, content_hash, size

spans         span_id, proc_id, name, start_ts, end_ts, attrs

effects       effect_id, proc_id, kind, attrs, idempotency_key
```

Indexed on `ts`, `proc_id`, `kind`, `path`. WAL mode for concurrent write/read. Explicit checkpoint before pack generation ensures the database file is self-contained.

## Commands

### `poe run [OPTIONS] -- <command>`

Runs the command under ptrace supervision. Captures all syscalls, classifies them into file/net/process events, records them to SQLite via a background writer thread. Captures stdout/stderr through pipe relay (forwarding to the terminal in real-time while also recording). Optionally samples call stacks via perf_event_open.

On exit, determines whether to emit a `.poepack`:
- **Crash** (SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT): always emit
- **Signal** (SIGTERM, SIGKILL, etc.): always emit
- **Non-zero exit code**: always emit
- **Clean exit (code 0)**: emit only if `--always` is set

Exits with the same exit code as the child process.

Options:
- `--always` -- emit packet even on success
- `--mode lite|full` -- capture mode (full includes more detail)
- `--output <dir>` -- output directory for the .poepack
- `--diff <baseline.poepack>` -- after the run, automatically diff against baseline

### `poe explain <packet> [--json]`

Analyzes a `.poepack` and produces a structured explanation:

- **Diagnosis**: detected error patterns with severity (critical/error/warning)
  - Crash signals (SIGSEGV, SIGABRT, etc.) with register dump and fault address
  - Permission denied errors on file operations
  - Missing files that appear significant
  - Failed network connections
  - Multiple processes killed by signals
  - Stderr pattern detection: OOM, timeouts, panics, tracebacks, exceptions
- **Failure info**: kind, description, exit code, signal
- **Process tree**: PIDs, commands, durations, exit status, parent-child relationships
- **Stack hotspots**: most frequent instruction pointers from stack samples
- **File activity**: total ops, unique paths, bytes read/written, most accessed paths, permission errors
- **Network activity**: total ops, connections with addresses, bytes sent/received, failed connections
- **Timeline**: interleaved chronological view of file, network, and process events (noise filtered)
- **Stderr tail**: last 50 lines of captured stderr
- **Stdout tail**: last 20 lines of captured stdout

With `--json`, outputs the full analysis as structured JSON suitable for AI consumption.

### `poe diff <baseline> <candidate> [--json]`

Compares two `.poepack` files to find behavioral divergences:

- Exit code changes
- Signal changes
- Duration delta (absolute and percentage)
- Process tree changes (new/missing processes)
- File changes (new/missing paths, new errors, byte count deltas)
- Network changes (new/missing connections, new errors, byte count deltas)
- Stderr changes (new lines not present in baseline)

### `poe query <packet> <query>`

Structured data retrieval from a `.poepack`:

- `summary` -- full summary JSON
- `processes` / `procs` -- process tree as JSON
- `events` -- last 100 events
- `files` -- all file operations
- `net` / `network` -- all network operations
- `stacks` -- stack samples with frame addresses
- `stdout` -- raw captured stdout
- `stderr` -- raw captured stderr
- `stats` -- event counts and byte totals
- `files:<pattern>` -- file ops matching path pattern
- `net:<pattern>` -- net ops matching address pattern
- `sql:<query>` -- raw SQL against trace.sqlite

### `poe doctor`

Checks system capabilities:
- Kernel version (>= 4.8 required for full ptrace)
- `ptrace_scope` setting (0 = permissive, 1 = restricted to children, which is fine)
- `perf_event_paranoid` (affects stack sampling availability)
- /proc filesystem availability
- `process_vm_readv` syscall availability

## How Capture Works

### Ptrace

poe uses Linux ptrace to intercept every syscall the child process makes. The flow:

1. Fork a child process
2. Child calls `PTRACE_TRACEME`, then `raise(SIGSTOP)` to pause itself
3. Parent waits for the SIGSTOP, sets ptrace options (`TRACESYSGOOD | TRACEFORK | TRACEVFORK | TRACECLONE | TRACEEXEC | TRACEEXIT`), then calls `PTRACE_SYSCALL` to continue
4. Each syscall causes two stops: one at entry (arguments available) and one at exit (return value available)
5. At entry, poe reads the syscall number and arguments from registers, reads strings/buffers from the child's memory via `process_vm_readv`
6. At exit, poe reads the return value and pairs it with the entry data to produce a complete event
7. Events are sent through an mpsc channel to a background database writer thread

Entry vs exit detection uses the `rax == -ENOSYS` heuristic (same approach as strace): at syscall entry, the kernel sets `rax = -38`, at exit it holds the return value. This is more robust than phase toggling, which can desynchronize after `PTRACE_EVENT_EXEC`.

### Syscall Classification

Every intercepted syscall is classified:

- **File ops**: open, openat, creat, close, read, write, pread64, pwrite64, readv, writev, rename, renameat, renameat2, unlink, unlinkat, mkdir, mkdirat, stat, fstat, lstat, newfstatat, chmod, fchmod, fchmodat, chown, fchown, lchown, fchownat, link, linkat, symlink, symlinkat, readlink, readlinkat, truncate, ftruncate, access, faccessat, faccessat2
- **Net ops**: socket, connect, bind, listen, accept, accept4, sendto, recvfrom, sendmsg, recvmsg, shutdown, getsockname, getpeername
- **Process ops**: execve, execveat, fork, vfork, clone, clone3, exit, exit_group (tracked via ptrace events, not decoded as file/net)

Path arguments are read from the child's address space. Socket addresses are decoded (IPv4, IPv6, Unix domain). Read/write byte counts come from the syscall return value.

### Stdio Capture

Stdout and stderr are captured through pipes created with `pipe2(O_CLOEXEC)`:

1. Before fork, create two pipe pairs (one for stdout, one for stderr)
2. In the child (before exec), dup2 the write ends onto fd 1 and fd 2
3. The O_CLOEXEC on the parent's read ends prevents the child from inheriting them after exec
4. Relay threads in the parent read from the pipes and simultaneously forward to the real stdout/stderr (so the user still sees output) and write to ring buffers
5. The ring buffers capture the last N bytes (default 1MB) of each stream

### Stack Sampling

When the kernel allows it (`perf_event_paranoid <= 1` or `CAP_PERFMON`), poe uses `perf_event_open` to sample call stacks at 99Hz:

1. Create a perf event with `PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK` / `PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN`
2. mmap a ring buffer to read samples
3. Parse samples to extract TID, timestamp, and call chain (array of instruction pointer addresses)
4. Drain remaining samples after the child exits

Stack sampling degrades silently when unavailable. It's optional -- poe's core value is in syscall tracing, not profiling.

## Noise Filtering

The explain output filters noise from the timeline and file activity:
- `/proc/self/*`, `/proc/thread-self/*`
- Dynamic linker files (`*.so`, `*.so.*`, `ld.so.cache`, `ld.so.preload`, `glibc-hwcaps/*`)
- Locale/encoding files (`locale-archive`, `gconv-modules`)
- NSS configuration (`nsswitch.conf`, `libnss_*`)
- `/dev/null`, `/dev/urandom`
- PATH search probes for executables
- Python packaging metadata (`__pycache__`, `.pyc`, `site-packages`, `METADATA`, etc.)
- Config file probes (`.cfg`, `.conf`)
- nscd socket and netlink family addresses in network activity

## Secret Redaction

Environment variables matching these patterns are replaced with `[REDACTED]`:

API keys, tokens, secrets, passwords, credentials, private keys, database URLs, connection strings, session data, auth headers, encryption keys, signing keys, webhook secrets, cloud provider credentials (AWS, GCP, Azure), CI tokens, and more (35+ patterns).

Bearer tokens appearing in any captured data are also redacted.

The redactor supports:
- Allowlist: keys that should never be redacted even if they match a pattern
- Denylist: additional keys to always redact beyond the built-in patterns

## Roadmap

### Phase 0: MVP (current -- complete)

Everything described above. Linux x86_64, ptrace-based capture, `.poepack` format, `poe run` / `poe explain` / `poe diff` / `poe query` / `poe doctor`.

### Phase 1: Native Instrumentation

`poe build -- make/ninja/cmake` wraps the compiler to inject entry/exit probes into C/C++ code at compile time. This gives function-level tracing without ptrace overhead, and crash-safe ring buffers that survive SIGSEGV. The clang wrapper adds `-finstrument-functions` or equivalent and links a small runtime library.

### Phase 2: Python Auto-hooks

Inject `sitecustomize.py` into the Python process to enable frame tracing, `faulthandler`, and structured exception capture. No changes to user code -- poe sets `PYTHONPATH` to include its hook before exec. Captures Python-level stack frames, exception chains, and variable snapshots.

### Phase 3: Rust Support

Inject `RUSTFLAGS` through cargo to add instrumentation to Rust programs. Capture panic hooks, backtraces, and structured error chains.

### Phase 4: Differential Execution

`poe run --diff <baseline> -- <candidate>` captures a new run and compares it against a baseline, highlighting the first point of behavioral divergence. Goes beyond the current diff command (which compares after the fact) to provide real-time divergence detection.

### Phase 5: Language Adapters

Generalized adapter interface for any language runtime. Each adapter implements:
- `on_load`: inject hooks into the process
- `on_frame`: capture language-level stack frames
- `on_exception`: capture structured error info
- `on_exit`: finalize and flush

### Phase 6: `poe serve`

HTTP API that accepts `.poepack` files and provides analysis endpoints. Enables integration with CI systems, editor extensions, and AI assistants. Stores packs for historical comparison.

### Phase 7: Distributed Tracing

Correlate poe captures across multiple processes and machines. Propagate trace IDs through environment variables or protocol headers. Reconstruct distributed execution graphs.

## Technical Notes

**Platform**: Linux x86_64 only (Phase 0). The syscall table, register layout, and ptrace semantics are all x86_64-specific. ARM64 support would require a parallel syscall decoder and register reader.

**Performance**: ptrace adds ~2x slowdown for syscall-heavy programs. This is acceptable for debugging but not production. The flight recorder model means the overhead is only paid during `poe run`, and packs are only written when something goes wrong.

**Limitations**:
- Stack sampling requires `perf_event_paranoid <= 1` or `CAP_PERFMON` capability
- ptrace can only trace child processes (when `ptrace_scope = 1`, which is the default)
- Programs that use ptrace themselves (debuggers, strace) cannot be traced
- Multithreaded programs work but thread creation is tracked via PTRACE_EVENT_CLONE
- If a syscall legitimately returns -38 (ENOSYS), the entry/exit heuristic will misclassify it (extremely rare in practice)

**Implementation language**: Rust. The codebase is ~6,500 lines across 32 source files. Dependencies are minimal and well-chosen: nix (ptrace/signal), rusqlite (bundled SQLite), clap (CLI), zip (pack format), chrono/uuid/sha2/serde (utilities).
