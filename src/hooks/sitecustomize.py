import sys
import os
import json
import time
import threading
import traceback
import faulthandler

_POE_FD = int(os.environ.get("_POE_HOOK_FD", "-1"))
_POE_TRACE_CALLS = os.environ.get("_POE_TRACE_CALLS", "1") == "1"
_POE_MAX_DEPTH = int(os.environ.get("_POE_MAX_DEPTH", "64"))
_POE_VAR_MAX_LEN = int(os.environ.get("_POE_VAR_MAX_LEN", "256"))
_POE_VAR_MAX_ITEMS = int(os.environ.get("_POE_VAR_MAX_ITEMS", "16"))

if _POE_FD < 0:
    _POE_FD = None

_lock = threading.Lock()
_start_ns = time.monotonic_ns()
_depth = {}


def _ts_ns():
    return time.monotonic_ns() - _start_ns


def _safe_repr(obj, max_len=_POE_VAR_MAX_LEN):
    try:
        r = repr(obj)
        if len(r) > max_len:
            return r[:max_len - 3] + "..."
        return r
    except Exception:
        return "<repr failed>"


def _capture_locals(frame, max_items=_POE_VAR_MAX_ITEMS):
    result = {}
    items = list(frame.f_locals.items())
    for k, v in items[:max_items]:
        if k.startswith("__"):
            continue
        result[k] = _safe_repr(v)
    return result


def _emit(record):
    if _POE_FD is None:
        return
    try:
        line = json.dumps(record, default=str) + "\n"
        data = line.encode("utf-8")
        with _lock:
            os.write(_POE_FD, data)
    except Exception:
        pass


def _is_user_frame(filename):
    if not filename:
        return False
    skip = (
        "<frozen",
        "/lib/python",
        "/site-packages/",
        "/dist-packages/",
        "sitecustomize.py",
        "importlib",
        "/nix/store/",
    )
    for s in skip:
        if s in filename:
            return False
    return True


def _trace_fn(frame, event, arg):
    tid = threading.get_ident()
    filename = frame.f_code.co_filename

    if not _is_user_frame(filename):
        return _trace_fn

    if event == "call":
        d = _depth.get(tid, 0)
        if d >= _POE_MAX_DEPTH:
            return _trace_fn
        _depth[tid] = d + 1

        _emit({
            "type": "call",
            "ts": _ts_ns(),
            "tid": tid,
            "func": frame.f_code.co_name,
            "file": filename,
            "line": frame.f_lineno,
            "depth": d,
        })

    elif event == "return":
        d = _depth.get(tid, 1) - 1
        _depth[tid] = max(d, 0)

        _emit({
            "type": "return",
            "ts": _ts_ns(),
            "tid": tid,
            "func": frame.f_code.co_name,
            "file": filename,
            "line": frame.f_lineno,
            "depth": max(d, 0),
            "retval": _safe_repr(arg),
        })

    elif event == "exception":
        exc_type, exc_value, exc_tb = arg
        _emit({
            "type": "exception",
            "ts": _ts_ns(),
            "tid": tid,
            "func": frame.f_code.co_name,
            "file": filename,
            "line": frame.f_lineno,
            "exc_type": exc_type.__name__ if exc_type else "Unknown",
            "exc_msg": _safe_repr(exc_value, 512),
            "locals": _capture_locals(frame),
        })

    return _trace_fn


def _excepthook(exc_type, exc_value, exc_tb):
    frames = []
    tb = exc_tb
    while tb is not None:
        f = tb.tb_frame
        frames.append({
            "file": f.f_code.co_filename,
            "line": tb.tb_lineno,
            "func": f.f_code.co_name,
            "locals": _capture_locals(f),
        })
        tb = tb.tb_next

    chain = []
    current = exc_value
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append({
            "type": type(current).__name__,
            "msg": _safe_repr(current, 1024),
            "cause": "chained" if current.__cause__ else ("context" if current.__context__ else None),
        })
        current = current.__cause__ or current.__context__

    _emit({
        "type": "unhandled_exception",
        "ts": _ts_ns(),
        "tid": threading.get_ident(),
        "exc_type": exc_type.__name__,
        "exc_msg": str(exc_value)[:1024],
        "traceback": frames,
        "chain": chain,
        "formatted": traceback.format_exception(exc_type, exc_value, exc_tb),
    })

    sys.__excepthook__(exc_type, exc_value, exc_tb)


def _init():
    faulthandler.enable()

    sys.excepthook = _excepthook

    if _POE_TRACE_CALLS and _POE_FD is not None:
        sys.settrace(_trace_fn)
        threading.settrace_all_threads(_trace_fn)


_init()
