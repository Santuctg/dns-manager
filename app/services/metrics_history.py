"""File-based metrics history: a 1-hour rolling record of host telemetry.

Samples are appended as JSON lines (one per ~5 s) by a daemon thread inside
each gunicorn worker and served read-only to the console charts. The file is
pruned to a 1-hour window; readers additionally drop stale samples and
de-duplicate 5-second buckets, so concurrent writers from multiple workers
collapse into one clean timeline. All recorder errors are swallowed: history
is best-effort and must never take the console down.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

from app.config import get_settings
from app.services.system_metrics import collect_metrics

logger = logging.getLogger(__name__)

WINDOW_MS = 3_600_000  # keep ~1 hour of samples
BUCKET_MS = 5_000  # reader de-duplication bucket
PRUNE_INTERVAL_MS = 60_000  # rewrite the file at most once a minute
SAMPLE_INTERVAL = 5.0  # seconds between recordings

_lock = threading.Lock()
_thread: threading.Thread | None = None
_stop = threading.Event()
_last_prune = 0.0


def _sum_counters(metrics: dict) -> tuple[int, int]:
    interfaces = (metrics.get("network") or {}).get("interfaces") or []
    rx = sum(int(row.get("rx_bytes") or 0) for row in interfaces)
    tx = sum(int(row.get("tx_bytes") or 0) for row in interfaces)
    return max(rx, 0), max(tx, 0)


def _prune(path: Path, now_ms: int) -> None:
    """Drop lines older than the window via atomic replace (temp file + rename)."""
    cutoff = now_ms - WINDOW_MS
    lines = []
    # errors="replace": a torn write that left invalid bytes must degrade to
    # skipped lines, never break the rewrite (which would grow the file forever).
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                continue  # valid JSON but not a sample: drop it
            if int(row.get("t", 0)) >= cutoff:
                lines.append(line)
        except (ValueError, TypeError):
            continue  # malformed line: drop it while we're rewriting anyway
    # Both gunicorn workers prune concurrently: the temp name must be unique
    # per process so one worker can never truncate the other's in-flight file.
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp.write_text("\n".join(lines) + ("\n" if lines else ""))
    os.replace(temp, path)


def record_sample(metrics: dict, *, path: Path, now_ms: int | None = None) -> None:
    """Append one sample line and keep the file inside the retention window."""
    global _last_prune
    sampled = int(metrics.get("sampled_at_ms") or 0) or int(time.time() * 1000)
    if now_ms is None:
        now_ms = sampled
    rx, tx = _sum_counters(metrics)
    row = {
        "t": sampled,
        "cpu": (metrics.get("cpu") or {}).get("usage_percent"),
        "mem": (metrics.get("memory") or {}).get("usage_percent"),
        "rx": rx,
        "tx": tx,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(json.dumps(row) + "\n")
    if _last_prune == 0.0 or (now_ms - _last_prune) >= PRUNE_INTERVAL_MS:
        _last_prune = now_ms
        try:
            _prune(path, now_ms)
        except OSError:
            pass  # best-effort prune; the reader drops stale rows anyway


def _rate(prev: dict, curr: dict, key: str) -> float | None:
    """B/s between consecutive samples; counter resets yield None."""
    before, after = prev.get(key), curr.get(key)
    dt = (curr["t"] - prev["t"]) / 1000
    if not all(isinstance(v, (int, float)) for v in (before, after)) or dt <= 0:
        return None
    delta = after - before
    return round(delta / dt, 2) if delta >= 0 else None


def read_history(*, path: Path | None = None, now_ms: int | None = None) -> list[dict]:
    """Return de-duplicated, windowed samples with computed input/output rates."""
    if path is None:
        path = Path(get_settings().metrics_history_path)
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    cutoff = now_ms - WINDOW_MS
    rows: list[dict] = []
    seen_buckets: set[int] = set()
    try:
        raw_lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    for line in raw_lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            t = int(item["t"])
        except (ValueError, TypeError, KeyError):
            continue  # malformed/partial line
        if t < cutoff or (t > now_ms + BUCKET_MS):
            continue
        bucket = t // BUCKET_MS
        if bucket in seen_buckets:
            continue  # second worker wrote the same bucket
        seen_buckets.add(bucket)
        rows.append(
            {
                "t": t,
                "cpu": item.get("cpu") if isinstance(item.get("cpu"), (int, float)) else None,
                "mem": item.get("mem") if isinstance(item.get("mem"), (int, float)) else None,
                "rx": item.get("rx") if isinstance(item.get("rx"), (int, float)) else None,
                "tx": item.get("tx") if isinstance(item.get("tx"), (int, float)) else None,
            }
        )
    rows.sort(key=lambda row: row["t"])
    history: list[dict] = []
    prev: dict | None = None
    for row in rows:
        history.append(
            {
                "t": row["t"],
                "cpu": row["cpu"],
                "mem": row["mem"],
                "input": _rate(prev, row, "rx") if prev else None,
                "output": _rate(prev, row, "tx") if prev else None,
            }
        )
        prev = row
    return history


def _recorder_loop() -> None:
    global _last_prune
    _last_prune = 0.0  # fresh process: prune on the first sample
    while not _stop.is_set():
        try:
            path = Path(get_settings().metrics_history_path)
            record_sample(collect_metrics(), path=path)
        except Exception:
            logger.warning("metrics history recorder sample failed", exc_info=True)
        _stop.wait(SAMPLE_INTERVAL)


def start_recorder() -> None:
    """Start the background recorder thread (idempotent, never raises)."""
    global _thread
    try:
        with _lock:
            if _thread is not None and _thread.is_alive():
                return
            _stop.clear()
            _thread = threading.Thread(target=_recorder_loop, name="metrics-history", daemon=True)
            _thread.start()
    except Exception:
        logger.warning("metrics history recorder could not start", exc_info=True)


def stop_recorder() -> None:
    """Stop the recorder thread if running (idempotent)."""
    global _thread
    with _lock:
        _stop.set()
        thread = _thread
        if thread is not None:
            # Join under the lock so a concurrent start_recorder() cannot clear
            # the stop event while this thread is still winding down (which
            # would leave two recorders running). Only drop the reference once
            # the thread is actually dead, so recorder_thread() never lies.
            thread.join(timeout=2)
            if not thread.is_alive():
                _thread = None


def recorder_thread() -> threading.Thread | None:
    """The live recorder thread, or None when it is not running (test hook)."""
    thread = _thread
    return thread if thread is not None and thread.is_alive() else None
