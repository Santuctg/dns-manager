"""Unit tests for the file-based metrics history recorder/reader."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from app.services.metrics_history import (
    read_history,
    record_sample,
    start_recorder,
    stop_recorder,
)

# Realistic base timestamp: prune throttling compares wall-clock deltas, so
# tests must not mix fake epoch values with the module-level prune state.
NOW = int(time.time() * 1000)


def _metrics(rx: int, tx: int, cpu: float = 14.3, mem: float = 19.7, t: int | None = None) -> dict:
    return {
        "sampled_at_ms": t if t is not None else NOW,
        "cpu": {"usage_percent": cpu},
        "memory": {"usage_percent": mem},
        "network": {"interfaces": [{"name": "eth0", "rx_bytes": rx, "tx_bytes": tx}]},
    }


def test_record_sample_appends_json_line(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    record_sample(_metrics(rx=1000, tx=2000, t=NOW), path=path)
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert rows == [{"t": NOW, "cpu": 14.3, "mem": 19.7, "rx": 1000, "tx": 2000}]


def test_record_sample_creates_parent_dirs(tmp_path: Path):
    path = tmp_path / "nested" / "dir" / "history.jsonl"
    record_sample(_metrics(rx=1, tx=2), path=path)
    assert path.is_file()


def test_read_history_computes_rates(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    record_sample(_metrics(rx=10_000, tx=20_000, t=NOW - 5000), path=path)
    record_sample(_metrics(rx=15_000, tx=26_000, t=NOW), path=path)
    rows = read_history(path=path, now_ms=NOW)
    assert len(rows) == 2
    assert rows[0]["input"] is None and rows[0]["output"] is None  # no predecessor
    assert rows[1]["input"] == 1000.0  # 5000 B / 5 s
    assert rows[1]["output"] == 1200.0  # 6000 B / 5 s
    assert rows[1]["cpu"] == 14.3 and rows[1]["mem"] == 19.7


def test_read_history_deduplicates_identical_samples(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    # Two gunicorn workers recording the same 5 s bucket. Align the pair to the
    # bucket grid so it can never straddle a 5 s boundary (a wall-clock pair
    # would flake depending on where NOW falls inside the bucket).
    bucket_start = (NOW // 5_000) * 5_000 - 5_000
    record_sample(_metrics(rx=100, tx=200, t=bucket_start), path=path)
    record_sample(_metrics(rx=999, tx=888, t=bucket_start + 1_000), path=path)
    rows = read_history(path=path, now_ms=NOW)
    # One sample per bucket, and the earliest of the pair is the keeper.
    assert [row["t"] for row in rows] == [bucket_start]


def test_read_history_drops_stale_samples(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    record_sample(_metrics(rx=1, tx=1, t=NOW - 7_200_000), path=path)
    record_sample(_metrics(rx=2, tx=2, t=NOW), path=path)
    rows = read_history(path=path, now_ms=NOW)
    assert [row["t"] for row in rows] == [NOW]


def test_malformed_lines_are_skipped(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    record_sample(_metrics(rx=5, tx=6, t=NOW - 20_000), path=path)
    with path.open("a") as handle:
        handle.write('{"t": 1, "cpu"')  # truncated write
        handle.write("\nnot json at all\n")
    rows = read_history(path=path, now_ms=NOW)
    assert [row["t"] for row in rows] == [NOW - 20_000]


def test_negative_delta_yields_null_rate(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    record_sample(_metrics(rx=50_000, tx=60_000, t=NOW - 10_000), path=path)
    record_sample(_metrics(rx=100, tx=200, t=NOW - 5000), path=path)  # counter reset
    rows = read_history(path=path, now_ms=NOW)
    assert rows[1]["input"] is None and rows[1]["output"] is None


def test_prune_keeps_window_and_replaces_atomically(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    record_sample(_metrics(rx=1, tx=1, t=NOW - 7_200_000), path=path)  # 2 h old
    # Jump past the 60 s prune throttle so this record triggers a prune.
    record_sample(_metrics(rx=2, tx=2, t=NOW + 120_000), path=path)
    record_sample(_metrics(rx=3, tx=3, t=NOW + 121_000), path=path)
    texts = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert all(row["t"] > NOW + 120_000 - 3_600_000 for row in texts), texts
    assert not list(tmp_path.glob("*.tmp")), "prune must use and clean a temp file"


def test_read_history_missing_file_returns_empty():
    assert read_history(path=Path("/nonexistent/dir/history.jsonl")) == []


def test_prune_does_not_clobber_foreign_temp_file(tmp_path: Path, monkeypatch):
    from app.services import metrics_history

    path = tmp_path / "history.jsonl"
    # The other gunicorn worker's in-flight temp file in the same directory.
    foreign = tmp_path / "history.jsonl.tmp"
    foreign.write_text("other-worker-in-flight\n")
    monkeypatch.setattr(metrics_history, "_last_prune", 0.0)  # force a prune now
    record_sample(_metrics(rx=1, tx=1, t=NOW), path=path)
    assert foreign.exists() and foreign.read_text() == "other-worker-in-flight\n", (
        "prune must write through its own pid-unique temp file, never the other worker's"
    )
    leftovers = sorted(p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp"))
    assert leftovers == ["history.jsonl.tmp"], f"own temp must be consumed by os.replace: {leftovers}"


def test_read_history_survives_binary_corruption(tmp_path: Path):
    path = tmp_path / "history.jsonl"
    record_sample(_metrics(rx=5, tx=6, t=NOW - 20_000), path=path)
    with path.open("ab") as handle:
        handle.write(b"\xff\xfe not utf-8\n")  # torn write left invalid bytes
    rows = read_history(path=path, now_ms=NOW)
    assert [row["t"] for row in rows] == [NOW - 20_000]


def test_prune_survives_non_object_lines(tmp_path: Path, monkeypatch):
    from app.services import metrics_history

    path = tmp_path / "history.jsonl"
    record_sample(_metrics(rx=5, tx=6, t=NOW - 20_000), path=path)
    with path.open("a") as handle:
        handle.write("5\n[1, 2]\n")  # valid JSON, but not an object
    monkeypatch.setattr(metrics_history, "_last_prune", 0.0)  # force a prune now
    record_sample(_metrics(rx=6, tx=7, t=NOW), path=path)
    kept = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert [row["t"] for row in kept] == [NOW - 20_000, NOW], kept


def test_recorder_survives_unwritable_path(tmp_path: Path, monkeypatch):
    from app.services import metrics_history

    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    path = blocker / "history.jsonl"  # parent is a file: mkdir/open must fail

    class _Settings:
        metrics_history_path = str(path)

    monkeypatch.setattr(metrics_history, "get_settings", lambda: _Settings())
    monkeypatch.setattr(metrics_history, "collect_metrics", lambda: _metrics(rx=1, tx=2))
    monkeypatch.setattr(metrics_history, "SAMPLE_INTERVAL", 0.05)
    try:
        start_recorder()  # must return without raising even though writes fail
        time.sleep(0.2)
        assert metrics_history.recorder_thread() is not None, (
            "recorder must keep looping past write failures instead of dying"
        )
        assert not path.exists()
    finally:
        stop_recorder()


def test_start_stop_recorder_is_idempotent(tmp_path: Path, monkeypatch):
    from app.services import metrics_history

    path = tmp_path / "history.jsonl"
    monkeypatch.setattr(metrics_history, "get_settings", lambda: type("S", (), {"metrics_history_path": str(path)})())
    monkeypatch.setattr(metrics_history, "collect_metrics", lambda: _metrics(rx=1, tx=2))
    monkeypatch.setattr(metrics_history, "SAMPLE_INTERVAL", 0.05)
    try:
        start_recorder()
        start_recorder()  # second call must not start a second thread
        assert len([t for t in threading.enumerate() if t.name == "metrics-history"]) == 1
        deadline = time.time() + 3
        while time.time() < deadline and (not path.is_file() or not path.read_text().strip()):
            time.sleep(0.02)
        assert path.is_file() and path.read_text().strip(), "recorder never wrote a sample"
        stop_recorder()
        stop_recorder()  # idempotent
        assert metrics_history.recorder_thread() is None
    finally:
        stop_recorder()  # never leak a recorder into the rest of the suite
