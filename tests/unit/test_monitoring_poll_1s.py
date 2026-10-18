from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_monitoring_uses_one_second_success_interval_and_dynamic_backoff():
    js = (ROOT / 'app/static/app.js').read_text()
    section = js.split('function startHostMonitoring()', 1)[1].split('async function logout()', 1)[0]
    assert 'const MONITOR_POLL_MS = 1000' in section
    assert 'const MONITOR_MAX_BACKOFF_MS = 30000' in section
    assert 'setTimeout(fetchOnce, nextDelayMs)' in section
    assert 'Math.min(MONITOR_MAX_BACKOFF_MS' in section
    assert 'setInterval(fetchOnce' not in section
    assert 'inFlight || stopped || document.hidden' in section
    assert 'clearTimeout(timer)' in section


def test_one_second_monitoring_label_and_version():
    js = (ROOT / 'app/static/app.js').read_text()
    assert 'Live · updates every 1 second' in js
    assert (ROOT / 'VERSION').read_text().strip() == '0.6.11'
