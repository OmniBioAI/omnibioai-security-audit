"""Track E4: audit/security_alerts.py -- vendor-neutral alert emission.

No real alerting vendor exists in this deployment, so these tests cover
the actual contract that matters: alerts carry the right shape, no
PHI/credentials leak into metadata by construction, repeated failures
dedupe instead of storming, a broken sink never propagates, and a
recovery condition always gets through.
"""
import json

import pytest

from audit.security_alerts import (
    FileAlertSink,
    SecurityAlert,
    _reset_dedup_state_for_tests,
    emit_security_alert,
)


@pytest.fixture(autouse=True)
def _clean_dedup_state():
    _reset_dedup_state_for_tests()
    yield
    _reset_dedup_state_for_tests()


class RecordingSink:
    def __init__(self):
        self.sent = []

    def send(self, alert: SecurityAlert) -> None:
        self.sent.append(alert)


class RaisingSink:
    def send(self, alert: SecurityAlert) -> None:
        raise RuntimeError("simulated alert backend outage")


def test_alert_carries_condition_severity_component_timestamp():
    sink = RecordingSink()
    alert = emit_security_alert(
        condition="integrity_verification_failed",
        severity="critical",
        component="integrity-verification",
        message="records failed verification",
        metadata={"events_invalid": 3},
        sink=sink,
    )
    assert alert is not None
    assert alert.condition == "integrity_verification_failed"
    assert alert.severity == "critical"
    assert alert.component == "integrity-verification"
    assert alert.timestamp  # non-empty, set automatically
    assert sink.sent == [alert]


def test_invalid_severity_falls_back_to_warning_not_dropped():
    sink = RecordingSink()
    alert = emit_security_alert(
        condition="x", severity="not-a-real-severity", component="c", message="m", sink=sink,
    )
    assert alert is not None
    assert alert.severity == "warning"
    assert sink.sent  # never silently dropped over a bad enum value


def test_metadata_never_includes_raw_row_content_by_construction():
    """This is a construction-discipline test, not a scanner: it asserts
    that emit_security_alert() only ever stores exactly the metadata dict
    the caller passed -- it never reaches into surrounding scope/globals
    to auto-enrich the payload with anything the caller didn't explicitly
    hand it. PHI-safety is therefore a property of what call sites pass,
    which is covered by inspection of the three real call sites below."""
    sink = RecordingSink()
    safe_metadata = {"events_invalid": 2, "service": "tes"}
    alert = emit_security_alert(
        condition="c", severity="warning", component="comp", message="m",
        metadata=safe_metadata, sink=sink,
    )
    assert alert.metadata == safe_metadata


def test_repeated_identical_condition_is_deduped_within_window():
    sink = RecordingSink()
    first = emit_security_alert(condition="poison_event_quarantined", severity="warning",
                                 component="audit-worker", message="m", sink=sink, _now=1000.0)
    second = emit_security_alert(condition="poison_event_quarantined", severity="warning",
                                  component="audit-worker", message="m", sink=sink, _now=1050.0,
                                  dedup_window_seconds=300)
    assert first is not None
    assert second is None
    assert len(sink.sent) == 1, "a burst of identical failures must not storm the sink"


def test_dedup_window_expiry_allows_a_new_alert():
    sink = RecordingSink()
    emit_security_alert(condition="c", severity="warning", component="comp", message="m",
                         sink=sink, _now=1000.0, dedup_window_seconds=300)
    third = emit_security_alert(condition="c", severity="warning", component="comp", message="m",
                                 sink=sink, _now=1301.0, dedup_window_seconds=300)
    assert third is not None
    assert len(sink.sent) == 2


def test_different_components_are_not_deduped_against_each_other():
    sink = RecordingSink()
    a = emit_security_alert(condition="c", severity="warning", component="worker", message="m", sink=sink, _now=1.0)
    b = emit_security_alert(condition="c", severity="warning", component="retention-cleanup", message="m", sink=sink, _now=1.0)
    assert a is not None
    assert b is not None
    assert len(sink.sent) == 2


def test_recovery_condition_bypasses_dedup():
    sink = RecordingSink()
    emit_security_alert(condition="backup_failed", severity="critical", component="backup", message="m",
                         sink=sink, _now=1.0)
    emit_security_alert(condition="backup_failed", severity="critical", component="backup", message="m",
                         sink=sink, _now=2.0)  # deduped
    recovered = emit_security_alert(condition="backup_failed_recovered", severity="info", component="backup",
                                     message="recovered", sink=sink, _now=2.0)
    assert recovered is not None
    assert len(sink.sent) == 2  # original failure + recovery, not the deduped repeat


def test_broken_sink_never_raises_and_alert_is_still_returned():
    alert = emit_security_alert(condition="c", severity="warning", component="comp", message="m",
                                 sink=RaisingSink())
    assert alert is not None  # emission was attempted, not silently no-op'd


def test_broken_sink_failure_is_itself_observable_on_stderr(capsys):
    emit_security_alert(condition="c", severity="warning", component="comp", message="m", sink=RaisingSink())
    captured = capsys.readouterr()
    assert "SECURITY-ALERT-EMISSION-FAILED" in captured.err


def test_default_stdout_sink_prints_json_line(capsys):
    emit_security_alert(condition="c", severity="info", component="comp", message="m")
    captured = capsys.readouterr()
    assert "[SECURITY-ALERT]" in captured.out
    json_part = captured.out.split("[SECURITY-ALERT] ", 1)[1].strip()
    parsed = json.loads(json_part)
    assert parsed["condition"] == "c"


def test_file_sink_writes_jsonl(tmp_path):
    path = tmp_path / "alerts.jsonl"
    sink = FileAlertSink(path)
    emit_security_alert(condition="a", severity="warning", component="comp", message="m1", sink=sink)
    emit_security_alert(condition="b", severity="critical", component="comp", message="m2", sink=sink)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["condition"] == "a"
    assert json.loads(lines[1])["condition"] == "b"


def test_env_configured_file_sink_used_when_no_explicit_sink_given(tmp_path, monkeypatch):
    log_file = tmp_path / "alerts.jsonl"
    monkeypatch.setenv("AUDIT_ALERT_LOG_FILE", str(log_file))
    emit_security_alert(condition="c", severity="warning", component="comp", message="m")
    assert log_file.exists()
    assert json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])["condition"] == "c"


def test_stdout_sink_used_when_no_env_configured(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("AUDIT_ALERT_LOG_FILE", raising=False)
    emit_security_alert(condition="c", severity="warning", component="comp", message="m")
    assert "[SECURITY-ALERT]" in capsys.readouterr().out
