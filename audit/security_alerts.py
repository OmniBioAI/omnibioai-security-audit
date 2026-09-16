"""Track E4: vendor-neutral security alert emission.

No alerting platform (PagerDuty/Slack/email/etc.) is wired up for this
deployment -- confirmed absent as of the 2026-09-16 backup incident (see
../../omnibioai-docs/security/mysql_backup_recovery_evidence.md) and
still true as of this track. Rather than hardcode a vendor this codebase
doesn't actually use, this module defines a minimal `AlertSink`
interface and a safe, PHI-free alert schema. Wiring a real vendor is a
deployment-time configuration change (implement `AlertSink`, point
`AUDIT_ALERT_SINK` at it), not a code change here.

Default sink (zero configuration required): stdout, as a single JSON
line per alert -- observable via `docker logs`/journald/whatever already
tails this process's output, exactly like every other [INFO]/[ERROR]
line this codebase already emits. Optionally, if AUDIT_ALERT_LOG_FILE is
set, alerts are additionally appended to that file as JSONL (same
pattern as AUDIT_HEALTH_STATUS_DIR's status files) for a monitoring
agent that tails files rather than stdout.

CRITICAL invariant: alert emission NEVER raises and NEVER blocks the
caller. `emit_security_alert()` catches and swallows every sink
failure -- an alerting-system outage must not become a new failure
mode, must not delay/gate durable persistence decisions, and must
never be mistaken for an authorization check. Call it for observability
only, always after the real decision (deny, quarantine, fail-closed)
has already happened, never before or instead of it.

Deduplication: repeated identical conditions from the same component
within `dedup_window_seconds` are suppressed after the first, so a
retry loop or a burst of poison events cannot become an alert storm.
A condition name ending in "_recovered" always bypasses dedup -- a
recovery signal must never be silently swallowed by the same window
that was suppressing the failure it recovered from.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

VALID_SEVERITIES = ("info", "warning", "critical")


@dataclass(frozen=True)
class SecurityAlert:
    condition: str        # stable machine-readable id, e.g. "integrity_verification_failed"
    severity: str         # one of VALID_SEVERITIES
    component: str        # e.g. "audit-worker", "retention-cleanup", "integrity-verification"
    message: str          # short, human-readable, PHI-free, no credentials/tokens
    metadata: dict        # safe diagnostic fields only -- counts/ids, never row content
    timestamp: str


class AlertSink:
    def send(self, alert: SecurityAlert) -> None:  # pragma: no cover -- interface
        raise NotImplementedError


class StdoutAlertSink(AlertSink):
    """Zero-configuration default -- always observable via process logs."""

    def send(self, alert: SecurityAlert) -> None:
        print(f"[SECURITY-ALERT] {json.dumps(asdict(alert), sort_keys=True)}", flush=True)


class FileAlertSink(AlertSink):
    """Opt-in JSONL file sink for a monitoring agent that tails files."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def send(self, alert: SecurityAlert) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(alert), sort_keys=True) + "\n")


def _default_sink() -> AlertSink:
    log_file = os.environ.get("AUDIT_ALERT_LOG_FILE")
    if log_file:
        return FileAlertSink(log_file)
    return StdoutAlertSink()


_DEDUP_LOCK = Lock()
_LAST_SENT: dict[str, float] = {}


def _reset_dedup_state_for_tests() -> None:
    """Test-only helper -- production code never calls this."""
    with _DEDUP_LOCK:
        _LAST_SENT.clear()


def emit_security_alert(
    *,
    condition: str,
    severity: str,
    component: str,
    message: str,
    metadata: dict | None = None,
    sink: AlertSink | None = None,
    dedup_window_seconds: float = 300.0,
    _now: float | None = None,
) -> SecurityAlert | None:
    """Emit a security alert. Returns the SecurityAlert actually sent, or
    None if suppressed as a duplicate. Never raises."""
    if severity not in VALID_SEVERITIES:
        severity = "warning"  # fail safe on a caller typo -- never drop an alert over a bad enum value

    metadata = dict(metadata or {})
    alert = SecurityAlert(
        condition=condition,
        severity=severity,
        component=component,
        message=message,
        metadata=metadata,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    key = f"{component}:{condition}"
    now = _now if _now is not None else time.monotonic()
    is_recovery = condition.endswith("_recovered")

    with _DEDUP_LOCK:
        last = _LAST_SENT.get(key)
        if not is_recovery and last is not None and (now - last) < dedup_window_seconds:
            return None
        _LAST_SENT[key] = now

    try:
        (sink or _default_sink()).send(alert)
    except Exception as e:  # noqa: BLE001 -- alert-emission failure must never propagate to the caller
        print(f"[SECURITY-ALERT-EMISSION-FAILED] condition={condition} component={component} error={type(e).__name__}", file=sys.stderr, flush=True)

    return alert
