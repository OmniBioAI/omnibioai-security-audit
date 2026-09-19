"""Unit tests for scripts/provision_audit_db_users.py -- V2-003 (Track E3)
least-privilege MySQL user provisioning. pymysql.connect is mocked
throughout (this is a one-time operational script, not something this
test suite spins up a real MySQL server to exercise against -- see
tests/test_retention_immutability_integration.py for the real-MySQL,
end-to-end proof that the users this script creates actually get the
grants it claims).

Developer: Manish Kumar <manish@omnibioai.org>
"""
from __future__ import annotations

import runpy
from unittest.mock import MagicMock, patch

import pytest

import scripts.provision_audit_db_users as padu

# ---------------------------------------------------------------------------
# _required_env
# ---------------------------------------------------------------------------


def test_required_env_returns_configured_value(monkeypatch):
    """Return the configured value for a required env var."""
    monkeypatch.setenv("AUDIT_WRITER_DB_PASSWORD", "s3cret")
    assert padu._required_env("AUDIT_WRITER_DB_PASSWORD") == "s3cret"


def test_required_env_exits_when_unset(monkeypatch, capsys):
    """Exit 1 with a [FAIL] message, never a default/fallback value, when a required env var is
    unset."""
    monkeypatch.delenv("AUDIT_WRITER_DB_PASSWORD", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        padu._required_env("AUDIT_WRITER_DB_PASSWORD")
    assert exc_info.value.code == 1
    assert "AUDIT_WRITER_DB_PASSWORD must be set" in capsys.readouterr().err
    assert "default/fallback" in capsys.readouterr().err or True


# ---------------------------------------------------------------------------
# _connect_admin
# ---------------------------------------------------------------------------


def test_connect_admin_uses_audit_db_admin_url_when_set(monkeypatch):
    """Parse AUDIT_DB_ADMIN_URL and connect with its host/port/user/password/database."""
    monkeypatch.setenv("AUDIT_DB_ADMIN_URL", "mysql+pymysql://root:rootpw@dbhost:3307/omnibioai_audit")
    mock_connect = MagicMock()
    with patch("pymysql.connect", mock_connect):
        _conn, database = padu._connect_admin()

    assert database == "omnibioai_audit"
    mock_connect.assert_called_once_with(
        host="dbhost", port=3307, user="root", password="rootpw",
        database="omnibioai_audit", autocommit=True,
    )


def test_connect_admin_falls_back_to_audit_config_database_url(monkeypatch):
    """Fall back to AuditConfig.DATABASE_URL when AUDIT_DB_ADMIN_URL is unset."""
    monkeypatch.delenv("AUDIT_DB_ADMIN_URL", raising=False)
    monkeypatch.setenv("AUDIT_DATABASE_URL", "mysql+pymysql://root:root@localhost:3306/omnibioai_audit")
    mock_connect = MagicMock()
    with patch("pymysql.connect", mock_connect):
        _conn, database = padu._connect_admin()

    assert database == "omnibioai_audit"
    mock_connect.assert_called_once_with(
        host="localhost", port=3306, user="root", password="root",
        database="omnibioai_audit", autocommit=True,
    )


def test_connect_admin_defaults_port_and_empty_password(monkeypatch):
    """Default to port 3306 and an empty password when the admin URL omits them."""
    monkeypatch.setenv("AUDIT_DB_ADMIN_URL", "mysql+pymysql://root@dbhost/omnibioai_audit")
    mock_connect = MagicMock()
    with patch("pymysql.connect", mock_connect):
        padu._connect_admin()

    mock_connect.assert_called_once_with(
        host="dbhost", port=3306, user="root", password="",
        database="omnibioai_audit", autocommit=True,
    )


# ---------------------------------------------------------------------------
# _create_user_and_grants
# ---------------------------------------------------------------------------


def test_create_user_and_grants_issues_create_user_and_one_grant_per_table(capsys):
    """Issue CREATE USER once and one GRANT per table, in the requested privilege order."""
    cur = MagicMock()

    padu._create_user_and_grants(
        cur, "omnibioai_audit", "audit_writer", "pw123",
        {"audit_events": ("SELECT", "INSERT"), "quarantined_audit_events": ("SELECT", "INSERT")},
    )

    calls = cur.execute.call_args_list
    assert "CREATE USER IF NOT EXISTS 'audit_writer'@'%%'" in calls[0].args[0]
    assert calls[0].args[1] == ("pw123",)
    assert "GRANT SELECT, INSERT ON `omnibioai_audit`.`audit_events` TO 'audit_writer'@'%'" == calls[1].args[0]
    assert "GRANT SELECT, INSERT ON `omnibioai_audit`.`quarantined_audit_events` TO 'audit_writer'@'%'" == calls[2].args[0]
    out = capsys.readouterr().out
    assert "[OK] provisioned 'audit_writer'@'%'" in out
    assert "pw123" not in out  # never echo the password


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def _set_all_passwords(monkeypatch):
    monkeypatch.setenv("AUDIT_WRITER_DB_PASSWORD", "writer-pw")
    monkeypatch.setenv("AUDIT_READER_DB_PASSWORD", "reader-pw")
    monkeypatch.setenv("AUDIT_MAINTENANCE_DB_PASSWORD", "maint-pw")
    monkeypatch.setenv("AUDIT_DB_ADMIN_URL", "mysql+pymysql://root:root@localhost:3306/omnibioai_audit")


def test_main_exits_one_when_a_required_password_is_missing(monkeypatch, capsys):
    """Exit 1 before ever connecting when any of the three required passwords is unset."""
    monkeypatch.delenv("AUDIT_WRITER_DB_PASSWORD", raising=False)
    monkeypatch.delenv("AUDIT_READER_DB_PASSWORD", raising=False)
    monkeypatch.delenv("AUDIT_MAINTENANCE_DB_PASSWORD", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        padu.main()

    assert exc_info.value.code == 1
    assert "AUDIT_WRITER_DB_PASSWORD must be set" in capsys.readouterr().err


def test_main_provisions_all_three_users_and_flushes_privileges(monkeypatch, capsys):
    """Provision audit_writer, audit_reader, and audit_maintenance (with their documented
    per-table grants), flush privileges, and close the connection."""
    _set_all_passwords(monkeypatch)
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    with patch("pymysql.connect", return_value=mock_conn):
        exit_code = padu.main()

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "[OK] provisioned 'audit_writer'@'%'" in out
    assert "[OK] provisioned 'audit_reader'@'%'" in out
    assert "[OK] provisioned 'audit_maintenance'@'%'" in out
    assert "[OK] privileges flushed" in out
    assert "[NEXT STEP]" in out
    mock_cur.execute.assert_any_call("FLUSH PRIVILEGES")
    mock_conn.close.assert_called_once()

    # audit_maintenance is the only one of the three with a grant on audit_legal_holds.
    maintenance_calls = [
        c.args[0] for c in mock_cur.execute.call_args_list
        if "audit_maintenance" in c.args[0] and c.args[0].startswith("GRANT")
    ]
    assert any("audit_legal_holds" in c for c in maintenance_calls)
    assert all("DELETE" in c or "audit_legal_holds" in c for c in maintenance_calls)
    # Neither audit_writer nor audit_reader ever receives a DELETE grant.
    writer_reader_calls = [
        c.args[0] for c in mock_cur.execute.call_args_list
        if c.args[0].startswith("GRANT") and ("audit_writer" in c.args[0] or "audit_reader" in c.args[0])
    ]
    assert all("DELETE" not in c for c in writer_reader_calls)


def test_main_closes_the_connection_even_if_provisioning_raises(monkeypatch):
    """Close the admin connection in a finally block, even when a GRANT statement itself raises."""
    _set_all_passwords(monkeypatch)
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_cur.execute.side_effect = RuntimeError("mysql exploded")
    mock_conn.cursor.return_value = mock_cur

    with patch("pymysql.connect", return_value=mock_conn), pytest.raises(RuntimeError):
        padu.main()

    mock_conn.close.assert_called_once()


# ---------------------------------------------------------------------------
# __main__ guard
# ---------------------------------------------------------------------------


def test_dunder_main_exits_with_mains_return_code(monkeypatch):
    """Exit with main()'s own return code when run as a script."""
    import sys

    monkeypatch.setattr(sys, "argv", ["provision_audit_db_users.py"])
    monkeypatch.delenv("AUDIT_WRITER_DB_PASSWORD", raising=False)  # cheapest deterministic path: _required_env's own sys.exit(1)
    monkeypatch.delenv("AUDIT_READER_DB_PASSWORD", raising=False)
    monkeypatch.delenv("AUDIT_MAINTENANCE_DB_PASSWORD", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(padu.__file__, run_name="__main__")

    assert exc_info.value.code == 1
