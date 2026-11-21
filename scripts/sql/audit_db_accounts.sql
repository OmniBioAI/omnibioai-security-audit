-- Audit-pipeline MySQL accounts, for an administrator connected as
-- root@localhost over the MySQL server's own socket (docker exec into the
-- MySQL container), so neither migrations nor provisioning need a
-- network-reachable root account. See docs/DATABASE_ACCOUNTS.md.
--
-- Inputs: session variables set on the same connection before this file.
--   @audit_db                      target schema (e.g. 'omnibioai_audit'); required
--   @audit_migrator_password       creates/grants audit_migrator when set
--   @audit_writer_password         \
--   @audit_reader_password          > same accounts and grants as
--   @audit_maintenance_password    /  scripts/provision_audit_db_users.py
-- An account whose variable is NULL is skipped entirely. Passwords are only
-- used through QUOTE() in prepared statements and are never selected.
-- CREATE USER IF NOT EXISTS leaves an existing account's password unchanged;
-- every GRANT is idempotent.

-- Stops here, before any account change, when @audit_db is unset: the
-- statement text is then not valid SQL and the mysql client aborts on it.
SET @s = IF(@audit_db IS NULL OR @audit_db = '', 'audit_db must be set', 'DO 0');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @audit_db_q = CONCAT('`', REPLACE(@audit_db, '`', '``'), '`');

-- audit_migrator: runs Alembic migrations (alembic/versions/*). Exactly what
-- `alembic upgrade head` needs on this schema, verified against MySQL 8.0;
-- REFERENCES is not needed, DROP only for `alembic downgrade` (grant it for
-- that operation and revoke it afterwards). CREATE TRIGGER from a non-SUPER
-- account also needs log_bin_trust_function_creators=1 on the server while
-- binary logging is on (error 1419 otherwise).
SET @s = IF(@audit_migrator_password IS NULL, 'DO 0',
  CONCAT('CREATE USER IF NOT EXISTS ''audit_migrator''@''%'' IDENTIFIED BY ', QUOTE(@audit_migrator_password)));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@audit_migrator_password IS NULL, 'DO 0',
  CONCAT('GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, TRIGGER ON ', @audit_db_q, '.* TO ''audit_migrator''@''%'''));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- audit_writer: SELECT, INSERT on audit_events, quarantined_audit_events.
SET @s = IF(@audit_writer_password IS NULL, 'DO 0',
  CONCAT('CREATE USER IF NOT EXISTS ''audit_writer''@''%'' IDENTIFIED BY ', QUOTE(@audit_writer_password)));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@audit_writer_password IS NULL, 'DO 0',
  CONCAT('GRANT SELECT, INSERT ON ', @audit_db_q, '.`audit_events` TO ''audit_writer''@''%'''));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@audit_writer_password IS NULL, 'DO 0',
  CONCAT('GRANT SELECT, INSERT ON ', @audit_db_q, '.`quarantined_audit_events` TO ''audit_writer''@''%'''));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- audit_reader: SELECT on audit_events, quarantined_audit_events.
SET @s = IF(@audit_reader_password IS NULL, 'DO 0',
  CONCAT('CREATE USER IF NOT EXISTS ''audit_reader''@''%'' IDENTIFIED BY ', QUOTE(@audit_reader_password)));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@audit_reader_password IS NULL, 'DO 0',
  CONCAT('GRANT SELECT ON ', @audit_db_q, '.`audit_events` TO ''audit_reader''@''%'''));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@audit_reader_password IS NULL, 'DO 0',
  CONCAT('GRANT SELECT ON ', @audit_db_q, '.`quarantined_audit_events` TO ''audit_reader''@''%'''));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- audit_maintenance: SELECT, DELETE on both event tables; SELECT, INSERT,
-- DELETE on audit_legal_holds.
SET @s = IF(@audit_maintenance_password IS NULL, 'DO 0',
  CONCAT('CREATE USER IF NOT EXISTS ''audit_maintenance''@''%'' IDENTIFIED BY ', QUOTE(@audit_maintenance_password)));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@audit_maintenance_password IS NULL, 'DO 0',
  CONCAT('GRANT SELECT, DELETE ON ', @audit_db_q, '.`audit_events` TO ''audit_maintenance''@''%'''));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@audit_maintenance_password IS NULL, 'DO 0',
  CONCAT('GRANT SELECT, DELETE ON ', @audit_db_q, '.`quarantined_audit_events` TO ''audit_maintenance''@''%'''));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@audit_maintenance_password IS NULL, 'DO 0',
  CONCAT('GRANT SELECT, INSERT, DELETE ON ', @audit_db_q, '.`audit_legal_holds` TO ''audit_maintenance''@''%'''));
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @audit_migrator_password = NULL, @audit_writer_password = NULL,
    @audit_reader_password = NULL, @audit_maintenance_password = NULL;
