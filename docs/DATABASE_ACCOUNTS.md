# Audit database accounts

| Account | Used by | Privileges (schema `omnibioai_audit`) |
|---|---|---|
| `audit_writer`@`%` | worker runtime (`AUDIT_WRITER_DATABASE_URL`) | SELECT, INSERT on `audit_events`, `quarantined_audit_events` |
| `audit_reader`@`%` | API runtime (`AUDIT_READER_DATABASE_URL`) | SELECT on `audit_events`, `quarantined_audit_events` |
| `audit_maintenance`@`%` | retention / legal holds | SELECT, DELETE on both event tables; SELECT, INSERT, DELETE on `audit_legal_holds` |
| `audit_migrator`@`%` | `alembic upgrade` only | SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, TRIGGER on `omnibioai_audit`.* |
| `root`@`localhost` | creating the accounts above (once per environment) | over the server's socket only |

Nothing in this repo needs a network-reachable root account (`root`@`%`).

## audit_migrator

The privilege list is exactly what `alembic upgrade head` needs for
`0001`–`0006`, measured on MySQL 8.0.46 by removing one privilege at a time:

- needed: SELECT, INSERT, UPDATE, DELETE (all four for `alembic_version`),
  CREATE, ALTER, INDEX, TRIGGER;
- not needed: REFERENCES;
- DROP: only for `alembic downgrade` (`0005` drops `audit_legal_holds`).
  Grant it for that operation and revoke it afterwards.

Server setting: with binary logging on (the MySQL 8 default) and
`log_bin_trust_function_creators=0`, `CREATE TRIGGER` from an account without
SUPER fails with error 1419. Set `log_bin_trust_function_creators=1` while a
migration that creates triggers runs (`0005` does), instead of migrating as an
administrative account. Same requirement as omnibioai-auth #105.

Triggers created by a migration get `DEFINER=audit_migrator@%`. Keep the
account (and its SELECT on `audit_legal_holds`, which the `_no_delete`
trigger bodies read) as long as such triggers exist; MySQL refuses to fire a
trigger whose definer is missing. The identity checks inside the triggers use
`USER()`, not `CURRENT_USER()`, so the definer does not change who may delete.

Run migrations with the migrator's URL in `AUDIT_DATABASE_URL`, passed at run
time only (never in compose):

```bash
AUDIT_DATABASE_URL="mysql+pymysql://audit_migrator:$(cat ~/.config/omnibioai/audit_migrator.pass)@mysql:3306/omnibioai_audit" \
  docker exec -e AUDIT_DATABASE_URL -w /app omnibioai-studio-security-audit-worker-1 alembic upgrade head
```

## Creating the accounts without a network-reachable root

`scripts/sql/audit_db_accounts.sql` creates any of the four accounts with the
same grants as `scripts/provision_audit_db_users.py` (checked by
`tests/test_audit_db_accounts_sql_integration.py`). Feed it to `mysql` inside
the MySQL container, authenticated as `root`@`localhost` over the socket.
Passwords come from mode-600 files and travel only on stdin:

```bash
M=omnibioai-studio-mysql-1
b64() { base64 -w0 < "$1"; }      # password file -> SQL literal-safe text
{
  printf "SET @audit_db = 'omnibioai_audit';\n"
  printf "SET @audit_migrator_password = FROM_BASE64('%s');\n" "$(b64 ~/.config/omnibioai/audit_migrator.pass)"
  # add @audit_writer_password / @audit_reader_password / @audit_maintenance_password the same way when needed
  cat scripts/sql/audit_db_accounts.sql
} | docker exec -i "$M" sh -c 'f=$(mktemp); trap "rm -f $f" EXIT; umask 077
      printf "[client]\nuser=root\npassword=%s\n" "$(cat /run/secrets/mysql-root-password 2>/dev/null || printf %s "$MYSQL_ROOT_PASSWORD")" > "$f"
      mysql --defaults-extra-file="$f" --protocol=socket'
```

Password files must hold the password with no trailing newline. An account
whose variable is not set is skipped; `CREATE USER IF NOT EXISTS` leaves an
existing account's password unchanged.

`scripts/provision_audit_db_users.py` still works where an admin account is
reachable over TCP (`AUDIT_DB_ADMIN_URL`), e.g. a throwaway test server.
