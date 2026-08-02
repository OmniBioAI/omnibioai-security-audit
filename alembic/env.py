from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure the repo root is importable when alembic is invoked from there
# (alembic.ini sets prepend_sys_path = . for this).
from audit.config import AuditConfig
from db.base import Base

# Imported for its side effect of registering AuditEventRecord onto
# Base.metadata, so target_metadata below is complete for autogenerate.
import db.models  # noqa: F401,E402

# this is the Alembic Config object, which provides access to values within
# the .ini file in use.
config = context.config

# Drive the connection from the same config the worker uses, rather than a
# URL hardcoded in alembic.ini -- keeps migrations and the worker pointed at
# the same database with no separate config to drift. Only applied as a
# fallback: if a caller has already set sqlalchemy.url on this Config object
# (tests/test_migrations.py does this to point migrations at an isolated
# throwaway database), that value wins -- real `alembic` CLI usage never
# sets it, so this is a no-op for normal operation.
if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option("sqlalchemy.url", AuditConfig.DATABASE_URL)

# Interpret the config file for Python logging. disable_existing_loggers
# defaults to True, which would silently disable every logger not
# explicitly listed in alembic.ini's [loggers] section for the rest of the
# process -- explicit False avoids that footgun.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Emits SQL to stdout instead of executing against a live connection.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode, against a live connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
