from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
# Import Base from your models
import os
import sys

# --- Start Path Modification ---
# Add the project root directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- End Path Modification ---

# --- Debugging Import ---
try:
    print(f"Attempting to import app.core.config from {project_root}")
    from app.core.config import settings
    print("Successfully imported settings:", settings.model_dump(exclude={'DATABASE_URL'})) # Print some settings safely
except Exception as e:
    print(f"ERROR importing app.core.config: {e}")
    import traceback
    traceback.print_exc()
# --- End Debugging Import ---

# Import the Base object from your models
from app.db.models import Base # Correct import

target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

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
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # --- Start Debug DB URL ---
    # Explicitly add the DATABASE_URL from settings to the config dict
    # Ensure settings are loaded correctly first (handled by the debug block above)
    db_url = settings.DATABASE_URL
    print(f"[DEBUG env.py] Using DATABASE_URL from settings: {db_url[:15]}...") # Print partial URL safely
    engine_config = config.get_section(config.config_ini_section, {})
    if not engine_config.get("sqlalchemy.url"):
        print("[DEBUG env.py] Injecting sqlalchemy.url from settings into engine_config.")
        engine_config["sqlalchemy.url"] = db_url
    else:
        print("[DEBUG env.py] sqlalchemy.url already present in engine_config.")
    # --- End Debug DB URL ---

    connectable = engine_from_config(
        engine_config, # Use the potentially modified dict
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
