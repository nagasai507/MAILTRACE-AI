from logging.config import fileConfig

from alembic import context
from flask import current_app

from app import create_app
from app.extensions import db

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

app = current_app if current_app else create_app()
with app.app_context():
    from app import models  # noqa: F401

target_metadata = db.metadata


def get_url():
    return app.config['SQLALCHEMY_DATABASE_URI']


def run_migrations_offline():
    context.configure(url=get_url(), target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={'paramstyle': 'named'})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    with db.engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
