"""Create the initial MailTrace schema."""

from alembic import op
import sqlalchemy as sa

revision = '0001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'user',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=190), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=30), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_attempts', sa.Integer(), nullable=False),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )
    op.create_index('ix_user_email', 'user', ['email'], unique=False)

    op.create_table(
        'case',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('case_number', sa.String(length=50), nullable=False),
        sa.Column('subject', sa.String(length=500), nullable=True),
        sa.Column('sender', sa.String(length=500), nullable=True),
        sa.Column('classification', sa.String(length=80), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('priority', sa.String(length=10), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=True),
        sa.Column('evidence_hash', sa.String(length=64), nullable=False),
        sa.Column('analysis_json', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_number'),
    )
    op.create_index('ix_case_classification', 'case', ['classification'], unique=False)
    op.create_index('ix_case_risk_score', 'case', ['risk_score'], unique=False)
    op.create_index('ix_case_status', 'case', ['status'], unique=False)
    op.create_index('ix_case_created_at', 'case', ['created_at'], unique=False)

    op.create_table(
        'case_note',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('author', sa.String(length=190), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['case.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_case_note_case_id', 'case_note', ['case_id'], unique=False)

    op.create_table(
        'indicator',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=30), nullable=True),
        sa.Column('value', sa.String(length=1000), nullable=True),
        sa.Column('risk', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['case.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_indicator_case_id', 'indicator', ['case_id'], unique=False)
    op.create_index('ix_indicator_kind', 'indicator', ['kind'], unique=False)

    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('actor', sa.String(length=190), nullable=True),
        sa.Column('action', sa.String(length=60), nullable=True),
        sa.Column('outcome', sa.String(length=20), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('detail', sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_log_at', 'audit_log', ['at'], unique=False)
    op.create_index('ix_audit_log_action', 'audit_log', ['action'], unique=False)


def downgrade():
    op.drop_index('ix_audit_log_action', table_name='audit_log')
    op.drop_index('ix_audit_log_at', table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_index('ix_indicator_kind', table_name='indicator')
    op.drop_index('ix_indicator_case_id', table_name='indicator')
    op.drop_table('indicator')
    op.drop_index('ix_case_note_case_id', table_name='case_note')
    op.drop_table('case_note')
    op.drop_index('ix_case_created_at', table_name='case')
    op.drop_index('ix_case_status', table_name='case')
    op.drop_index('ix_case_risk_score', table_name='case')
    op.drop_index('ix_case_classification', table_name='case')
    op.drop_table('case')
    op.drop_index('ix_user_email', table_name='user')
    op.drop_table('user')
