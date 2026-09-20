"""Add finding intelligence fields.

Revision ID: 20260916_day7
Revises: 20260916_initial
Create Date: 2026-09-16 20:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '20260916_day7'
down_revision = '20260916_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.add_column(sa.Column('fingerprint', sa.String(length=255), nullable=True, server_default='manual'))
        batch_op.add_column(sa.Column('priority', sa.String(length=25), nullable=True, server_default='normal'))
        batch_op.add_column(sa.Column('occurrence_count', sa.Integer(), nullable=True, server_default='1'))

    op.execute("UPDATE findings SET fingerprint = COALESCE(fingerprint, CONCAT(CAST(website_id AS VARCHAR), ':', CAST(scan_id AS VARCHAR), ':', CAST(category AS VARCHAR))) WHERE fingerprint IS NULL")
    op.execute("UPDATE findings SET priority = COALESCE(priority, 'normal') WHERE priority IS NULL")
    op.execute("UPDATE findings SET occurrence_count = COALESCE(occurrence_count, 1) WHERE occurrence_count IS NULL")

    with op.batch_alter_table('findings') as batch_op:
        batch_op.alter_column('fingerprint', nullable=False)
        batch_op.alter_column('priority', nullable=False)
        batch_op.alter_column('occurrence_count', nullable=False)
        batch_op.create_index(batch_op.f('ix_findings_fingerprint'), ['fingerprint'], unique=False)
        batch_op.create_index(batch_op.f('ix_findings_priority'), ['priority'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_priority'))
        batch_op.drop_index(batch_op.f('ix_findings_fingerprint'))
        batch_op.drop_column('occurrence_count')
        batch_op.drop_column('priority')
        batch_op.drop_column('fingerprint')
