"""Add monitoring scheduling, history, and comparison metadata.

Revision ID: 20260916_day10_monitoring
Revises: 20260916_day7
Create Date: 2026-09-16 21:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '20260916_day10_monitoring'
down_revision = '20260916_day7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('monitoring_targets') as batch_op:
        batch_op.alter_column('last_checked_at', new_column_name='last_check_at')
        batch_op.add_column(sa.Column('schedule', sa.String(length=20), nullable=True, server_default='daily'))
        batch_op.add_column(sa.Column('last_scan_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('previous_scan_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('paused_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('failure_count', sa.Integer(), nullable=True, server_default='0'))
        batch_op.add_column(sa.Column('last_error', sa.String(length=255), nullable=True))
        batch_op.create_index(batch_op.f('ix_monitoring_targets_schedule'), ['schedule'], unique=False)
        batch_op.create_index(batch_op.f('ix_monitoring_targets_last_scan_id'), ['last_scan_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_monitoring_targets_previous_scan_id'), ['previous_scan_id'], unique=False)
        batch_op.create_unique_constraint('uq_monitoring_business_website', ['business_id', 'website_id'])

    op.execute("UPDATE monitoring_targets SET schedule = 'daily' WHERE schedule IS NULL")
    op.execute("UPDATE monitoring_targets SET failure_count = 0 WHERE failure_count IS NULL")
    op.execute("UPDATE monitoring_targets SET paused_at = NULL WHERE paused_at IS NULL")

    with op.batch_alter_table('monitoring_targets') as batch_op:
        batch_op.alter_column('schedule', nullable=False)
        batch_op.alter_column('failure_count', nullable=False)


def downgrade() -> None:
    with op.batch_alter_table('monitoring_targets') as batch_op:
        batch_op.drop_constraint('uq_monitoring_business_website', type_='unique')
        batch_op.drop_index(batch_op.f('ix_monitoring_targets_previous_scan_id'))
        batch_op.drop_index(batch_op.f('ix_monitoring_targets_last_scan_id'))
        batch_op.drop_index(batch_op.f('ix_monitoring_targets_schedule'))
        batch_op.drop_column('last_error')
        batch_op.drop_column('failure_count')
        batch_op.drop_column('paused_at')
        batch_op.drop_column('previous_scan_id')
        batch_op.drop_column('last_scan_id')
        batch_op.drop_column('schedule')
        batch_op.alter_column('last_check_at', new_column_name='last_checked_at')
