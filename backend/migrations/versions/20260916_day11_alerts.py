"""Add alert model and lifecycle tracking.

Revision ID: 20260916_day11_alerts
Revises: 20260916_day10_monitoring
Create Date: 2026-09-16 23:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '20260916_day11_alerts'
down_revision = '20260916_day10_monitoring'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('business_id', sa.String(length=36), nullable=False),
        sa.Column('website_id', sa.String(length=36), nullable=True),
        sa.Column('monitoring_id', sa.String(length=36), nullable=True),
        sa.Column('scan_id', sa.String(length=36), nullable=True),
        sa.Column('finding_id', sa.String(length=36), nullable=True),
        sa.Column('alert_type', sa.String(length=80), nullable=False),
        sa.Column('severity', sa.String(length=25), nullable=False, server_default='info'),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=25), nullable=False, server_default='open'),
        sa.Column('deduplication_key', sa.String(length=255), nullable=False),
        sa.Column('alert_metadata', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.ForeignKeyConstraint(['business_id'], ['businesses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['website_id'], ['websites.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['monitoring_id'], ['monitoring_targets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('deduplication_key', name='uq_alert_deduplication_key'),
    )
    op.create_index(op.f('ix_alerts_business_id'), 'alerts', ['business_id'], unique=False)
    op.create_index(op.f('ix_alerts_website_id'), 'alerts', ['website_id'], unique=False)
    op.create_index(op.f('ix_alerts_monitoring_id'), 'alerts', ['monitoring_id'], unique=False)
    op.create_index(op.f('ix_alerts_scan_id'), 'alerts', ['scan_id'], unique=False)
    op.create_index(op.f('ix_alerts_finding_id'), 'alerts', ['finding_id'], unique=False)
    op.create_index(op.f('ix_alerts_alert_type'), 'alerts', ['alert_type'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_index(op.f('ix_alerts_created_at'), 'alerts', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_alerts_created_at'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_status'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_severity'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_alert_type'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_finding_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_scan_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_monitoring_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_website_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_business_id'), table_name='alerts')
    op.drop_table('alerts')
