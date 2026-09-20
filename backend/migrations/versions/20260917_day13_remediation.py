"""Add remediation workflow and verification tracking.

Revision ID: 20260917_day13_remediation
Revises: 20260916_day11_alerts
Create Date: 2026-09-17 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '20260917_day13_remediation'
down_revision = '20260916_day11_alerts'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'finding_remediation',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('business_id', sa.String(length=36), nullable=False),
        sa.Column('website_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=25), nullable=False, server_default='open'),
        sa.Column('remediation_notes', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_requested_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_scan_id', sa.String(length=36), nullable=True),
        sa.Column('verification_result', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('(CURRENT_TIMESTAMP)')),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['business_id'], ['businesses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['website_id'], ['websites.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['verification_scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('finding_id', name='uq_finding_remediation_finding'),
    )
    op.create_index(op.f('ix_finding_remediation_finding_id'), 'finding_remediation', ['finding_id'], unique=False)
    op.create_index(op.f('ix_finding_remediation_business_id'), 'finding_remediation', ['business_id'], unique=False)
    op.create_index(op.f('ix_finding_remediation_website_id'), 'finding_remediation', ['website_id'], unique=False)
    op.create_index(op.f('ix_finding_remediation_user_id'), 'finding_remediation', ['user_id'], unique=False)
    op.create_index(op.f('ix_finding_remediation_status'), 'finding_remediation', ['status'], unique=False)
    op.create_index(op.f('ix_finding_remediation_verification_scan_id'), 'finding_remediation', ['verification_scan_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_finding_remediation_verification_scan_id'), table_name='finding_remediation')
    op.drop_index(op.f('ix_finding_remediation_status'), table_name='finding_remediation')
    op.drop_index(op.f('ix_finding_remediation_user_id'), table_name='finding_remediation')
    op.drop_index(op.f('ix_finding_remediation_website_id'), table_name='finding_remediation')
    op.drop_index(op.f('ix_finding_remediation_business_id'), table_name='finding_remediation')
    op.drop_index(op.f('ix_finding_remediation_finding_id'), table_name='finding_remediation')
    op.drop_table('finding_remediation')
