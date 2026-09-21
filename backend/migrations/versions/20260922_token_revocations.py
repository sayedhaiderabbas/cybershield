"""Add server-side JWT token revocation storage.

Revision ID: 20260922_token_revocations
Revises: 20260920_schema_reconciliation
Create Date: 2026-09-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = '20260922_token_revocations'
down_revision = '20260920_schema_reconciliation'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'token_revocations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('jti', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('reason', sa.String(length=100), nullable=False, server_default='logout'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('jti'),
    )
    op.create_index('ix_token_revocations_id', 'token_revocations', ['id'], unique=False)
    op.create_index('ix_token_revocations_jti', 'token_revocations', ['jti'], unique=True)
    op.create_index('ix_token_revocations_user_id', 'token_revocations', ['user_id'], unique=False)
    op.create_index('ix_token_revocations_expires_at', 'token_revocations', ['expires_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_token_revocations_expires_at', table_name='token_revocations')
    op.drop_index('ix_token_revocations_user_id', table_name='token_revocations')
    op.drop_index('ix_token_revocations_jti', table_name='token_revocations')
    op.drop_index('ix_token_revocations_id', table_name='token_revocations')
    op.drop_table('token_revocations')
