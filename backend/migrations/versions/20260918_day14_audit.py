"""Extend security events for append-only audit trail support.

Revision ID: 20260918_day14_audit
Revises: 20260917_day13_remediation
Create Date: 2026-09-18 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '20260918_day14_audit'
down_revision = '20260917_day13_remediation'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('security_events') as batch_op:
        batch_op.add_column(sa.Column('actor_user_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('action', sa.String(length=120), nullable=True, server_default='ACCESS'))
        batch_op.add_column(sa.Column('resource_type', sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column('resource_id', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('outcome', sa.String(length=20), nullable=True, server_default='SUCCESS'))
        batch_op.add_column(sa.Column('request_id', sa.String(length=120), nullable=True))
        batch_op.create_index(batch_op.f('ix_security_events_actor_user_id'), ['actor_user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_action'), ['action'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_resource_type'), ['resource_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_resource_id'), ['resource_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_outcome'), ['outcome'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_request_id'), ['request_id'], unique=False)
        batch_op.create_foreign_key('fk_security_events_actor_user_id_users', 'users', ['actor_user_id'], ['id'], ondelete='SET NULL')

    op.execute("UPDATE security_events SET action = 'ACCESS' WHERE action IS NULL")
    op.execute("UPDATE security_events SET outcome = 'SUCCESS' WHERE outcome IS NULL")
    op.execute("UPDATE security_events SET event_type = UPPER(event_type) WHERE event_type IS NOT NULL")

    with op.batch_alter_table('security_events') as batch_op:
        batch_op.alter_column('action', existing_type=sa.String(length=120), nullable=False)
        batch_op.alter_column('outcome', existing_type=sa.String(length=20), nullable=False)


def downgrade() -> None:
    with op.batch_alter_table('security_events') as batch_op:
        batch_op.drop_constraint('fk_security_events_actor_user_id_users', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_security_events_request_id'))
        batch_op.drop_index(batch_op.f('ix_security_events_outcome'))
        batch_op.drop_index(batch_op.f('ix_security_events_resource_id'))
        batch_op.drop_index(batch_op.f('ix_security_events_resource_type'))
        batch_op.drop_index(batch_op.f('ix_security_events_action'))
        batch_op.drop_index(batch_op.f('ix_security_events_actor_user_id'))
        batch_op.drop_column('request_id')
        batch_op.drop_column('outcome')
        batch_op.drop_column('resource_id')
        batch_op.drop_column('resource_type')
        batch_op.drop_column('action')
        batch_op.drop_column('actor_user_id')
