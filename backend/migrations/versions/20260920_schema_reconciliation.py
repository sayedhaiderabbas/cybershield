"""Reconcile current report, audit, and model-declared index schema.

Revision ID: 20260920_schema_reconciliation
Revises: 20260918_day14_audit
Create Date: 2026-09-20 16:55:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = '20260920_schema_reconciliation'
down_revision = '20260918_day14_audit'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add nullable columns first so existing report rows remain writable while
    # requested_by and report_type are backfilled from authoritative records.
    with op.batch_alter_table('reports') as batch_op:
        batch_op.add_column(sa.Column('requested_by', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('website_id', sa.String(length=36), nullable=True))
        batch_op.add_column(
            sa.Column(
                'report_type',
                sa.String(length=60),
                nullable=True,
                server_default='security_assessment',
            )
        )
        batch_op.add_column(sa.Column('generated_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('risk_score_snapshot', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('risk_model_version', sa.String(length=25), nullable=True))
        batch_op.add_column(sa.Column('report_metadata', sa.Text(), nullable=True))

    op.execute(
        sa.text(
            """
            UPDATE reports
            SET requested_by = (
                SELECT owner_id
                FROM businesses
                WHERE businesses.id = reports.business_id
            )
            WHERE requested_by IS NULL
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE reports
            SET report_type = 'security_assessment'
            WHERE report_type IS NULL
            """
        )
    )

    connection = op.get_bind()
    missing_requesters = connection.execute(
        sa.text('SELECT COUNT(*) FROM reports WHERE requested_by IS NULL')
    ).scalar_one()
    if missing_requesters:
        raise RuntimeError(
            'Cannot reconcile reports: existing rows have no owning business user.'
        )

    with op.batch_alter_table('reports') as batch_op:
        batch_op.alter_column(
            'requested_by',
            existing_type=sa.String(length=36),
            nullable=False,
        )
        batch_op.alter_column(
            'report_type',
            existing_type=sa.String(length=60),
            nullable=False,
            server_default='security_assessment',
        )
        batch_op.alter_column(
            'status',
            existing_type=sa.String(length=25),
            server_default='pending',
        )
        batch_op.create_foreign_key(
            'fk_reports_requested_by_users',
            'users',
            ['requested_by'],
            ['id'],
            ondelete='SET NULL',
        )
        batch_op.create_foreign_key(
            'fk_reports_website_id_websites',
            'websites',
            ['website_id'],
            ['id'],
            ondelete='SET NULL',
        )
        batch_op.create_index('ix_reports_requested_by', ['requested_by'], unique=False)
        batch_op.create_index('ix_reports_website_id', ['website_id'], unique=False)

    with op.batch_alter_table('findings') as batch_op:
        batch_op.create_index('ix_findings_category', ['category'], unique=False)

    with op.batch_alter_table('monitoring_targets') as batch_op:
        batch_op.create_index('ix_monitoring_targets_website_id', ['website_id'], unique=False)

    with op.batch_alter_table('security_events') as batch_op:
        batch_op.create_index('ix_security_events_created_at', ['created_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('security_events') as batch_op:
        batch_op.drop_index('ix_security_events_created_at')

    with op.batch_alter_table('monitoring_targets') as batch_op:
        batch_op.drop_index('ix_monitoring_targets_website_id')

    with op.batch_alter_table('findings') as batch_op:
        batch_op.drop_index('ix_findings_category')

    with op.batch_alter_table('reports') as batch_op:
        batch_op.drop_index('ix_reports_website_id')
        batch_op.drop_index('ix_reports_requested_by')
        batch_op.drop_constraint('fk_reports_website_id_websites', type_='foreignkey')
        batch_op.drop_constraint('fk_reports_requested_by_users', type_='foreignkey')
        batch_op.alter_column(
            'status',
            existing_type=sa.String(length=25),
            server_default='draft',
        )
        batch_op.drop_column('report_metadata')
        batch_op.drop_column('risk_model_version')
        batch_op.drop_column('risk_score_snapshot')
        batch_op.drop_column('generated_at')
        batch_op.drop_column('report_type')
        batch_op.drop_column('website_id')
        batch_op.drop_column('requested_by')
