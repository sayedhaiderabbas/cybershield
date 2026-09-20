"""Initial CyberShield schema.

Revision ID: 20260916_initial
Revises: 
Create Date: 2026-09-16 16:50:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '20260916_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_id', 'users', ['id'])

    op.create_table(
        'businesses',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('owner_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('industry', sa.String(length=255), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('owner_id', 'name', name='uq_business_owner_name'),
    )
    op.create_index('ix_businesses_id', 'businesses', ['id'])
    op.create_index('ix_businesses_owner_id', 'businesses', ['owner_id'])

    op.create_table(
        'websites',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('business_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('normalized_url', sa.String(length=2048), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['business_id'], ['businesses.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('business_id', 'normalized_url', name='uq_business_url'),
    )
    op.create_index('ix_websites_business_id', 'websites', ['business_id'])
    op.create_index('ix_websites_hostname', 'websites', ['hostname'])
    op.create_index('ix_websites_id', 'websites', ['id'])
    op.create_index('ix_websites_normalized_url', 'websites', ['normalized_url'])

    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('website_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='queued'),
        sa.Column('scan_type', sa.String(length=50), nullable=False, server_default='baseline'),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('error_code', sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(['website_id'], ['websites.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scans_id', 'scans', ['id'])
    op.create_index('ix_scans_status', 'scans', ['status'])
    op.create_index('ix_scans_website_id', 'scans', ['website_id'])

    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('website_id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=25), nullable=False, server_default='open'),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.Column('references', sa.Text(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['website_id'], ['websites.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_findings_id', 'findings', ['id'])
    op.create_index('ix_findings_scan_id', 'findings', ['scan_id'])
    op.create_index('ix_findings_severity', 'findings', ['severity'])
    op.create_index('ix_findings_status', 'findings', ['status'])
    op.create_index('ix_findings_website_id', 'findings', ['website_id'])

    op.create_table(
        'reports',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('business_id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=25), nullable=False, server_default='draft'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('artifact_path', sa.String(length=1024), nullable=True),
        sa.ForeignKeyConstraint(['business_id'], ['businesses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_reports_business_id', 'reports', ['business_id'])
    op.create_index('ix_reports_id', 'reports', ['id'])

    op.create_table(
        'monitoring_targets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('business_id', sa.String(length=36), nullable=False),
        sa.Column('website_id', sa.String(length=36), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('interval_minutes', sa.Integer(), nullable=False, server_default='1440'),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_check_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['business_id'], ['businesses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['website_id'], ['websites.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_monitoring_targets_business_id', 'monitoring_targets', ['business_id'])
    op.create_index('ix_monitoring_targets_id', 'monitoring_targets', ['id'])

    op.create_table(
        'security_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('business_id', sa.String(length=36), nullable=True),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=25), nullable=False, server_default='info'),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('metadata', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['business_id'], ['businesses.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_security_events_business_id', 'security_events', ['business_id'])
    op.create_index('ix_security_events_event_type', 'security_events', ['event_type'])
    op.create_index('ix_security_events_id', 'security_events', ['id'])

    op.create_table(
        'subscriptions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('business_id', sa.String(length=36), nullable=False),
        sa.Column('plan_name', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=25), nullable=False, server_default='active'),
        sa.Column('current_period_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['business_id'], ['businesses.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_subscriptions_business_id', 'subscriptions', ['business_id'])
    op.create_index('ix_subscriptions_id', 'subscriptions', ['id'])


def downgrade() -> None:
    op.drop_index('ix_subscriptions_id', table_name='subscriptions')
    op.drop_index('ix_subscriptions_business_id', table_name='subscriptions')
    op.drop_table('subscriptions')

    op.drop_index('ix_security_events_id', table_name='security_events')
    op.drop_index('ix_security_events_event_type', table_name='security_events')
    op.drop_index('ix_security_events_business_id', table_name='security_events')
    op.drop_table('security_events')

    op.drop_index('ix_monitoring_targets_id', table_name='monitoring_targets')
    op.drop_index('ix_monitoring_targets_business_id', table_name='monitoring_targets')
    op.drop_table('monitoring_targets')

    op.drop_index('ix_reports_id', table_name='reports')
    op.drop_index('ix_reports_business_id', table_name='reports')
    op.drop_table('reports')

    op.drop_index('ix_findings_website_id', table_name='findings')
    op.drop_index('ix_findings_status', table_name='findings')
    op.drop_index('ix_findings_severity', table_name='findings')
    op.drop_index('ix_findings_scan_id', table_name='findings')
    op.drop_index('ix_findings_id', table_name='findings')
    op.drop_table('findings')

    op.drop_index('ix_scans_website_id', table_name='scans')
    op.drop_index('ix_scans_status', table_name='scans')
    op.drop_index('ix_scans_id', table_name='scans')
    op.drop_table('scans')

    op.drop_index('ix_websites_normalized_url', table_name='websites')
    op.drop_index('ix_websites_id', table_name='websites')
    op.drop_index('ix_websites_hostname', table_name='websites')
    op.drop_index('ix_websites_business_id', table_name='websites')
    op.drop_table('websites')

    op.drop_index('ix_businesses_owner_id', table_name='businesses')
    op.drop_index('ix_businesses_id', table_name='businesses')
    op.drop_table('businesses')

    op.drop_index('ix_users_id', table_name='users')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
