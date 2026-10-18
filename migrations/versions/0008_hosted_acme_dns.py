"""Hosted ACME-DNS credential persistence.

Revision ID: 0008_hosted_acme_dns
Revises: 0007_acme_dns_delegation
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_hosted_acme_dns"
down_revision: Union[str, None] = "0007_acme_dns_delegation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ssl_acme_dns_credentials',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('certificate_id', sa.Integer(), sa.ForeignKey('ssl_certificates.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('server_url', sa.String(512), nullable=False),
        sa.Column('username_ciphertext', sa.Text(), nullable=False),
        sa.Column('password_ciphertext', sa.Text(), nullable=False),
        sa.Column('subdomain', sa.String(255), nullable=False),
        sa.Column('fulldomain', sa.String(512), nullable=False),
        sa.Column('challenge_domain', sa.String(512), nullable=False),
        sa.Column('verified', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('verified_at', sa.DateTime(timezone=True)),
        sa.Column('last_verification_error', sa.Text()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('ssl_acme_dns_credentials')
