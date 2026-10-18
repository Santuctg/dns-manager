"""SSL management persistence.

Revision ID: 0006_ssl_management
Revises: 0005_admin_user_permissions
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0006_ssl_management'
down_revision: Union[str, None] = '0005_admin_user_permissions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('ssl_certificates',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('domain', sa.String(253), nullable=False),
        sa.Column('provider', sa.String(32), nullable=False),
        sa.Column('auto_renew', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('redirect_http', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('status', sa.String(32), nullable=False, server_default='NOT_ISSUED'),
        sa.Column('issuer', sa.String(255)), sa.Column('issued_at', sa.DateTime(timezone=True)), sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('last_renewal_at', sa.DateTime(timezone=True)), sa.Column('last_renewal_status', sa.String(32)), sa.Column('last_error', sa.Text()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False), sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('domain'))
    op.create_index('ix_ssl_certificates_domain','ssl_certificates',['domain'],unique=True)
    op.create_table('ssl_provider_credentials',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('certificate_id', sa.Integer(), sa.ForeignKey('ssl_certificates.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('provider', sa.String(32), nullable=False), sa.Column('token_ciphertext', sa.Text(), nullable=False), sa.Column('token_last4', sa.String(4)),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False), sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False))
    op.create_table('ssl_operations',
        sa.Column('id', sa.Integer(), primary_key=True), sa.Column('domain', sa.String(253), nullable=False), sa.Column('action', sa.String(32), nullable=False),
        sa.Column('status', sa.String(32), nullable=False), sa.Column('challenge_name', sa.String(512)), sa.Column('challenge_value', sa.Text()),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False), sa.Column('completed_at', sa.DateTime(timezone=True)), sa.Column('error_message', sa.Text()))
    op.create_index('ix_ssl_operations_domain','ssl_operations',['domain'])


def downgrade() -> None:
    op.drop_table('ssl_operations'); op.drop_table('ssl_provider_credentials'); op.drop_table('ssl_certificates')
