"""ACME DNS delegation persistence.

Revision ID: 0007_acme_dns_delegation
Revises: 0006_ssl_management
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007_acme_dns_delegation"
down_revision: Union[str, None] = "0006_ssl_management"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ssl_acme_delegations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("certificate_id", sa.Integer(), sa.ForeignKey("ssl_certificates.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("challenge_domain", sa.String(512), nullable=False),
        sa.Column("delegation_id", sa.String(32), nullable=False, unique=True),
        sa.Column("delegated_fqdn", sa.String(512), nullable=False, unique=True),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("last_verification_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ssl_acme_delegations_domain", "ssl_acme_delegations", ["domain"])


def downgrade() -> None:
    op.drop_index("ix_ssl_acme_delegations_domain", table_name="ssl_acme_delegations")
    op.drop_table("ssl_acme_delegations")
