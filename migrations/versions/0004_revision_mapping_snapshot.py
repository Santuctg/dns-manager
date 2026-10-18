"""Store mapping snapshots on config revisions.

Revision ID: 0004_revision_mapping_snapshot
Revises: 0003_auth_sessions
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_revision_mapping_snapshot"
down_revision = "0003_auth_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("config_revisions") as batch_op:
        batch_op.add_column(sa.Column("mapping_snapshot", sa.Text(), nullable=True))
    op.execute("UPDATE config_revisions SET mapping_snapshot = '{}' WHERE mapping_snapshot IS NULL")
    with op.batch_alter_table("config_revisions") as batch_op:
        batch_op.alter_column("mapping_snapshot", existing_type=sa.Text(), nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("config_revisions") as batch_op:
        batch_op.drop_column("mapping_snapshot")
