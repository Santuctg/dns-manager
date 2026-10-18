"""Initial DNS Manager schema.

Revision ID: 0001_initial
Revises: None
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_roles_name", "roles", ["name"])

    op.create_table(
        "permissions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_permissions_name", "permissions", ["name"])

    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("permission_id", sa.Integer(), sa.ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_role_id", "users", ["role_id"])

    op.create_table(
        "mappings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("upstream_scheme", sa.String(length=8), nullable=False),
        sa.Column("upstream_host", sa.String(length=255), nullable=False),
        sa.Column("upstream_port", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("websocket_enabled", sa.Boolean(), nullable=False),
        sa.Column("preserve_host", sa.Boolean(), nullable=False),
        sa.Column("tls_verify", sa.Boolean(), nullable=False),
        sa.Column("custom_timeout", sa.Integer(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("updated_by", sa.Integer(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("domain"),
    )
    op.create_index("ix_mappings_domain", "mappings", ["domain"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("object_type", sa.String(length=64), nullable=True),
        sa.Column("object_id", sa.String(length=128), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for name, columns in [
        ("ix_audit_logs_user_id", ["user_id"]),
        ("ix_audit_logs_username", ["username"]),
        ("ix_audit_logs_action", ["action"]),
        ("ix_audit_logs_object_type", ["object_type"]),
        ("ix_audit_logs_source_ip", ["source_ip"]),
        ("ix_audit_logs_status", ["status"]),
        ("ix_audit_logs_created_at", ["created_at"]),
    ]:
        op.create_index(name, "audit_logs", columns)

    op.create_table(
        "config_revisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("revision", sa.String(length=64), nullable=False),
        sa.Column("dnsmasq_config", sa.Text(), nullable=False),
        sa.Column("nginx_config", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.UniqueConstraint("revision"),
    )
    op.create_index("ix_config_revisions_revision", "config_revisions", ["revision"])
    op.create_index("ix_config_revisions_created_at", "config_revisions", ["created_at"])
    op.create_index("ix_config_revisions_status", "config_revisions", ["status"])

    op.create_table(
        "settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.UniqueConstraint("key"),
    )
    op.create_index("ix_settings_key", "settings", ["key"])


def downgrade() -> None:
    op.drop_index("ix_settings_key", table_name="settings")
    op.drop_table("settings")
    op.drop_index("ix_config_revisions_status", table_name="config_revisions")
    op.drop_index("ix_config_revisions_created_at", table_name="config_revisions")
    op.drop_index("ix_config_revisions_revision", table_name="config_revisions")
    op.drop_table("config_revisions")
    for name in [
        "ix_audit_logs_created_at",
        "ix_audit_logs_status",
        "ix_audit_logs_source_ip",
        "ix_audit_logs_object_type",
        "ix_audit_logs_action",
        "ix_audit_logs_username",
        "ix_audit_logs_user_id",
    ]:
        op.drop_index(name, table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_mappings_domain", table_name="mappings")
    op.drop_table("mappings")
    op.drop_index("ix_users_role_id", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
    op.drop_table("role_permissions")
    op.drop_index("ix_permissions_name", table_name="permissions")
    op.drop_table("permissions")
    op.drop_index("ix_roles_name", table_name="roles")
    op.drop_table("roles")
