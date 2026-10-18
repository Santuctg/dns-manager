"""Seed default roles and permissions.

Revision ID: 0002_seed_rbac
Revises: 0001_initial
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_seed_rbac"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PERMISSIONS = (
    "mapping.view",
    "mapping.create",
    "mapping.update",
    "mapping.delete",
    "config.apply",
    "config.rollback",
    "user.view",
    "user.create",
    "user.update",
    "user.delete",
    "role.view",
    "role.manage",
    "audit.view",
    "system.view",
    "system.manage",
    "backup.create",
    "backup.restore",
)

ROLE_PERMISSIONS = {
    "super_admin": set(PERMISSIONS),
    "admin": {
        "mapping.view",
        "mapping.create",
        "mapping.update",
        "mapping.delete",
        "config.apply",
        "audit.view",
        "system.view",
    },
    "viewer": {"mapping.view", "audit.view", "system.view"},
}

ROLE_DESCRIPTIONS = {
    "super_admin": "Full system administration",
    "admin": "Mapping administration and configuration apply access",
    "viewer": "Read-only access to mappings, system status, and audit logs",
}


def upgrade() -> None:
    connection = op.get_bind()
    permissions = sa.table(
        "permissions",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
    )
    roles = sa.table(
        "roles",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
    )
    role_permissions = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
    )

    op.bulk_insert(permissions, [{"name": name, "description": None} for name in PERMISSIONS])
    op.bulk_insert(
        roles,
        [{"name": name, "description": ROLE_DESCRIPTIONS[name]} for name in ROLE_PERMISSIONS],
    )

    permission_ids = dict(connection.execute(sa.select(permissions.c.name, permissions.c.id)).all())
    role_ids = dict(connection.execute(sa.select(roles.c.name, roles.c.id)).all())
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": role_ids[role_name], "permission_id": permission_ids[permission_name]}
            for role_name, permission_names in ROLE_PERMISSIONS.items()
            for permission_name in sorted(permission_names)
        ],
    )


def downgrade() -> None:
    connection = op.get_bind()
    role_permissions = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
    )
    roles = sa.table("roles", sa.column("id", sa.Integer), sa.column("name", sa.String))
    permissions = sa.table("permissions", sa.column("id", sa.Integer), sa.column("name", sa.String))

    role_ids = [
        row[0]
        for row in connection.execute(sa.select(roles.c.id).where(roles.c.name.in_(tuple(ROLE_PERMISSIONS)))).all()
    ]
    if role_ids:
        connection.execute(sa.delete(role_permissions).where(role_permissions.c.role_id.in_(role_ids)))
    connection.execute(sa.delete(roles).where(roles.c.name.in_(tuple(ROLE_PERMISSIONS))))
    connection.execute(sa.delete(permissions).where(permissions.c.name.in_(PERMISSIONS)))
