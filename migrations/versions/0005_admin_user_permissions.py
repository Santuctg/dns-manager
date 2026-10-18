"""Grant user administration and role view permissions to admin.

Revision ID: 0005_admin_user_permissions
Revises: 0004_revision_mapping_snapshot
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0005_admin_user_permissions'
down_revision: Union[str, None] = '0004_revision_mapping_snapshot'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NAMES = ('user.view','user.create','user.update','user.delete','role.view')


def upgrade() -> None:
    bind = op.get_bind()
    roles = sa.table('roles', sa.column('id', sa.Integer), sa.column('name', sa.String))
    permissions = sa.table('permissions', sa.column('id', sa.Integer), sa.column('name', sa.String))
    rp = sa.table('role_permissions', sa.column('role_id', sa.Integer), sa.column('permission_id', sa.Integer))
    admin_id = bind.execute(sa.select(roles.c.id).where(roles.c.name == 'admin')).scalar_one()
    perm_ids = dict(bind.execute(sa.select(permissions.c.name, permissions.c.id).where(permissions.c.name.in_(NAMES))).all())
    existing = set(bind.execute(sa.select(rp.c.permission_id).where(rp.c.role_id == admin_id)).scalars())
    for name in NAMES:
        pid = perm_ids[name]
        if pid not in existing:
            bind.execute(sa.insert(rp).values(role_id=admin_id, permission_id=pid))


def downgrade() -> None:
    bind = op.get_bind()
    roles = sa.table('roles', sa.column('id', sa.Integer), sa.column('name', sa.String))
    permissions = sa.table('permissions', sa.column('id', sa.Integer), sa.column('name', sa.String))
    rp = sa.table('role_permissions', sa.column('role_id', sa.Integer), sa.column('permission_id', sa.Integer))
    admin_id = bind.execute(sa.select(roles.c.id).where(roles.c.name == 'admin')).scalar_one()
    perm_ids = [row[0] for row in bind.execute(sa.select(permissions.c.id).where(permissions.c.name.in_(NAMES))).all()]
    bind.execute(sa.delete(rp).where(rp.c.role_id == admin_id, rp.c.permission_id.in_(perm_ids)))
