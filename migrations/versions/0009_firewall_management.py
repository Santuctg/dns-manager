"""Firewall management.
Revision ID: 0009_firewall_management
Revises: 0008_hosted_acme_dns
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision='0009_firewall_management'; down_revision='0008_hosted_acme_dns'; branch_labels=None; depends_on=None

def upgrade():
    op.create_table('firewall_policies',
      sa.Column('id',sa.Integer(),primary_key=True), sa.Column('enabled',sa.Boolean(),nullable=False,server_default=sa.false()),
      sa.Column('default_incoming',sa.String(16),nullable=False,server_default='deny'), sa.Column('default_outgoing',sa.String(16),nullable=False,server_default='allow'),
      sa.Column('desired_revision',sa.Integer(),nullable=False,server_default='0'), sa.Column('applied_revision',sa.Integer(),nullable=False,server_default='0'),
      sa.Column('pending_revision',sa.Integer()), sa.Column('last_applied_at',sa.DateTime(timezone=True)), sa.Column('last_applied_user_id',sa.Integer(),sa.ForeignKey('users.id')))
    op.create_table('firewall_rules', sa.Column('id',sa.Integer(),primary_key=True), sa.Column('policy_id',sa.Integer(),sa.ForeignKey('firewall_policies.id',ondelete='CASCADE'),nullable=False),
      sa.Column('action',sa.String(8),nullable=False),sa.Column('protocol',sa.String(8),nullable=False),sa.Column('port_start',sa.Integer(),nullable=False),sa.Column('port_end',sa.Integer()),
      sa.Column('source_cidr',sa.String(64),nullable=False),sa.Column('purpose',sa.String(16),nullable=False,server_default='custom'),sa.Column('enabled',sa.Boolean(),nullable=False,server_default=sa.true()),
      sa.Column('sort_key',sa.Integer(),nullable=False,server_default='100'),sa.Column('comment',sa.String(255)))
    op.create_index('ix_firewall_rules_policy_id','firewall_rules',['policy_id'])
    op.create_table('firewall_revisions',sa.Column('id',sa.Integer(),primary_key=True),sa.Column('revision',sa.Integer(),nullable=False),sa.Column('status',sa.String(24),nullable=False,server_default='draft'),sa.Column('snapshot_token',sa.String(96)),sa.Column('payload_json',sa.Text()),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False))
    bind=op.get_bind(); perms=sa.table('permissions',sa.column('id',sa.Integer),sa.column('name',sa.String),sa.column('description',sa.String)); roles=sa.table('roles',sa.column('id',sa.Integer),sa.column('name',sa.String)); rp=sa.table('role_permissions',sa.column('role_id',sa.Integer),sa.column('permission_id',sa.Integer))
    bind.execute(sa.insert(perms).values(name='firewall.manage',description='Manage host firewall'))
    pid=bind.execute(sa.select(perms.c.id).where(perms.c.name=='firewall.manage')).scalar_one(); rid=bind.execute(sa.select(roles.c.id).where(roles.c.name=='super_admin')).scalar_one(); bind.execute(sa.insert(rp).values(role_id=rid,permission_id=pid))
    bind.execute(sa.insert(sa.table('firewall_policies',sa.column('id'),sa.column('enabled'),sa.column('default_incoming'),sa.column('default_outgoing'),sa.column('desired_revision'),sa.column('applied_revision'))).values(id=1,enabled=False,default_incoming='deny',default_outgoing='allow',desired_revision=0,applied_revision=0))

def downgrade():
    bind=op.get_bind(); perms=sa.table('permissions',sa.column('id',sa.Integer),sa.column('name',sa.String),sa.column('description',sa.String)); rp=sa.table('role_permissions',sa.column('permission_id',sa.Integer)); ids=[r[0] for r in bind.execute(sa.select(perms.c.id).where(perms.c.name=='firewall.manage')).all()]
    if ids: bind.execute(sa.delete(rp).where(rp.c.permission_id.in_(ids))); bind.execute(sa.delete(perms).where(perms.c.id.in_(ids)))
    op.drop_table('firewall_revisions'); op.drop_index('ix_firewall_rules_policy_id',table_name='firewall_rules'); op.drop_table('firewall_rules'); op.drop_table('firewall_policies')
