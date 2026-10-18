"""Multiple source CIDRs per logical firewall rule.

Revision ID: 0010_firewall_rule_sources
Revises: 0009_firewall_management
"""
from alembic import op
import sqlalchemy as sa
revision='0010_firewall_rule_sources'
down_revision='0009_firewall_management'
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('firewall_rule_sources',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('rule_id',sa.Integer(),sa.ForeignKey('firewall_rules.id',ondelete='CASCADE'),nullable=False),
        sa.Column('source_cidr',sa.String(64),nullable=False),
        sa.Column('sort_key',sa.Integer(),nullable=False),
        sa.UniqueConstraint('rule_id','source_cidr',name='uq_firewall_rule_source'),
        sa.UniqueConstraint('rule_id','sort_key',name='uq_firewall_source_order'))
    op.create_index('ix_firewall_rule_sources_rule_id','firewall_rule_sources',['rule_id'])
    conn=op.get_bind()
    conn.execute(sa.text('INSERT INTO firewall_rule_sources (rule_id,source_cidr,sort_key) SELECT id,source_cidr,0 FROM firewall_rules'))

def downgrade():
    conn=op.get_bind()
    # Downgrade keeps each rule's legacy first source; additional sources are lost.
    conn.execute(sa.text('UPDATE firewall_rules SET source_cidr=(SELECT source_cidr FROM firewall_rule_sources WHERE rule_id=firewall_rules.id ORDER BY sort_key LIMIT 1) WHERE EXISTS (SELECT 1 FROM firewall_rule_sources WHERE rule_id=firewall_rules.id)'))
    op.drop_index('ix_firewall_rule_sources_rule_id',table_name='firewall_rule_sources')
    op.drop_table('firewall_rule_sources')
