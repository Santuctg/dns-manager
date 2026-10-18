from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base

def utcnow(): return datetime.now(timezone.utc)

class FirewallPolicy(Base):
    __tablename__='firewall_policies'
    id: Mapped[int]=mapped_column(Integer,primary_key=True,default=1)
    enabled: Mapped[bool]=mapped_column(Boolean,nullable=False,default=False)
    default_incoming: Mapped[str]=mapped_column(String(16),nullable=False,default='deny')
    default_outgoing: Mapped[str]=mapped_column(String(16),nullable=False,default='allow')
    desired_revision: Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    applied_revision: Mapped[int]=mapped_column(Integer,nullable=False,default=0)
    pending_revision: Mapped[int|None]=mapped_column(Integer,nullable=True)
    last_applied_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    last_applied_user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'),nullable=True)
    rules: Mapped[list['FirewallRule']]=relationship(back_populates='policy',cascade='all, delete-orphan',order_by='FirewallRule.sort_key')

class FirewallRule(Base):
    __tablename__='firewall_rules'
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    policy_id: Mapped[int]=mapped_column(ForeignKey('firewall_policies.id',ondelete='CASCADE'),nullable=False,default=1,index=True)
    action: Mapped[str]=mapped_column(String(8),nullable=False)
    protocol: Mapped[str]=mapped_column(String(8),nullable=False)
    port_start: Mapped[int]=mapped_column(Integer,nullable=False)
    port_end: Mapped[int|None]=mapped_column(Integer,nullable=True)
    source_cidr: Mapped[str]=mapped_column(String(64),nullable=False)
    purpose: Mapped[str]=mapped_column(String(16),nullable=False,default='custom')
    enabled: Mapped[bool]=mapped_column(Boolean,nullable=False,default=True)
    sort_key: Mapped[int]=mapped_column(Integer,nullable=False,default=100)
    comment: Mapped[str|None]=mapped_column(String(255),nullable=True)
    policy: Mapped[FirewallPolicy]=relationship(back_populates='rules')
    sources: Mapped[list['FirewallRuleSource']]=relationship(back_populates='rule', cascade='all, delete-orphan',order_by='FirewallRuleSource.sort_key',lazy='selectin')

class FirewallRuleSource(Base):
    __tablename__='firewall_rule_sources'
    __table_args__=(UniqueConstraint('rule_id','source_cidr',name='uq_firewall_rule_source'),UniqueConstraint('rule_id','sort_key',name='uq_firewall_source_order'))
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    rule_id: Mapped[int]=mapped_column(ForeignKey('firewall_rules.id',ondelete='CASCADE'),nullable=False,index=True)
    source_cidr: Mapped[str]=mapped_column(String(64),nullable=False)
    sort_key: Mapped[int]=mapped_column(Integer,nullable=False)
    rule: Mapped[FirewallRule]=relationship(back_populates='sources')

class FirewallRevision(Base):
    __tablename__='firewall_revisions'
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    revision: Mapped[int]=mapped_column(Integer,nullable=False,index=True)
    status: Mapped[str]=mapped_column(String(24),nullable=False,default='draft')
    snapshot_token: Mapped[str|None]=mapped_column(String(96),nullable=True)
    payload_json: Mapped[str|None]=mapped_column(Text,nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,default=utcnow)
