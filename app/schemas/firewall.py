from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field, model_validator

class FirewallPolicyUpdate(BaseModel):
    enabled: bool
    default_incoming: str = Field(pattern='^(deny|reject)$')
    default_outgoing: str = Field(pattern='^(allow|deny)$')

class FirewallRuleCreate(BaseModel):
    action: str = Field(pattern='^(allow|deny)$')
    protocol: str = Field(pattern='^(tcp|udp|both)$')
    port_start: int = Field(ge=1, le=65535)
    port_end: int | None = Field(default=None, ge=1, le=65535)
    source_cidr: str | None = None
    source_cidrs: list[str] | None = Field(default=None, min_length=1, max_length=32)

    @model_validator(mode='after')
    def check_sources(self):
        from ipaddress import ip_network
        if self.source_cidrs is None and self.source_cidr is None:
            raise ValueError('source_cidr or source_cidrs required')
        sources=self.source_cidrs if self.source_cidrs is not None else [self.source_cidr]
        canon=[]
        for value in sources:
            if not isinstance(value,str) or not value.strip() or ',' in value or '\n' in value or '\r' in value:
                raise ValueError('invalid source CIDR')
            network=str(ip_network(value.strip(),strict=False))
            if network in canon: raise ValueError('duplicate source CIDR')
            canon.append(network)
        if self.source_cidr is not None and self.source_cidrs is not None and str(ip_network(self.source_cidr.strip(),strict=False))!=canon[0]:
            raise ValueError('source_cidr must equal first source_cidrs entry')
        self.source_cidr=canon[0]
        self.source_cidrs=canon
        return self
    purpose: str = Field(default='custom', pattern='^(web|dns|ssh|custom)$')
    enabled: bool = True
    sort_key: int = 100
    comment: str | None = Field(default=None,max_length=255)

class FirewallRuleUpdate(FirewallRuleCreate): pass

class FirewallRuleRead(FirewallRuleCreate):
    model_config=ConfigDict(from_attributes=True)
    id:int

class FirewallPolicyRead(FirewallPolicyUpdate):
    model_config=ConfigDict(from_attributes=True)
    id:int
    desired_revision:int
    applied_revision:int
    pending_revision:int|None
    rules:list[FirewallRuleRead]=[]

class FirewallApplyRequest(BaseModel):
    high_risk_confirmed: bool=False
    management_cidr: str|None=None
