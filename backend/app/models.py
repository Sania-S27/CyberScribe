# app/models.py
import uuid
from sqlalchemy import Column, Integer, String, TIMESTAMP, Boolean, ForeignKey, Text, Enum, DECIMAL, JSON, LargeBinary, DateTime, Index, text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class Tenant(Base):
    __tablename__ = "tenants"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    company_name = Column(String(255), nullable=False)
    subscription_status = Column(String(50), default="active", nullable=True)
    tech_stack = Column(Text, default="General IT Infrastructure")
    webhook_url = Column(String(500), nullable=True)
    auth_token = Column(String(255), nullable=True)
    kms_key_arn = Column(String(512), nullable=True)
    remediation_policy = Column(String(50), default="NOTIFY", nullable=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    users = relationship("User", back_populates="tenant")
    assets = relationship("AssetComponent", back_populates="tenant")
    matches = relationship("ThreatMatch", back_populates="tenant")
    containment_actions = relationship("ContainmentAction", back_populates="tenant")
    notifications = relationship("TenantNotification", back_populates="tenant")

class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default='analyst')
    is_mfa_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="users")

class AssetComponent(Base):
    __tablename__ = "_asset_components" 
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    software_name = Column(String(255), nullable=False)
    software_version = Column(String(100), nullable=False)
    cpe_uri = Column(String(255), nullable=True)
    environment = Column(String(50), default='production')
    
    encrypted_internal_ip = Column(LargeBinary(256), nullable=True)
    encrypted_host_name = Column(LargeBinary(256), nullable=True)
    encryption_iv = Column(LargeBinary(64), nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="assets")
    threat_matches = relationship("ThreatMatch", back_populates="asset")

class ThreatReport(Base):
    __tablename__ = "threat_reports"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_url = Column(String(768), unique=True, nullable=True)
    title = Column(String(1000), nullable=False)
    summary = Column(Text(16777215), nullable=True)
    severity = Column(Enum('low', 'medium', 'high', 'critical'), default='medium', nullable=False)
    stix_bundle = Column(JSON, nullable=True)
    cve_id = Column(String(255), nullable=True)
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    matches = relationship("ThreatMatch", back_populates="report")

class ThreatMatch(Base):
    __tablename__ = "_threat_matches"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    asset_component_id = Column(String(36), ForeignKey("_asset_components.id", ondelete="CASCADE"), nullable=True)
    threat_report_id = Column(String(36), ForeignKey("threat_reports.id", ondelete="CASCADE"), nullable=False)
    
  
    status = Column(Enum('OPEN', 'IN_PROGRESS', 'RESOLVED', 'unmitigated', 'mitigated', 'triaged', 'patched', 'active', name='threat_status'), default='OPEN')    
    ai_confidence_score = Column(DECIMAL(5, 2), nullable=False)
    ai_matching_reason = Column(Text(16777215), nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="matches")
    asset = relationship("AssetComponent", back_populates="threat_matches")
    report = relationship("ThreatReport", back_populates="matches")
    playbooks = relationship("MitigationPlaybook", back_populates="match")

class MitigationPlaybook(Base):
    __tablename__ = "mitigation_playbooks"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    threat_match_id = Column(String(36), ForeignKey("_threat_matches.id", ondelete="CASCADE"), nullable=False)
    platform_target = Column(String(100), nullable=False)
    remediation_script = Column(Text, nullable=False)
    is_automated_applicable = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())

    match = relationship("ThreatMatch", back_populates="playbooks")

class Admin(Base):
    __tablename__ = "admins"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="super_admin")
    created_at = Column(DateTime, server_default=func.now())


CONTAINMENT_ACTION_STATUSES = (
    'PENDING',
    'SIMULATED',
    'DISPATCHED',
    'RECEIVED',
    'APPLIED',
    'VERIFIED',
    'FAILED',
    'REJECTED',
    'EXPIRED',
    'ROLLED_BACK'
)

class ContainmentAction(Base):
    __tablename__ = "_containment_actions"
    __table_args__ = (
        Index(
            "uq_active_tenant_indicator",
            "tenant_id",
            "indicator_value",
            unique=True,
            sqlite_where=text("status IN ('PENDING', 'SIMULATED', 'DISPATCHED', 'RECEIVED', 'APPLIED', 'VERIFIED')"),
            postgresql_where=text("status IN ('PENDING', 'SIMULATED', 'DISPATCHED', 'RECEIVED', 'APPLIED', 'VERIFIED')")
        ),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    action_id = Column(String(64), unique=True, nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_report_id = Column(String(36), ForeignKey("threat_reports.id", ondelete="SET NULL"), nullable=True, index=True)
    threat_match_id = Column(String(36), ForeignKey("_threat_matches.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Target indicator specification
    indicator_value = Column(String(255), nullable=False, index=True)
    indicator_type = Column(String(50), default="ipv4", nullable=False)
    
    # Action type and deterministic policy decision
    action_type = Column(String(50), default="BLOCK_IPV4_DESTINATION", nullable=False)
    policy_decision = Column(String(50), nullable=False)  # QUALIFIED, REJECTED
    policy_rule = Column(String(100), nullable=True)
    
    # Deterministic state machine distinguishing simulation, SOAR delivery, real execution, and terminal states
    status = Column(
        Enum(*CONTAINMENT_ACTION_STATUSES, name='containment_action_status', native_enum=False),
        default='PENDING',
        nullable=False,
        index=True
    )
    
    # TTL and lifecycle verification timestamps
    ttl_seconds = Column(Integer, default=3600, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    applied_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    rolled_back_at = Column(DateTime, nullable=True)
    
    # Rule definition, execution telemetry, and safe diagnostics (secrets prohibited)
    rule_spec = Column(JSON, nullable=True)
    execution_output = Column(Text(16777215), nullable=True)
    error_message = Column(Text(16777215), nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="containment_actions")
    threat_report = relationship("ThreatReport")
    threat_match = relationship("ThreatMatch")
    audit_logs = relationship("ContainmentAuditLog", back_populates="action", cascade="all, delete-orphan")


class ContainmentAuditLog(Base):
    __tablename__ = "_containment_audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    action_id = Column(String(36), ForeignKey("_containment_actions.id", ondelete="CASCADE"), nullable=True, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Audit event taxonomy
    event_type = Column(String(50), nullable=False)
    actor = Column(String(100), default="AUTONOMOUS_POLICY_ENGINE", nullable=False)
    previous_status = Column(String(50), nullable=True)
    new_status = Column(String(50), nullable=True)
    
    # Safe diagnostics and policy decision reasons (secrets strictly stripped)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    action = relationship("ContainmentAction", back_populates="audit_logs")
    tenant = relationship("Tenant")


PATCH_PROPOSAL_STATUSES = (
    'PROPOSED',
    'APPROVED',
    'REJECTED',
    'SIMULATED',
    'APPLIED',
    'VERIFIED',
    'FAILED',
    'ROLLED_BACK'
)

class PatchProposal(Base):
    __tablename__ = "_patch_proposals"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    proposal_id = Column(String(64), unique=True, nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_match_id = Column(String(36), ForeignKey("_threat_matches.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_component_id = Column(String(36), ForeignKey("_asset_components.id", ondelete="SET NULL"), nullable=True, index=True)

    package_name = Column(String(255), nullable=False, index=True)
    current_version = Column(String(100), nullable=True)
    target_version = Column(String(100), nullable=True)
    package_manager = Column(String(50), default="dnf", nullable=False)
    priority = Column(String(50), default="HIGH", nullable=False)

    status = Column(
        Enum(*PATCH_PROPOSAL_STATUSES, name='patch_proposal_status', native_enum=False),
        default='PROPOSED',
        nullable=False,
        index=True
    )

    is_simulated = Column(Boolean, default=True, nullable=False)
    command_spec = Column(JSON, nullable=True)
    verification_spec = Column(JSON, nullable=True)

    execution_output = Column(Text(16777215), nullable=True)
    verification_output = Column(Text(16777215), nullable=True)
    error_message = Column(Text(16777215), nullable=True)

    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    applied_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")
    threat_match = relationship("ThreatMatch")
    asset = relationship("AssetComponent")
    audit_logs = relationship("PatchAuditLog", back_populates="proposal", cascade="all, delete-orphan")


class PatchAuditLog(Base):
    __tablename__ = "_patch_audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    proposal_id = Column(String(36), ForeignKey("_patch_proposals.id", ondelete="CASCADE"), nullable=True, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)

    event_type = Column(String(50), nullable=False)
    actor = Column(String(100), default="AUTONOMOUS_PATCH_ENGINE", nullable=False)
    previous_status = Column(String(50), nullable=True)
    new_status = Column(String(50), nullable=True)

    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    proposal = relationship("PatchProposal", back_populates="audit_logs")
    tenant = relationship("Tenant")


class TenantNotification(Base):
    __tablename__ = "_tenant_notifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    delivery_id = Column(String(64), unique=True, nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_report_id = Column(String(36), ForeignKey("threat_reports.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    channel = Column(String(50), default="WEBHOOK", nullable=False, index=True)  # WEBHOOK, EMAIL
    
    recipient_url = Column(String(500), nullable=True)
    status = Column(String(50), default="RECORDED_LOCALLY", nullable=False)  # DELIVERED, FAILED, RECORDED_LOCALLY
    status_code = Column(Integer, nullable=True)
    delivered = Column(Boolean, default=False, nullable=False)
    human_confirmed = Column(Boolean, default=False, nullable=False)
    
    cve_id = Column(String(255), nullable=True)
    affected_component = Column(String(255), nullable=True)
    installed_version = Column(String(100), nullable=True)
    fixed_version = Column(String(100), nullable=True)
    
    payload = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)

    tenant = relationship("Tenant")
    threat_report = relationship("ThreatReport")
