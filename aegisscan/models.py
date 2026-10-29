"""
models.py — AegisScan Database Models (Tables)
===============================================
Each class here represents one table in the SQLite database.
SQLAlchemy reads these classes and creates the actual tables automatically.

Tables:
  - Target       : a website we want to scan
  - Scan         : one scan run against a target
  - Finding      : a single vulnerability found during a scan
  - EvaluationRun: the result of comparing a scan against known flaws

Think of each class as a "blueprint" for a database table.
Each Column(...) becomes one column in that table.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean,
    DateTime, ForeignKey, Text
)
from sqlalchemy.orm import relationship
from database import Base


# ---------------------------------------------------------------------------
# Table 1: Target
# ---------------------------------------------------------------------------
# A Target is a website we want to scan.
# Can be a local testbed or a verified external website.
# ---------------------------------------------------------------------------
class Target(Base):
    __tablename__ = "targets"

    id                  = Column(Integer, primary_key=True, index=True)
    name                = Column(String,  nullable=False)           # human-readable name
    base_url            = Column(String,  nullable=False, unique=True)  # the canonical URL
    target_type         = Column(String,  default="local")         # "local" or "external"
    is_verified         = Column(Boolean, default=False)           # verified ownership flag
    verified_at         = Column(DateTime, nullable=True)
    verification_method = Column(String,  nullable=True)          # "http" or "dns"
    created_at          = Column(DateTime, default=datetime.utcnow) # auto-set on creation

    # Relationships
    scans      = relationship("Scan", back_populates="target")
    challenges = relationship("VerificationChallenge", back_populates="target")
    grants     = relationship("AuthorizationGrant", back_populates="target")

    def __repr__(self):
        return f"<Target id={self.id} name='{self.name}' url='{self.base_url}' type='{self.target_type}' verified={self.is_verified}>"


# ---------------------------------------------------------------------------
# Table 2: Scan
# ---------------------------------------------------------------------------
# A Scan is one run of the scanner against a Target.
# Status values: "running" → "completed" or "failed"
# ---------------------------------------------------------------------------
class Scan(Base):
    __tablename__ = "scans"

    id                     = Column(Integer,  primary_key=True, index=True)
    target_id              = Column(Integer,  ForeignKey("targets.id"), nullable=False)
    started_at             = Column(DateTime, default=datetime.utcnow)
    finished_at            = Column(DateTime, nullable=True)   # None while still running
    status                 = Column(String,   default="running")  # running / completed / failed
    scan_mode              = Column(String,   default="deep")     # deep / basic / local_lab / external_basic / external_deep
    target_type            = Column(String,   default="local")    # local / external
    authorization_grant_id = Column(Integer,  nullable=True)
    requests_count         = Column(Integer,  default=0)
    duration_seconds       = Column(Float,    default=0.0)
    scan_policy_json       = Column(Text,     nullable=True)

    # Relationships
    target   = relationship("Target",       back_populates="scans")
    findings = relationship("Finding",      back_populates="scan")
    evaluations = relationship("EvaluationRun", back_populates="scan")
    passport_record = relationship("ScanPassport", uselist=False, back_populates="scan")
    chain_record    = relationship("ScanChainRecord", uselist=False, back_populates="scan")

    def __repr__(self):
        return f"<Scan id={self.id} target_id={self.target_id} mode='{self.scan_mode}' status='{self.status}'>"



# ---------------------------------------------------------------------------
# Table 3: Finding
# ---------------------------------------------------------------------------
# A Finding is one vulnerability discovered during a Scan.
#
# vulnerability_type : e.g. "SQL Injection", "Reflected XSS"
# status             : "confirmed" | "potential" | "not_reproducible"
# severity           : "Critical" | "High" | "Medium" | "Low" | "Info"
# location           : the URL + parameter where the flaw was found
# evidence           : what the scanner observed (e.g. SQL error text)
# remediation_advice : how to fix it (plain English)
# ---------------------------------------------------------------------------
class Finding(Base):
    __tablename__ = "findings"

    id                  = Column(Integer, primary_key=True, index=True)
    scan_id             = Column(Integer, ForeignKey("scans.id"), nullable=False)
    vulnerability_type  = Column(String, nullable=False)
    status              = Column(String, default="potential")   # confirmed / potential / not_reproducible
    severity            = Column(String, nullable=False)
    location            = Column(String, nullable=False)        # URL or parameter
    evidence            = Column(Text,   nullable=True)         # what was observed
    remediation_advice  = Column(Text,   nullable=True)         # how to fix it
    category            = Column(String, default="vulnerability") # vulnerability / verified_control / informational / not_reproducible

    # Relationship back to the Scan
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return (
            f"<Finding id={self.id} type='{self.vulnerability_type}' "
            f"severity='{self.severity}' status='{self.status}'>"
        )


# ---------------------------------------------------------------------------
# Table 4: EvaluationRun
# ---------------------------------------------------------------------------
# After a scan we compare findings against AegisLab's known ground-truth
# flaws and record accuracy metrics.
#
# true_positives  : findings that correctly matched a known flaw
# false_positives : findings that did NOT match any known flaw
# false_negatives : known flaws the scanner MISSED entirely
# true_negatives  : known benign controls correctly not flagged
# precision       : TP / (TP + FP)
# recall          : TP / (TP + FN)
# f1_score        : harmonic mean of precision and recall
# stage           : "pre_validation" or "post_validation"
# tp_list/fp_list/fn_list : JSON-encoded name lists for report display
# ---------------------------------------------------------------------------
class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id              = Column(Integer, primary_key=True, index=True)
    scan_id         = Column(Integer, ForeignKey("scans.id"), nullable=False)

    true_positives  = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    false_negatives = Column(Integer, default=0)
    true_negatives  = Column(Integer, default=0)

    precision       = Column(Float, default=0.0)
    recall          = Column(Float, default=0.0)
    f1_score        = Column(Float, default=0.0)

    stage           = Column(String, default="post_validation")

    tp_list         = Column(Text, default="[]")
    fp_list         = Column(Text, default="[]")
    fn_list         = Column(Text, default="[]")

    scan = relationship("Scan", back_populates="evaluations")

    def __repr__(self):
        return (
            f"<EvaluationRun scan_id={self.scan_id} stage={self.stage} "
            f"P={self.precision:.2f} R={self.recall:.2f} F1={self.f1_score:.2f}>"
        )


# ---------------------------------------------------------------------------
# Table 5: ScanPassport
# ---------------------------------------------------------------------------
# Cryptographically signed scan passport.
# Contains deterministic findings digests, payload hash, Ed25519 signature,
# and public key identifier.
# ---------------------------------------------------------------------------
class ScanPassport(Base):
    __tablename__ = "scan_passports"

    id             = Column(Integer, primary_key=True, index=True)
    scan_id        = Column(Integer, ForeignKey("scans.id"), nullable=False, unique=True)
    passport_json  = Column(Text,    nullable=False)
    payload_hash   = Column(String,  nullable=False, index=True)
    signature      = Column(String,  nullable=False)
    public_key_id  = Column(String,  nullable=False)
    created_at     = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="passport_record")

    def __repr__(self):
        return f"<ScanPassport scan_id={self.scan_id} hash='{self.payload_hash[:12]}...'>"


# ---------------------------------------------------------------------------
# Table 6: ScanChainRecord
# ---------------------------------------------------------------------------
# Append-only SHA-256 hash-chain linking completed scans sequentially.
# H_n = SHA256(canonical_record_n || H_(n-1))
# ---------------------------------------------------------------------------
class ScanChainRecord(Base):
    __tablename__ = "scan_chain_records"

    id              = Column(Integer, primary_key=True, index=True)
    sequence_number = Column(Integer, unique=True, nullable=False, index=True)
    scan_id         = Column(Integer, ForeignKey("scans.id"), nullable=False, unique=True)
    previous_hash   = Column(String,  nullable=False)
    payload_hash    = Column(String,  nullable=False)
    chain_hash      = Column(String,  nullable=False, index=True)
    timestamp       = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="chain_record")

    def __repr__(self):
        return f"<ScanChainRecord seq={self.sequence_number} scan_id={self.scan_id} hash='{self.chain_hash[:12]}...'>"


# ---------------------------------------------------------------------------
# Table 7: VerificationChallenge
# ---------------------------------------------------------------------------
# Cryptographically random domain control challenge.
# User hosts token at https://<target>/.well-known/aegisscan-verification.txt
# ---------------------------------------------------------------------------
class VerificationChallenge(Base):
    __tablename__ = "verification_challenges"

    id              = Column(Integer,  primary_key=True, index=True)
    target_id       = Column(Integer,  ForeignKey("targets.id"), nullable=False, index=True)
    challenge_token = Column(String,   nullable=False, index=True)
    challenge_type  = Column(String,   default="http")  # "http" or "dns"
    status          = Column(String,   default="pending")  # "pending", "verified", "expired", "revoked"
    created_at      = Column(DateTime, default=datetime.utcnow)
    expires_at      = Column(DateTime, nullable=False)
    verified_at     = Column(DateTime, nullable=True)
    last_checked_at = Column(DateTime, nullable=True)
    failure_reason  = Column(Text,     nullable=True)

    target = relationship("Target", back_populates="challenges")

    def __repr__(self):
        return f"<VerificationChallenge id={self.id} target_id={self.target_id} status='{self.status}'>"


# ---------------------------------------------------------------------------
# Table 8: AuthorizationGrant
# ---------------------------------------------------------------------------
# Formal authorization record establishing legal permission and scope bounds.
# ---------------------------------------------------------------------------
class AuthorizationGrant(Base):
    __tablename__ = "authorization_grants"

    id                     = Column(Integer,  primary_key=True, index=True)
    target_id              = Column(Integer,  ForeignKey("targets.id"), nullable=False, index=True)
    approved_hostname      = Column(String,   nullable=False)
    authorized_by          = Column(String,   nullable=False)
    scan_mode              = Column(String,   default="external_basic")  # "external_basic", "external_deep"
    allowed_paths          = Column(Text,     default='["/"]')
    excluded_paths         = Column(Text,     default='["/logout", "/signout", "/delete", "/admin"]')
    max_requests           = Column(Integer,  default=100)
    rate_limit_per_second  = Column(Float,    default=2.0)
    valid_from             = Column(DateTime, default=datetime.utcnow)
    expires_at             = Column(DateTime, nullable=False)
    operator_acknowledgment= Column(Text,     nullable=False)
    status                 = Column(String,   default="active")  # "active", "revoked", "expired"
    created_at             = Column(DateTime, default=datetime.utcnow)

    target = relationship("Target", back_populates="grants")

    def __repr__(self):
        return f"<AuthorizationGrant id={self.id} host='{self.approved_hostname}' mode='{self.scan_mode}' status='{self.status}'>"


# ---------------------------------------------------------------------------
# Table 9: AuditEvent
# ---------------------------------------------------------------------------
# Immutable append-only audit trail for target authorization events.
# ---------------------------------------------------------------------------
class AuditEvent(Base):
    __tablename__ = "audit_events"

    id         = Column(Integer,  primary_key=True, index=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String,   nullable=False, index=True)
    target_id  = Column(Integer,  nullable=True, index=True)
    scan_id    = Column(Integer,  nullable=True, index=True)
    operator   = Column(String,   default="system")
    details    = Column(Text,     nullable=True)

    def __repr__(self):
        return f"<AuditEvent id={self.id} event='{self.event_type}' at={self.timestamp}>"



