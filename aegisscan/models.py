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
    Column, Integer, String, Float,
    DateTime, ForeignKey, Text
)
from sqlalchemy.orm import relationship
from database import Base


# ---------------------------------------------------------------------------
# Table 1: Target
# ---------------------------------------------------------------------------
# A Target is a website we want to scan.
# Example: { id: 1, name: "AegisLab", base_url: "http://127.0.0.1:5001" }
# ---------------------------------------------------------------------------
class Target(Base):
    __tablename__ = "targets"

    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String,  nullable=False)           # human-readable name
    base_url   = Column(String,  nullable=False, unique=True)  # the URL to scan
    created_at = Column(DateTime, default=datetime.utcnow) # auto-set on creation

    # Relationship: one Target can have many Scans
    # "back_populates" lets us go the other direction: scan.target
    scans = relationship("Scan", back_populates="target")

    def __repr__(self):
        return f"<Target id={self.id} name='{self.name}' url='{self.base_url}'>"


# ---------------------------------------------------------------------------
# Table 2: Scan
# ---------------------------------------------------------------------------
# A Scan is one run of the scanner against a Target.
# Status values: "running" → "completed" or "failed"
# ---------------------------------------------------------------------------
class Scan(Base):
    __tablename__ = "scans"

    id          = Column(Integer,  primary_key=True, index=True)
    target_id   = Column(Integer,  ForeignKey("targets.id"), nullable=False)
    started_at  = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)   # None while still running
    status      = Column(String,   default="running")  # running / completed / failed

    # Relationships
    target   = relationship("Target",       back_populates="scans")
    findings = relationship("Finding",      back_populates="scan")
    evaluations = relationship("EvaluationRun", back_populates="scan")

    def __repr__(self):
        return f"<Scan id={self.id} target_id={self.target_id} status='{self.status}'>"


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

