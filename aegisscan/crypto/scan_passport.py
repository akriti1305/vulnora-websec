"""
scan_passport.py -- Cryptographic Scan Passport Generation & Verification (Phase 12)
====================================================================================
Generates deterministic, cryptographically signed scan passports using Ed25519
digital signatures and canonical JSON serialization.

Key Features:
- Deterministic canonical JSON serialization (RFC 8785 compliant sorting).
- SHA-256 evidence digests with sensitive canary token sanitization.
- Self-contained verifiable passport artifact exportable as JSON.
- Independent signature verification against trusted public keys.
- Clear distinction between VALID, INVALID, and UNVERIFIABLE verification states.
- Explicit non-repudiation and provenance disclaimer.
"""

import re
import json
import base64
import hashlib
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime

from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import serialization

from models import Scan, Target, Finding, ScanPassport
from crypto.key_manager import get_key_manager, KeyManager

SCHEMA_VERSION = "2.0"
SCANNER_VERSION = "AegisScan 2.0"
PROVENANCE_DISCLAIMER = (
    "A cryptographic signature proves the origin and integrity of the signed scan record "
    "against tampering; it does not guarantee that every vulnerability finding is objectively correct."
)

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


def canonical_serialize(data: Any) -> bytes:
    """
    Deterministically serializes data into canonical JSON bytes.
    - Keys are lexicographically sorted at every depth level.
    - Compact separators (',', ':') with zero extraneous whitespace.
    - Explicit UTF-8 encoding.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str
    ).encode("utf-8")


def sanitize_evidence_text(evidence: Optional[str]) -> str:
    """
    Redacts sensitive secrets, credentials, and canary tokens before hashing/digesting.
    Never includes raw secret tokens or unmasked credentials in the passport digest.
    """
    if not evidence:
        return ""
    text = str(evidence)
    # Mask canary token variations
    text = re.sub(r"AEGIS_CANARY_[A-Za-z0-9_]+", "[REDACTED_CANARY_TOKEN]", text)
    # Mask common sensitive parameter patterns
    text = re.sub(r"(password|passwd|pwd|secret|token|api[_-]?key)=([^&\s]+)", r"\1=[REDACTED]", text, flags=re.IGNORECASE)
    return text


def build_finding_evidence_digest(finding: Any, fallback_id: int = 0) -> Dict[str, Any]:
    """
    Computes a canonical evidence digest dictionary for an individual finding.
    Supports both SQLAlchemy Finding model instances and raw finding dictionaries.
    """
    if isinstance(finding, dict):
        f_id = finding.get("finding_id") or finding.get("id") or fallback_id
        v_type = finding.get("vulnerability_type", "Unknown")
        sev = finding.get("severity", "Info")
        status = finding.get("status", "potential")
        loc = finding.get("location", "")
        ev = finding.get("evidence", "")
    else:
        f_id = getattr(finding, "id", None) or fallback_id
        v_type = getattr(finding, "vulnerability_type", "Unknown")
        sev = getattr(finding, "severity", "Info")
        status = getattr(finding, "status", "potential")
        loc = getattr(finding, "location", "")
        ev = getattr(finding, "evidence", "")

    sanitized_ev = sanitize_evidence_text(ev)
    ev_digest = hashlib.sha256(sanitized_ev.encode("utf-8")).hexdigest()

    return {
        "finding_id": int(f_id),
        "vulnerability_type": str(v_type),
        "severity": str(sev),
        "status": str(status),
        "location": str(loc),
        "evidence_digest": ev_digest,
    }


def create_scan_passport(
    scan_id: int,
    target_identifier: str,
    findings: List[Any],
    scan_started_at: Optional[Union[datetime, str]] = None,
    scan_finished_at: Optional[Union[datetime, str]] = None,
    scan_mode: str = "standard",
    key_mgr: Optional[KeyManager] = None,
) -> Dict[str, Any]:
    """
    Constructs and signs a canonical Scan Passport.

    Returns the complete passport dictionary including canonical_payload_hash
    and digital_signature.
    """
    km = key_mgr or get_key_manager()

    # Format timestamp
    if scan_finished_at:
        ts = scan_finished_at.isoformat() if isinstance(scan_finished_at, datetime) else str(scan_finished_at)
    elif scan_started_at:
        ts = scan_started_at.isoformat() if isinstance(scan_started_at, datetime) else str(scan_started_at)
    else:
        ts = datetime.utcnow().isoformat()

    # Build and sort findings digests deterministically
    raw_digests = [
        build_finding_evidence_digest(f, fallback_id=idx + 1)
        for idx, f in enumerate(findings)
    ]
    # Deterministic multi-key sort: type, location, severity, finding_id
    sorted_digests = sorted(
        raw_digests,
        key=lambda d: (
            d["vulnerability_type"],
            d["location"],
            SEVERITY_ORDER.get(d["severity"], 99),
            d["finding_id"]
        )
    )

    # Summaries
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    val_counts = {"confirmed": 0, "potential": 0, "not_reproducible": 0}
    type_counts: Dict[str, int] = {}

    for d in sorted_digests:
        sev = d["severity"]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        st = d["status"]
        val_counts[st] = val_counts.get(st, 0) + 1
        vt = d["vulnerability_type"]
        type_counts[vt] = type_counts.get(vt, 0) + 1

    # Overall risk determination
    if sev_counts.get("Critical", 0) > 0:
        overall_risk = "Critical"
    elif sev_counts.get("High", 0) > 0:
        overall_risk = "High"
    elif sev_counts.get("Medium", 0) > 0:
        overall_risk = "Medium"
    elif sev_counts.get("Low", 0) > 0:
        overall_risk = "Low"
    elif sev_counts.get("Info", 0) > 0:
        overall_risk = "Info"
    else:
        overall_risk = "Clean"

    # Construct the signed payload (signature and self-hash are excluded from signing)
    signed_payload = {
        "passport_schema_version": SCHEMA_VERSION,
        "scan_id": int(scan_id),
        "target_identifier": str(target_identifier),
        "scan_timestamp": ts,
        "scan_mode": str(scan_mode),
        "scanner_version": SCANNER_VERSION,
        "findings_summary": {
            "total_findings": len(sorted_digests),
            "severity_breakdown": sev_counts,
            "vulnerability_types": type_counts,
        },
        "findings_evidence_digests": sorted_digests,
        "validation_statuses": val_counts,
        "overall_risk_summary": overall_risk,
        "signing_algorithm": "Ed25519",
        "public_key_identifier": km.get_public_key_id(),
    }

    # Deterministic canonical serialization & signing
    canonical_bytes = canonical_serialize(signed_payload)
    canonical_hash = hashlib.sha256(canonical_bytes).hexdigest()
    raw_signature = km.sign(canonical_bytes)
    digital_signature = base64.b64encode(raw_signature).decode("ascii")

    return {
        **signed_payload,
        "canonical_payload_hash": canonical_hash,
        "digital_signature": digital_signature,
    }


def verify_scan_passport(
    passport: Dict[str, Any],
    trusted_public_key: Optional[Union[Any, str, bytes]] = None,
    key_mgr: Optional[KeyManager] = None
) -> Dict[str, Any]:
    """
    Independently verifies a Scan Passport:
    1. Validates schema version.
    2. Strips digital_signature and canonical_payload_hash.
    3. Recomputes canonical serialization and SHA-256 payload hash.
    4. Verifies the Ed25519 signature using the provided or registered public key.
    
    Returns structured verification result with status: 'VALID', 'INVALID', or 'UNVERIFIABLE'.
    """
    km = key_mgr or get_key_manager()

    if not isinstance(passport, dict):
        return {
            "status": "UNVERIFIABLE",
            "valid": False,
            "hash_match": False,
            "signature_valid": False,
            "reason": "Passport payload is not a valid JSON dictionary",
            "disclaimer": PROVENANCE_DISCLAIMER,
        }

    # 1. Check schema version
    schema_ver = passport.get("passport_schema_version")
    if schema_ver != SCHEMA_VERSION:
        return {
            "status": "UNVERIFIABLE",
            "valid": False,
            "hash_match": False,
            "signature_valid": False,
            "reason": f"Unsupported passport schema version: '{schema_ver}'. Expected: '{SCHEMA_VERSION}'",
            "disclaimer": PROVENANCE_DISCLAIMER,
        }

    # 2. Check required envelope fields
    signature_b64 = passport.get("digital_signature")
    claimed_hash = passport.get("canonical_payload_hash")

    if not signature_b64 or not claimed_hash:
        return {
            "status": "UNVERIFIABLE",
            "valid": False,
            "hash_match": False,
            "signature_valid": False,
            "reason": "Passport missing digital_signature or canonical_payload_hash",
            "disclaimer": PROVENANCE_DISCLAIMER,
        }

    # 3. Reconstruct signed payload without envelope
    payload_to_verify = {
        k: v for k, v in passport.items()
        if k not in ("digital_signature", "canonical_payload_hash")
    }

    # 4. Canonical re-serialization and hash calculation
    canonical_bytes = canonical_serialize(payload_to_verify)
    recalculated_hash = hashlib.sha256(canonical_bytes).hexdigest()

    if recalculated_hash != claimed_hash:
        return {
            "status": "INVALID",
            "valid": False,
            "scan_id": passport.get("scan_id"),
            "canonical_payload_hash": claimed_hash,
            "recalculated_hash": recalculated_hash,
            "hash_match": False,
            "signature_valid": False,
            "reason": (
                "Payload hash mismatch: Data has been tampered with or modified "
                f"(claimed {claimed_hash[:12]}... != recalculated {recalculated_hash[:12]}...)"
            ),
            "disclaimer": PROVENANCE_DISCLAIMER,
        }

    # 5. Decode digital signature
    try:
        raw_signature = base64.b64decode(signature_b64)
        if len(raw_signature) != 64:
            raise ValueError(f"Invalid signature byte length: {len(raw_signature)} != 64")
    except Exception as e:
        return {
            "status": "INVALID",
            "valid": False,
            "scan_id": passport.get("scan_id"),
            "canonical_payload_hash": claimed_hash,
            "recalculated_hash": recalculated_hash,
            "hash_match": True,
            "signature_valid": False,
            "reason": f"Malformed Ed25519 digital signature format: {str(e)}",
            "disclaimer": PROVENANCE_DISCLAIMER,
        }

    # 6. Resolve public key
    try:
        if trusted_public_key is not None:
            pub_key = km.resolve_public_key(trusted_public_key)
            pub_id = f"ed25519:{hashlib.sha256(pub_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()[:16]}"
        else:
            # Use local scanner public key; verify key ID matches
            pub_id = km.get_public_key_id()
            passport_pub_id = passport.get("public_key_identifier")
            if passport_pub_id and passport_pub_id != pub_id:
                return {
                    "status": "UNVERIFIABLE",
                    "valid": False,
                    "scan_id": passport.get("scan_id"),
                    "canonical_payload_hash": claimed_hash,
                    "recalculated_hash": recalculated_hash,
                    "hash_match": True,
                    "signature_valid": False,
                    "public_key_identifier": passport_pub_id,
                    "reason": (
                        f"Unrecognized public key '{passport_pub_id}'. "
                        f"Local scanner active public key is '{pub_id}'. "
                        "Verification requires the corresponding historical public key."
                    ),
                    "disclaimer": PROVENANCE_DISCLAIMER,
                }
            pub_key = km.get_public_key()
    except Exception as e:
        return {
            "status": "UNVERIFIABLE",
            "valid": False,
            "scan_id": passport.get("scan_id"),
            "canonical_payload_hash": claimed_hash,
            "recalculated_hash": recalculated_hash,
            "hash_match": True,
            "signature_valid": False,
            "reason": f"Failed to resolve public key: {str(e)}",
            "disclaimer": PROVENANCE_DISCLAIMER,
        }

    # 7. Verify Ed25519 digital signature
    sig_valid = km.verify(raw_signature, canonical_bytes, public_key=pub_key)
    if not sig_valid:
        return {
            "status": "INVALID",
            "valid": False,
            "scan_id": passport.get("scan_id"),
            "canonical_payload_hash": claimed_hash,
            "recalculated_hash": recalculated_hash,
            "hash_match": True,
            "signature_valid": False,
            "public_key_identifier": pub_id,
            "reason": "Digital signature verification failed. Signature does not match payload with this public key.",
            "disclaimer": PROVENANCE_DISCLAIMER,
        }

    return {
        "status": "VALID",
        "valid": True,
        "scan_id": passport.get("scan_id"),
        "canonical_payload_hash": claimed_hash,
        "recalculated_hash": recalculated_hash,
        "hash_match": True,
        "signature_valid": True,
        "public_key_identifier": pub_id,
        "signing_algorithm": passport.get("signing_algorithm", "Ed25519"),
        "reason": "Ed25519 digital signature and canonical SHA-256 payload hash verified successfully.",
        "disclaimer": PROVENANCE_DISCLAIMER,
    }


def save_scan_passport(db: Session, scan_id: int, passport: Dict[str, Any]) -> ScanPassport:
    """
    Persists a generated passport into the scan_passports database table.
    Overwrites or updates if a record already exists for the scan_id.
    """
    record = db.query(ScanPassport).filter(ScanPassport.scan_id == scan_id).first()
    passport_json_str = json.dumps(passport, indent=2)

    if record:
        record.passport_json = passport_json_str
        record.payload_hash = passport["canonical_payload_hash"]
        record.signature = passport["digital_signature"]
        record.public_key_id = passport["public_key_identifier"]
        record.created_at = datetime.utcnow()
    else:
        record = ScanPassport(
            scan_id=scan_id,
            passport_json=passport_json_str,
            payload_hash=passport["canonical_payload_hash"],
            signature=passport["digital_signature"],
            public_key_id=passport["public_key_identifier"],
            created_at=datetime.utcnow()
        )
        db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_or_create_scan_passport(
    db: Session,
    scan_id: int,
    key_mgr: Optional[KeyManager] = None
) -> Tuple[Dict[str, Any], ScanPassport]:
    """
    Retrieves the stored passport for a scan, or generates and signs a new passport
    if none exists yet.
    """
    record = db.query(ScanPassport).filter(ScanPassport.scan_id == scan_id).first()
    if record:
        passport_dict = json.loads(record.passport_json)
        return passport_dict, record

    # Generate on-the-fly from Scan and Target records
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found in database")
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    target_url = target.base_url if target else "Unknown"

    passport_dict = create_scan_passport(
        scan_id=scan.id,
        target_identifier=target_url,
        findings=scan.findings,
        scan_started_at=scan.started_at,
        scan_finished_at=scan.finished_at,
        scan_mode="standard",
        key_mgr=key_mgr
    )
    new_record = save_scan_passport(db, scan.id, passport_dict)
    return passport_dict, new_record
