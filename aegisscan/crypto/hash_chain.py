"""
hash_chain.py -- SHA-256 Append-Only Scan History Hash Chain (Phase 12)
========================================================================
Implements a tamper-evident cryptographic hash chain linking completed scans:
  H_n = SHA256( canonical_record_n || H_(n-1) )

Key Concepts:
- Genesis Hash: Explicit initial anchor '0' * 64.
- Sequence Continuity: Enforces 1, 2, 3... ordering without gaps.
- Tamper Evident: Any alteration to historical payload hashes, timestamps,
  or chain hashes breaks the chain downstream.
- Signed Chain Head: Emits a signed checkpoint of the latest chain head to mitigate
  local SQLite database rewrite risks.
"""

import hashlib
import base64
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session

from models import ScanChainRecord, Scan
from crypto.key_manager import get_key_manager, KeyManager
from crypto.scan_passport import canonical_serialize

GENESIS_HASH = "0" * 64
HASH_CHAIN_LIMITATIONS = (
    "A plain hash chain in a mutable SQLite database cannot prove that the entire history "
    "was never rewritten without external notarization, an append-only transparency log, "
    "or an externally archived signed checkpoint."
)


def compute_chain_hash(
    sequence_number: int,
    scan_id: int,
    payload_hash: str,
    previous_hash: str
) -> str:
    """
    Computes H_n = SHA256( canonical_serialize(record_fields) || previous_hash ).
    """
    record_payload = {
        "sequence_number": int(sequence_number),
        "scan_id": int(scan_id),
        "payload_hash": str(payload_hash),
        "previous_hash": str(previous_hash),
    }
    canonical_bytes = canonical_serialize(record_payload)
    chain_input = canonical_bytes + str(previous_hash).encode("utf-8")
    return hashlib.sha256(chain_input).hexdigest()


def record_scan_in_chain(
    db: Session,
    scan_id: int,
    payload_hash: str
) -> ScanChainRecord:
    """
    Appends a completed scan to the hash chain in database.
    If the scan is already chained, returns the existing record.
    """
    existing = db.query(ScanChainRecord).filter(ScanChainRecord.scan_id == scan_id).first()
    if existing:
        return existing

    # Find the latest chain record
    latest = (
        db.query(ScanChainRecord)
        .order_by(ScanChainRecord.sequence_number.desc())
        .first()
    )

    if latest is None:
        sequence_number = 1
        previous_hash = GENESIS_HASH
    else:
        sequence_number = latest.sequence_number + 1
        previous_hash = latest.chain_hash

    chain_hash = compute_chain_hash(
        sequence_number=sequence_number,
        scan_id=scan_id,
        payload_hash=payload_hash,
        previous_hash=previous_hash
    )

    record = ScanChainRecord(
        sequence_number=sequence_number,
        scan_id=scan_id,
        previous_hash=previous_hash,
        payload_hash=payload_hash,
        chain_hash=chain_hash,
        timestamp=datetime.utcnow()
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def verify_hash_chain(
    db: Session,
    key_mgr: Optional[KeyManager] = None
) -> Dict[str, Any]:
    """
    Audits the entire scan history hash chain:
    - Verifies sequence numbers are consecutive starting from 1.
    - Verifies previous_hash pointers match the prior record's chain_hash.
    - Recomputes SHA-256 chain hashes from canonical records.
    - Generates a signed checkpoint of the chain head.

    Returns structured verification results with errors list and status.
    """
    km = key_mgr or get_key_manager()
    records = (
        db.query(ScanChainRecord)
        .order_by(ScanChainRecord.sequence_number.asc())
        .all()
    )

    if not records:
        return {
            "valid": True,
            "status": "EMPTY",
            "total_records": 0,
            "chain_head": GENESIS_HASH,
            "genesis_hash": GENESIS_HASH,
            "errors": [],
            "signed_checkpoint": None,
            "limitations": HASH_CHAIN_LIMITATIONS,
        }

    errors: List[str] = []
    expected_seq = 1
    expected_prev_hash = GENESIS_HASH

    for rec in records:
        # Check sequence continuity
        if rec.sequence_number != expected_seq:
            errors.append(
                f"Sequence gap detected: Record scan_id={rec.scan_id} has sequence={rec.sequence_number}, "
                f"expected {expected_seq}."
            )

        # Check previous hash link
        if rec.previous_hash != expected_prev_hash:
            errors.append(
                f"Hash link broken at sequence {rec.sequence_number} (scan_id={rec.scan_id}): "
                f"stored previous_hash='{rec.previous_hash[:16]}...' != expected '{expected_prev_hash[:16]}...'."
            )

        # Recompute chain hash
        recalculated_hash = compute_chain_hash(
            sequence_number=rec.sequence_number,
            scan_id=rec.scan_id,
            payload_hash=rec.payload_hash,
            previous_hash=rec.previous_hash
        )

        if rec.chain_hash != recalculated_hash:
            errors.append(
                f"Chain hash tampering at sequence {rec.sequence_number} (scan_id={rec.scan_id}): "
                f"stored chain_hash='{rec.chain_hash[:16]}...' != recalculated '{recalculated_hash[:16]}...'."
            )

        expected_prev_hash = rec.chain_hash
        expected_seq = rec.sequence_number + 1

    latest_record = records[-1]
    is_valid = len(errors) == 0

    # Emit signed checkpoint for chain head if chain is healthy
    signed_checkpoint = None
    if is_valid:
        checkpoint_data = {
            "sequence_number": latest_record.sequence_number,
            "chain_head": latest_record.chain_hash,
            "scan_id": latest_record.scan_id,
            "total_records": len(records),
            "timestamp": latest_record.timestamp.isoformat() if latest_record.timestamp else datetime.utcnow().isoformat(),
        }
        cp_bytes = canonical_serialize(checkpoint_data)
        cp_sig = base64.b64encode(km.sign(cp_bytes)).decode("ascii")
        signed_checkpoint = {
            **checkpoint_data,
            "digital_signature": cp_sig,
            "signing_algorithm": "Ed25519",
            "public_key_identifier": km.get_public_key_id(),
        }

    return {
        "valid": is_valid,
        "status": "VERIFIED" if is_valid else "TAMPERED",
        "total_records": len(records),
        "chain_head": latest_record.chain_hash,
        "genesis_hash": GENESIS_HASH,
        "errors": errors,
        "signed_checkpoint": signed_checkpoint,
        "limitations": HASH_CHAIN_LIMITATIONS,
    }
