"""
crypto/__init__.py -- Cryptographic Provenance & Scan Passports Package
========================================================================
Exposes KeyManager, scan passport generator/verifier, and SHA-256 hash-chaining.
"""

from crypto.key_manager import KeyManager, get_key_manager, reset_key_manager
from crypto.scan_passport import (
    create_scan_passport,
    verify_scan_passport,
    canonical_serialize,
    save_scan_passport,
    get_or_create_scan_passport,
    SCHEMA_VERSION,
    SCANNER_VERSION,
    PROVENANCE_DISCLAIMER,
)
from crypto.hash_chain import (
    compute_chain_hash,
    record_scan_in_chain,
    verify_hash_chain,
    GENESIS_HASH,
    HASH_CHAIN_LIMITATIONS,
)

__all__ = [
    "KeyManager",
    "get_key_manager",
    "reset_key_manager",
    "create_scan_passport",
    "verify_scan_passport",
    "canonical_serialize",
    "save_scan_passport",
    "get_or_create_scan_passport",
    "SCHEMA_VERSION",
    "SCANNER_VERSION",
    "PROVENANCE_DISCLAIMER",
    "compute_chain_hash",
    "record_scan_in_chain",
    "verify_hash_chain",
    "GENESIS_HASH",
    "HASH_CHAIN_LIMITATIONS",
]
