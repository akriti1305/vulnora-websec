"""
tests/test_provenance_passports.py -- Cryptographic Provenance & Scan Passport Tests (Phase 12)
================================================================================================
Comprehensive test suite covering:
  1. Key generation & export (PEM, Raw, Base64, Hex, KeyID)
  2. Key persistence across application restarts
  3. Passport creation & canary token sanitization
  4. Valid signature & canonical SHA-256 payload verification
  5. Tampered finding detection (hash & signature failure)
  6. Tampered timestamp / scan ID detection
  7. Invalid / corrupt signature rejection
  8. Wrong public key rejection
  9. Unsupported schema version rejection
 10. Hash-chain creation and sequence continuity (H_n = SHA256(rec_n || H_(n-1)))
 11. Hash-chain tampering detection
 12. Hash-chain missing record / sequence gap detection
 13. Database persistence & Scan model relationships
 14. API endpoints for passport retrieval, download, verify, public-key, and chain audit
"""

import sys
import os
import unittest
import json
import base64
import tempfile
import shutil
from datetime import datetime

# Path setups for aegisscan and aegislab
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_scan_dir = os.path.join(_root, "aegisscan")
_lab_dir = os.path.join(_root, "aegislab")
_lab_site = os.path.join(_lab_dir, "venv", "Lib", "site-packages")

for p in (_lab_site, _scan_dir, _lab_dir):
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from models import Target, Scan, Finding, ScanPassport, ScanChainRecord
from crypto.key_manager import KeyManager
from crypto.scan_passport import (
    create_scan_passport,
    verify_scan_passport,
    canonical_serialize,
    save_scan_passport,
    get_or_create_scan_passport,
    SCHEMA_VERSION,
    PROVENANCE_DISCLAIMER,
)
from crypto.hash_chain import (
    compute_chain_hash,
    record_scan_in_chain,
    verify_hash_chain,
    GENESIS_HASH,
)
from main import app


class TestProvenanceAndPassports(unittest.TestCase):
    """
    Test suite for Phase 12 Ed25519 digital signatures and SHA-256 hash chains.
    """

    def setUp(self):
        # Create an isolated temporary directory for keys
        self.temp_dir = tempfile.mkdtemp()
        self.km = KeyManager(secrets_dir=self.temp_dir)

        # Set up an in-memory SQLite database with StaticPool
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )
        self.TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSession()

        # Create baseline Target and Scan
        self.target = Target(name="AegisLab Test", base_url="http://127.0.0.1:5001")
        self.db.add(self.target)
        self.db.commit()

        self.scan = Scan(
            target_id=self.target.id,
            status="completed",
            started_at=datetime(2026, 10, 28, 22, 0, 0),
            finished_at=datetime(2026, 10, 28, 22, 5, 0),
        )
        self.db.add(self.scan)
        self.db.commit()

        # Add sample findings
        self.finding1 = Finding(
            scan_id=self.scan.id,
            vulnerability_type="SQL Injection",
            severity="Critical",
            status="confirmed",
            location="http://127.0.0.1:5001/login (field: username)",
            evidence="SQL syntax error detected in response body.",
            remediation_advice="Use parameterized queries."
        )
        self.finding2 = Finding(
            scan_id=self.scan.id,
            vulnerability_type="Indirect Prompt Injection",
            severity="Critical",
            status="confirmed",
            location="http://127.0.0.1:5001/assistant/query",
            evidence="Canary token AEGIS_CANARY_20261028_X7K9 disclosed in assistant response.",
            remediation_advice="Isolate untrusted context."
        )
        self.db.add_all([self.finding1, self.finding2])
        self.db.commit()

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_key_generation_and_export(self):
        """1. KeyManager generates valid Ed25519 keypair and exports all standard formats."""
        pub_id = self.km.get_public_key_id()
        self.assertTrue(pub_id.startswith("ed25519:"))
        self.assertEqual(len(pub_id), len("ed25519:") + 16)

        # PEM export
        pem = self.km.get_public_key_pem()
        self.assertIn("-----BEGIN PUBLIC KEY-----", pem)
        self.assertIn("-----END PUBLIC KEY-----", pem)

        # Raw bytes (Ed25519 public keys are exactly 32 bytes)
        raw = self.km.get_public_key_raw()
        self.assertEqual(len(raw), 32)

        # Hex export (64 lowercase hex characters)
        hex_key = self.km.get_public_key_hex()
        self.assertEqual(len(hex_key), 64)
        self.assertEqual(hex_key, raw.hex())

        # Base64 export (44 chars)
        b64_key = self.km.get_public_key_b64()
        self.assertEqual(len(b64_key), 44)
        self.assertEqual(base64.b64decode(b64_key), raw)

        # Confirm private key file exists on disk
        self.assertTrue(os.path.exists(self.km.private_key_path))
        self.assertTrue(os.path.exists(self.km.public_key_path))

    def test_key_persistence_across_restarts(self):
        """2. Keys persist across scanner restarts; same identity is maintained."""
        first_pub_id = self.km.get_public_key_id()
        first_pub_hex = self.km.get_public_key_hex()

        # Simulate restarting the application by instantiating a new KeyManager in the same directory
        reloaded_km = KeyManager(secrets_dir=self.temp_dir)
        self.assertEqual(reloaded_km.get_public_key_id(), first_pub_id)
        self.assertEqual(reloaded_km.get_public_key_hex(), first_pub_hex)

        # Verify a signature created by the first instance verifies with the reloaded instance
        test_payload = b"AegisScan Verification Challenge 2026"
        signature = self.km.sign(test_payload)
        self.assertTrue(reloaded_km.verify(signature, test_payload))

    def test_passport_creation_and_canary_sanitization(self):
        """3. Passport creation properly populates all fields and sanitizes canary tokens."""
        passport = create_scan_passport(
            scan_id=self.scan.id,
            target_identifier=self.target.base_url,
            findings=[self.finding1, self.finding2],
            scan_started_at=self.scan.started_at,
            scan_finished_at=self.scan.finished_at,
            scan_mode="standard",
            key_mgr=self.km
        )

        self.assertEqual(passport["passport_schema_version"], SCHEMA_VERSION)
        self.assertEqual(passport["scan_id"], self.scan.id)
        self.assertEqual(passport["target_identifier"], "http://127.0.0.1:5001")
        self.assertEqual(passport["signing_algorithm"], "Ed25519")
        self.assertEqual(passport["public_key_identifier"], self.km.get_public_key_id())
        self.assertIn("canonical_payload_hash", passport)
        self.assertIn("digital_signature", passport)

        # Verify findings evidence digest contains redacted canary token, not raw secret
        digests = passport["findings_evidence_digests"]
        self.assertEqual(len(digests), 2)
        for d in digests:
            self.assertIn("evidence_digest", d)
            self.assertEqual(len(d["evidence_digest"]), 64)

        # Raw passport string must not leak the raw canary value
        passport_str = json.dumps(passport)
        self.assertNotIn("AEGIS_CANARY_20261028_X7K9", passport_str)

    def test_valid_signature_verification(self):
        """4. Valid passport signature passes independent verification."""
        passport = create_scan_passport(
            scan_id=self.scan.id,
            target_identifier=self.target.base_url,
            findings=[self.finding1, self.finding2],
            scan_started_at=self.scan.started_at,
            scan_finished_at=self.scan.finished_at,
            key_mgr=self.km
        )

        res = verify_scan_passport(passport, key_mgr=self.km)
        self.assertEqual(res["status"], "VALID")
        self.assertTrue(res["valid"])
        self.assertTrue(res["hash_match"])
        self.assertTrue(res["signature_valid"])
        self.assertIn(PROVENANCE_DISCLAIMER, res["disclaimer"])

    def test_tampered_finding_detection(self):
        """5. Modifying any finding field causes verification failure (hash & signature reject)."""
        passport = create_scan_passport(
            scan_id=self.scan.id,
            target_identifier=self.target.base_url,
            findings=[self.finding1, self.finding2],
            scan_started_at=self.scan.started_at,
            scan_finished_at=self.scan.finished_at,
            key_mgr=self.km
        )

        # Attacker tries to downgrade severity of Critical SQLi to Low
        tampered = json.loads(json.dumps(passport))
        tampered["findings_evidence_digests"][0]["severity"] = "Low"

        res = verify_scan_passport(tampered, key_mgr=self.km)
        self.assertEqual(res["status"], "INVALID")
        self.assertFalse(res["valid"])
        self.assertFalse(res["hash_match"])
        self.assertIn("Payload hash mismatch", res["reason"])

    def test_tampered_timestamp_or_scan_id_detection(self):
        """6. Modifying metadata (timestamp or scan_id) is immediately detected."""
        passport = create_scan_passport(
            scan_id=self.scan.id,
            target_identifier=self.target.base_url,
            findings=[self.finding1],
            key_mgr=self.km
        )

        # Tamper timestamp
        tampered_ts = json.loads(json.dumps(passport))
        tampered_ts["scan_timestamp"] = "2099-01-01T00:00:00"
        res_ts = verify_scan_passport(tampered_ts, key_mgr=self.km)
        self.assertEqual(res_ts["status"], "INVALID")
        self.assertFalse(res_ts["valid"])

        # Tamper scan_id
        tampered_id = json.loads(json.dumps(passport))
        tampered_id["scan_id"] = 9999
        res_id = verify_scan_passport(tampered_id, key_mgr=self.km)
        self.assertEqual(res_id["status"], "INVALID")
        self.assertFalse(res_id["valid"])

    def test_invalid_signature_rejection(self):
        """7. Corrupted or invalid signatures are rejected even if hash is forged."""
        passport = create_scan_passport(
            scan_id=self.scan.id,
            target_identifier=self.target.base_url,
            findings=[self.finding1],
            key_mgr=self.km
        )

        corrupt = json.loads(json.dumps(passport))
        # Provide arbitrary 64-byte random signature
        bad_sig = base64.b64encode(b"\x00" * 64).decode("ascii")
        corrupt["digital_signature"] = bad_sig

        res = verify_scan_passport(corrupt, key_mgr=self.km)
        self.assertEqual(res["status"], "INVALID")
        self.assertFalse(res["valid"])
        self.assertTrue(res["hash_match"])  # hash matched, but signature failed
        self.assertFalse(res["signature_valid"])
        self.assertIn("verification failed", res["reason"])

    def test_wrong_public_key_rejection(self):
        """8. Verification with an unauthorized / untrusted public key is rejected."""
        passport = create_scan_passport(
            scan_id=self.scan.id,
            target_identifier=self.target.base_url,
            findings=[self.finding1],
            key_mgr=self.km
        )

        # Create an independent separate keypair
        other_dir = tempfile.mkdtemp()
        try:
            other_km = KeyManager(secrets_dir=other_dir)
            # Verify passing other public key explicitly
            res = verify_scan_passport(passport, trusted_public_key=other_km.get_public_key(), key_mgr=self.km)
            self.assertEqual(res["status"], "INVALID")
            self.assertFalse(res["signature_valid"])
        finally:
            shutil.rmtree(other_dir, ignore_errors=True)

    def test_unsupported_schema_version_rejection(self):
        """9. Passports with unknown schema versions are marked UNVERIFIABLE."""
        passport = create_scan_passport(
            scan_id=self.scan.id,
            target_identifier=self.target.base_url,
            findings=[],
            key_mgr=self.km
        )
        passport["passport_schema_version"] = "99.0"
        res = verify_scan_passport(passport, key_mgr=self.km)
        self.assertEqual(res["status"], "UNVERIFIABLE")
        self.assertFalse(res["valid"])
        self.assertIn("Unsupported passport schema version", res["reason"])

    def test_hash_chain_creation_and_continuity(self):
        """10. SHA-256 hash chain creates sequential blocks linking each scan to prior hash."""
        # Chain scan 1
        rec1 = record_scan_in_chain(self.db, scan_id=1, payload_hash="hash_for_scan_1")
        self.assertEqual(rec1.sequence_number, 1)
        self.assertEqual(rec1.previous_hash, GENESIS_HASH)
        expected_h1 = compute_chain_hash(1, 1, "hash_for_scan_1", GENESIS_HASH)
        self.assertEqual(rec1.chain_hash, expected_h1)

        # Chain scan 2
        rec2 = record_scan_in_chain(self.db, scan_id=2, payload_hash="hash_for_scan_2")
        self.assertEqual(rec2.sequence_number, 2)
        self.assertEqual(rec2.previous_hash, rec1.chain_hash)
        expected_h2 = compute_chain_hash(2, 2, "hash_for_scan_2", rec1.chain_hash)
        self.assertEqual(rec2.chain_hash, expected_h2)

        # Chain scan 3
        rec3 = record_scan_in_chain(self.db, scan_id=3, payload_hash="hash_for_scan_3")
        self.assertEqual(rec3.sequence_number, 3)
        self.assertEqual(rec3.previous_hash, rec2.chain_hash)

        # Audit entire chain
        audit = verify_hash_chain(self.db, key_mgr=self.km)
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["status"], "VERIFIED")
        self.assertEqual(audit["total_records"], 3)
        self.assertEqual(audit["chain_head"], rec3.chain_hash)
        self.assertEqual(len(audit["errors"]), 0)
        self.assertIsNotNone(audit["signed_checkpoint"])
        self.assertEqual(audit["signed_checkpoint"]["sequence_number"], 3)

    def test_hash_chain_tampering_detection(self):
        """11. Tampering with an intermediate record in the hash chain is detected."""
        rec1 = record_scan_in_chain(self.db, scan_id=10, payload_hash="valid_hash_10")
        rec2 = record_scan_in_chain(self.db, scan_id=11, payload_hash="valid_hash_11")
        rec3 = record_scan_in_chain(self.db, scan_id=12, payload_hash="valid_hash_12")

        # Tamper record 2's payload_hash directly in database
        rec2.payload_hash = "forged_malicious_payload_hash"
        self.db.commit()

        audit = verify_hash_chain(self.db, key_mgr=self.km)
        self.assertFalse(audit["valid"])
        self.assertEqual(audit["status"], "TAMPERED")
        self.assertGreater(len(audit["errors"]), 0)
        self.assertTrue(any("Chain hash tampering" in e for e in audit["errors"]))

    def test_hash_chain_missing_record_detection(self):
        """12. Deleting an intermediate record causes sequence and parent hash link failure."""
        rec1 = record_scan_in_chain(self.db, scan_id=20, payload_hash="valid_hash_20")
        rec2 = record_scan_in_chain(self.db, scan_id=21, payload_hash="valid_hash_21")
        rec3 = record_scan_in_chain(self.db, scan_id=22, payload_hash="valid_hash_22")

        # Delete intermediate record 2
        self.db.delete(rec2)
        self.db.commit()

        audit = verify_hash_chain(self.db, key_mgr=self.km)
        self.assertFalse(audit["valid"])
        self.assertEqual(audit["status"], "TAMPERED")
        self.assertTrue(any("Sequence gap" in e or "Hash link broken" in e for e in audit["errors"]))

    def test_database_persistence_and_relationships(self):
        """13. ScanPassport and ScanChainRecord models properly persist and link to Scan."""
        passport_dict, passport_record = get_or_create_scan_passport(self.db, scan_id=self.scan.id, key_mgr=self.km)
        chain_record = record_scan_in_chain(self.db, scan_id=self.scan.id, payload_hash=passport_dict["canonical_payload_hash"])

        # Reload scan in a fresh query
        reloaded_scan = self.db.query(Scan).filter(Scan.id == self.scan.id).first()
        self.assertIsNotNone(reloaded_scan.passport_record)
        self.assertIsNotNone(reloaded_scan.chain_record)
        self.assertEqual(reloaded_scan.passport_record.payload_hash, passport_dict["canonical_payload_hash"])
        self.assertEqual(reloaded_scan.chain_record.chain_hash, chain_record.chain_hash)

    def test_passport_api_endpoints_and_download(self):
        """14. API endpoints for passport JSON, download, verification, and public key work."""
        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db

        try:
            from fastapi.testclient import TestClient
            client = TestClient(app)

            # 1. Export public key
            pub_res = client.get("/api/passports/public-key")
            self.assertEqual(pub_res.status_code, 200)
            pub_data = pub_res.json()
            self.assertEqual(pub_data["signing_algorithm"], "Ed25519")
            self.assertIn("ed25519:", pub_data["public_key_identifier"])
            self.assertIn("-----BEGIN PUBLIC KEY-----", pub_data["public_key_pem"])

            # 2. Retrieve passport JSON
            pass_res = client.get(f"/api/scans/{self.scan.id}/passport")
            self.assertEqual(pass_res.status_code, 200)
            pass_data = pass_res.json()
            self.assertEqual(pass_data["scan_id"], self.scan.id)
            self.assertEqual(pass_data["passport_schema_version"], "2.0")

            # 3. Test ?download=true attachment header
            dl_res = client.get(f"/api/scans/{self.scan.id}/passport?download=true")
            self.assertEqual(dl_res.status_code, 200)
            self.assertIn("content-disposition", [k.lower() for k in dl_res.headers.keys()])
            content_disp = dl_res.headers.get("content-disposition", "")
            self.assertIn(f'attachment; filename="scan_{self.scan.id}_passport.json"', content_disp)

            # 4. Verify passport endpoint
            ver_res = client.get(f"/api/scans/{self.scan.id}/passport/verify")
            self.assertEqual(ver_res.status_code, 200)
            ver_data = ver_res.json()
            self.assertEqual(ver_data["status"], "VALID")
            self.assertTrue(ver_data["valid"])
            self.assertTrue(ver_data["signature_valid"])

            # 5. History hash-chain audit endpoint
            record_scan_in_chain(self.db, scan_id=self.scan.id, payload_hash=pass_data["canonical_payload_hash"])
            chain_res = client.get("/api/scans/history/verify")
            self.assertEqual(chain_res.status_code, 200)
            chain_data = chain_res.json()
            self.assertTrue(chain_data["valid"])
            self.assertEqual(chain_data["status"], "VERIFIED")
            self.assertIn("signed_checkpoint", chain_data)
        finally:
            app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
