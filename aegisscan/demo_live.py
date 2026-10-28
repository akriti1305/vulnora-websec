"""
demo_phase12.py -- Genuine Live End-to-End Demonstration (Phase 12 / 13)
========================================================================
A genuine, fully automated demonstration script for live college evaluation:
  1. Verifies / starts local AegisLab benchmark target.
  2. Executes real Scan #1 pipeline (crawling, detectors, active validation).
  3. Persists real findings and generates an Ed25519 signed scan passport.
  4. Cryptographically verifies original passport signature and canonical hash.
  5. Demonstrates tampering detection by altering finding severity in test copy.
  6. Executes real Scan #2 pipeline (in secure mode) against the target.
  7. Audits append-only SHA-256 hash-chain (H_2 = SHA256(rec_2 || H_1)).
  8. Reloads persisted Ed25519 keys from disk and re-verifies original passport.
"""

import sys
import os
import time
import json
import threading

_root = os.path.abspath(os.path.dirname(__file__))
_scan_dir = os.path.join(_root, "aegisscan")
_lab_dir = os.path.join(_root, "aegislab")
_lab_site = os.path.join(_lab_dir, "venv", "Lib", "site-packages")

for p in (_lab_site, _scan_dir, _lab_dir):
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

import httpx
from database import SessionLocal, engine, Base, init_db
from models import Target, Scan, Finding, ScanPassport, ScanChainRecord
from crypto import (
    get_key_manager,
    reset_key_manager,
    KeyManager,
    create_scan_passport,
    verify_scan_passport,
    get_or_create_scan_passport,
    record_scan_in_chain,
    verify_hash_chain,
    GENESIS_HASH,
)
from api.routes import start_scan, compare_scans


def ensure_aegislab_running(target_url="http://127.0.0.1:5001"):
    """Check if AegisLab is running; if not, spin it up in a daemon thread."""
    try:
        with httpx.Client(timeout=1.5) as client:
            resp = client.get(target_url)
            if resp.status_code in (200, 302, 404):
                print(f"[OK] AegisLab is active at {target_url}")
                return
    except Exception:
        pass

    print(f"[*] Starting local AegisLab Flask target in background thread...")
    import app as flask_app_mod
    lab_app = flask_app_mod.app

    def run_flask():
        lab_app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)

    t = threading.Thread(target=run_flask, daemon=True)
    t.start()

    # Wait for target readiness
    for _ in range(10):
        time.sleep(0.5)
        try:
            with httpx.Client(timeout=1.0) as client:
                r = client.get(target_url)
                if r.status_code in (200, 302, 404):
                    print(f"[OK] AegisLab successfully started and ready at {target_url}")
                    return
        except Exception:
            pass
    print("[!] Warning: Could not verify AegisLab responsiveness within 5 seconds.")


def run_live_demonstration():
    print("=" * 82)
    print("   AEGISSCAN 2.0 -- LIVE PIPELINE, PASSPORT & PROVENANCE CHAIN DEMONSTRATION")
    print("=" * 82)

    init_db(engine)
    db = SessionLocal()
    km = get_key_manager()
    ensure_aegislab_running()

    target_url = "http://127.0.0.1:5001"

    # Step 1: Active Ed25519 Signing Identity
    print("\n" + "-" * 82)
    print("STEP 1: SCANNER CRYPTOGRAPHIC IDENTITY (Ed25519)")
    print("-" * 82)
    pub_id = km.get_public_key_id()
    pub_hex = km.get_public_key_hex()
    pub_b64 = km.get_public_key_b64()
    print(f"  Public Key Identifier : {pub_id}")
    print(f"  Public Key (Hex)      : {pub_hex}")
    print(f"  Public Key (Base64)   : {pub_b64}")
    print(f"  Private Key Storage   : {km.private_key_path}")

    # Step 2: Genuine Scan #1 (Vulnerable Mode)
    print("\n" + "-" * 82)
    print("STEP 2: RUNNING GENUINE SCAN #1 (Vulnerable Mode Baseline)")
    print("-" * 82)
    # Ensure lab is in vulnerable mode
    try:
        with httpx.Client(timeout=3) as c:
            c.post(f"{target_url}/assistant/config", json={"secure_mode": False})
            c.post(f"{target_url}/assistant/reset")
    except Exception:
        pass

    scan1_res = start_scan({
        "target_url": target_url,
        "target_name": "AegisLab Baseline (Vulnerable)",
        "scan_mode": "deep"
    }, db=db)
    scan1_id = scan1_res["scan_id"]

    print(f"\n  [Scan #1 Result]")
    print(f"    Scan ID             : #{scan1_id}")
    print(f"    Target URL          : {scan1_res['target_url']}")
    print(f"    Scan Mode           : {scan1_res['scan_mode'].upper()}")
    print(f"    Pages Crawled       : {scan1_res['pages_crawled']}")
    print(f"    Total Findings      : {scan1_res['findings_count']}")
    print(f"    Active Vulns        : {scan1_res['active_vulnerabilities_count']}")
    print(f"    Verified Controls   : {scan1_res['verified_controls_count']}")
    print(f"    Informational       : {scan1_res['informational_count']}")
    print(f"    Report URL          : {scan1_res['report_url']}")

    # Step 3: Verify Original Scan #1 Passport
    print("\n" + "-" * 82)
    print("STEP 3: CRYPTOGRAPHIC PASSPORT VERIFICATION (Scan #1)")
    print("-" * 82)
    passport1, _ = get_or_create_scan_passport(db, scan_id=scan1_id)
    v1 = verify_scan_passport(passport1)

    print(f"  Passport Schema       : v{passport1['passport_schema_version']}")
    print(f"  Canonical Hash        : {passport1['canonical_payload_hash']}")
    print(f"  Digital Signature     : {passport1['digital_signature'][:40]}... ({len(passport1['digital_signature'])} chars)")
    print(f"  Verification Status   : {v1['status']}")
    print(f"  Signature Valid       : {v1['signature_valid']}")
    print(f"  Payload Hash Match    : {v1['hash_match']}")
    print(f"  Verification Result   : {v1['reason']}")
    assert v1["valid"] is True, "Scan #1 passport must verify successfully!"

    # Step 4: Tampering Detection Demonstration
    print("\n" + "-" * 82)
    print("STEP 4: TAMPERING ATTACK SIMULATION & SIGNATURE REJECTION")
    print("-" * 82)
    tampered_copy = json.loads(json.dumps(passport1))
    if tampered_copy["findings_evidence_digests"]:
        orig_sev = tampered_copy["findings_evidence_digests"][0]["severity"]
        tampered_copy["findings_evidence_digests"][0]["severity"] = "Low" if orig_sev == "Critical" else "Critical"
        print(f"  [Attack]: Altered finding #1 severity from '{orig_sev}' to '{tampered_copy['findings_evidence_digests'][0]['severity']}'")
    else:
        tampered_copy["findings_summary"]["total_findings"] = 0
        print(f"  [Attack]: Forged total findings count to 0")

    vtamper = verify_scan_passport(tampered_copy)
    print(f"  Verification Status   : {vtamper['status']}")
    print(f"  Is Valid              : {vtamper['valid']}")
    print(f"  Payload Hash Match    : {vtamper['hash_match']}")
    print(f"  Signature Valid       : {vtamper['signature_valid']}")
    print(f"  Tamper Detection Msg  : {vtamper['reason']}")
    assert vtamper["valid"] is False, "Tampered passport must be rejected!"
    print(f"  [PASS] Tampering successfully detected and rejected!")

    # Step 5: Execute Genuine Scan #2 (Fixed / Secure Mode)
    print("\n" + "-" * 82)
    print("STEP 5: RUNNING GENUINE SCAN #2 (Fixed / Secure Mode)")
    print("-" * 82)
    try:
        with httpx.Client(timeout=3) as c:
            r_reset = c.post(f"{target_url}/assistant/reset")
            r_cfg = c.post(f"{target_url}/assistant/config", json={"secure_mode": True})
            print(f"  [+] Switched AegisLab to Secure Mode: {r_cfg.json().get('state_config', {})}")
    except Exception as e:
        print(f"  [!] Failed to switch AegisLab to Secure Mode: {e}")

    scan2_res = start_scan({
        "target_url": target_url,
        "target_name": "AegisLab Rescan (Secure Mode)",
        "scan_mode": "deep"
    }, db=db)
    scan2_id = scan2_res["scan_id"]

    print(f"\n  [Scan #2 Result]")
    print(f"    Scan ID             : #{scan2_id}")
    print(f"    Target URL          : {scan2_res['target_url']}")
    print(f"    Scan Mode           : {scan2_res['scan_mode'].upper()}")
    print(f"    Active Vulns        : {scan2_res['active_vulnerabilities_count']}")
    print(f"    Verified Controls   : {scan2_res['verified_controls_count']}")
    print(f"    Report URL          : {scan2_res['report_url']}")

    # Step 6: Differential Vulnerable vs Fixed Comparison
    print("\n" + "-" * 82)
    print("STEP 6: DIFFERENTIAL COMPARISON (#" + str(scan1_id) + " vs #" + str(scan2_id) + ")")
    print("-" * 82)
    cmp_res = compare_scans(a=scan1_id, b=scan2_id, db=db)
    print(f"  Previously Confirmed  : {cmp_res['previously_confirmed_count']}")
    print(f"  Still Confirmed       : {cmp_res['still_confirmed_count']}")
    print(f"  Resolved After Retest : {cmp_res['resolved_after_retest_count']}")
    print(f"  Newly Detected        : {cmp_res['newly_detected_count']}")
    print(f"  Not Retested          : {cmp_res['not_retested_count']}")
    if cmp_res["resolved_after_retest"]:
        print(f"\n  Resolved Findings:")
        for rf in cmp_res["resolved_after_retest"][:3]:
            print(f"    - {rf['vulnerability_type']} at {rf['location']}")

    # Step 7: Audit 2-Record Hash Chain
    print("\n" + "-" * 82)
    print("STEP 7: APPEND-ONLY SHA-256 HASH-CHAIN INTEGRITY AUDIT")
    print("-" * 82)
    chain_audit = verify_hash_chain(db)
    records = db.query(ScanChainRecord).order_by(ScanChainRecord.sequence_number.asc()).all()
    print(f"  Total Chain Length    : {chain_audit['total_records']} record(s)")
    print(f"  Continuous Integrity  : {chain_audit['valid']}")
    print(f"  Ledger Status         : {chain_audit['status']}")
    print(f"  Ledger Head Hash (H_n): {chain_audit['chain_head']}")

    for rec in records[-2:]:
        print(f"    Seq #{rec.sequence_number}: Scan #{rec.scan_id} | Hash: {rec.chain_hash[:24]}... | Prev: {rec.previous_hash[:16]}...")

    assert len(records) >= 2, "Hash chain must contain at least two records!"
    assert chain_audit["valid"] is True, "Hash chain audit must be valid!"
    print("  [PASS] Two-record cryptographic hash-chain confirmed and continuous!")

    # Step 8: Persistence Across Application Restarts
    print("\n" + "-" * 82)
    print("STEP 8: KEY RELOAD ACROSS APPLICATION RESTARTS")
    print("-" * 82)
    reloaded_km = KeyManager(secrets_dir=km.secrets_dir)
    print(f"  First Key ID          : {pub_id}")
    print(f"  Reloaded Key ID       : {reloaded_km.get_public_key_id()}")
    assert reloaded_km.get_public_key_id() == pub_id, "Reloaded key ID must match original!"

    v_reloaded = verify_scan_passport(passport1, key_mgr=reloaded_km)
    print(f"  Re-verification Status: {v_reloaded['status']}")
    print(f"  Re-verification Valid : {v_reloaded['valid']}")
    assert v_reloaded["valid"] is True, "Original passport must verify with reloaded key!"
    print("  [PASS] Keys successfully reloaded and passport re-verified!")

    print("\n" + "=" * 82)
    print("   LIVE DEMONSTRATION COMPLETED SUCCESSFULLY -- ALL VERIFICATIONS PASSED")
    print("=" * 82)

    db.close()


if __name__ == "__main__":
    run_live_demonstration()
