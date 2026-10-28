"""
api/routes.py -- AegisScan API Endpoints (Phase 5)
====================================================
Routes:
  POST /api/scans                        run full 5-detector pipeline
  GET  /api/scans/{id}                   scan status
  GET  /api/scans/{id}/findings          findings JSON
  GET  /api/scans/{id}/report            HTML security report
  POST /api/scans/{id}/evaluate          run evaluation harness (P/R/F1)
  GET  /api/scans/compare?a=N&b=M        compare two scans (fixed/new/persists)
  GET  /api/scans/compare/report?a=N&b=M HTML comparison report

Full scan pipeline (POST /api/scans):
  1. Crawl
  2. SQLi detector  -> validate (control request) -> score
  3. XSS detector   -> validate (control request) -> score
  4. IDOR detector  -> score directly
  5. Header detector -> score directly
  6. Cookie detector -> score directly
  7. Evaluation harness (pre + post validation)
  8. Save all findings + EvaluationRuns to DB
"""

import os
from urllib.parse import urlparse
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from database import get_db
from models import Target, Scan, Finding, EvaluationRun as EvaluationRunModel

from discovery import crawler
from detectors import sqli_detector, xss_detector, idor_detector
from scope import ScopeGuard
from detectors import header_detector, cookie_detector
from detectors import ai_discovery, prompt_injection_detector, tool_integrity_monitor
from detectors import context_taint_tracker, agent_permission_analyzer
import validation
import risk
import report
import evaluation as evaluator

router = APIRouter(prefix="/api", tags=["AegisScan"])


# ---------------------------------------------------------------------------
# Scope Guard: restrict scanning to authorized hosts only
# ---------------------------------------------------------------------------
DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

def get_allowed_hosts() -> set:
    """
    Returns the set of permitted hostnames/IPs for scanning.
    Always includes localhost, 127.0.0.1, and ::1 by default.
    Can be extended via the AEGISSCAN_ALLOWED_HOSTS environment variable
    (comma-separated list of hostnames or IPs).
    """
    allowed = set(DEFAULT_ALLOWED_HOSTS)
    env_hosts = os.environ.get("AEGISSCAN_ALLOWED_HOSTS", "").strip()
    if env_hosts:
        for host in env_hosts.split(","):
            cleaned = host.strip().lower()
            if cleaned:
                allowed.add(cleaned)
    return allowed


def validate_target_scope(target_url: str) -> None:
    """
    Scope Guard: Validates that the target URL resolves to an authorized host.
    Raises HTTPException(400) if target is outside allowed scope.
    """
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
    except Exception:
        hostname = None

    if not hostname:
        raise HTTPException(
            status_code=400,
            detail="Invalid target_url. Must include scheme and host (e.g. http://127.0.0.1:5001)."
        )

    allowed = get_allowed_hosts()
    if hostname.lower() not in allowed:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Scope violation: Scanning target host '{hostname}' is not permitted. "
                f"AegisScan is restricted to authorized targets only ({', '.join(sorted(allowed))}). "
                f"Scanning targets you do not own or lack explicit permission to test is prohibited."
            )
        )


# ---------------------------------------------------------------------------
# Helper: convert a ScoredFinding to a plain dict for DB + evaluation
# ---------------------------------------------------------------------------
def _scored_to_dict(sf) -> dict:
    return {
        "vulnerability_type": sf.vuln_type,
        "severity"          : sf.severity,
        "status"            : sf.status,
        "location"          : sf.location,
        "evidence"          : sf.evidence,
        "payload"           : sf.payload,
        "remediation"       : sf.remediation_advice,
    }


# ---------------------------------------------------------------------------
# POST /api/scans -- Run a full 5-detector scan
# ---------------------------------------------------------------------------
@router.post("/scans", summary="Start a new scan (all 5 detectors + evaluation)")
def start_scan(payload: dict, db: Session = Depends(get_db)):
    """
    Request body:
        { "target_url": "http://127.0.0.1:5001", "target_name": "AegisLab" }

    Runs the full pipeline and returns a JSON summary.
    View HTML report: GET /api/scans/{id}/report
    """
    target_url  = payload.get("target_url")
    target_name = payload.get("target_name", "Unnamed Target")

    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")

    # Scope guard enforcement
    validate_target_scope(target_url)

    target = db.query(Target).filter(Target.base_url == target_url).first()
    if not target:
        target = Target(name=target_name, base_url=target_url)
        db.add(target)
        db.commit()
        db.refresh(target)

    scan = Scan(target_id=target.id, status="running", started_at=datetime.utcnow())
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id

    print(f"\n[AegisScan] ===== Scan #{scan_id} started against {target_url} =====")

    try:
        # ---- Step 1: Crawl -----------------------------------------------
        print("[AegisScan] Step 1/6 -- Crawling...")
        disc = crawler.crawl(target_url)
        print(f"[AegisScan]   Pages={len(disc.visited_urls)} Forms={len(disc.all_forms)}")

        # ---- Step 2: SQLi ---------------------------------------------------
        print("[AegisScan] Step 2/6 -- SQL Injection...")
        sqli_raw    = sqli_detector.detect(disc)
        sqli_val    = validation.validate_sqli_findings(sqli_raw)
        sqli_scored = risk.score_sqli_findings(sqli_val)

        # ---- Step 3: XSS ---------------------------------------------------
        print("[AegisScan] Step 3/6 -- Reflected XSS...")
        xss_raw    = xss_detector.detect(disc)
        xss_val    = validation.validate_xss_findings(xss_raw)
        xss_scored = risk.score_xss_findings(xss_val)

        # ---- Step 4: IDOR --------------------------------------------------
        print("[AegisScan] Step 4/6 -- IDOR...")
        idor_raw    = idor_detector.detect(disc)
        idor_scored = risk.score_idor_findings(idor_raw)

        # ---- Step 5: Headers -----------------------------------------------
        print("[AegisScan] Step 5/6 -- Security Headers...")
        hdr_raw    = header_detector.detect(disc)
        hdr_scored = risk.score_header_findings(hdr_raw)

        # ---- Step 6: Cookies -----------------------------------------------
        print("[AegisScan] Step 6/8 -- Cookie flags...")
        ck_raw    = cookie_detector.detect(disc)
        ck_scored = risk.score_cookie_findings(ck_raw)

        # ---- Step 7: AI Feature & Manifest Discovery (Phase 8) -------------
        print("[AegisScan] Step 7/8 -- AI Feature & Manifest Discovery...")
        scan_mode = payload.get("scan_mode", "deep").lower()
        ai_disc = ai_discovery.detect_ai_features(disc, target_url, scan_mode=scan_mode)

        # ---- Step 8: Indirect Prompt Injection & Canary Validation (Phase 9)
        print("[AegisScan] Step 8/9 -- Indirect Prompt Injection & Canary Validation...")
        ai_prompt_findings = prompt_injection_detector.detect_indirect_prompt_injection(disc, ai_disc)

        # ---- Step 9: Tool Integrity & Anti-Rug-Pull Monitor (Phase 10) ------
        print("[AegisScan] Step 9/10 -- Tool Integrity & Anti-Rug-Pull Verification...")
        guard = ScopeGuard()
        tool_integrity_res = tool_integrity_monitor.verify_tool_integrity(
            ai_discovery_result=ai_disc,
            target_base_url=target_url,
            scan_mode=scan_mode,
            scope_guard=guard
        )
        tool_integrity_findings = tool_integrity_res.findings

        # ---- Step 10: Context Taint Tracking & Excessive Agency (Phase 11) ---
        print("[AegisScan] Step 10/10 -- Context Taint Tracking & Excessive Agency Analysis...")
        perm_res = agent_permission_analyzer.analyze_agent_permissions(
            ai_discovery_result=ai_disc,
            target_base_url=target_url,
            scan_mode=scan_mode,
            scope_guard=guard,
            prompt_findings=ai_prompt_findings,
            tool_findings=tool_integrity_findings
        )
        perm_findings = perm_res.findings

        # ---- Collect all scored findings ------------------------------------
        all_scored = (
            sqli_scored + xss_scored + idor_scored + hdr_scored + ck_scored +
            ai_disc.findings + ai_prompt_findings + tool_integrity_findings + perm_findings
        )
        all_dicts = [_scored_to_dict(sf) for sf in all_scored]

        # ---- Evaluation (pre-validation = raw detections) ------------------
        # Build raw (unvalidated) finding list for pre-validation evaluation
        raw_dicts = []
        for raw in sqli_raw:
            raw_dicts.append({
                "vulnerability_type": "SQL Injection",
                "location": f"{raw.form.action} (field: {raw.field_name})",
                "evidence": raw.evidence, "status": "raw",
            })
        for raw in xss_raw:
            raw_dicts.append({
                "vulnerability_type": "Reflected XSS",
                "location": raw.location,
                "evidence": raw.evidence, "status": "raw",
            })
        for raw in idor_raw:
            raw_dicts.append({
                "vulnerability_type": "IDOR (Broken Access Control)",
                "location": f"{raw.baseline_url} (param: {raw.param_name})",
                "evidence": raw.evidence, "status": "raw",
            })
        for raw in hdr_raw:
            raw_dicts.append({
                "vulnerability_type": "Missing Security Header",
                "location": raw.page_url,
                "evidence": raw.evidence, "status": "raw",
            })
        for raw in ck_raw:
            raw_dicts.append({
                "vulnerability_type": "Insecure Cookie",
                "location": raw.page_url,
                "evidence": f"Missing '{raw.missing_flag}' flag on cookie '{raw.cookie_name}'. Header: {raw.evidence}",
                "status": "raw",
            })

        print("[AegisScan] Running evaluation harness (pre-validation)...")
        eval_pre  = evaluator.evaluate_scan(raw_dicts,  "pre_validation",  scan_id, db)
        print("[AegisScan] Running evaluation harness (post-validation)...")
        eval_post = evaluator.evaluate_scan(all_dicts, "post_validation", scan_id, db)

        # ---- Save findings to DB ------------------------------------------
        for d in all_dicts:
            db.add(Finding(
                scan_id            = scan_id,
                vulnerability_type = d["vulnerability_type"],
                status             = d["status"],
                severity           = d["severity"],
                location           = d["location"],
                evidence           = d["evidence"],
                remediation_advice = d["remediation"],
            ))
        db.commit()

        scan.status      = "completed"
        scan.finished_at = datetime.utcnow()
        db.commit()

        print(f"[AegisScan] ===== Scan #{scan_id} done. Findings={len(all_dicts)} =====")

        return {
            "scan_id"       : scan_id,
            "target_url"    : target_url,
            "status"        : "completed",
            "pages_crawled" : len(disc.visited_urls),
            "forms_found"   : len(disc.all_forms),
            "findings_count": len(all_dicts),
            "breakdown"     : {
                "sqli"               : len(sqli_scored),
                "xss"                : len(xss_scored),
                "idor"               : len(idor_scored),
                "headers"            : len(hdr_scored),
                "cookies"            : len(ck_scored),
                "ai_discovery"       : len(ai_disc.findings),
                "ai_injection"       : len(ai_prompt_findings),
                "tool_integrity"     : len(tool_integrity_findings),
                "permission_analysis": len(perm_findings),
            },
            "tool_integrity_summary": {
                "verified_tools": tool_integrity_res.verified_count,
                "changed_tools": tool_integrity_res.changed_count,
                "missing_baseline_tools": tool_integrity_res.missing_baseline_count,
                "total_tools": tool_integrity_res.total_tools,
            },
            "permission_summary": {
                "unapproved_actions": perm_res.unapproved_actions_count,
                "properly_gated_actions": perm_res.properly_gated_actions_count,
                "approval_gate_enforced": perm_res.approval_gate_enforced,
                "taint_graphs_count": len(perm_res.taint_graphs),
                "unified_attack_paths_count": len(perm_res.unified_attack_paths),
            },
            "evaluation": {
                "pre_validation" : {
                    "precision": eval_pre.precision,
                    "recall"   : eval_pre.recall,
                    "f1"       : eval_pre.f1_score,
                    "TP": eval_pre.true_positives,
                    "FP": eval_pre.false_positives,
                    "FN": eval_pre.false_negatives,
                },
                "post_validation": {
                    "precision": eval_post.precision,
                    "recall"   : eval_post.recall,
                    "f1"       : eval_post.f1_score,
                    "TP": eval_post.true_positives,
                    "FP": eval_post.false_positives,
                    "FN": eval_post.false_negatives,
                },
            },
            "report_url": f"http://127.0.0.1:8000/api/scans/{scan_id}/report",
        }

    except Exception as e:
        scan.status      = "failed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


# ---------------------------------------------------------------------------
# GET /api/scans/compare?a=N&b=M -- Compare two scans (JSON)
# ---------------------------------------------------------------------------
@router.get("/scans/compare", summary="Compare two scans")
def compare_scans(a: int, b: int, db: Session = Depends(get_db)):
    """
    Compare scan A (baseline) vs scan B (re-scan).

    Identity key: (vulnerability_type, normalised location path, extra)
    Returns:
      fixed    -- in A, NOT in B  (vulnerability was resolved)
      new      -- in B, NOT in A  (new vulnerability appeared)
      persists -- in both A and B (still open)
    """
    scan_a = db.query(Scan).filter(Scan.id == a).first()
    scan_b = db.query(Scan).filter(Scan.id == b).first()
    if not scan_a:
        raise HTTPException(status_code=404, detail=f"Scan {a} not found")
    if not scan_b:
        raise HTTPException(status_code=404, detail=f"Scan {b} not found")

    def finding_key(f):
        """Normalised identity: type + path + specific differentiator."""
        from urllib.parse import urlparse
        loc = f.location or ""
        clean = loc.split(" (")[0].strip()
        try:
            path = urlparse(clean).path.rstrip("/") or "/"
        except Exception:
            path = clean

        extra = ""
        if f.vulnerability_type == "Missing Security Header":
            for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]:
                if h.lower() in (f.evidence or "").lower():
                    extra = h
                    break
        elif f.vulnerability_type == "Insecure Cookie":
            for fl in ["HttpOnly", "Secure"]:
                if fl.lower() in (f.evidence or "").lower():
                    extra = fl
                    break
        elif "field:" in loc:
            extra = loc.split("field:")[-1].rstrip(")").strip()
        elif "param:" in loc:
            extra = loc.split("param:")[-1].rstrip(")").strip()

        return (f.vulnerability_type, path, extra)

    keys_a = {finding_key(f): f for f in scan_a.findings}
    keys_b = {finding_key(f): f for f in scan_b.findings}

    set_a = set(keys_a)
    set_b = set(keys_b)

    def fmt(f):
        return {
            "vulnerability_type": f.vulnerability_type,
            "severity"          : f.severity,
            "status"            : f.status,
            "location"          : f.location,
        }

    fixed    = [fmt(keys_a[k]) for k in (set_a - set_b)]
    new      = [fmt(keys_b[k]) for k in (set_b - set_a)]
    persists = [fmt(keys_a[k]) for k in (set_a & set_b)]

    return {
        "scan_a"          : a,
        "scan_b"          : b,
        "total_in_a"      : len(scan_a.findings),
        "total_in_b"      : len(scan_b.findings),
        "fixed_count"     : len(fixed),
        "new_count"       : len(new),
        "persists_count"  : len(persists),
        "fixed"           : fixed,
        "new"             : new,
        "persists"        : persists,
        "compare_report_url": f"http://127.0.0.1:8000/api/scans/compare/report?a={a}&b={b}",
    }


# ---------------------------------------------------------------------------
# GET /api/scans/compare/report?a=N&b=M -- HTML comparison view
# ---------------------------------------------------------------------------
@router.get("/scans/compare/report", summary="HTML comparison report",
            response_class=HTMLResponse)
def compare_report(a: int, b: int, db: Session = Depends(get_db)):
    """Visual before/after comparison as an HTML page."""
    # Reuse the JSON compare logic
    cmp = compare_scans(a=a, b=b, db=db)

    all_scans = []
    for s in db.query(Scan).order_by(Scan.id.desc()).all():
        t = db.query(Target).filter(Target.id == s.target_id).first()
        all_scans.append({
            "id": s.id,
            "target_name": t.name if t else "Unknown",
            "findings_count": len(s.findings),
        })

    html = report.generate_compare_report(
        scan_a_id = a,
        scan_b_id = b,
        compare   = cmp,
        all_scans = all_scans,
    )
    return HTMLResponse(content=html, status_code=200)


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id} -- Scan status
# ---------------------------------------------------------------------------
@router.get("/scans/{scan_id}", summary="Get scan status")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return {
        "scan_id"       : scan.id,
        "target_id"     : scan.target_id,
        "status"        : scan.status,
        "started_at"    : scan.started_at,
        "finished_at"   : scan.finished_at,
        "findings_count": len(scan.findings),
    }


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}/findings -- JSON findings list
# ---------------------------------------------------------------------------
@router.get("/scans/{scan_id}/findings", summary="List findings for a scan")
def get_findings(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return {
        "scan_id": scan_id,
        "count"  : len(scan.findings),
        "findings": [
            {
                "finding_id"        : f.id,
                "vulnerability_type": f.vulnerability_type,
                "status"            : f.status,
                "severity"          : f.severity,
                "location"          : f.location,
                "evidence"          : f.evidence,
                "remediation_advice": f.remediation_advice,
            }
            for f in scan.findings
        ]
    }


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}/report -- HTML report
# ---------------------------------------------------------------------------
@router.get("/scans/{scan_id}/report", summary="HTML security report",
            response_class=HTMLResponse)
def get_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    target = db.query(Target).filter(Target.id == scan.target_id).first()

    findings_data = [
        {
            "vulnerability_type": f.vulnerability_type,
            "severity"          : f.severity,
            "status"            : f.status,
            "location"          : f.location,
            "evidence"          : f.evidence or "",
            "payload"           : "",
            "remediation"       : f.remediation_advice or "",
        }
        for f in scan.findings
    ]

    # Load post-validation evaluation for the report summary box
    eval_runs = (
        db.query(EvaluationRunModel)
        .filter(EvaluationRunModel.scan_id == scan_id)
        .all()
    )
    eval_data = {}
    for er in eval_runs:
        eval_data[er.stage] = {
            "precision": er.precision,
            "recall"   : er.recall,
            "f1"       : er.f1_score,
            "TP"       : er.true_positives,
            "FP"       : er.false_positives,
            "FN"       : er.false_negatives,
            "tp_list"  : json.loads(er.tp_list or "[]"),
            "fp_list"  : json.loads(er.fp_list or "[]"),
            "fn_list"  : json.loads(er.fn_list or "[]"),
        }

    html = report.generate_html_report(
        scan_id          = scan_id,
        target_url       = target.base_url if target else "Unknown",
        target_name      = target.name     if target else "Unknown",
        all_findings     = findings_data,
        scan_started_at  = scan.started_at,
        scan_finished_at = scan.finished_at,
        eval_data        = eval_data,
    )
    return HTMLResponse(content=html, status_code=200)





# ---------------------------------------------------------------------------
# POST /api/scans/{scan_id}/evaluate -- Re-run evaluation harness
# ---------------------------------------------------------------------------
@router.post("/scans/{scan_id}/evaluate",
             summary="Run evaluation harness for a completed scan")
def run_evaluate(scan_id: int, db: Session = Depends(get_db)):
    """
    (Re-)run the precision/recall/F1 evaluation for a scan.
    Useful if you want to re-evaluate without re-scanning.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    findings_dicts = [
        {
            "vulnerability_type": f.vulnerability_type,
            "location"          : f.location,
            "evidence"          : f.evidence or "",
            "status"            : f.status,
        }
        for f in scan.findings
    ]

    # Ensure pre-validation baseline is preserved (or computed if missing)
    pre_eval = (
        db.query(EvaluationRunModel)
        .filter(
            EvaluationRunModel.scan_id == scan_id,
            EvaluationRunModel.stage == "pre_validation"
        )
        .first()
    )
    if pre_eval is None:
        evaluator.evaluate_scan(
            findings_dicts, "pre_validation", scan_id, db
        )

    # Only delete existing post_validation run for this scan
    db.query(EvaluationRunModel).filter(
        EvaluationRunModel.scan_id == scan_id,
        EvaluationRunModel.stage == "post_validation"
    ).delete()
    db.commit()

    eval_run = evaluator.evaluate_scan(
        findings_dicts, "post_validation", scan_id, db
    )

    return {
        "scan_id"  : scan_id,
        "stage"    : "post_validation",
        "TP"       : eval_run.true_positives,
        "FP"       : eval_run.false_positives,
        "FN"       : eval_run.false_negatives,
        "precision": eval_run.precision,
        "recall"   : eval_run.recall,
        "f1"       : eval_run.f1_score,
        "tp_list"  : json.loads(eval_run.tp_list),
        "fp_list"  : json.loads(eval_run.fp_list),
        "fn_list"  : json.loads(eval_run.fn_list),
    }


# ---------------------------------------------------------------------------
# POST /api/lab/rugpull-scenario -- Controlled Scenario C verification runner
# ---------------------------------------------------------------------------
@router.post("/lab/rugpull-scenario", summary="Execute controlled Scenario C Tool Rug-Pull benchmark")
def lab_rugpull_scenario(payload: dict = Body(...)):
    """
    Executes the 10-step Tool Rug-Pull verification against authorized local lab.
    """
    target_url = payload.get("target_url", "http://127.0.0.1:5001")
    guard = ScopeGuard()
    if not guard.is_allowed(target_url):
        raise HTTPException(status_code=403, detail=f"Target {target_url} is out of authorized scope.")

    result = tool_integrity_monitor.run_controlled_lab_rugpull_scenario(
        target_base_url=target_url,
        scope_guard=guard
    )
    return result


# ---------------------------------------------------------------------------
# POST /api/lab/poison-scenario -- Controlled Scenario B verification runner
# ---------------------------------------------------------------------------
@router.post("/lab/poison-scenario", summary="Execute controlled Scenario B Poisoned Tool Description benchmark")
def lab_poison_scenario(payload: dict = Body(...)):
    """
    Executes the Scenario B Poisoned Tool Description verification against authorized local lab.
    """
    target_url = payload.get("target_url", "http://127.0.0.1:5001")
    guard = ScopeGuard()
    if not guard.is_allowed(target_url):
        raise HTTPException(status_code=403, detail=f"Target {target_url} is out of authorized scope.")

    result = tool_integrity_monitor.run_controlled_lab_poison_scenario(
        target_base_url=target_url,
        scope_guard=guard
    )
    return result


# ---------------------------------------------------------------------------
# POST /api/lab/scenario-e -- Controlled Scenario E approval gate runner
# ---------------------------------------------------------------------------
@router.post("/lab/scenario-e", summary="Execute controlled Scenario E Approval Gate benchmark")
def lab_scenario_e(payload: dict = Body(...)):
    """
    Executes the controlled Scenario E high-impact action approval gate verification.
    """
    target_url = payload.get("target_url", "http://127.0.0.1:5001")
    guard = ScopeGuard()
    if not guard.is_allowed(target_url):
        raise HTTPException(status_code=403, detail=f"Target {target_url} is out of authorized scope.")

    result = agent_permission_analyzer.run_controlled_lab_scenario_e(
        target_base_url=target_url,
        scope_guard=guard
    )
    return result