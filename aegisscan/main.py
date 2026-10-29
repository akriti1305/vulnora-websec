"""
main.py — AegisScan Entry Point & Web UI
=========================================
Provides:
  - Web UI (Server-rendered Jinja2, dark mode, no JS framework):
      GET  /             -- Home dashboard (scan launcher, past scans table, notice)
      POST /scan/start   -- Start a scan from UI form and redirect to report
      GET  /compare      -- Compare two scans with dropdown picker
      GET  /scans/{id}   -- Shortcut to view scan report
  - REST API:
      Under /api/... via api/routes.py
"""

from typing import Optional
from urllib.parse import quote_plus
from fastapi import FastAPI, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from database import engine, Base, get_db, init_db
import models
from models import Target, Scan, Finding
from api.routes import router, get_allowed_hosts, compare_scans, start_scan
import report

# 1. Create database tables and apply migrations
init_db(engine)

# 2. FastAPI application
app = FastAPI(
    title       ="AegisScan",
    description ="Web Application Vulnerability Scanner — Academic Project",
    version     ="0.2.0"
)

# 3. Include API routes
app.include_router(router)


from authorization import get_target_status_summary

def _get_scans_summary_list(db: Session):
    """Helper to query past scans with target names, modes, categories, and passports."""
    from risk import classify_finding_category
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    scans_data = []
    for s in scans:
        target = db.query(Target).filter(Target.id == s.target_id).first()
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        active_vulns = 0
        controls_count = 0
        info_count = 0

        for f in s.findings:
            cat = getattr(f, "category", "") or classify_finding_category(f.vulnerability_type, f.status)
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1
            if cat in ("confirmed_vulnerability", "potential_vulnerability"):
                active_vulns += 1
            elif cat == "verified_control":
                controls_count += 1
            elif cat == "informational":
                info_count += 1

        scans_data.append({
            "id": s.id,
            "target_name": target.name if target else "Unknown",
            "target_url": target.base_url if target else "",
            "scan_mode": getattr(s, "scan_mode", "deep") or "deep",
            "status": s.status,
            "started_at": s.started_at.strftime("%Y-%m-%d %H:%M:%S") if s.started_at else "-",
            "findings_count": len(s.findings),
            "active_vulns_count": active_vulns,
            "verified_controls_count": controls_count,
            "informational_count": info_count,
            "severity_counts": sev_counts,
            "has_passport": bool(s.passport_record),
            "passport_url": f"/api/scans/{s.id}/passport",
            "passport_verify_url": f"/api/scans/{s.id}/passport/verify",
            "chain_sequence": s.chain_record.sequence_number if s.chain_record else None,
            "chain_hash": s.chain_record.chain_hash[:16] + "..." if s.chain_record else None,
            "report_url": f"/api/scans/{s.id}/report",
        })
    return scans_data


# ---------------------------------------------------------------------------
# UI Page 1: Home Dashboard (GET /)
# ---------------------------------------------------------------------------
@app.get("/", summary="AegisScan Home Dashboard", response_class=HTMLResponse)
def home_page(error: Optional[str] = None, db: Session = Depends(get_db)):
    """
    Server-rendered Home dashboard:
      - New scan form (target URL + name + mode selection)
      - Quick scan comparison launcher
      - Real-time KPI summary cards
      - Table of past scans with status, mode, findings, passport verification
      - Visible 'Authorised Use Only' scope banner
    """
    scans_data = _get_scans_summary_list(db)
    allowed = sorted(list(get_allowed_hosts()))

    # Compute global platform KPI stats
    total_scans = len(scans_data)
    total_active_vulns = sum(s["active_vulns_count"] for s in scans_data)
    total_controls = sum(s["verified_controls_count"] for s in scans_data)
    total_passports = sum(1 for s in scans_data if s["has_passport"])

    from crypto.hash_chain import verify_hash_chain
    try:
        chain_audit = verify_hash_chain(db)
        chain_status = chain_audit.get("status", "VERIFIED")
    except Exception:
        chain_status = "INITIALIZING"

    stats = {
        "total_scans": total_scans,
        "total_active_vulns": total_active_vulns,
        "total_controls": total_controls,
        "total_passports": total_passports,
        "chain_status": chain_status,
    }

    # Registered targets status
    targets = db.query(Target).order_by(Target.id.desc()).all()
    targets_data = []
    for t in targets:
        s = get_target_status_summary(db, t.id)
        if s:
            targets_data.append(s)

    html = report.generate_home_page(
        scans=scans_data,
        allowed_hosts=allowed,
        error_message=error,
        stats=stats,
        targets=targets_data,
    )
    return HTMLResponse(content=html, status_code=200)


# ---------------------------------------------------------------------------
# UI Action: Launch Scan via Form (POST /scan/start)
# ---------------------------------------------------------------------------
@app.post("/scan/start", summary="Start scan from UI form")
def form_start_scan(
    target_url: str = Form(...),
    target_name: str = Form("Unnamed Target"),
    scan_mode: str = Form("deep"),
    db: Session = Depends(get_db)
):
    """
    Receives scan launch from web form.
    Calls start_scan pipeline with selected scan_mode and redirects to the HTML report.
    Catches scope violations and redirects to home with an error banner.
    """
    try:
        res = start_scan({
            "target_url": target_url.strip(),
            "target_name": target_name.strip(),
            "scan_mode": scan_mode.strip(),
        }, db=db)
        new_scan_id = res["scan_id"]
        return RedirectResponse(url=f"/api/scans/{new_scan_id}/report", status_code=303)
    except HTTPException as e:
        return RedirectResponse(url=f"/?error={quote_plus(e.detail)}", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/?error={quote_plus(str(e))}", status_code=303)


# ---------------------------------------------------------------------------
# UI Page 2: Compare Page (GET /compare)
# ---------------------------------------------------------------------------
@app.get("/compare", summary="Compare Scans UI", response_class=HTMLResponse)
def compare_page(
    a: Optional[int] = None,
    b: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    Server-rendered Compare page:
      - Dropdown selectors listing all completed scans
      - Shows differential comparison (fixed, persisting, new) when a & b are selected
    """
    scans_data = _get_scans_summary_list(db)
    cmp_data = None
    if a is not None and b is not None:
        try:
            cmp_data = compare_scans(a=a, b=b, db=db)
        except HTTPException:
            cmp_data = None

    html = report.generate_compare_report(
        scan_a_id=a,
        scan_b_id=b,
        compare=cmp_data,
        all_scans=scans_data,
    )
    return HTMLResponse(content=html, status_code=200)


# ---------------------------------------------------------------------------
# UI Shortcut: GET /scans/{scan_id} -> redirect to report
# ---------------------------------------------------------------------------
@app.get("/scans/{scan_id}", summary="View Scan Report Shortcut")
def view_scan_shortcut(scan_id: int):
    return RedirectResponse(url=f"/api/scans/{scan_id}/report", status_code=303)
