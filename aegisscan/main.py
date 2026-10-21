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

from database import engine, Base, get_db
import models
from models import Target, Scan, Finding
from api.routes import router, get_allowed_hosts, compare_scans, start_scan
import report

# 1. Create database tables
Base.metadata.create_all(bind=engine)

# 2. FastAPI application
app = FastAPI(
    title       ="AegisScan",
    description ="Web Application Vulnerability Scanner — Academic Project",
    version     ="0.2.0"
)

# 3. Include API routes
app.include_router(router)


def _get_scans_summary_list(db: Session):
    """Helper to query past scans with target names and severity counts."""
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    scans_data = []
    for s in scans:
        target = db.query(Target).filter(Target.id == s.target_id).first()
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in s.findings:
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1

        scans_data.append({
            "id": s.id,
            "target_name": target.name if target else "Unknown",
            "target_url": target.base_url if target else "",
            "status": s.status,
            "started_at": s.started_at.strftime("%Y-%m-%d %H:%M:%S") if s.started_at else "-",
            "findings_count": len(s.findings),
            "severity_counts": sev_counts,
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
      - New scan form (target URL + name)
      - Quick scan comparison launcher
      - Table of past scans with status, dates, findings, severity badges
      - Visible 'Authorised Use Only' notice
    """
    scans_data = _get_scans_summary_list(db)
    allowed = sorted(list(get_allowed_hosts()))
    html = report.generate_home_page(
        scans=scans_data,
        allowed_hosts=allowed,
        error_message=error,
    )
    return HTMLResponse(content=html, status_code=200)


# ---------------------------------------------------------------------------
# UI Action: Launch Scan via Form (POST /scan/start)
# ---------------------------------------------------------------------------
@app.post("/scan/start", summary="Start scan from UI form")
def form_start_scan(
    target_url: str = Form(...),
    target_name: str = Form("Unnamed Target"),
    db: Session = Depends(get_db)
):
    """
    Receives scan launch from web form.
    Calls start_scan pipeline and redirects to the generated HTML report.
    Catches scope violations and redirects to home with an error banner.
    """
    try:
        res = start_scan({"target_url": target_url.strip(), "target_name": target_name.strip()}, db=db)
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
