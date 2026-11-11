"""
tests/test_scan_execution.py -- Unit tests for background scan execution, concurrency, and reports
===================================================================================================
Tests non-blocking scan execution, thread-safe DB sessions, concurrency limiting (HTTP 429),
status transitions (pending -> running -> completed/failed/cancelled), and graceful UI rendering.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure aegisscan is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan")))

from database import Base
from models import Target, Scan, AuditEvent
import api.routes as routes


class TestScanExecution(unittest.TestCase):
    def setUp(self):
        # Create an isolated shared in-memory SQLite database for each test
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()
        with routes._SCAN_LOCK:
            routes._ACTIVE_SCAN_IDS.clear()

    def tearDown(self):
        with routes._SCAN_LOCK:
            routes._ACTIVE_SCAN_IDS.clear()
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_background_scan_launch_returns_running(self):
        """Validates that start_scan with background=True returns status 'running' immediately."""
        with patch.object(routes, "_scan_worker_thread"):
            resp = routes.start_scan({
                "target_url": "http://127.0.0.1:5001",
                "target_name": "AegisLab Local",
                "scan_mode": "deep",
                "background": True,
            }, db=self.db)

            self.assertEqual(resp["status"], "running")
            self.assertIn("scan_id", resp)
            self.assertIn("report_url", resp)

            scan = self.db.query(Scan).filter(Scan.id == resp["scan_id"]).first()
            self.assertIsNotNone(scan)
            self.assertEqual(scan.status, "running")

    def test_concurrency_limit_returns_429(self):
        """Validates that exceeding MAX_CONCURRENT_SCANS raises HTTP 429."""
        with routes._SCAN_LOCK:
            routes._ACTIVE_SCAN_IDS.add(998)
            routes._ACTIVE_SCAN_IDS.add(999)

        with self.assertRaises(HTTPException) as ctx:
            routes.start_scan({
                "target_url": "http://127.0.0.1:5001",
                "target_name": "AegisLab Local",
                "scan_mode": "deep",
            }, db=self.db)

        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("Maximum concurrent scans", ctx.exception.detail)

    def test_running_scan_report_renders_progress_page(self):
        """Validates that get_report on a running scan renders progress view."""
        target = Target(name="Lab", base_url="http://127.0.0.1:5001", target_type="local", is_verified=True)
        self.db.add(target)
        self.db.commit()

        scan = Scan(target_id=target.id, status="running", scan_mode="deep", target_type="local")
        self.db.add(scan)
        self.db.commit()

        resp = routes.get_report(scan.id, db=self.db)
        self.assertEqual(resp.status_code, 200)
        content = resp.body.decode("utf-8")
        self.assertIn("Security Assessment In Progress", content)
        self.assertIn(f"#{scan.id}", content)
        self.assertIn("Auto-refreshing status", content)

    def test_failed_scan_report_renders_failure_page(self):
        """Validates that get_report on a failed scan renders failure view without crashing."""
        target = Target(name="Lab", base_url="http://127.0.0.1:5001", target_type="local", is_verified=True)
        self.db.add(target)
        self.db.commit()

        scan = Scan(target_id=target.id, status="failed", scan_mode="deep", target_type="local")
        self.db.add(scan)
        self.db.commit()

        event = AuditEvent(
            event_type="scan_failed",
            scan_id=scan.id,
            target_id=target.id,
            details="Simulated pipeline connection timeout to host"
        )
        self.db.add(event)
        self.db.commit()

        resp = routes.get_report(scan.id, db=self.db)
        self.assertEqual(resp.status_code, 200)
        content = resp.body.decode("utf-8")
        self.assertIn("Security Assessment Failed", content)
        self.assertIn("Simulated pipeline connection timeout to host", content)

    def test_cancel_scan_transitions_status(self):
        """Validates that cancelling a running scan updates status to 'cancelled' and logs audit event."""
        target = Target(name="Lab", base_url="http://127.0.0.1:5001", target_type="local", is_verified=True)
        self.db.add(target)
        self.db.commit()

        scan = Scan(target_id=target.id, status="running", scan_mode="deep", target_type="local")
        self.db.add(scan)
        self.db.commit()

        with routes._SCAN_LOCK:
            routes._ACTIVE_SCAN_IDS.add(scan.id)

        resp = routes.cancel_scan_endpoint(scan.id, db=self.db)
        self.assertEqual(resp["status"], "cancelled")

        # Verify DB status
        self.db.refresh(scan)
        self.assertEqual(scan.status, "cancelled")
        # Verify slot released
        with routes._SCAN_LOCK:
            self.assertNotIn(scan.id, routes._ACTIVE_SCAN_IDS)


if __name__ == "__main__":
    unittest.main()
