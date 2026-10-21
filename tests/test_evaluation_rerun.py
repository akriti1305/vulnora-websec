"""
tests/test_evaluation_rerun.py
==============================
Regression tests for evaluation re-run behavior in api/routes.py.
Verifies that:
  - Re-evaluating a scan preserves the pre_validation baseline.
  - post_validation is refreshed correctly.
  - Repeated evaluation runs are idempotent and consistent.
  - A missing pre_validation run is safely restored.
"""

import sys
import os
import unittest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure aegisscan is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "aegisscan")))

from database import Base
from models import Target, Scan, Finding, EvaluationRun
from api.routes import run_evaluate


class TestEvaluationRerun(unittest.TestCase):

    def setUp(self):
        # Create an isolated in-memory SQLite database for testing
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

        # Seed test Target and Scan
        self.target = Target(name="Test Target", base_url="http://127.0.0.1:5001")
        self.db.add(self.target)
        self.db.commit()

        self.scan = Scan(target_id=self.target.id, status="completed", started_at=datetime.utcnow(), finished_at=datetime.utcnow())
        self.db.add(self.scan)
        self.db.commit()

        # Add findings matching AegisLab ground truth
        f1 = Finding(
            scan_id=self.scan.id,
            vulnerability_type="SQL Injection",
            status="confirmed",
            severity="Critical",
            location="http://127.0.0.1:5001/login (field: username)",
            evidence="sqlite3.OperationalError: near syntax error",
            remediation_advice="Use parameterised queries"
        )
        f2 = Finding(
            scan_id=self.scan.id,
            vulnerability_type="Reflected XSS",
            status="confirmed",
            severity="High",
            location="http://127.0.0.1:5001/search (field: q)",
            evidence="<script>alert('AEGISSCAN_XSS')</script>",
            remediation_advice="Escape HTML"
        )
        self.db.add_all([f1, f2])
        self.db.commit()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_pre_validation_preserved_on_rerun(self):
        """Calling run_evaluate must NOT delete existing pre_validation evaluation run."""
        # Initial pre_validation run
        pre_run = EvaluationRun(
            scan_id=self.scan.id,
            stage="pre_validation",
            true_positives=2,
            false_positives=0,
            false_negatives=7,
            precision=1.0,
            recall=0.2222,
            f1_score=0.3636,
            tp_list="[\"SQL Injection on /login\", \"Reflected XSS on /search\"]",
            fp_list="[]",
            fn_list="[]"
        )
        # Initial post_validation run
        post_run = EvaluationRun(
            scan_id=self.scan.id,
            stage="post_validation",
            true_positives=1,
            false_positives=0,
            false_negatives=8,
            precision=1.0,
            recall=0.1111,
            f1_score=0.2000,
            tp_list="[\"SQL Injection on /login\"]",
            fp_list="[]",
            fn_list="[]"
        )
        self.db.add_all([pre_run, post_run])
        self.db.commit()

        # Re-run evaluation
        res = run_evaluate(scan_id=self.scan.id, db=self.db)
        self.assertEqual(res["scan_id"], self.scan.id)
        self.assertEqual(res["stage"], "post_validation")

        # Verify database state
        eval_runs = self.db.query(EvaluationRun).filter(EvaluationRun.scan_id == self.scan.id).all()
        stages = {er.stage for er in eval_runs}

        # Both pre_validation and post_validation must be present
        self.assertIn("pre_validation", stages)
        self.assertIn("post_validation", stages)
        self.assertEqual(len(eval_runs), 2)

        # Check that pre_validation preserved its original metrics
        preserved_pre = [er for er in eval_runs if er.stage == "pre_validation"][0]
        self.assertEqual(preserved_pre.true_positives, 2)
        self.assertEqual(preserved_pre.f1_score, 0.3636)

    def test_missing_pre_validation_restored(self):
        """If pre_validation was previously deleted or missing, re-evaluating restores it."""
        # Only post_validation exists initially
        post_run = EvaluationRun(
            scan_id=self.scan.id,
            stage="post_validation",
            true_positives=1,
            false_positives=0,
            false_negatives=8,
            precision=1.0,
            recall=0.1111,
            f1_score=0.2000
        )
        self.db.add(post_run)
        self.db.commit()

        res = run_evaluate(scan_id=self.scan.id, db=self.db)
        self.assertEqual(res["scan_id"], self.scan.id)

        eval_runs = self.db.query(EvaluationRun).filter(EvaluationRun.scan_id == self.scan.id).all()
        stages = {er.stage for er in eval_runs}

        self.assertIn("pre_validation", stages)
        self.assertIn("post_validation", stages)
        self.assertEqual(len(eval_runs), 2)

    def test_repeated_evaluation_idempotent(self):
        """Calling run_evaluate multiple times must not create duplicate runs."""
        run_evaluate(scan_id=self.scan.id, db=self.db)
        run_evaluate(scan_id=self.scan.id, db=self.db)
        run_evaluate(scan_id=self.scan.id, db=self.db)

        eval_runs = self.db.query(EvaluationRun).filter(EvaluationRun.scan_id == self.scan.id).all()
        self.assertEqual(len(eval_runs), 2)
        stages = [er.stage for er in eval_runs]
        self.assertEqual(sorted(stages), ["post_validation", "pre_validation"])


if __name__ == "__main__":
    unittest.main()
