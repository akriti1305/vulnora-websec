"""
database.py — AegisScan Database Setup
=======================================
This file is responsible for two things:
  1. Creating a connection to the SQLite database file (aegisscan.db)
  2. Providing a "session" that our API routes use to read/write data

We use SQLAlchemy — a popular Python library that lets us work with
databases using Python objects instead of writing raw SQL.

Key concepts:
  - engine    : the connection to the database file
  - SessionLocal : a factory that creates database sessions (one per request)
  - Base      : the parent class all our models (tables) will inherit from
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# -----------------------------------------------------------------------
# Database file location
# -----------------------------------------------------------------------
# "sqlite:///aegisscan.db" means: create (or open) a file called
# "aegisscan.db" in the current working directory.
# The three slashes "///" mean it's a relative path.
DATABASE_URL = "sqlite:///aegisscan.db"

# -----------------------------------------------------------------------
# Engine — the connection to the database
# -----------------------------------------------------------------------
# check_same_thread=False is needed for SQLite when used with FastAPI,
# because FastAPI handles requests in threads.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# -----------------------------------------------------------------------
# SessionLocal — a session factory
# -----------------------------------------------------------------------
# Each API request will create one session, use it, and then close it.
# autocommit=False  → we manually commit changes (safer)
# autoflush=False   → don't auto-write to DB before a query
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# -----------------------------------------------------------------------
# Base — the parent class for all our database models
# -----------------------------------------------------------------------
# Every table (Target, Scan, Finding, EvaluationRun) will inherit from Base.
Base = declarative_base()


def upgrade_schema(db_engine=None):
    """Ensure newly added Phase 12/13/14 columns and tables exist in SQLite database."""
    eng = db_engine or engine
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(eng)
        tables = inspector.get_table_names()

        with eng.connect() as conn:
            # 1. Check targets table for Phase 14 columns
            if "targets" in tables:
                target_cols = [c["name"] for c in inspector.get_columns("targets")]
                if "target_type" not in target_cols:
                    conn.execute(text("ALTER TABLE targets ADD COLUMN target_type VARCHAR(32) DEFAULT 'local'"))
                    conn.commit()
                if "is_verified" not in target_cols:
                    conn.execute(text("ALTER TABLE targets ADD COLUMN is_verified BOOLEAN DEFAULT 0"))
                    conn.commit()
                if "verified_at" not in target_cols:
                    conn.execute(text("ALTER TABLE targets ADD COLUMN verified_at DATETIME"))
                    conn.commit()
                if "verification_method" not in target_cols:
                    conn.execute(text("ALTER TABLE targets ADD COLUMN verification_method VARCHAR(32)"))
                    conn.commit()

            # 2. Check scans table for Phase 12/13/14 columns
            if "scans" in tables:
                cols = [c["name"] for c in inspector.get_columns("scans")]
                if "scan_mode" not in cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN scan_mode VARCHAR(32) DEFAULT 'deep'"))
                    conn.commit()
                if "target_type" not in cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN target_type VARCHAR(32) DEFAULT 'local'"))
                    conn.commit()
                if "authorization_grant_id" not in cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN authorization_grant_id INTEGER"))
                    conn.commit()
                if "requests_count" not in cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN requests_count INTEGER DEFAULT 0"))
                    conn.commit()
                if "duration_seconds" not in cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN duration_seconds FLOAT DEFAULT 0.0"))
                    conn.commit()
                if "scan_policy_json" not in cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN scan_policy_json TEXT"))
                    conn.commit()

            # 3. Check findings table for category
            if "findings" in tables:
                cols = [c["name"] for c in inspector.get_columns("findings")]
                if "category" not in cols:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN category VARCHAR(64) DEFAULT 'potential_vulnerability'"))
                    conn.commit()

            # 4. Check evaluation_runs table for true_negatives
            if "evaluation_runs" in tables:
                cols = [c["name"] for c in inspector.get_columns("evaluation_runs")]
                if "true_negatives" not in cols:
                    conn.execute(text("ALTER TABLE evaluation_runs ADD COLUMN true_negatives INTEGER DEFAULT 0"))
                    conn.commit()
    except Exception:
        pass


def init_db(db_engine=None):
    """Initialize all tables and apply migrations."""
    eng = db_engine or engine
    Base.metadata.create_all(bind=eng)
    upgrade_schema(eng)


# Run upgrade on module load for persistent databases
upgrade_schema(engine)


# -----------------------------------------------------------------------
# Dependency: get_db()
# -----------------------------------------------------------------------
# This is a FastAPI "dependency" — routes call it to get a DB session.
# The "yield" makes it a generator: code before yield = setup,
# code after yield = cleanup (session is always closed after the request).
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
