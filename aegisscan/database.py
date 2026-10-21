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
