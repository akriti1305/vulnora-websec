"""
AegisLab — Deliberately Vulnerable Flask Application
=====================================================
This app is INTENTIONALLY INSECURE for academic testing purposes only.
It should ONLY be run locally. Never deploy this to the internet.

Vulnerabilities included (one per route):
  1. SQL Injection        → POST /login
  2. Reflected XSS        → GET  /search
  3. IDOR (Broken Access) → GET  /user/profile
  4. Missing Sec Headers  → all routes (no headers set)
  5. Insecure Cookies     → session cookie (no HttpOnly, no Secure)
"""

import os
import sqlite3
from flask import (
    Flask, request, render_template,
    redirect, url_for, session, g
)
from markupsafe import Markup

# ---------------------------------------------------------------------------
# SECURE_MODE -- for before/after comparison testing
# ---------------------------------------------------------------------------
# Set environment variable AEGISLAB_SECURE=1 to enable parameterised queries
# on the /login route ONLY. All other vulnerabilities stay active.
#
# Usage:
#   Normal (vulnerable):  python app.py
#   Secure /login:        set AEGISLAB_SECURE=1 && python app.py   (Windows)
#                         AEGISLAB_SECURE=1 python app.py          (Linux/Mac)
#
# This lets you demo a before/after comparison: scan with SECURE_MODE off
# (scan A), fix the SQLi, restart, scan again (scan B), then compare.
# ---------------------------------------------------------------------------
SECURE_MODE = os.environ.get("AEGISLAB_SECURE", "0").strip() == "1"
if SECURE_MODE:
    print("[AegisLab] SECURE_MODE=ON -- /login uses parameterised queries")
else:
    print("[AegisLab] SECURE_MODE=OFF -- /login is vulnerable to SQLi (default)")

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Secret key is needed for Flask sessions (intentionally weak for demo)
app.secret_key = "aegislab_weak_secret"

# ----- VULNERABILITY 5: Insecure Cookie Configuration ---------------------
# By default Flask sets HttpOnly=True. We intentionally disable it so that
# JavaScript can read the session cookie (a real security flaw).
# The Secure flag is also False, meaning the cookie is sent over plain HTTP.
app.config["SESSION_COOKIE_HTTPONLY"] = False   # ← vulnerable: JS can steal it
app.config["SESSION_COOKIE_SECURE"]   = False   # ← vulnerable: sent over HTTP too
# -------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Phase 7 — AegisLab 2.0 AI Assistant & Security Lab Blueprint
# ---------------------------------------------------------------------------
from ai_assistant import ai_blueprint
app.register_blueprint(ai_blueprint)



# ---------------------------------------------------------------------------
# Database — In-Memory SQLite
# ---------------------------------------------------------------------------
DATABASE = ":memory:"   # fresh DB every time the app starts

def get_db():
    """
    Return a database connection stored on Flask's 'g' object.
    The 'g' object lives for one request, so each request gets the
    SAME connection (but a new one per request is also fine here).

    We use a module-level _db variable instead because ':memory:' databases
    are per-connection — we need ONE shared connection for the whole app.
    """
    db = getattr(app, "_db", None)
    if db is None:
        db = sqlite3.connect(DATABASE, check_same_thread=False)
        db.row_factory = sqlite3.Row   # lets us access columns by name
        app._db = db
    return db


def init_db():
    """
    Create the users table and seed 3 fake users.
    Passwords are stored in plain text — another intentional flaw for realism.
    """
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email    TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        )
    """)
    db.execute("""
        INSERT INTO users (username, password, email, role) VALUES
            ('alice',  'password123', 'alice@aegislab.local',  'admin'),
            ('bob',    'qwerty456',   'bob@aegislab.local',    'user'),
            ('charlie','letmein789', 'charlie@aegislab.local', 'user')
    """)
    db.commit()


# Run init_db once when the app starts
with app.app_context():
    init_db()


# ---------------------------------------------------------------------------
# Route 1 — Home Page (links to all vulnerable features)
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """
    Home page — lists all vulnerable features with links/forms.
    A crawler starting here will discover all other routes.
    """
    logged_in_user = session.get("username")
    return render_template("index.html", logged_in_user=logged_in_user)


# ---------------------------------------------------------------------------
# Route 2 — SQL Injection: POST /login
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    VULNERABILITY: SQL Injection

    The username and password are placed DIRECTLY into the SQL query string
    using Python f-string formatting — never do this in a real app.

    Safe SQLi test payload (no data destruction):
        Username:  ' OR '1'='1
        Password:  anything
    This makes the query always return the first row, bypassing the password check.
    """
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()

        if SECURE_MODE:
            # ---- SECURE: parameterised query (NOT injectable) ---------------
            # This is what a properly written app looks like.
            # The ? placeholders are filled by SQLite safely -- the driver
            # ensures user input is never treated as SQL syntax.
            query  = "SELECT * FROM users WHERE username = ? AND password = ?"
            result = db.execute(query, (username, password)).fetchone()
            error  = None if result else "Invalid username or password."
            # -----------------------------------------------------------------
        else:
            # ---- VULNERABLE: raw string concatenation (injectable) ----------
            # A real app would NEVER do this.
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            # -----------------------------------------------------------------
            try:
                result = db.execute(query).fetchone()
                error  = None
            except sqlite3.OperationalError as e:
                # Show raw SQL error -- intentional information disclosure flaw
                error  = f"Database error: {e}"
                result = None
            if not result and not error:
                error = "Invalid username or password."

        if result:
            session["username"] = result["username"]
            session["user_id"]  = result["id"]
            success = f"Logged in as: {result['username']} (role: {result['role']})"
        else:
            success = None

    return render_template("login.html", error=error, success=success)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Route 3 — Reflected XSS: GET /search?q=...
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    """
    VULNERABILITY: Reflected XSS (Cross-Site Scripting)

    The search query 'q' is echoed back into the HTML page without any
    sanitisation or escaping.

    Flask's Jinja2 normally auto-escapes variables, so we use Markup()
    to intentionally bypass that protection — never do this in a real app.

    XSS test payload:
        /search?q=<script>alert('XSS')</script>
    """
    query = request.args.get("q", "")

    # ---- VULNERABLE OUTPUT -----------------------------------------------
    # Markup() tells Jinja2 "trust this string, do not escape it".
    # A real app would just pass 'query' normally (Jinja2 would auto-escape it).
    unsafe_query = Markup(query)   # ← intentionally unsafe
    # ----------------------------------------------------------------------

    return render_template("search.html", query=unsafe_query)


# ---------------------------------------------------------------------------
# Route 4 — IDOR / Broken Access Control: GET /user/profile?id=...
# ---------------------------------------------------------------------------
@app.route("/user/profile")
def profile():
    """
    VULNERABILITY: Insecure Direct Object Reference (IDOR)

    The app fetches the profile for whichever 'id' is in the URL,
    WITHOUT checking whether the logged-in user is allowed to see that profile.

    A real app would verify: session['user_id'] == requested_id (or admin role).

    IDOR test:
        Log in as alice (id=1), then visit /user/profile?id=2 to see bob's profile.
    """
    user_id = request.args.get("id", 1)

    db = get_db()
    # ---- VULNERABLE QUERY ------------------------------------------------
    # No ownership check. Any id works regardless of who is logged in.
    user = db.execute(
        "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    # ----------------------------------------------------------------------

    return render_template("profile.html", user=user, requested_id=user_id)


# ---------------------------------------------------------------------------
# DECOY 1 — /decoy/echo  (looks like XSS, is safe)
# ---------------------------------------------------------------------------
# The 'q' parameter is reflected back, but HTML-ESCAPED via Jinja2's
# default auto-escaping.  A real XSS detector testing <script>AEGISSCAN_XSS</script>
# would see the marker in the raw HTML as &lt;script&gt;, i.e. escaped.
# The XSS validation step SHOULD catch this (escaped = not vulnerable).
# If the raw detector still flags it, the validation step should filter it.
# ---------------------------------------------------------------------------
@app.route("/decoy/echo")
def decoy_echo():
    """
    DECOY: Looks like Reflected XSS, but is safe.
    Input is reflected via Jinja2's auto-escaping (the safe default).
    """
    q = request.args.get("q", "")
    # NOTE: NO Markup() here -- Jinja2 will auto-escape <, >, & etc.
    return render_template("decoy_echo.html", query=q)


# ---------------------------------------------------------------------------
# DECOY 2 — /decoy/login  (always says Welcome, looks like bypass, is not)
# ---------------------------------------------------------------------------
# Shows "Welcome" and "Logout" on EVERY response regardless of input.
# A naive SQLi detector might think the login was bypassed.
# The validation control-request check SHOULD expose this as a false positive
# because the control value (testvalue123) ALSO gets a "Welcome" response.
# ---------------------------------------------------------------------------
@app.route("/decoy/login", methods=["GET", "POST"])
def decoy_login():
    """
    DECOY: Looks like a login bypass, but is not.
    Shows 'Welcome' on every POST regardless of credentials.
    The validation layer's control test should detect this as noise.
    """
    if request.method == "POST":
        # Always returns Welcome -- not an actual authentication
        return render_template("decoy_login.html", always_welcome=True)
    return render_template("decoy_login.html", always_welcome=False)


# ---------------------------------------------------------------------------
# DECOY 3 — /decoy/product?id=N  (public product catalogue, NOT private)
# ---------------------------------------------------------------------------
# Each ID returns a different *public* product. There is no private user data.
# An IDOR detector will see different content per ID and HTTP 200 for all --
# which looks like IDOR. But it's actually a public catalogue.
# We do NOT hide this -- if the IDOR detector flags it, it's an honest FP.
# ---------------------------------------------------------------------------
DECOY_PRODUCTS = {
    "1": {"name": "Widget Alpha",  "desc": "A robust and reliable widget.",  "price": "$9.99"},
    "2": {"name": "Gadget Beta",   "desc": "Compact gadget for everyday use.", "price": "$14.99"},
    "3": {"name": "Doohickey Gamma","desc": "Precision-engineered doohickey.", "price": "$24.99"},
    "4": {"name": "Thingamajig Delta","desc": "Versatile thingamajig, 2-pack.","price": "$19.99"},
    "5": {"name": "Contraption Epsilon","desc": "Patent-pending contraption.", "price": "$49.99"},
}

@app.route("/decoy/product")
def decoy_product():
    """
    DECOY: Public product catalogue with ID-based lookup.
    Each ID returns a different PUBLIC product -- no private user data.
    An IDOR detector may flag this; if so it is a legitimate false positive.
    """
    product_id = request.args.get("id", "1")
    product = DECOY_PRODUCTS.get(str(product_id), None)
    return render_template("decoy_product.html", product=product,
                           product_id=product_id)


# ---------------------------------------------------------------------------
# Run the app
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # debug=True is fine for local academic use; never use in production
    app.run(host="127.0.0.1", port=5001, debug=True)
