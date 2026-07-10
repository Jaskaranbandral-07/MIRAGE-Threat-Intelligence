"""
MIRAGE Decoy — Deliberately Vulnerable Flask Honeypot
=====================================================

This application intentionally reintroduces three real audit bugs from
Bartigo Systems for research purposes:

  Bug 1 — Exposed JWT secret via /debug/config and /api/token
  Bug 2 — Authentication bypass (hardcoded admin/admin + role tampering)
  Bug 3 — Permissive CORS on every response (Access-Control-Allow-Origin: *)

Additional decoy routes present enticing attack surface:
  /.env, /.git/config, /robots.txt, /api/users, /api/admin, /api/upload

Every request is logged to the MIRAGE database via the middleware module.

WARNING: This is a HONEYPOT — intentionally insecure.  Never deploy
outside an isolated research network.
"""

import sys
import os
import json
import logging
import datetime

# ---------------------------------------------------------------------------
# Path bootstrap — project root on sys.path
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    make_response,
    session as flask_session,
    redirect,
    url_for,
)

# JWT — imported conditionally so the app still starts if PyJWT is missing
try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = "flask-session-key-bartigo-2024"  # weak on purpose

# ---- Bug 1: Exposed JWT Secret (hardcoded module-level constant) ---------
JWT_SECRET = "super-secret-jwt-key-2024-mirage"

# ---------------------------------------------------------------------------
# Register MIRAGE request-logging middleware
# ---------------------------------------------------------------------------
from middleware import register_middleware  # noqa: E402

register_middleware(app)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("mirage.decoy")

# ==========================================================================
# Bug 3: Permissive CORS — applied on EVERY response
# ==========================================================================

@app.after_request
def _apply_cors(response):
    """Attach wide-open CORS headers to every response."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = (
        "GET, POST, PUT, DELETE, OPTIONS"
    )
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response


# ==========================================================================
# Fake user data
# ==========================================================================
FAKE_USERS = [
    {"id": 1, "name": "Alice Chen",        "email": "alice.chen@bartigo.com",       "role": "admin"},
    {"id": 2, "name": "Bob Martinez",       "email": "bob.martinez@bartigo.com",     "role": "developer"},
    {"id": 3, "name": "Carol Okonkwo",      "email": "carol.okonkwo@bartigo.com",    "role": "analyst"},
    {"id": 4, "name": "David Kim",          "email": "david.kim@bartigo.com",        "role": "developer"},
    {"id": 5, "name": "Eva Johansson",      "email": "eva.johansson@bartigo.com",    "role": "operations"},
    {"id": 6, "name": "Frank Dubois",       "email": "frank.dubois@bartigo.com",     "role": "developer"},
    {"id": 7, "name": "Grace Nakamura",     "email": "grace.nakamura@bartigo.com",   "role": "admin"},
    {"id": 8, "name": "Hassan Al-Rashid",   "email": "hassan.alrashid@bartigo.com",  "role": "security"},
]

# ==========================================================================
# Routes
# ==========================================================================

# ---- Landing page --------------------------------------------------------

@app.route("/")
def index():
    """Render the fake internal portal landing page."""
    return render_template("index.html")


# ---- Bug 2: Authentication bypass (admin/admin + role= param) ------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Vulnerable login route.

    Accepts hardcoded admin/admin credentials.  Also vulnerable to
    parameter tampering: including ``role=admin`` in the POST body
    bypasses all credential checks.
    """
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    role     = request.form.get("role", "")

    # Bug 2a: hardcoded credentials
    authenticated = (username == "admin" and password == "admin")

    # Bug 2b: role-parameter bypass
    if role == "admin":
        authenticated = True

    if authenticated:
        flask_session["user"] = username or "admin"
        flask_session["role"] = "admin"
        logger.info("Login SUCCESS for user=%s (role bypass=%s)", username, role == "admin")
        return redirect(url_for("admin_panel"))

    logger.info("Login FAILED for user=%s", username)
    return render_template("login.html", error="Invalid username or password."), 401


# ---- Admin panel ---------------------------------------------------------

@app.route("/admin")
def admin_panel():
    """Fake admin panel — always renders regardless of session."""
    return render_template("admin.html")


# ---- Bug 1: Exposed JWT config & token endpoint --------------------------

@app.route("/debug/config")
def debug_config():
    """Return the JWT secret and fake infrastructure details as JSON."""
    return jsonify({
        "jwt_secret": JWT_SECRET,
        "database": {
            "host": "db-internal.bartigo.local",
            "port": 5432,
            "name": "bartigo_prod",
            "user": "app_service",
            "password": "Pg@Bart1g0_2024!",
        },
        "redis": "redis://cache.bartigo.local:6379/0",
        "aws": {
            "region": "us-east-1",
            "s3_bucket": "bartigo-uploads-2024",
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        "app": {
            "version": "3.8.2-rc1",
            "environment": "staging",
            "debug_mode": True,
        },
    })


@app.route("/api/token", methods=["POST", "GET"])
def issue_token():
    """
    Issue a JWT signed with the exposed secret.

    Accepts optional ``username`` and ``role`` query / form params.
    Defaults to guest / viewer.
    """
    username = request.values.get("username", "guest")
    role     = request.values.get("role", "viewer")

    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24),
    }

    if pyjwt:
        token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
    else:
        # Fallback: base64-encoded JSON (insecure, but keeps the app working)
        import base64
        token = base64.urlsafe_b64encode(json.dumps(payload, default=str).encode()).decode()

    return jsonify({"token": token, "expires_in": 86400})


# ---- API routes ----------------------------------------------------------

@app.route("/api/users")
def api_users():
    """Return the fake user list as JSON."""
    return jsonify({"users": FAKE_USERS, "total": len(FAKE_USERS)})


@app.route("/api/admin")
def api_admin():
    """Return fake admin panel data as JSON."""
    return jsonify({
        "system": {
            "active_users": 1247,
            "api_requests_24h": 83412,
            "uptime_percent": 99.97,
            "open_incidents": 3,
        },
        "services": [
            {"name": "auth-service",   "status": "healthy", "version": "2.4.1"},
            {"name": "api-gateway",    "status": "healthy", "version": "3.8.2"},
            {"name": "worker-queue",   "status": "degraded","version": "1.9.7"},
            {"name": "file-storage",   "status": "healthy", "version": "1.2.0"},
        ],
    })


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """Fake file upload endpoint — accepts but stores nothing."""
    filename = "unknown"
    if "file" in request.files:
        filename = request.files["file"].filename or "unnamed"
    return jsonify({
        "status": "success",
        "message": f"File '{filename}' uploaded successfully.",
        "storage_path": f"/data/uploads/{filename}",
    })


# ---- Sensitive-looking files (attract scanners) --------------------------

@app.route("/.env")
def fake_env():
    """Return a convincing but fake .env file."""
    content = (
        "# Bartigo Systems — Environment Configuration\n"
        "# WARNING: Do not commit this file to version control!\n"
        "\n"
        "APP_ENV=staging\n"
        "APP_DEBUG=true\n"
        "APP_SECRET=flask-session-key-bartigo-2024\n"
        "\n"
        "DB_HOST=db-internal.bartigo.local\n"
        "DB_PORT=5432\n"
        "DB_NAME=bartigo_prod\n"
        "DB_USER=app_service\n"
        "DB_PASSWORD=Pg@Bart1g0_2024!\n"
        "\n"
        "REDIS_URL=redis://cache.bartigo.local:6379/0\n"
        "\n"
        "JWT_SECRET=super-secret-jwt-key-2024-mirage\n"
        "\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "AWS_REGION=us-east-1\n"
        "S3_BUCKET=bartigo-uploads-2024\n"
        "\n"
        "SMTP_HOST=mail.bartigo.local\n"
        "SMTP_PORT=587\n"
        "SMTP_USER=notifications@bartigo.com\n"
        "SMTP_PASS=Sm7p!Bartigo2024\n"
    )
    resp = make_response(content)
    resp.headers["Content-Type"] = "text/plain"
    return resp


@app.route("/robots.txt")
def robots_txt():
    """Return a robots.txt that deliberately lists juicy paths."""
    content = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /api/\n"
        "Disallow: /debug/config\n"
        "Disallow: /.env\n"
        "Disallow: /.git/\n"
        "Disallow: /api/token\n"
        "Disallow: /api/upload\n"
        "Disallow: /backup/\n"
        "Disallow: /internal/\n"
    )
    resp = make_response(content)
    resp.headers["Content-Type"] = "text/plain"
    return resp


@app.route("/.git/config")
def fake_git_config():
    """Return a fake .git/config pointing at a private repo."""
    content = (
        "[core]\n"
        "    repositoryformatversion = 0\n"
        "    filemode = true\n"
        "    bare = false\n"
        "    logallrefupdates = true\n"
        "[remote \"origin\"]\n"
        "    url = git@github.com:bartigo-systems/internal-portal.git\n"
        "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n"
        "    remote = origin\n"
        "    merge = refs/heads/main\n"
        "[user]\n"
        "    name = deploy-bot\n"
        "    email = deploy-bot@bartigo.com\n"
    )
    resp = make_response(content)
    resp.headers["Content-Type"] = "text/plain"
    return resp


# ==========================================================================
# Entry point
# ==========================================================================

if __name__ == "__main__":
    logger.info("Starting MIRAGE decoy honeypot on %s:%s", Config.DECOY_HOST, Config.DECOY_PORT)
    app.run(
        host=Config.DECOY_HOST,
        port=Config.DECOY_PORT,
        debug=False,  # debug=False in production; Flask reloader conflicts with middleware
    )
