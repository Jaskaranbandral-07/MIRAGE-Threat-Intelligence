#!/usr/bin/env python3
"""
Wordpot — WordPress Honeypot Server
=====================================
A Flask-based honeypot that mimics a vulnerable WordPress installation.
Captures login attempts, exposes fake XML-RPC, REST API endpoints, and
logs every request in a unified JSON format.

Part of the MIRAGE Threat Intelligence Project.
"""

import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone

from flask import Flask, request, redirect, jsonify, Response

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_FILE = os.environ.get("HONEYPOT_LOG", "/var/log/honeypot/wordpot.json")
HONEYPOT_NAME = "wordpot"
LISTEN_PORT = int(os.environ.get("HONEYPOT_PORT", 8081))

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

logger = logging.getLogger("wordpot")
logger.setLevel(logging.INFO)
_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(logging.Formatter("[%(asctime)s] %(message)s"))
logger.addHandler(_console)

_log_file_handle = None


def _ensure_log_dir() -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def _get_log_handle():
    global _log_file_handle
    if _log_file_handle is None or _log_file_handle.closed:
        _ensure_log_dir()
        _log_file_handle = open(LOG_FILE, "a", encoding="utf-8")
    return _log_file_handle


def log_event(
    event_type: str,
    source_ip: str = "",
    source_port: int = 0,
    username: str = "",
    password: str = "",
    raw_input: str = "",
    details: dict | None = None,
) -> None:
    """Write a JSON event to the log file and stdout."""
    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": source_port,
        "protocol": "wordpress",
        "honeypot": HONEYPOT_NAME,
        "username": username,
        "password": password,
        "raw_input": raw_input,
        "details": details or {},
    }
    line = json.dumps(record)
    fh = _get_log_handle()
    fh.write(line + "\n")
    fh.flush()
    logger.info(line)


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Disable the default Flask request logger to avoid duplicate output
logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _client_ip() -> str:
    """Return the real client IP, respecting X-Forwarded-For if present."""
    return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")


def _client_port() -> int:
    """Return the client source port when available."""
    try:
        return request.environ.get("REMOTE_PORT", 0)
    except Exception:
        return 0


@app.before_request
def log_all_requests():
    """Log every incoming HTTP request."""
    log_event(
        "connection",
        source_ip=_client_ip(),
        source_port=_client_port(),
        raw_input=f"{request.method} {request.full_path}",
        details={
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode("utf-8", errors="replace"),
            "user_agent": request.headers.get("User-Agent", ""),
        },
    )


# ---- WordPress homepage ----

WP_HOME = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My WordPress Site</title>
<meta name="generator" content="WordPress 6.4.3">
<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">
</head>
<body class="home blog">
<div id="page">
  <header id="masthead">
    <h1 class="site-title"><a href="/">My WordPress Site</a></h1>
    <p class="site-description">Just another WordPress site</p>
  </header>
  <main id="primary">
    <article class="post">
      <h2><a href="/2024/01/hello-world/">Hello world!</a></h2>
      <p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p>
      <footer class="entry-footer">
        <span class="posted-on">Posted on January 1, 2024</span>
        <span class="byline"> by <a href="/author/admin/">admin</a></span>
      </footer>
    </article>
  </main>
  <footer id="colophon">
    <p>Proudly powered by <a href="https://wordpress.org/">WordPress</a></p>
  </footer>
</div>
<!-- Performance optimance by W3 Total Cache -->
</body>
</html>"""


@app.route("/")
def index():
    return WP_HOME, 200, {"Content-Type": "text/html; charset=UTF-8"}


# ---- Login page ----

WP_LOGIN_FORM = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log In &lsaquo; My WordPress Site &#8212; WordPress</title>
<meta name="robots" content="noindex, nofollow">
<style>
body { background: #f0f0f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; }
#login { width: 320px; margin: 10%% auto; }
#login h1 a { background-image: url(/wp-admin/images/wordpress-logo.svg); width: 84px; height: 84px; display: block; margin: 0 auto 25px; text-indent: -9999px; background-size: 84px; }
.login form { background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; padding: 26px 24px; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
.login label { font-size: 14px; }
.login input[type=text], .login input[type=password] { width: 100%%; padding: 5px; font-size: 24px; margin: 2px 0 16px; }
.login .button-primary { width: 100%%; padding: 6px; font-size: 14px; background: #2271b1; border-color: #2271b1; color: #fff; cursor: pointer; border-radius: 3px; }
.login #login_error { border-left: 4px solid #d63638; background: #fff; padding: 12px; margin-bottom: 20px; }
</style>
</head>
<body class="login">
<div id="login">
  <h1><a href="https://wordpress.org/">WordPress</a></h1>
  %(error_block)s
  <form method="post" action="/wp-login.php">
    <label for="user_login">Username or Email Address</label>
    <input type="text" name="log" id="user_login" value="">
    <label for="user_pass">Password</label>
    <input type="password" name="pwd" id="user_pass" value="">
    <p class="forgetmenot"><label><input type="checkbox" name="rememberme" value="forever"> Remember Me</label></p>
    <input type="submit" class="button button-primary" value="Log In">
    <input type="hidden" name="redirect_to" value="/wp-admin/">
  </form>
  <p><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body>
</html>"""

LOGIN_ERROR = '<div id="login_error"><strong>Error:</strong> Invalid username or incorrect password. <a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>'


@app.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    if request.method == "POST":
        username = request.form.get("log", "")
        password = request.form.get("pwd", "")
        log_event(
            "login_attempt",
            source_ip=_client_ip(),
            source_port=_client_port(),
            username=username,
            password=password,
            raw_input=f"POST /wp-login.php log={username}",
        )
        return WP_LOGIN_FORM % {"error_block": LOGIN_ERROR}, 200, {"Content-Type": "text/html; charset=UTF-8"}

    return WP_LOGIN_FORM % {"error_block": ""}, 200, {"Content-Type": "text/html; charset=UTF-8"}


# ---- wp-admin redirect ----

@app.route("/wp-admin/")
@app.route("/wp-admin")
def wp_admin():
    return redirect("/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1", code=302)


# ---- XML-RPC ----

XMLRPC_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>WordPress XML-RPC server accepts POST requests only.</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>"""


@app.route("/xmlrpc.php", methods=["GET", "POST"])
def xmlrpc():
    if request.method == "POST":
        log_event(
            "command",
            source_ip=_client_ip(),
            source_port=_client_port(),
            raw_input=request.get_data(as_text=True)[:2048],
            details={"endpoint": "xmlrpc.php"},
        )
    return Response(XMLRPC_RESPONSE, mimetype="text/xml")


# ---- REST API: users ----

FAKE_USERS = [
    {"id": 1, "name": "admin", "slug": "admin", "description": "", "link": "/author/admin/",
     "avatar_urls": {"24": "", "48": "", "96": ""}},
    {"id": 2, "name": "editor", "slug": "editor", "description": "", "link": "/author/editor/",
     "avatar_urls": {"24": "", "48": "", "96": ""}},
]


@app.route("/wp-json/wp/v2/users")
def wp_users():
    return jsonify(FAKE_USERS)


# ---- REST API: posts ----

FAKE_POSTS = [
    {
        "id": 1, "date": "2024-01-01T00:00:00", "slug": "hello-world",
        "status": "publish", "type": "post",
        "title": {"rendered": "Hello world!"},
        "content": {"rendered": "<p>Welcome to WordPress. This is your first post.</p>"},
        "author": 1, "categories": [1], "tags": [],
    },
]


@app.route("/wp-json/wp/v2/posts")
def wp_posts():
    return jsonify(FAKE_POSTS)


# ---- wp-content directory listing ----

WP_CONTENT_DIR = """<!DOCTYPE html>
<html><head><title>Index of /wp-content/</title></head>
<body>
<h1>Index of /wp-content/</h1>
<pre>
<a href="/wp-content/plugins/">plugins/</a>
<a href="/wp-content/themes/">themes/</a>
<a href="/wp-content/uploads/">uploads/</a>
</pre>
</body></html>"""


@app.route("/wp-content/")
@app.route("/wp-content")
def wp_content():
    return WP_CONTENT_DIR, 200, {"Content-Type": "text/html; charset=UTF-8"}


# ---- readme.html ----

WP_README = """<!DOCTYPE html>
<html><head><title>WordPress &rsaquo; ReadMe</title></head>
<body>
<h1>WordPress</h1>
<p>Version 6.4.3</p>
<p>Semantic Personal Publishing Platform</p>
<h2>First Steps With WordPress</h2>
<ol>
<li>Go to your WordPress dashboard: <a href="/wp-admin/">/wp-admin/</a></li>
<li>Log in using the username and password you chose during the installation.</li>
</ol>
</body></html>"""


@app.route("/readme.html")
def readme():
    return WP_README, 200, {"Content-Type": "text/html; charset=UTF-8"}


# ---- Catch-all 404 ----

WP_404 = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Page not found &#8211; My WordPress Site</title>
<meta name="generator" content="WordPress 6.4.3">
</head>
<body class="error404">
<div id="page">
  <header id="masthead">
    <h1 class="site-title"><a href="/">My WordPress Site</a></h1>
  </header>
  <main id="primary">
    <section class="error-404 not-found">
      <header class="page-header"><h1 class="page-title">Oops! That page can&rsquo;t be found.</h1></header>
      <div class="page-content">
        <p>It looks like nothing was found at this location. Maybe try a search?</p>
      </div>
    </section>
  </main>
  <footer id="colophon">
    <p>Proudly powered by <a href="https://wordpress.org/">WordPress</a></p>
  </footer>
</div>
</body>
</html>"""


@app.errorhandler(404)
def page_not_found(_e):
    return WP_404, 404, {"Content-Type": "text/html; charset=UTF-8"}


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def _handle_signal(sig, _frame):
    """Handle SIGTERM / SIGINT for graceful shutdown."""
    logger.info("Received signal %s — shutting down Wordpot", signal.Signals(sig).name)
    global _log_file_handle
    if _log_file_handle and not _log_file_handle.closed:
        _log_file_handle.close()
    sys.exit(0)


def main():
    """Entry point — start Flask development server."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _ensure_log_dir()
    logger.info("Wordpot honeypot starting on port %d", LISTEN_PORT)

    app.run(host="0.0.0.0", port=LISTEN_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
