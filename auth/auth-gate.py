#!/usr/bin/env python3
"""
IceLaborVPN Authentication Gate v2
Validates authentication via Guacamole before allowing access to any service.

All services (including Guacamole) are protected. Users authenticate via
the /auth/login page which validates credentials against Guacamole's API.
"""

import os
import json
import secrets
import time
import subprocess
import urllib.request
import urllib.error
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse, urlencode

# Configuration
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8089
SESSION_TIMEOUT = 3600 * 8  # 8 hours
GUACAMOLE_API = 'http://127.0.0.1:8085/guacamole/api'
SECRET_KEY = os.environ.get('AUTH_SECRET_KEY', secrets.token_hex(32))

# In-memory session store
sessions = {}

def authenticate_guacamole(username, password, totp=None):
    """Authenticate against Guacamole API and return token if successful."""
    try:
        # Build auth data
        auth_data = f"username={urllib.parse.quote(username)}&password={urllib.parse.quote(password)}"
        if totp:
            auth_data += f"&guac-totp={urllib.parse.quote(totp)}"

        url = f"{GUACAMOLE_API}/tokens"
        req = urllib.request.Request(
            url,
            data=auth_data.encode('utf-8'),
            method='POST'
        )
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')

        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                return {
                    'success': True,
                    'token': data.get('authToken'),
                    'username': data.get('username'),
                    'dataSource': data.get('dataSource')
                }
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8', errors='ignore')
        print(f"[AUTH] Guacamole auth failed: {e.code} - {error_body[:200]}")

        # Check if TOTP is required
        if e.code == 403 and 'TOTP' in error_body.upper():
            return {'success': False, 'need_totp': True, 'error': 'TOTP required'}

        return {'success': False, 'error': f'Authentication failed (HTTP {e.code})'}
    except Exception as e:
        print(f"[AUTH] Error authenticating: {e}")
        return {'success': False, 'error': str(e)}

def verify_guacamole_token(token, data_source='postgresql'):
    """Verify a Guacamole auth token is valid."""
    try:
        url = f"{GUACAMOLE_API}/session/data/{data_source}/self?token={token}"
        req = urllib.request.Request(url, method='GET')
        req.add_header('Accept', 'application/json')

        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except:
        return False

def create_session(username):
    """Create a new session and return the session ID."""
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        'username': username,
        'created': time.time(),
        'last_access': time.time()
    }
    return session_id

def verify_session(session_id):
    """Verify a session is valid and not expired."""
    if not session_id or session_id not in sessions:
        return False

    session = sessions[session_id]
    if time.time() - session['created'] > SESSION_TIMEOUT:
        del sessions[session_id]
        return False

    session['last_access'] = time.time()
    return True

def get_session_user(session_id):
    """Get the username for a session."""
    if session_id and session_id in sessions:
        return sessions[session_id].get('username')
    return None

def cleanup_sessions():
    """Remove expired sessions."""
    now = time.time()
    expired = [sid for sid, s in sessions.items() if now - s['created'] > SESSION_TIMEOUT]
    for sid in expired:
        del sessions[sid]

# ==========================================================================
# Fail2ban Management
# ==========================================================================

def get_fail2ban_status():
    """Get status of all fail2ban jails with banned IPs."""
    try:
        result = subprocess.run(
            ['sudo', 'fail2ban-client', 'status'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return {'error': 'Failed to query fail2ban'}

        # Parse jail list from output
        jails = []
        for line in result.stdout.splitlines():
            if 'Jail list:' in line:
                jail_names = [j.strip() for j in line.split(':', 1)[1].split(',')]
                break
        else:
            return {'jails': [], 'total_banned': 0}

        total_banned = 0
        for jail_name in jail_names:
            jail_info = _get_jail_status(jail_name)
            if jail_info:
                jails.append(jail_info)
                total_banned += jail_info['currently_banned']

        return {'jails': jails, 'total_banned': total_banned}
    except Exception as e:
        print(f"[AUTH] fail2ban status error: {e}")
        return {'error': str(e)}

def _get_jail_status(jail_name):
    """Get detailed status for a single jail."""
    try:
        result = subprocess.run(
            ['sudo', 'fail2ban-client', 'status', jail_name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None

        info = {
            'name': jail_name,
            'currently_failed': 0,
            'total_failed': 0,
            'currently_banned': 0,
            'total_banned': 0,
            'banned_ips': []
        }

        for line in result.stdout.splitlines():
            line = line.strip()
            if 'Currently failed:' in line:
                info['currently_failed'] = int(line.split(':')[-1].strip())
            elif 'Total failed:' in line:
                info['total_failed'] = int(line.split(':')[-1].strip())
            elif 'Currently banned:' in line:
                info['currently_banned'] = int(line.split(':')[-1].strip())
            elif 'Total banned:' in line:
                info['total_banned'] = int(line.split(':')[-1].strip())
            elif 'Banned IP list:' in line:
                ip_str = line.split(':',1)[-1].strip()
                if ip_str:
                    info['banned_ips'] = [ip.strip() for ip in ip_str.split()]

        return info
    except Exception as e:
        print(f"[AUTH] jail status error for {jail_name}: {e}")
        return None

def fail2ban_unban(jail, ip):
    """Unban an IP from a specific jail."""
    # Validate inputs to prevent command injection
    if not jail.replace('-', '').replace('_', '').isalnum():
        return {'success': False, 'error': 'Invalid jail name'}
    if not _is_valid_ip(ip):
        return {'success': False, 'error': 'Invalid IP address'}

    try:
        result = subprocess.run(
            ['sudo', 'fail2ban-client', 'set', jail, 'unbanip', ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print(f"[AUTH] Unbanned {ip} from {jail}")
            return {'success': True}
        else:
            return {'success': False, 'error': result.stderr.strip() or result.stdout.strip()}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def fail2ban_ban(jail, ip, bantime=None):
    """Ban an IP in a specific jail, optionally with custom bantime."""
    if not jail.replace('-', '').replace('_', '').isalnum():
        return {'success': False, 'error': 'Invalid jail name'}
    if not _is_valid_ip(ip):
        return {'success': False, 'error': 'Invalid IP address'}

    try:
        # First unban if already banned (to reset timer)
        subprocess.run(
            ['sudo', 'fail2ban-client', 'set', jail, 'unbanip', ip],
            capture_output=True, text=True, timeout=5
        )
        # Now ban with optional custom bantime
        cmd = ['sudo', 'fail2ban-client', 'set', jail, 'banip', ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[AUTH] Banned {ip} in {jail}")
            return {'success': True}
        else:
            return {'success': False, 'error': result.stderr.strip() or result.stdout.strip()}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def _is_valid_ip(ip):
    """Basic IP address validation."""
    import re
    # IPv4
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return all(0 <= int(p) <= 255 for p in ip.split('.'))
    # IPv6 (simplified check)
    if re.match(r'^[0-9a-fA-F:]+$', ip) and ':' in ip:
        return True
    return False

# HTML Templates
LOGIN_PAGE = '''<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IceLaborVPN - Login</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d1117 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            color: #fff;
        }}
        .container {{
            max-width: 420px;
            width: 100%;
        }}
        .logo {{ font-size: 4em; text-align: center; margin-bottom: 20px; }}
        h1 {{
            font-size: 1.8em;
            text-align: center;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #64ffda, #48bb78);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .subtitle {{
            text-align: center;
            color: #8892b0;
            margin-bottom: 30px;
        }}
        .login-box {{
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(100,255,218,0.2);
            border-radius: 16px;
            padding: 30px;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            color: #8892b0;
            margin-bottom: 8px;
            font-size: 0.9em;
        }}
        input {{
            width: 100%;
            padding: 12px 15px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(100,255,218,0.2);
            border-radius: 8px;
            color: #fff;
            font-size: 1em;
            transition: border-color 0.2s;
        }}
        input:focus {{
            outline: none;
            border-color: #64ffda;
        }}
        input::placeholder {{
            color: #4a5568;
        }}
        .btn {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(90deg, #64ffda, #48bb78);
            border: none;
            border-radius: 8px;
            color: #0f0f23;
            font-size: 1em;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(100,255,218,0.3);
        }}
        .btn:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }}
        .error {{
            background: rgba(255,107,107,0.1);
            border: 1px solid rgba(255,107,107,0.3);
            color: #ff6b6b;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9em;
        }}
        .info {{
            background: rgba(100,255,218,0.05);
            border: 1px solid rgba(100,255,218,0.2);
            color: #64ffda;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.85em;
            text-align: center;
        }}
        .back {{
            text-align: center;
            margin-top: 20px;
        }}
        .back a {{
            color: #64ffda;
            text-decoration: none;
        }}
        .back a:hover {{
            text-decoration: underline;
        }}
        .spinner {{
            display: none;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(15,15,35,0.3);
            border-top-color: #0f0f23;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 10px;
        }}
        .btn.loading .spinner {{ display: inline-block; }}
        .btn.loading {{ display: flex; align-items: center; justify-content: center; }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔐</div>
        <h1>IceLaborVPN Login</h1>
        <p class="subtitle">Authenticate with your Guacamole credentials</p>

        <div class="login-box">
            {error}

            <div class="info">
                🛡️ Protected by fail2ban and TOTP 2FA
            </div>

            <form method="POST" action="/auth/login" id="loginForm">
                <input type="hidden" name="redirect" value="{redirect}">

                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required
                           placeholder="Enter your username" autocomplete="username">
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required
                           placeholder="Enter your password" autocomplete="current-password">
                </div>

                <div class="form-group">
                    <label for="totp">TOTP Code (2FA)</label>
                    <input type="text" id="totp" name="totp" required
                           placeholder="6-digit code from authenticator app"
                           pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code">
                </div>

                <button type="submit" class="btn" id="submitBtn">
                    <span class="spinner"></span>
                    <span class="btn-text">Login</span>
                </button>
            </form>
        </div>

        <div class="back">
            <a href="/">← Back to Home</a>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function() {{
            const btn = document.getElementById('submitBtn');
            btn.classList.add('loading');
            btn.disabled = true;
            document.querySelector('.btn-text').textContent = 'Authenticating...';
        }});
    </script>
</body>
</html>'''

SUCCESS_PAGE = '''<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="2;url={redirect}">
    <title>IceLaborVPN - Login Successful</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d1117 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #fff;
        }}
        .container {{ text-align: center; }}
        .icon {{ font-size: 4em; margin-bottom: 20px; }}
        h1 {{ color: #64ffda; margin-bottom: 10px; }}
        p {{ color: #8892b0; }}
        a {{ color: #64ffda; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h1>Authentication Successful</h1>
        <p>Welcome, {username}! Redirecting...</p>
        <p><a href="{redirect}">Click here if not redirected</a></p>
    </div>
</body>
</html>'''

class AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[AUTH] {self.address_string()} - {format % args}")

    def get_cookie(self, name):
        if 'Cookie' not in self.headers:
            return None
        cookie = SimpleCookie(self.headers['Cookie'])
        if name in cookie:
            return cookie[name].value
        return None

    def set_cookie(self, name, value, max_age=SESSION_TIMEOUT, path='/'):
        cookie = f"{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
        self.send_header('Set-Cookie', cookie)

    def clear_cookie(self, name, path='/'):
        cookie = f"{name}=; Path={path}; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
        self.send_header('Set-Cookie', cookie)

    def send_html(self, status, html):
        body = html.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, data):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if len(sessions) > 100:
            cleanup_sessions()

        if path == '/auth/verify':
            # nginx auth_request endpoint
            session_id = self.get_cookie('icelabor_session')
            if verify_session(session_id):
                self.send_response(200)
                self.end_headers()
            else:
                self.send_response(401)
                self.end_headers()

        elif path == '/auth/login':
            redirect_to = query.get('redirect', ['/'])[0]
            # Sanitize redirect to prevent open redirect
            if not redirect_to.startswith('/'):
                redirect_to = '/'

            html = LOGIN_PAGE.format(redirect=redirect_to, error='')
            self.send_html(200, html)

        elif path == '/auth/logout':
            session_id = self.get_cookie('icelabor_session')
            if session_id and session_id in sessions:
                del sessions[session_id]

            self.send_response(302)
            self.clear_cookie('icelabor_session')
            self.send_header('Location', '/')
            self.end_headers()

        elif path == '/auth/status':
            session_id = self.get_cookie('icelabor_session')
            is_auth = verify_session(session_id)
            username = get_session_user(session_id) if is_auth else None

            self.send_json(200, {
                'authenticated': is_auth,
                'username': username
            })

        elif path == '/auth/fail2ban':
            # Fail2ban status - requires authentication
            session_id = self.get_cookie('icelabor_session')
            if not verify_session(session_id):
                self.send_json(401, {'error': 'Not authenticated'})
                return

            status = get_fail2ban_status()
            self.send_json(200, status)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        if path == '/auth/fail2ban/unban':
            # Unban IP - requires authentication
            session_id = self.get_cookie('icelabor_session')
            if not verify_session(session_id):
                self.send_json(401, {'error': 'Not authenticated'})
                return

            try:
                data = json.loads(body.decode('utf-8'))
                jail = data.get('jail', '')
                ip = data.get('ip', '')
            except (json.JSONDecodeError, AttributeError):
                self.send_json(400, {'error': 'Invalid JSON'})
                return

            if not jail or not ip:
                self.send_json(400, {'error': 'Missing jail or ip'})
                return

            user = get_session_user(session_id)
            print(f"[AUTH] User {user} requested unban of {ip} from {jail}")
            result = fail2ban_unban(jail, ip)
            self.send_json(200 if result['success'] else 400, result)
            return

        elif path == '/auth/fail2ban/ban':
            # Ban IP - requires authentication
            session_id = self.get_cookie('icelabor_session')
            if not verify_session(session_id):
                self.send_json(401, {'error': 'Not authenticated'})
                return

            try:
                data = json.loads(body.decode('utf-8'))
                jail = data.get('jail', '')
                ip = data.get('ip', '')
            except (json.JSONDecodeError, AttributeError):
                self.send_json(400, {'error': 'Invalid JSON'})
                return

            if not jail or not ip:
                self.send_json(400, {'error': 'Missing jail or ip'})
                return

            user = get_session_user(session_id)
            print(f"[AUTH] User {user} requested ban of {ip} in {jail}")
            result = fail2ban_ban(jail, ip)
            self.send_json(200 if result['success'] else 400, result)
            return

        elif path == '/auth/login':
            # Parse form data
            form_data = parse_qs(body.decode('utf-8'))
            username = form_data.get('username', [''])[0]
            password = form_data.get('password', [''])[0]
            totp = form_data.get('totp', [''])[0]
            redirect_to = form_data.get('redirect', ['/'])[0]

            # Sanitize redirect
            if not redirect_to.startswith('/'):
                redirect_to = '/'

            if not username or not password:
                error_html = '<div class="error">Username and password are required</div>'
                html = LOGIN_PAGE.format(redirect=redirect_to, error=error_html)
                self.send_html(400, html)
                return

            # Authenticate against Guacamole
            result = authenticate_guacamole(username, password, totp)

            if result['success']:
                # Create session
                session_id = create_session(result.get('username', username))

                # Send success page with cookie
                html = SUCCESS_PAGE.format(
                    username=result.get('username', username),
                    redirect=redirect_to
                )

                self.send_response(200)
                self.set_cookie('icelabor_session', session_id)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                body = html.encode('utf-8')
                self.send_header('Content-Length', len(body))
                self.end_headers()
                self.wfile.write(body)
            else:
                # Show error
                error_msg = result.get('error', 'Authentication failed')
                if result.get('need_totp'):
                    error_msg = 'TOTP code is required'

                error_html = f'<div class="error">{error_msg}</div>'
                html = LOGIN_PAGE.format(redirect=redirect_to, error=error_html)
                self.send_html(401, html)

        else:
            self.send_response(404)
            self.end_headers()

def main():
    print(f"[AUTH] IceLaborVPN Auth Gate v2 starting on {LISTEN_HOST}:{LISTEN_PORT}")
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), AuthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[AUTH] Shutting down...")
        server.shutdown()

if __name__ == '__main__':
    main()
