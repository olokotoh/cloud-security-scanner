#!/usr/bin/env python3
"""
Vulnerable Flask Application for Security Training
WARNING: This application contains intentional security vulnerabilities
DO NOT deploy in production!
"""

from flask import Flask, request, render_template_string, session, redirect
import sqlite3
import os
import pickle
import base64
import subprocess

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret key
app.secret_key = "super_secret_key_123"
API_KEY = 'fndjdjsjc8g8g8shnsnsnendnndndneskwkkS'

# VULNERABILITY 2: Debug mode enabled
app.config['DEBUG'] = True

# Hardcoded database credentials
DB_USER = "admin"
DB_PASSWORD = "Password123!"
API_KEY = "sk-1234567890abcdef"

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user@example.com')")
    conn.commit()
    conn.close()

init_db()

# Home page with XSS vulnerability
@app.route('/')
def index():
    # VULNERABILITY 3: XSS - No input sanitization
    name = request.args.get('name', 'Guest')
    template = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable App</title></head>
    <body>
        <h1>Welcome {name}!</h1>
        <h2>Vulnerable Features:</h2>
        <ul>
            <li><a href="/search">User Search (SQL Injection)</a></li>
            <li><a href="/ping">Ping Tool (Command Injection)</a></li>
            <li><a href="/admin">Admin Panel (Auth Bypass)</a></li>
            <li><a href="/profile">Profile (Insecure Deserialization)</a></li>
        </ul>
    </body>
    </html>
    '''
    return render_template_string(template)

# VULNERABILITY 4: SQL Injection
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # Vulnerable SQL query - direct string concatenation
        sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
        try:
            c.execute(sql)
            results = c.fetchall()
            conn.close()
            return f"<h1>Search Results:</h1><pre>{results}</pre><br><a href='/search'>Back</a>"
        except Exception as e:
            return f"<h1>Error:</h1><pre>{str(e)}</pre>"

    return '''
    <html>
    <body>
        <h1>User Search</h1>
        <form action="/search">
            <input type="text" name="q" placeholder="Search username">
            <input type="submit" value="Search">
        </form>
        <p>Try: admin' OR '1'='1</p>
    </body>
    </html>
    '''

# VULNERABILITY 5: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if host:
        # Vulnerable - direct command execution with user input
        try:
            result = subprocess.check_output(f"ping -c 2 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5)
            return f"<h1>Ping Results:</h1><pre>{result.decode()}</pre><br><a href='/ping'>Back</a>"
        except Exception as e:
            return f"<h1>Error:</h1><pre>{str(e)}</pre>"

    return '''
    <html>
    <body>
        <h1>Ping Tool</h1>
        <form action="/ping">
            <input type="text" name="host" placeholder="Enter host">
            <input type="submit" value="Ping">
        </form>
        <p>Try: 127.0.0.1; ls -la</p>
    </body>
    </html>
    '''

# VULNERABILITY 6: Missing authentication/authorization
@app.route('/admin')
def admin():
    # No authentication check!
    return f'''
    <html>
    <body>
        <h1>Admin Panel</h1>
        <p>Database Password: {DB_PASSWORD}</p>
        <p>API Key: {API_KEY}</p>
        <p>Secret Key: {app.secret_key}</p>
        <h2>All Users:</h2>
        <pre>{get_all_users()}</pre>
    </body>
    </html>
    '''

def get_all_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    results = c.fetchall()
    conn.close()
    return results

# VULNERABILITY 7: Insecure Deserialization
@app.route('/profile')
def profile():
    profile_data = request.args.get('data', '')
    if profile_data:
        try:
            # Vulnerable - deserializing untrusted data
            decoded = base64.b64decode(profile_data)
            user_obj = pickle.loads(decoded)
            return f"<h1>Profile:</h1><pre>{user_obj}</pre>"
        except Exception as e:
            return f"<h1>Error:</h1><pre>{str(e)}</pre>"

    return '''
    <html>
    <body>
        <h1>User Profile</h1>
        <p>Provide base64 encoded profile data</p>
        <form action="/profile">
            <input type="text" name="data" placeholder="Base64 encoded data">
            <input type="submit" value="Load Profile">
        </form>
    </body>
    </html>
    '''

# VULNERABILITY 8: Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('name', 'app.py')
    try:
        # Vulnerable - no path validation
        with open(filename, 'r') as f:
            content = f.read()
        return f"<h1>File: {filename}</h1><pre>{content}</pre>"
    except Exception as e:
        return f"<h1>Error:</h1><pre>{str(e)}</pre>"

# VULNERABILITY 9: SSRF (Server-Side Request Forgery)
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', '')
    if url:
        try:
            import urllib.request
            # Vulnerable - no URL validation
            response = urllib.request.urlopen(url)
            content = response.read()
            return f"<h1>Fetched Content:</h1><pre>{content[:1000]}</pre>"
        except Exception as e:
            return f"<h1>Error:</h1><pre>{str(e)}</pre>"

    return '''
    <html>
    <body>
        <h1>URL Fetcher</h1>
        <form action="/fetch">
            <input type="text" name="url" placeholder="Enter URL">
            <input type="submit" value="Fetch">
        </form>
    </body>
    </html>
    '''

if __name__ == '__main__':
    # VULNERABILITY 10: Listening on all interfaces with debug mode
    app.run(host='0.0.0.0', port=5000, debug=True)
