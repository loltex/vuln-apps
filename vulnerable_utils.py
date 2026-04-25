# vulnerable_utils.py
# ⚠️  INTENTIONALLY VULNERABLE - FOR SNYK SCANNING / SECURITY EDUCATION ONLY
# DO NOT DEPLOY TO PRODUCTION
# Vulnerabilities: Insecure Deserialization, Weak Cryptography, Open Redirect

import pickle
import hashlib
import base64
from flask import Flask, request, redirect

app = Flask(__name__)

# ----------------------------------------------------------------
# VULN #1: Insecure Deserialization (CWE-502)
# Snyk will flag: "Use of pickle with untrusted data allows arbitrary code execution"
# Fix: Never deserialize untrusted data with pickle.
#      Use safe formats like JSON (json.loads) with schema validation instead.
# ----------------------------------------------------------------
@app.route("/load_session")
def load_session():
    session_data = request.args.get("data")
    # Vulnerable: attacker can craft a pickle payload to execute arbitrary code
    decoded = base64.b64decode(session_data)
    user = pickle.loads(decoded)
    return f"Welcome back, {user.get('name', 'unknown')}"

# ----------------------------------------------------------------
# VULN #2: Weak Cryptography / Broken Hash (CWE-328)
# Snyk will flag: "Use of MD5 is cryptographically weak"
# Fix: Use bcrypt, argon2, or scrypt for passwords.
#      For general hashing use SHA-256 at minimum: hashlib.sha256(...)
# ----------------------------------------------------------------
def hash_password(password: str) -> str:
    # Vulnerable: MD5 is fast and broken — trivially reversible via rainbow tables
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash

# ----------------------------------------------------------------
# VULN #3: Open Redirect (CWE-601)
# Snyk will flag: "Unvalidated redirect destination"
# Fix: Whitelist allowed redirect targets, or only allow relative paths.
#      Check: if not url.startswith("/") or url.startswith("//") → reject.
# ----------------------------------------------------------------
ALLOWED_HOSTS = ["myapp.com"]

@app.route("/login")
def login():
    next_url = request.args.get("next", "/dashboard")
    # Vulnerable: attacker crafts ?next=https://evil.com to redirect after login
    return redirect(next_url)

if __name__ == "__main__":
    app.run()
