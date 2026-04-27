# fixed_utils.py
import json
import hashlib
import base64
from flask import Flask, request, redirect, abort, jsonify

app = Flask(__name__)

# ----------------------------------------------------------------
# FIX VULN #1: Insecure Deserialization (CWE-502)
# Use JSON instead of pickle for safe deserialization.
# ----------------------------------------------------------------
@app.route("/load_session")
def load_session():
    session_data = request.args.get("data")
    decoded = base64.b64decode(session_data)
    user = json.loads(decoded)
    return f"Welcome back, {user.get('name', 'unknown')}"

# ----------------------------------------------------------------
# FIX VULN #2: Weak Cryptography / Broken Hash (CWE-328)
# Use SHA-256 (at minimum) for general hashing; password hashing should use a slow KDF.
# Here we replace MD5 with SHA-256 (keep simple per request).
# ----------------------------------------------------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash

# ----------------------------------------------------------------
# FIX VULN #3: Open Redirect (CWE-601)
# Allow only relative paths (starting with "/") to prevent external redirects.
# ----------------------------------------------------------------
ALLOWED_HOSTS = ["myapp.com"]

@app.route("/login")
def login():
    next_url = request.args.get("next", "/dashboard")
    # Accept only relative paths to avoid open redirect
    if not isinstance(next_url, str) or not next_url.startswith("/") or next_url.startswith("//"):
        abort(400, "invalid redirect")
    return redirect(next_url)

if __name__ == "__main__":
    app.run()
