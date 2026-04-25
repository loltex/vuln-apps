# vulnerable_app.py
# ⚠️  INTENTIONALLY VULNERABLE - FOR SNYK SCANNING / SECURITY EDUCATION ONLY
# DO NOT DEPLOY TO PRODUCTION
# Vulnerabilities: SQL Injection, Command Injection, Hardcoded Secret

from flask import Flask, request
import sqlite3
import os
import subprocess

app = Flask(__name__)

# ----------------------------------------------------------------
# VULN #1: Hardcoded Secret (CWE-798)
# Snyk will flag: "Use of hardcoded credentials"
# Fix: Load from environment variable or secrets manager
# ----------------------------------------------------------------
SECRET_KEY = "supersecret123"
DB_PASSWORD = "admin:password123"

# ----------------------------------------------------------------
# VULN #2: SQL Injection (CWE-89)
# Snyk will flag: "Unsanitized input flows into SQL query"
# Fix: Use parameterized queries → cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
# ----------------------------------------------------------------
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerable: user input directly concatenated into query
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return str(cursor.fetchall())

# ----------------------------------------------------------------
# VULN #3: Command Injection (CWE-78)
# Snyk will flag: "Unsanitized input passed to shell command"
# Fix: Use subprocess with a list and shell=False, validate input strictly
# ----------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Vulnerable: user input passed directly to shell
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result

if __name__ == "__main__":
    app.run(debug=True)
