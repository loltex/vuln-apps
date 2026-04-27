# fixed_app.py
from flask import Flask, request, abort, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

# ----------------------------------------------------------------
# Fix VULN #1: Hardcoded Secret (CWE-798)
# Load secrets from environment (or a secrets manager)
# ----------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# If you want Flask to use SECRET_KEY:
if SECRET_KEY:
    app.config["SECRET_KEY"] = SECRET_KEY

# ----------------------------------------------------------------
# Fix VULN #2: SQL Injection (CWE-89)
# Use parameterized queries and ensure the id is present
# ----------------------------------------------------------------
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    if user_id is None:
        abort(400, "missing id")

    # Use parameterized query (sqlite3 uses ? placeholders)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        rows = cursor.fetchall()
    finally:
        conn.close()

    return jsonify(rows)

# ----------------------------------------------------------------
# Fix VULN #3: Command Injection (CWE-78)
# Pass arguments as a list with shell=False
# ----------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host")
    if not host:
        abort(400, "missing host")

    # Use a list and shell=False to avoid shell interpretation
    try:
        result = subprocess.check_output(
            ["ping", "-c", "1", host],
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=5,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "output": e.output}), 502
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "timeout"}), 504

    return jsonify({"success": True, "output": result})

if __name__ == "__main__":
    app.run(debug=True)
