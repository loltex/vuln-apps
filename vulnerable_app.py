from flask import Flask, request, abort, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

# Load secrets from environment
SECRET_KEY = os.environ.get("SECRET_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Parameterized (safe) query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    rows = cursor.fetchall()
    # Don’t forget to close a connection 
    conn.close()
    return jsonify(rows)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Use a list and shell=False to avoid command injection
    result = subprocess.check_output(["ping", "-c", "1", host], shell=False, text=True)
    return result

if __name__ == "__main__":
    app.run(debug=True)
