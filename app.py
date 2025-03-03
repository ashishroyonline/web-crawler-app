from flask import Flask, request, jsonify, render_template
import sqlite3
import os
import time

app = Flask(__name__)

# Define database path for Render's environment
DB_PATH = "/tmp/scan_results.db"

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS findings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT,
                  vulnerability TEXT,
                  severity TEXT,
                  details TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.close()

# Simulated web crawling function
def run_crawler(url):
    time.sleep(5)  # Simulating scanning delay
    findings = [
        ("SQL Injection Vulnerability", "Critical", url),
        ("XSS Vulnerability", "High", url),
        ("PII Exposure", "Medium", "Found 2 sensitive items")
    ]
    return findings

# Save findings to the database
def save_findings(findings):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for finding in findings:
        cursor.execute('''INSERT INTO findings (url, vulnerability, severity, details)
                          VALUES (?, ?, ?, ?)''',
                       (finding[2], finding[0], finding[1], finding[2]))
    conn.commit()
    conn.close()

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Scan endpoint
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    findings = run_crawler(url)
    save_findings(findings)
    
    return jsonify({"findings": findings})

# Run the application
if __name__ == "__main__":
    init_db()  # Ensure database is created before starting the app
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)  # Use debug=False for production
