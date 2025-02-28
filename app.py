from flask import Flask, request, jsonify, render_template
import subprocess
import time
import sqlite3
import os

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('scan_results.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS findings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT,
                  vulnerability TEXT,
                  severity TEXT,
                  details TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.close()

# Run the crawler (replace with your crawler logic)
def run_crawler(url):
    # Simulate scanning (replace with actual crawler logic)
    time.sleep(5)  # Simulate a delay
    findings = [
        ("SQL Injection Vulnerability", "Critical", url),
        ("XSS Vulnerability", "High", url),
        ("PII Exposure", "Medium", "Found 2 sensitive items")
    ]
    return findings

# Save findings to the database
def save_findings(findings):
    conn = sqlite3.connect('scan_results.db')
    cursor = conn.cursor()
    for finding in findings:
        cursor.execute('''INSERT INTO findings (url, vulnerability, severity, details)
                          VALUES (?, ?, ?, ?)''',
                       (finding[2], finding[0], finding[1], finding[2]))
    conn.commit()
    conn.close()

# Home page
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Render's PORT or default to 5000
    app.run(host="0.0.0.0", port=port, debug=True)

