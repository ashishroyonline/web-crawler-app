import re
import time
import random
import sqlite3
import csv
import logging
import requests
import os
from flask import Flask, request, jsonify, render_template
from urllib.robotparser import RobotFileParser
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from fpdf import FPDF

# ================ Configuration ================
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
]
REQUEST_DELAY = 2  # Seconds between requests

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ================ Core Classes ================
class EthicalCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        logging.info("EthicalCrawler initialized with user-agent: %s", self.session.headers['User-Agent'])
        
    def check_robots_txt(self, base_url):
        try:
            rp = RobotFileParser()
            robots_url = f"{base_url.rstrip('/')}/robots.txt"
            rp.set_url(robots_url)
            rp.read()
            logging.info("Robots.txt parsed successfully for %s", base_url)
            return rp
        except Exception as e:
            logging.error("Robots.txt error: %s", str(e))
            return None

    def safe_request(self, url):
        try:
            time.sleep(REQUEST_DELAY)
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            return response
        except Exception as e:
            logging.error("Request failed: %s", str(e))
            return None

class VulnerabilityScanner:
    SQLI_PATTERNS = [r'(\%27)|(\')|(--)|(\%23)|(#)', r'((\%3D)|(=))[^\n]*((\%27)|(\')|(--)|(\%3B)|(;))']
    XSS_PATTERNS = [r'<script>.*?</script>', r'onerror\s*=\s*["\']?.*?["\']?']
    GDPR_PATTERNS = [r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b']

    def scan_content(self, text, url):
        findings = []
        for pattern in self.SQLI_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(("SQL Injection Vulnerability", "Critical", url))
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(("XSS Vulnerability", "High", url))
        for pattern in self.GDPR_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                findings.append(("PII Exposure", "Medium", f"Found {len(matches)} sensitive items"))
        return findings

class DynamicAnalyzer:
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
        self.driver = webdriver.Chrome(options=chrome_options)

    def test_xss(self, url):
        try:
            self.driver.get(url)
            payload = "<script>alert('XSS')</script>"
            inputs = self.driver.find_elements(By.TAG_NAME, 'input')
            for input_field in inputs:
                input_field.send_keys(payload)
            if '?' in url:
                self.driver.get(f"{url}&test={payload}")
            if payload in self.driver.page_source:
                return [("XSS Vulnerability (Dynamic)", "Critical", url)]
            return []
        except Exception as e:
            logging.error(f"Dynamic analysis error: {e}")
            return []
        finally:
            self.driver.quit()

class ReportGenerator:
    @staticmethod
    def generate_csv(findings):
        with open('vulnerability_report.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Vulnerability", "Severity", "Details"])
            writer.writerows(findings)
        logging.info("CSV report generated: vulnerability_report.csv")

    @staticmethod
    def generate_pdf(findings):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Vulnerability Assessment Report", ln=1, align='C')
        for idx, finding in enumerate(findings, 1):
            pdf.cell(200, 10, txt=f"{idx}. {finding[0]} ({finding[1]})", ln=1)
            pdf.cell(200, 10, txt=f"Details: {finding[2]}", ln=1)
            pdf.cell(200, 10, txt="-"*50, ln=1)
        pdf.output("vulnerability_report.pdf")
        logging.info("PDF report generated: vulnerability_report.pdf")

class ResultStorage:
    def __init__(self):
        self.conn = sqlite3.connect('scan_results.db')
        self._create_table()

    def _create_table(self):
        self.conn.execute('''CREATE TABLE IF NOT EXISTS findings
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              url TEXT,
              vulnerability TEXT,
              severity TEXT,
              details TEXT,
              timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    def save_finding(self, finding):
        self.conn.execute('''INSERT INTO findings (url, vulnerability, severity, details)
                          VALUES (?, ?, ?, ?)''',
                          (finding[2], finding[0], finding[1], finding[2]))
        self.conn.commit()
        logging.info(f"Finding saved to database: {finding}")

# ================ Flask Application ================
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    crawler = EthicalCrawler()
    scanner = VulnerabilityScanner()
    dynamic_analyzer = DynamicAnalyzer()
    storage = ResultStorage()
    reporter = ReportGenerator()

    response = crawler.safe_request(url)
    if not response:
        return jsonify({"error": "Failed to fetch the URL"}), 500

    static_findings = scanner.scan_content(response.text, url)
    dynamic_findings = dynamic_analyzer.test_xss(url)
    
    all_findings = static_findings + dynamic_findings
    
    for finding in all_findings:
        storage.save_finding(finding)
    
    reporter.generate_csv(all_findings)
    reporter.generate_pdf(all_findings)

    return jsonify({"findings": all_findings})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
