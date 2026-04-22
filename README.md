# Static JavaScript Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-lightgrey)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight, web-based static analysis tool that scans JavaScript source code for common security vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), Command Injection, and Hardcoded Secrets.

![Scanner Screenshot](screenshots/demo.png)

## Features

- 🔍 **Static Analysis** – Scans JavaScript files without execution.
- 🌐 **Remote URL Scanning** – Fetches and analyzes JavaScript from live websites.
- 📁 **File Upload** – Supports `.js`, `.html`, and `.php` files.
- 🧩 **Embedded Code Extraction** – Extracts JavaScript from HTML `<script>` tags and PHP blocks.
- 🛡️ **CWE Mapping** – Each vulnerability is mapped to its Common Weakness Enumeration (CWE) ID.
- 📊 **Detailed Reports** – Provides line numbers, descriptions, and actionable remediation guidance.
- 🚀 **Web Interface** – Clean, responsive UI built with Bootstrap.

## Vulnerabilities Detected

| Vulnerability | CWE ID |
| :--- | :--- |
| SQL Injection | CWE-89 |
| Cross-Site Scripting (XSS) | CWE-79 |
| Command Injection | CWE-78 |
| Hardcoded Secrets | CWE-798 |
| Insecure `eval()` | CWE-95 |

## Installation

### Prerequisites

- Python 3.10 or higher
- Git

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/group16/static-js-security-scanner.git
   cd static-js-security-scanner
   
  2. Create and activate a virtual environment
   python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

3.Install dependencies
export PIP_BREAK_SYSTEM_PACKAGES=1   # Only needed on Kali Linux
pip install -r requirements.txt

4.Run the application
python app.py

5.Open your browser to http://127.0.0.1:5000

Usage
Scan a Local File

    1.Click "Browse..." and select a .js, .html, or .php file.

    2.Click "Scan Now".

Scan a Remote URL

    1.Enter a URL (e.g., a raw GitHub JavaScript file) in the "Or Enter URL" field.

    2.Click "Scan Now".

The scanner will display a report listing any vulnerabilities found, along with line numbers, CWE IDs, and remediation suggestions.

Project Structure

static-js-scanner/
├── app.py                 # Flask application entry point
├── requirements.txt       # Python dependencies
├── scanner/               # Core scanning engine
│   ├── input_handler.py
│   ├── web_fetcher.py
│   ├── code_extractor.py
│   ├── parser.py
│   ├── core_engine.py
│   ├── cwe_mapper.py
│   ├── vulnerability.py
│   ├── report_generator.py
│   └── rules/             # Vulnerability detection rules
│       ├── sql_injection.py
│       ├── xss.py
│       ├── command_injection.py
│       └── hardcoded_secrets.py
├── web/                   # Web interface routes and forms
│   ├── routes.py
│   └── forms.py
├── templates/             # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── scan_result.html
│   └── error.html
├── static/                # CSS and JavaScript assets
├── data/                  # CWE database (JSON)
└── tests/                 # Unit tests

Contributing

Contributions are welcome! Please follow these steps:

    1.Fork the repository.

    2.Create a new branch: git checkout -b feature/your-feature-name.

    3.Make your changes and commit them: git commit -m 'Add some feature'.

    4.Push to the branch: git push origin feature/your-feature-name.

   5.Open a Pull Request.

Please ensure your code follows the existing style and includes appropriate tests.

Testing

Run the test suite with:
pytest tests/

License

This project is licensed under the MIT License – see the LICENSE file for details.

Authors

    .Brian Kilawe – GitHub

    .Kenneth Maina – GitHub

    .Radhia Kijida – GitHub

    .Princess Michael – GitHub

    .Walter Arobogast – GitHub

*University of Dodoma – Final Year Project 2025/2026*

Acknowledgments

    .OWASP Top 10 and CWE for vulnerability classification.

   . Supervisor: Mr. Bakii
    
   
