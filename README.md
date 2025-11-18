# Nuclei Template Generator - Python Edition

A standalone Python application for generating Nuclei templates with an improved modern UI.  
This is a Python port of the original [PortSwigger Nuclei Template Generator](https://github.com/portswigger/nuclei-template-generator) Burp Suite plugin.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## Features

### 🎯 Template Generation
- Intuitive GUI for building Nuclei templates
- Paste and parse raw HTTP requests and responses
- Auto-generate word, regex, status, and binary matchers from selections
- Multi-line selection splitting
- Auto-detect body/header part for matchers
- Status matcher auto-added from response
- Smart binary matcher detection for non-ASCII data

### 📝 Template Editing
- YAML syntax highlighting
- CVE/CWE/Severity classification dialog
- Edit and modify existing templates
- Supports multiple matcher types

### ⚡ Template Execution
- Run templates directly inside the application
- Auto-generate full Nuclei CLI commands
- Command history & re-execution
- Real-time, colorized nuclei output
- CLI flag helper panel

### ⌨️ Productivity & UI
- Dark/Light themes
- Adjustable fonts
- Clean modern layout
- Persistent configuration
- Many keyboard shortcuts:
  - `Ctrl+N` New template  
  - `Ctrl+O` Open template  
  - `Ctrl+S` Save  
  - `Ctrl+Enter` Execute  
  - `Ctrl+R` CLI flags helper  
  - `Ctrl++/-` Font size  
  - `Ctrl+Q` Quit  
  - `Ctrl+Tab` Switch tab  

---

# Installation

## 1. Install Nuclei

### **Linux / macOS**
```bash
# Option 1: Install via Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Option 2: Install via package manager
# macOS (Homebrew)
brew install nuclei

# Debian/Ubuntu
sudo apt install nuclei
Windows Installation (Simple Guide)
Visit the official Nuclei releases page:
https://github.com/projectdiscovery/nuclei/releases

Download the latest:
nuclei_X.Y.Z_windows_amd64.zip

Unzip it.

Move the extracted nuclei folder to:

makefile
Copy code
C:\Program Files\nuclei
Open PowerShell as Administrator and set PATH:

powershell
Copy code
setx PATH "$env:PATH;C:\Program Files\nuclei"
Close and reopen PowerShell, then verify:

powershell
Copy code
nuclei -version
2. Install Python Application
Clone the project
bash
Copy code
git clone https://github.com/your-username/nuclei-template-generator-python
cd nuclei-template-generator-python
Create a virtual environment (recommended)
bash
Copy code
python -m venv venv
Activate it:

Linux/macOS

bash
Copy code
source venv/bin/activate
Windows

powershell
Copy code
venv\Scripts\activate
Install dependencies
bash
Copy code
pip install -r requirements.txt
Run the application
bash
Copy code
python nuclei_generator.py
Usage Guide
1. Paste Request/Response
Insert raw HTTP request and response into the respective panels.

2. Create Matchers
Select text → click “Add Matcher from Selection”
or add matchers manually.

3. Generate Template
Fill template metadata → click Generate Template YAML.

4. Execute
Use the Execute tab to run your template and see output instantly.

Example Templates
SQL Injection
yaml
Copy code
id: sql-injection-test
info:
  name: SQL Injection Test
  author: security-team
  severity: high
  tags: sqli, injection
requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/users?id=1'"
    matchers:
      - type: word
        part: body
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-01756"
      - type: status
        status:
          - 500
Reflected XSS
yaml
Copy code
id: xss-reflected
info:
  name: Reflected XSS
  author: security-team
  severity: medium
  tags: xss, injection
requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=<script>alert(1)</script>"
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(1)</script>"
      - type: word
        part: header
        words:
          - "text/html"
      - type: status
        status:
          - 200
Troubleshooting
Nuclei Not Found
Verify installation:

bash
Copy code
nuclei -version
PyQt6 Issues
bash
Copy code
pip install --upgrade PyQt6
YAML Errors
Check indentation (2 spaces)

Ensure required fields: id, info, requests

Roadmap
Request/response history

Template validation

Template testing framework

Bulk creation

Marketplace integration

Template diff viewer

License
MIT License — same as the original Burp Suite plugin.

Happy Template Hunting! 🎯


