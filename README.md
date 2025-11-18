# Nuclei Template Generator - Python Edition

A standalone Python application for generating Nuclei templates with an improved modern UI.  
This is a Python port of the original PortSwigger Nuclei Template Generator.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## Features

### 🎯 Template Generation
- Visual GUI for creating Nuclei templates  
- Paste raw HTTP requests & responses  
- Automatic matcher generation (word, regex, binary)  
- Multi-line text selection → auto-split into matchers  
- Auto-detect matcher part (header/body)  
- Auto-add status matcher from HTTP response  

### 📝 Template Editing
- YAML syntax highlighting  
- Add CVE, CWE, CVSS scoring  
- Edit/update existing templates  
- Multiple matcher type support  

### ⚡ Template Execution
- Execute templates directly  
- Auto-generate Nuclei CLI command  
- Execution history + rerun  
- Colorized live output  
- CLI flag helper window  

### 🎨 UI & Productivity
- Light & Dark themes  
- Adjustable fonts  
- Persistent settings  
- Keyboard shortcuts  
- Modern interface  

---

# Installation

## 1. Install Nuclei

### **Linux / macOS**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# or package managers
brew install nuclei        # macOS
sudo apt install nuclei    # Ubuntu/Debian
```

---

### **Windows Installation Guide**

1. Visit:  
   https://github.com/projectdiscovery/nuclei/releases

2. Download the latest release:  
   **nuclei_*_windows_amd64.zip**

3. Extract the ZIP file.

4. Move the folder to:
```
C:\Program Files
uclei
```

5. Open **PowerShell (Run as Administrator)** and set PATH:
```powershell
setx PATH "$env:PATH;C:\Program Files
uclei"
```

6. Verify installation:
```powershell
nuclei -version
```

---

# 2. Install Python Application

### Clone the project
```bash
git clone https://github.com/your-username/nuclei-template-generator-python
cd nuclei-template-generator-python
```

### Create virtual environment
```bash
python -m venv venv
```

Activate:

**Linux/macOS**
```bash
source venv/bin/activate
```

**Windows**
```powershell
venv\Scriptsctivate
```

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run the application
```bash
python nuclei_generator.py
```

---

# Usage Guide

### 1. Paste Request/Response
Paste raw HTTP request & response into the text panels.

### 2. Create Matchers
Select text → click **Add Matcher from Selection**  
(or use Add Word/Add Regex manually)

### 3. Generate Template
Fill template fields → click **Generate Template YAML**

### 4. Execute Template
Switch to Execute tab → enter target → click Run

---

# Example Templates

### SQL Injection
```yaml
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
```

### Reflected XSS
```yaml
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
```

---

# Troubleshooting

### Nuclei not found
```bash
nuclei -version
```

### PyQt6 issues
```bash
pip install --upgrade PyQt6
```

### YAML errors
- Use 2 spaces indentation  
- Ensure fields exist: `id`, `info`, `requests`  

---

# License
MIT License

---

**Happy Template Hunting! 🎯**
