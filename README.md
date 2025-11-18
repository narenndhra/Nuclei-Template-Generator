# Nuclei Template Generator - Python Edition

A standalone Python application for generating Nuclei templates with an improved modern UI.  
This is a Python port of the original PortSwigger Nuclei Template Generator.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

### 🎯 Template Generation
- GUI-based Nuclei template builder  
- Parse raw HTTP requests & responses  
- Auto-create word, regex, status & binary matchers  
- Multi-line selection splitting  
- Auto-detect header/body part  
- Auto-add response status matchers  

### 📝 Template Editing
- YAML syntax highlighting  
- CVE/CWE/Severity classification  
- Modify existing templates  
- Supports multiple matcher types  

### ⚡ Template Execution
- Run templates directly inside the UI  
- Auto-generate full Nuclei CLI commands  
- Command history & re-run  
- Real-time colorized output  
- CLI flag helper  

### 🎨 UI & Productivity
- Light/Dark themes  
- Adjustable font sizes  
- Persistent configuration  
- Keyboard shortcuts  
- Modern clean layout  

# Installation

## 1. Install Nuclei

### Linux / macOS
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
brew install nuclei
sudo apt install nuclei
```

### Windows
1. Download latest **windows_amd64.zip** from:  
   https://github.com/projectdiscovery/nuclei/releases

2. Extract it.

3. Move folder to:
```
C:\Program Files\nuclei
```

4. Set PATH (PowerShell Admin):
```powershell
setx PATH "$env:PATH;C:\Program Files\nuclei"
```

5. Verify:
```powershell
nuclei -version
```

## 2. Install Python Application

### Clone
```bash
git clone https://github.com/your-username/nuclei-template-generator-python
cd nuclei-template-generator-python
```

### Virtual environment
```bash
python -m venv venv
```

Activate:

Linux/macOS:
```bash
source venv/bin/activate
```

Windows:
```powershell
venv\Scripts\activate
```

### Install requirements
```bash
pip install -r requirements.txt
```

### Run
```bash
python nuclei_generator.py
```

# Usage

1. Paste HTTP request/response  
2. Create matchers  
3. Generate template YAML  
4. Execute template  

# License
MIT License

**Happy Template Hunting! 🎯**
