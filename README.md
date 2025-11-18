# Nuclei Template Generator - Python Edition

A standalone Python application for generating Nuclei templates with an improved modern UI. This is a Python port of the [PortSwigger Nuclei Template Generator](https://github.com/portswigger/nuclei-template-generator) Burp Suite plugin.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

### 🎯 Template Generation
- **Visual Template Creation**: Create Nuclei templates through an intuitive GUI
- **HTTP Request/Response Parsing**: Paste HTTP requests and responses directly
- **Automatic Matcher Creation**: Select text to automatically create word, regex, or binary matchers
- **Multi-line Selection Support**: Automatically splits multi-line selections into separate words
- **Binary Matcher Detection**: Auto-creates binary matchers for non-ASCII characters
- **Smart Part Detection**: Auto-sets the 'part' field (header/body) based on selection location
- **Status Matcher Auto-inclusion**: Every template includes a status matcher from the response

### 📝 Template Editing
- **Syntax Highlighting**: YAML syntax highlighting for better readability
- **CVE Classification**: Built-in dialog for adding CVE information (CVE-ID, CWE-ID, CVSS scores)
- **Template Modification**: Add matchers and requests to existing templates
- **Multiple Matcher Types**: Support for word, regex, status, and binary matchers

### ⚡ Template Execution
- **Instant Execution**: Execute templates directly from the application
- **CLI Command Generation**: Auto-generates complete nuclei CLI commands
- **Command History**: Stores and allows re-execution of previous commands
- **CLI Flag Helper**: Quick reference for nuclei CLI flags (Ctrl+R)
- **Colored Output**: Syntax-highlighted nuclei output
- **Progress Tracking**: Real-time execution status

### ⌨️ Productivity Features
- **Comprehensive Keyboard Shortcuts**:
  - `F1`: Open nuclei documentation
  - `Ctrl+Enter`: Execute current template
  - `Ctrl+Shift+E`: Jump to template editor
  - `Ctrl+L`: Jump to CLI input field
  - `Ctrl+R`: Show CLI argument helper
  - `Ctrl+S`: Save current template
  - `Ctrl++/-`: Increase/decrease font size
  - `Ctrl+Q`: Quit application
  - `Ctrl+N`: New template
  - `Ctrl+O`: Open template

- **Tab Management**:
  - `Ctrl+Tab` / `Ctrl+PageDown`: Next tab
  - `Ctrl+Shift+Tab` / `Ctrl+PageUp`: Previous tab
  - `Ctrl+W`: Close current tab
  - Mouse scroll over tabs to navigate

### ⚙️ Configuration
- **Auto-detection**: Automatically finds nuclei binary in PATH
- **Custom Paths**: Configure custom nuclei binary and template directory paths
- **Default Author**: Uses system username as default template author
- **Persistent Settings**: Saves all configuration between sessions

### 🎨 User Interface
- **Modern Design**: Clean, professional interface
- **Dark & Light Themes**: Choose your preferred theme
- **Adjustable Font Size**: Customize editor and output font sizes
- **Responsive Layout**: Splitview design for efficient workflow
- **Status Updates**: Real-time status bar notifications

## Installation

### Prerequisites
- Python 3.8 or higher
- Nuclei installed and accessible in PATH (or configured manually)

### Install Nuclei
```bash
# macOS/Linux
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or using package managers
brew install nuclei  # macOS
apt install nuclei   # Ubuntu/Debian
```

### Install Python Application

#### Automated Installation (Recommended)

**Linux/macOS:**
```bash
# Make installer executable
chmod +x install.sh

# Run installer
./install.sh
```

**Windows:**
```batch
# Run installer
install.bat
```

The installer will:
- ✓ Check Python installation
- ✓ Detect Nuclei (if installed)
- ✓ Create virtual environment
- ✓ Install dependencies
- ✓ Create launcher shortcuts
- ✓ Set up desktop integration

#### Manual Installation

1. **Clone or download the repository**:
```bash
# Create a project directory
mkdir nuclei-template-generator-python
cd nuclei-template-generator-python
```

2. **Save the files**:
   - Save the main Python code as `nuclei_generator.py`
   - Save the requirements file as `requirements.txt`

3. **Create virtual environment** (recommended):
```bash
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

4. **Install dependencies**:
```bash
pip install -r requirements.txt
```

5. **Run the application**:
```bash
python nuclei_generator.py
```

### Create Desktop Launcher (Optional)

#### Linux
Create `~/.local/share/applications/nuclei-generator.desktop`:
```ini
[Desktop Entry]
Name=Nuclei Template Generator
Exec=/path/to/venv/bin/python /path/to/nuclei_generator.py
Icon=utilities-terminal
Type=Application
Categories=Development;Security;
Terminal=false
```

#### macOS
Create an Automator Application or use:
```bash
#!/bin/bash
cd /path/to/nuclei-template-generator-python
source venv/bin/activate
python nuclei_generator.py
```

#### Windows

**Option 1: Create a Batch File**

Create `nuclei-generator.bat`:
```batch
@echo off
cd /d C:\path\to\nuclei-template-generator-python
call venv\Scripts\activate.bat
python nuclei_generator.py
pause
```

**Option 2: Create a VBS Script (No Console Window)**

Create `nuclei-generator.vbs`:
```vbscript
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\path\to\nuclei-template-generator-python"
WshShell.Run "cmd /c venv\Scripts\activate.bat && python nuclei_generator.py", 0, False
Set WshShell = Nothing
```

**Option 3: Create a Windows Shortcut**

1. Right-click on Desktop → New → Shortcut
2. Enter target:
   ```
   C:\path\to\nuclei-template-generator-python\venv\Scripts\pythonw.exe C:\path\to\nuclei-template-generator-python\nuclei_generator.py
   ```
3. Name it "Nuclei Template Generator"
4. Right-click shortcut → Properties → Change Icon
5. Browse to `C:\Windows\System32\shell32.dll` and select an icon

**Option 4: Create a PowerShell Script**

Create `nuclei-generator.ps1`:
```powershell
Set-Location "C:\path\to\nuclei-template-generator-python"
& ".\venv\Scripts\Activate.ps1"
python nuclei_generator.py
```

Then create a shortcut with target:
```
powershell.exe -ExecutionPolicy Bypass -File "C:\path\to\nuclei-template-generator-python\nuclei-generator.ps1"
```

**Option 5: Pin to Start Menu/Taskbar**

1. Create any of the above shortcuts
2. Right-click the shortcut
3. Select "Pin to Start" or "Pin to Taskbar"

## Usage Guide

### Basic Workflow

1. **Paste HTTP Request/Response**:
   - Paste your HTTP request in the left "HTTP Request" section
   - Paste the corresponding HTTP response in the "HTTP Response" section

2. **Create Matchers**:
   - Select text in the request or response
   - Click "Add Matcher from Selection"
   - OR use the manual matcher buttons (Add Word Matcher, Add Regex Matcher, etc.)

3. **Configure Template**:
   - Fill in Template ID
   - Set Severity level
   - Add Author name
   - Add Tags (comma-separated)

4. **Generate Template**:
   - Click "Generate Template YAML"
   - Review the generated YAML in the editor

5. **Execute Template**:
   - Switch to "Execute" tab
   - Enter target URL
   - Add CLI flags if needed
   - Click "Execute Template"

### Advanced Features

#### Adding CVE Classification
1. Go to Edit → Add CVE Classification
2. Fill in CVE-ID, CWE-ID, CVSS Score, and Metrics
3. Click OK to add to template

#### Manual Matcher Creation
1. Click "Add Word Matcher", "Add Regex Matcher", or "Add Status Matcher"
2. Configure:
   - Part (body/header/all)
   - Patterns or status codes
   - Case sensitivity option
3. Click OK

#### Using Command History
1. Execute templates as normal
2. View history in "Execute" tab
3. Double-click any command to re-execute

#### CLI Flag Helper
1. Press `Ctrl+R` or click "CLI Helper"
2. View common nuclei CLI flags
3. Add flags to your execution command

### Configuration

#### Settings Tab
- **Nuclei Binary Path**: Path to nuclei executable
  - Click "Auto-detect" to find automatically
  - Or "Browse" to select manually
  
- **Template Directory**: Default save location for templates

- **Theme**: Choose Dark or Light theme

- **Font Size**: Adjust editor font size (8-24)

Click "Save Settings" to persist configuration.

## Example Templates

### SQL Injection Detection
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

### XSS Detection
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

## Keyboard Shortcuts Reference

| Shortcut | Action |
|----------|--------|
| `F1` | Open Nuclei documentation |
| `Ctrl+N` | New template |
| `Ctrl+O` | Open template |
| `Ctrl+S` | Save template |
| `Ctrl+Shift+S` | Save template as |
| `Ctrl+Enter` | Execute template |
| `Ctrl+Shift+E` | Jump to editor |
| `Ctrl+L` | Jump to CLI input |
| `Ctrl+R` | Show CLI helper |
| `Ctrl++` | Increase font size |
| `Ctrl+-` | Decrease font size |
| `Ctrl+Q` | Quit application |
| `Ctrl+Tab` | Next tab |
| `Ctrl+Shift+Tab` | Previous tab |
| `Ctrl+W` | Close tab |

## Differences from Burp Suite Plugin

### Advantages
✅ **Standalone Application**: No need for Burp Suite  
✅ **Cross-platform**: Works on any OS with Python  
✅ **Modern UI**: Improved visual design with PyQt6  
✅ **Free & Open Source**: No Burp Suite license required  
✅ **Direct Execution**: Built-in template execution  
✅ **Better Themes**: Enhanced dark/light theme support  

### Limitations
❌ **No Burp Integration**: Doesn't integrate with Burp Suite Proxy/Repeater  
❌ **No Intruder Integration**: No direct payload position support  
❌ **Manual Request/Response**: Must paste HTTP data manually  

## Troubleshooting

### Nuclei Not Found
```bash
# Verify nuclei is installed
nuclei -version

# Add to PATH if needed
export PATH=$PATH:~/go/bin

# Or use "Auto-detect" in Settings
```

### PyQt6 Installation Issues
```bash
# On Ubuntu/Debian
sudo apt-get install python3-pyqt6

# Or using pip
pip install --upgrade PyQt6
```

### Template Execution Fails
1. Check nuclei path in Settings
2. Verify target URL is accessible
3. Check CLI flags are valid
4. Review output for error messages

### YAML Syntax Errors
1. Ensure proper indentation (2 spaces)
2. Check for required fields (id, info, requests)
3. Validate YAML syntax online if needed

## Contributing

Contributions are welcome! Areas for improvement:
- Additional matcher types (DSL, extractors)
- Template validation
- Bulk template generation
- Template testing framework
- Import/export features
- Template marketplace integration

## Credits

- **Original Plugin**: [PortSwigger Nuclei Template Generator](https://github.com/portswigger/nuclei-template-generator) by [@forgedhallpass](https://github.com/forgedhallpass)
- **Nuclei**: [ProjectDiscovery](https://github.com/projectdiscovery/nuclei)
- **Python Port**: Improved and redesigned for standalone use

## License

MIT License - Same as the original Burp Suite plugin

---

## Support

For issues, questions, or feature requests:
- Check the troubleshooting section
- Review nuclei documentation: https://docs.projectdiscovery.io/
- Open an issue with detailed information

## Roadmap

- [ ] Request/response history management
- [ ] Template validation and testing
- [ ] Batch template generation
- [ ] Template library browser
- [ ] Auto-update nuclei templates
- [ ] Export to multiple formats
- [ ] Template diffing tool
- [ ] Collaborative template editing

---

**Happy Template Hunting! 🎯**
