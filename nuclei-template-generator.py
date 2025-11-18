"""
Nuclei Template Generator - Python Version
A standalone application for generating Nuclei templates with HTTP request/response analysis
"""

import sys
import os
import json
import re
import yaml
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import getpass

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel, QFileDialog,
    QTabWidget, QSplitter, QMessageBox, QComboBox, QCheckBox,
    QGroupBox, QScrollArea, QListWidget, QDialog, QDialogButtonBox,
    QSpinBox, QToolBar, QMenu, QMenuBar, QStatusBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QSettings
from PyQt6.QtGui import (
    QAction, QKeySequence, QFont, QTextCharFormat, 
    QColor, QSyntaxHighlighter, QTextCursor, QIcon
)


class YAMLHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for YAML"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))
        keyword_format.setFontWeight(700)
        keywords = [
            'id', 'info', 'name', 'author', 'severity', 'description', 
            'reference', 'classification', 'metadata', 'tags', 'requests',
            'matchers', 'extractors', 'method', 'path', 'headers', 'body',
            'matchers-condition', 'words', 'regex', 'status', 'dsl', 'binary',
            'condition', 'part', 'type', 'case-insensitive', 'cve-id',
            'cvss-metrics', 'cvss-score', 'cwe-id', 'payloads', 'attack',
            'raw'
        ]
        
        for word in keywords:
            pattern = f"\\b{word}\\b:"
            self.highlighting_rules.append((re.compile(pattern), keyword_format))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#CE9178"))
        self.highlighting_rules.append((re.compile(r'"[^"]*"'), string_format))
        self.highlighting_rules.append((re.compile(r"'[^']*'"), string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))
        self.highlighting_rules.append((re.compile(r'#[^\n]*'), comment_format))
        
        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#B5CEA8"))
        self.highlighting_rules.append((re.compile(r'\b\d+\b'), number_format))
    
    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class CVEDialog(QDialog):
    """Dialog for CVE information input"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add CVE Classification")
        self.setModal(True)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # CVE ID
        cve_layout = QHBoxLayout()
        cve_layout.addWidget(QLabel("CVE ID:"))
        self.cve_input = QLineEdit()
        self.cve_input.setPlaceholderText("CVE-2024-XXXXX")
        cve_layout.addWidget(self.cve_input)
        layout.addLayout(cve_layout)
        
        # CWE ID
        cwe_layout = QHBoxLayout()
        cwe_layout.addWidget(QLabel("CWE ID:"))
        self.cwe_input = QLineEdit()
        self.cwe_input.setPlaceholderText("CWE-79")
        cwe_layout.addWidget(self.cwe_input)
        layout.addLayout(cwe_layout)
        
        # CVSS Score
        cvss_layout = QHBoxLayout()
        cvss_layout.addWidget(QLabel("CVSS Score:"))
        self.cvss_input = QLineEdit()
        self.cvss_input.setPlaceholderText("7.5")
        cvss_layout.addWidget(self.cvss_input)
        layout.addLayout(cvss_layout)
        
        # CVSS Metrics
        layout.addWidget(QLabel("CVSS Metrics:"))
        self.cvss_metrics = QTextEdit()
        self.cvss_metrics.setPlaceholderText("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.cvss_metrics.setMaximumHeight(60)
        layout.addWidget(self.cvss_metrics)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def get_data(self) -> Dict:
        return {
            'cve-id': self.cve_input.text(),
            'cwe-id': self.cwe_input.text(),
            'cvss-score': self.cvss_input.text(),
            'cvss-metrics': self.cvss_metrics.toPlainText()
        }


class HTTPRequestResponseWidget(QWidget):
    """Widget for displaying and parsing HTTP requests/responses"""
    
    text_selected = pyqtSignal(str, str, str)  # text, location, status_code
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # HTTP Request section
        req_group = QGroupBox("HTTP Request")
        req_layout = QVBoxLayout()
        self.request_text = QTextEdit()
        self.request_text.setPlaceholderText(
            "Paste your HTTP request here...\n\n"
            "Example:\n"
            "GET /api/users HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: Mozilla/5.0\n"
            "Accept: application/json"
        )
        req_layout.addWidget(self.request_text)
        req_group.setLayout(req_layout)
        layout.addWidget(req_group)
        
        # HTTP Response section
        resp_group = QGroupBox("HTTP Response")
        resp_layout = QVBoxLayout()
        self.response_text = QTextEdit()
        self.response_text.setPlaceholderText(
            "Paste your HTTP response here...\n\n"
            "Example:\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: application/json\n"
            "Content-Length: 123\n\n"
            '{"status": "success", "data": {...}}'
        )
        self.response_text.textChanged.connect(self.on_response_changed)
        resp_layout.addWidget(self.response_text)
        resp_group.setLayout(resp_layout)
        layout.addWidget(resp_group)
        
        # Selection info
        self.selection_label = QLabel("Select text in request/response to create matchers")
        self.selection_label.setStyleSheet("color: #888; font-style: italic;")
        layout.addWidget(self.selection_label)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        self.parse_btn = QPushButton("Parse Request")
        self.parse_btn.clicked.connect(self.parse_request)
        btn_layout.addWidget(self.parse_btn)
        
        self.add_matcher_btn = QPushButton("Add Matcher from Selection")
        self.add_matcher_btn.clicked.connect(self.add_matcher_from_selection)
        btn_layout.addWidget(self.add_matcher_btn)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_all)
        btn_layout.addWidget(self.clear_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
    
    def on_response_changed(self):
        """Extract status code when response changes"""
        response = self.response_text.toPlainText()
        status = self.extract_status_code(response)
        if status:
            self.selection_label.setText(f"Status Code: {status}")
    
    def extract_status_code(self, response: str) -> Optional[str]:
        """Extract HTTP status code from response"""
        match = re.search(r'HTTP/[\d.]+\s+(\d{3})', response)
        return match.group(1) if match else None
    
    def parse_request(self):
        """Parse HTTP request and emit signal"""
        request = self.request_text.toPlainText()
        if not request.strip():
            QMessageBox.warning(self, "Warning", "Please enter an HTTP request")
            return
        
        QMessageBox.information(
            self, 
            "Request Parsed", 
            "Request parsed successfully! You can now add matchers by selecting text."
        )
    
    def add_matcher_from_selection(self):
        """Add matcher from selected text"""
        # Try response first
        cursor = self.response_text.textCursor()
        if cursor.hasSelection():
            selected_text = cursor.selectedText()
            status = self.extract_status_code(self.response_text.toPlainText())
            
            # Determine if selection is in header or body
            response = self.response_text.toPlainText()
            cursor_pos = cursor.selectionStart()
            header_end = response.find('\n\n')
            location = 'header' if cursor_pos < header_end else 'body'
            
            self.text_selected.emit(selected_text, location, status or "200")
            return
        
        # Try request
        cursor = self.request_text.textCursor()
        if cursor.hasSelection():
            selected_text = cursor.selectedText()
            request = self.request_text.toPlainText()
            cursor_pos = cursor.selectionStart()
            header_end = request.find('\n\n')
            location = 'header' if cursor_pos < header_end else 'body'
            
            self.text_selected.emit(selected_text, location, "200")
            return
        
        QMessageBox.warning(
            self,
            "No Selection",
            "Please select text in the request or response first"
        )
    
    def clear_all(self):
        """Clear all text fields"""
        self.request_text.clear()
        self.response_text.clear()
        self.selection_label.setText("Select text in request/response to create matchers")
    
    def get_request_data(self) -> Dict:
        """Parse and return request data"""
        request = self.request_text.toPlainText()
        lines = request.split('\n')
        
        if not lines:
            return {}
        
        # Parse first line (method, path, protocol)
        first_line = lines[0].split()
        method = first_line[0] if len(first_line) > 0 else 'GET'
        path = first_line[1] if len(first_line) > 1 else '/'
        
        # Parse headers
        headers = {}
        body_start = -1
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Parse body
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
        
        return {
            'method': method,
            'path': [path],
            'headers': headers,
            'body': body.strip()
        }


class TemplateEditorWidget(QWidget):
    """Widget for editing nuclei templates with syntax highlighting"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.current_file = None
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.template_id = QLineEdit()
        self.template_id.setPlaceholderText("Template ID")
        toolbar.addWidget(QLabel("ID:"))
        toolbar.addWidget(self.template_id)
        
        self.severity = QComboBox()
        self.severity.addItems(['info', 'low', 'medium', 'high', 'critical'])
        self.severity.setCurrentText('medium')
        toolbar.addWidget(QLabel("Severity:"))
        toolbar.addWidget(self.severity)
        
        toolbar.addStretch()
        layout.addLayout(toolbar)
        
        # Template editor
        self.editor = QTextEdit()
        self.editor.setPlaceholderText("Template YAML will appear here...")
        font = QFont("Courier New", 10)
        self.editor.setFont(font)
        
        # Apply syntax highlighting
        self.highlighter = YAMLHighlighter(self.editor.document())
        
        layout.addWidget(self.editor)
        
        # Info section
        info_layout = QHBoxLayout()
        
        self.author = QLineEdit()
        self.author.setPlaceholderText("Author")
        self.author.setText(getpass.getuser())
        info_layout.addWidget(QLabel("Author:"))
        info_layout.addWidget(self.author)
        
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("Tags (comma-separated)")
        info_layout.addWidget(QLabel("Tags:"))
        info_layout.addWidget(self.tags)
        
        layout.addLayout(info_layout)
        
        self.setLayout(layout)
    
    def get_template_yaml(self) -> str:
        """Get current template YAML"""
        return self.editor.toPlainText()
    
    def set_template_yaml(self, yaml_content: str):
        """Set template YAML content"""
        self.editor.setText(yaml_content)


class NucleiTemplateGenerator(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.settings = QSettings('NucleiGenerator', 'Settings')
        self.command_history = []
        self.current_template_data = self.get_default_template()
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        self.setWindowTitle("Nuclei Template Generator - Python Edition")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # Main layout - horizontal splitter
        main_layout = QHBoxLayout()
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - HTTP Request/Response
        self.http_widget = HTTPRequestResponseWidget()
        self.http_widget.text_selected.connect(self.add_matcher)
        splitter.addWidget(self.http_widget)
        
        # Right side - Tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        
        # Generator Tab
        self.generator_tab = QWidget()
        self.setup_generator_tab()
        self.tab_widget.addTab(self.generator_tab, "Generator")
        
        # Execution Tab
        self.execution_tab = QWidget()
        self.setup_execution_tab()
        self.tab_widget.addTab(self.execution_tab, "Execute")
        
        # Settings Tab
        self.settings_tab = QWidget()
        self.setup_settings_tab()
        self.tab_widget.addTab(self.settings_tab, "Settings")
        
        splitter.addWidget(self.tab_widget)
        splitter.setSizes([600, 800])
        
        main_layout.addWidget(splitter)
        main_widget.setLayout(main_layout)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Set dark theme
        self.set_dark_theme()
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        new_action = QAction("&New Template", self)
        new_action.setShortcut(QKeySequence.StandardKey.New)
        new_action.triggered.connect(self.new_template)
        file_menu.addAction(new_action)
        
        open_action = QAction("&Open Template", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self.open_template)
        file_menu.addAction(open_action)
        
        save_action = QAction("&Save Template", self)
        save_action.setShortcut(QKeySequence.StandardKey.Save)
        save_action.triggered.connect(self.save_template)
        file_menu.addAction(save_action)
        
        save_as_action = QAction("Save &As...", self)
        save_as_action.setShortcut(QKeySequence.StandardKey.SaveAs)
        save_as_action.triggered.connect(self.save_template_as)
        file_menu.addAction(save_as_action)
        
        file_menu.addSeparator()
        
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("&Edit")
        
        add_cve = QAction("Add &CVE Classification", self)
        add_cve.triggered.connect(self.add_cve_classification)
        edit_menu.addAction(add_cve)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        zoom_in = QAction("Zoom &In", self)
        zoom_in.setShortcut("Ctrl++")
        zoom_in.triggered.connect(self.zoom_in)
        view_menu.addAction(zoom_in)
        
        zoom_out = QAction("Zoom &Out", self)
        zoom_out.setShortcut("Ctrl+-")
        zoom_out.triggered.connect(self.zoom_out)
        view_menu.addAction(zoom_out)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        docs_action = QAction("Nuclei &Documentation", self)
        docs_action.setShortcut("F1")
        docs_action.triggered.connect(self.open_documentation)
        help_menu.addAction(docs_action)
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        """Create toolbar"""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        execute_action = QAction("Execute Template", self)
        execute_action.setShortcut("Ctrl+Return")
        execute_action.triggered.connect(self.execute_template)
        toolbar.addAction(execute_action)
        
        toolbar.addSeparator()
        
        generate_action = QAction("Generate Template", self)
        generate_action.triggered.connect(self.generate_template)
        toolbar.addAction(generate_action)
        
        toolbar.addSeparator()
        
        editor_action = QAction("Jump to Editor", self)
        editor_action.setShortcut("Ctrl+Shift+E")
        editor_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(0))
        toolbar.addAction(editor_action)
    
    def setup_generator_tab(self):
        """Setup the generator tab"""
        layout = QVBoxLayout()
        
        # Template editor
        self.template_editor = TemplateEditorWidget()
        layout.addWidget(self.template_editor)
        
        # Matcher section
        matcher_group = QGroupBox("Matchers")
        matcher_layout = QVBoxLayout()
        
        # Matcher list
        self.matcher_list = QListWidget()
        matcher_layout.addWidget(self.matcher_list)
        
        # Matcher controls
        matcher_btn_layout = QHBoxLayout()
        
        add_word_matcher = QPushButton("Add Word Matcher")
        add_word_matcher.clicked.connect(lambda: self.show_add_matcher_dialog('word'))
        matcher_btn_layout.addWidget(add_word_matcher)
        
        add_regex_matcher = QPushButton("Add Regex Matcher")
        add_regex_matcher.clicked.connect(lambda: self.show_add_matcher_dialog('regex'))
        matcher_btn_layout.addWidget(add_regex_matcher)
        
        add_status_matcher = QPushButton("Add Status Matcher")
        add_status_matcher.clicked.connect(lambda: self.show_add_matcher_dialog('status'))
        matcher_btn_layout.addWidget(add_status_matcher)
        
        remove_matcher = QPushButton("Remove Selected")
        remove_matcher.clicked.connect(self.remove_selected_matcher)
        matcher_btn_layout.addWidget(remove_matcher)
        
        matcher_layout.addLayout(matcher_btn_layout)
        matcher_group.setLayout(matcher_layout)
        layout.addWidget(matcher_group)
        
        # Generate button
        generate_btn = QPushButton("Generate Template YAML")
        generate_btn.clicked.connect(self.generate_template)
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #0e639c;
                color: white;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
        """)
        layout.addWidget(generate_btn)
        
        self.generator_tab.setLayout(layout)
    
    def setup_execution_tab(self):
        """Setup the execution tab"""
        layout = QVBoxLayout()
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target URL:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        # CLI input
        cli_layout = QHBoxLayout()
        cli_layout.addWidget(QLabel("CLI Flags:"))
        self.cli_input = QLineEdit()
        self.cli_input.setPlaceholderText("-v -debug")
        cli_layout.addWidget(self.cli_input)
        
        cli_help_btn = QPushButton("CLI Helper")
        cli_help_btn.setShortcut("Ctrl+R")
        cli_help_btn.clicked.connect(self.show_cli_helper)
        cli_layout.addWidget(cli_help_btn)
        
        layout.addLayout(cli_layout)
        
        # Execute button
        execute_btn = QPushButton("Execute Template")
        execute_btn.setShortcut("Ctrl+Return")
        execute_btn.clicked.connect(self.execute_template)
        execute_btn.setStyleSheet("""
            QPushButton {
                background-color: #0c7d4c;
                color: white;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0ea361;
            }
        """)
        layout.addWidget(execute_btn)
        
        # Output
        layout.addWidget(QLabel("Output:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier New", 10))
        layout.addWidget(self.output_text)
        
        # Command history
        layout.addWidget(QLabel("Command History:"))
        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.rerun_command)
        layout.addWidget(self.history_list)
        
        self.execution_tab.setLayout(layout)
    
    def setup_settings_tab(self):
        """Setup settings tab"""
        layout = QVBoxLayout()
        
        # Nuclei path
        nuclei_layout = QHBoxLayout()
        nuclei_layout.addWidget(QLabel("Nuclei Binary Path:"))
        self.nuclei_path = QLineEdit()
        self.nuclei_path.setPlaceholderText("/usr/bin/nuclei")
        nuclei_layout.addWidget(self.nuclei_path)
        
        browse_nuclei = QPushButton("Browse")
        browse_nuclei.clicked.connect(self.browse_nuclei_path)
        nuclei_layout.addWidget(browse_nuclei)
        
        auto_detect = QPushButton("Auto-detect")
        auto_detect.clicked.connect(self.auto_detect_nuclei)
        nuclei_layout.addWidget(auto_detect)
        
        layout.addLayout(nuclei_layout)
        
        # Template directory
        template_layout = QHBoxLayout()
        template_layout.addWidget(QLabel("Template Directory:"))
        self.template_dir = QLineEdit()
        self.template_dir.setPlaceholderText(str(Path.home() / ".config/nuclei/templates"))
        template_layout.addWidget(self.template_dir)
        
        browse_template = QPushButton("Browse")
        browse_template.clicked.connect(self.browse_template_dir)
        template_layout.addWidget(browse_template)
        
        layout.addLayout(template_layout)
        
        # Theme
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(['Dark', 'Light'])
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_layout.addWidget(self.theme_combo)
        theme_layout.addStretch()
        layout.addLayout(theme_layout)
        
        # Font size
        font_layout = QHBoxLayout()
        font_layout.addWidget(QLabel("Editor Font Size:"))
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 24)
        self.font_size.setValue(10)
        self.font_size.valueChanged.connect(self.change_font_size)
        font_layout.addWidget(self.font_size)
        font_layout.addStretch()
        layout.addLayout(font_layout)
        
        # Save settings button
        save_settings_btn = QPushButton("Save Settings")
        save_settings_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_settings_btn)
        
        layout.addStretch()
        self.settings_tab.setLayout(layout)
    
    def get_default_template(self) -> Dict:
        """Get default template structure"""
        return {
            'id': '',
            'info': {
                'name': '',
                'author': getpass.getuser(),
                'severity': 'medium',
                'description': '',
                'tags': []
            },
            'requests': [{
                'method': 'GET',
                'path': ['/'],
                'matchers': []
            }]
        }
    
    def add_matcher(self, text: str, location: str, status: str):
        """Add matcher from selected text"""
        # Determine matcher type
        is_binary = any(ord(c) > 127 for c in text)
        
        matcher = {
            'type': 'binary' if is_binary else 'word',
            'part': location,
        }
        
        if is_binary:
            matcher['binary'] = [text.encode().hex()]
        else:
            # Split multi-line into separate words
            words = [line.strip() for line in text.split('\n') if line.strip()]
            matcher['words'] = words
        
        # Add status matcher if not already present
        has_status = any(
            m.get('type') == 'status' 
            for m in self.current_template_data['requests'][0]['matchers']
        )
        
        if not has_status:
            status_matcher = {
                'type': 'status',
                'status': [int(status)]
            }
            self.current_template_data['requests'][0]['matchers'].append(status_matcher)
        
        self.current_template_data['requests'][0]['matchers'].append(matcher)
        self.update_matcher_list()
        self.statusBar().showMessage(f"Added {matcher['type']} matcher")
    
    def update_matcher_list(self):
        """Update the matcher list display"""
        self.matcher_list.clear()
        matchers = self.current_template_data['requests'][0]['matchers']
        
        for i, matcher in enumerate(matchers):
            matcher_type = matcher.get('type', 'unknown')
            part = matcher.get('part', 'body')
            
            if matcher_type == 'word':
                words = matcher.get('words', [])
                display = f"[{matcher_type}] {part}: {', '.join(words[:3])}{'...' if len(words) > 3 else ''}"
            elif matcher_type == 'regex':
                regex = matcher.get('regex', [])
                display = f"[{matcher_type}] {part}: {', '.join(regex[:2])}{'...' if len(regex) > 2 else ''}"
            elif matcher_type == 'status':
                status = matcher.get('status', [])
                display = f"[{matcher_type}] Status: {', '.join(map(str, status))}"
            elif matcher_type == 'binary':
                display = f"[{matcher_type}] {part}: (binary data)"
            else:
                display = f"[{matcher_type}] {part}"
            
            self.matcher_list.addItem(display)
    
    def show_add_matcher_dialog(self, matcher_type: str):
        """Show dialog to add a matcher manually"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Add {matcher_type.capitalize()} Matcher")
        layout = QVBoxLayout()
        
        # Part selection
        part_layout = QHBoxLayout()
        part_layout.addWidget(QLabel("Part:"))
        part_combo = QComboBox()
        part_combo.addItems(['body', 'header', 'all'])
        part_layout.addWidget(part_combo)
        layout.addLayout(part_layout)
        
        # Content input
        if matcher_type == 'status':
            content_layout = QHBoxLayout()
            content_layout.addWidget(QLabel("Status Codes (comma-separated):"))
            content_input = QLineEdit()
            content_input.setPlaceholderText("200, 201, 204")
            content_layout.addWidget(content_input)
            layout.addLayout(content_layout)
        else:
            layout.addWidget(QLabel(f"{matcher_type.capitalize()} patterns (one per line):"))
            content_input = QTextEdit()
            content_input.setPlaceholderText(
                "success\nadmin\nlogged in" if matcher_type == 'word' 
                else r"admin.*panel\nuser_id=\d+"
            )
            content_input.setMaximumHeight(100)
            layout.addWidget(content_input)
        
        # Case insensitive option
        if matcher_type in ['word', 'regex']:
            case_check = QCheckBox("Case Insensitive")
            layout.addWidget(case_check)
        else:
            case_check = None
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            matcher = {'type': matcher_type}
            
            if matcher_type != 'status':
                matcher['part'] = part_combo.currentText()
            
            if matcher_type == 'status':
                status_codes = [
                    int(s.strip()) 
                    for s in content_input.text().split(',') 
                    if s.strip().isdigit()
                ]
                matcher['status'] = status_codes
            elif matcher_type == 'word':
                words = [
                    line.strip() 
                    for line in content_input.toPlainText().split('\n') 
                    if line.strip()
                ]
                matcher['words'] = words
                if case_check and case_check.isChecked():
                    matcher['case-insensitive'] = True
            elif matcher_type == 'regex':
                patterns = [
                    line.strip() 
                    for line in content_input.toPlainText().split('\n') 
                    if line.strip()
                ]
                matcher['regex'] = patterns
                if case_check and case_check.isChecked():
                    matcher['case-insensitive'] = True
            
            self.current_template_data['requests'][0]['matchers'].append(matcher)
            self.update_matcher_list()
            self.statusBar().showMessage(f"Added {matcher_type} matcher")
    
    def remove_selected_matcher(self):
        """Remove selected matcher from list"""
        current_row = self.matcher_list.currentRow()
        if current_row >= 0:
            del self.current_template_data['requests'][0]['matchers'][current_row]
            self.update_matcher_list()
            self.statusBar().showMessage("Matcher removed")
    
    def generate_template(self):
        """Generate nuclei template YAML"""
        # Update template data from editor fields
        template_id = self.template_editor.template_id.text() or 'custom-template'
        
        # Get request data from HTTP widget
        request_data = self.http_widget.get_request_data()
        
        if request_data:
            self.current_template_data['requests'][0].update({
                'method': request_data.get('method', 'GET'),
                'path': request_data.get('path', ['/']),
            })
            
            if request_data.get('headers'):
                self.current_template_data['requests'][0]['headers'] = request_data['headers']
            
            if request_data.get('body'):
                self.current_template_data['requests'][0]['body'] = request_data['body']
        
        # Update info section
        self.current_template_data['id'] = template_id
        self.current_template_data['info'].update({
            'name': self.template_editor.template_id.text() or 'Custom Template',
            'author': self.template_editor.author.text() or getpass.getuser(),
            'severity': self.template_editor.severity.currentText(),
            'tags': [
                tag.strip() 
                for tag in self.template_editor.tags.text().split(',') 
                if tag.strip()
            ]
        })
        
        # Generate YAML
        yaml_content = yaml.dump(
            self.current_template_data, 
            default_flow_style=False, 
            sort_keys=False,
            allow_unicode=True
        )
        
        self.template_editor.set_template_yaml(yaml_content)
        self.statusBar().showMessage("Template generated successfully")
        
        # Show notification
        QMessageBox.information(
            self,
            "Template Generated",
            f"Template '{template_id}' has been generated successfully!"
        )
    
    def execute_template(self):
        """Execute the nuclei template"""
        nuclei_path = self.nuclei_path.text() or 'nuclei'
        target = self.target_input.text()
        
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target URL")
            return
        
        # Save template temporarily
        template_yaml = self.template_editor.get_template_yaml()
        if not template_yaml.strip():
            QMessageBox.warning(self, "Warning", "Please generate a template first")
            return
        
        # Create temporary template file
        temp_dir = Path.home() / '.nuclei-generator-temp'
        temp_dir.mkdir(exist_ok=True)
        
        template_id = self.current_template_data.get('id', 'temp-template')
        template_file = temp_dir / f"{template_id}.yaml"
        
        with open(template_file, 'w') as f:
            f.write(template_yaml)
        
        # Build command
        cli_flags = self.cli_input.text().split() if self.cli_input.text() else []
        command = [nuclei_path, '-t', str(template_file), '-u', target] + cli_flags
        
        # Add to history
        command_str = ' '.join(command)
        if command_str not in self.command_history:
            self.command_history.append(command_str)
            self.history_list.addItem(command_str)
        
        self.output_text.clear()
        self.output_text.append(f"Executing: {command_str}\n")
        self.output_text.append("=" * 80 + "\n")
        
        self.statusBar().showMessage("Executing template...")
        
        try:
            # Execute nuclei
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            self.output_text.append(result.stdout)
            if result.stderr:
                self.output_text.append("\nErrors:\n")
                self.output_text.append(result.stderr)
            
            self.statusBar().showMessage("Execution completed")
            
        except subprocess.TimeoutExpired:
            self.output_text.append("\nExecution timed out after 60 seconds")
            self.statusBar().showMessage("Execution timed out")
        except FileNotFoundError:
            self.output_text.append(f"\nError: Nuclei binary not found at '{nuclei_path}'")
            self.output_text.append("Please configure the correct path in Settings")
            self.statusBar().showMessage("Nuclei not found")
        except Exception as e:
            self.output_text.append(f"\nError: {str(e)}")
            self.statusBar().showMessage("Execution failed")
    
    def rerun_command(self, item):
        """Rerun a command from history"""
        command = item.text()
        parts = command.split()
        
        # Extract target and template
        try:
            target_idx = parts.index('-u')
            self.target_input.setText(parts[target_idx + 1])
        except (ValueError, IndexError):
            pass
        
        self.execute_template()
    
    def show_cli_helper(self):
        """Show CLI flag helper"""
        helper_text = """
Common Nuclei CLI Flags:

-v, -verbose          Show verbose output
-debug                Show debug output
-json                 Output in JSON format
-silent               Show only results
-nc, -no-color        Disable colors
-stats                Show statistics
-metrics              Show metrics
-rate-limit int       Rate limit (default 150)
-bulk-size int        Parallel checks (default 25)
-c int                Concurrent templates (default 25)
-timeout int          Timeout in seconds (default 5)
-retries int          Number of retries (default 1)
-severity string      Filter by severity (info,low,medium,high,critical)
-exclude-severity     Exclude severities
-author string        Filter by author
-tags string          Filter by tags
-exclude-tags         Exclude tags
-proxy string         HTTP proxy
-system-resolvers     Use system DNS resolvers
-disable-redirects    Disable redirects
"""
        
        dialog = QDialog(self)
        dialog.setWindowTitle("CLI Flag Helper")
        dialog.setModal(False)
        
        layout = QVBoxLayout()
        text = QTextEdit()
        text.setPlainText(helper_text)
        text.setReadOnly(True)
        text.setFont(QFont("Courier New", 10))
        layout.addWidget(text)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)
        
        dialog.setLayout(layout)
        dialog.resize(600, 500)
        dialog.show()
    
    def add_cve_classification(self):
        """Add CVE classification to template"""
        dialog = CVEDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            cve_data = dialog.get_data()
            
            if 'classification' not in self.current_template_data['info']:
                self.current_template_data['info']['classification'] = {}
            
            self.current_template_data['info']['classification'].update(
                {k: v for k, v in cve_data.items() if v}
            )
            
            self.generate_template()
            self.statusBar().showMessage("CVE classification added")
    
    def new_template(self):
        """Create a new template"""
        self.current_template_data = self.get_default_template()
        self.template_editor.editor.clear()
        self.template_editor.template_id.clear()
        self.template_editor.tags.clear()
        self.template_editor.severity.setCurrentText('medium')
        self.matcher_list.clear()
        self.http_widget.clear_all()
        self.statusBar().showMessage("New template created")
    
    def open_template(self):
        """Open existing template"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Template",
            str(Path.home()),
            "YAML Files (*.yaml *.yml);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    template_data = yaml.safe_load(f)
                
                self.current_template_data = template_data
                yaml_content = yaml.dump(
                    template_data, 
                    default_flow_style=False, 
                    sort_keys=False
                )
                self.template_editor.set_template_yaml(yaml_content)
                
                # Update UI fields
                if 'id' in template_data:
                    self.template_editor.template_id.setText(template_data['id'])
                
                if 'info' in template_data:
                    info = template_data['info']
                    if 'author' in info:
                        self.template_editor.author.setText(info['author'])
                    if 'severity' in info:
                        self.template_editor.severity.setCurrentText(info['severity'])
                    if 'tags' in info:
                        self.template_editor.tags.setText(', '.join(info['tags']))
                
                # Update matcher list
                self.update_matcher_list()
                
                self.template_editor.current_file = file_path
                self.statusBar().showMessage(f"Opened: {file_path}")
                
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to open template: {str(e)}"
                )
    
    def save_template(self):
        """Save current template"""
        if self.template_editor.current_file:
            self.save_template_to_file(self.template_editor.current_file)
        else:
            self.save_template_as()
    
    def save_template_as(self):
        """Save template as new file"""
        template_id = self.template_editor.template_id.text() or 'template'
        default_name = f"{template_id}.yaml"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Template",
            str(Path.home() / default_name),
            "YAML Files (*.yaml *.yml);;All Files (*)"
        )
        
        if file_path:
            self.save_template_to_file(file_path)
            self.template_editor.current_file = file_path
    
    def save_template_to_file(self, file_path: str):
        """Save template to specified file"""
        try:
            yaml_content = self.template_editor.get_template_yaml()
            
            with open(file_path, 'w') as f:
                f.write(yaml_content)
            
            self.statusBar().showMessage(f"Saved: {file_path}")
            QMessageBox.information(
                self,
                "Success",
                f"Template saved successfully to:\n{file_path}"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save template: {str(e)}"
            )
    
    def browse_nuclei_path(self):
        """Browse for nuclei binary"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Nuclei Binary",
            "/usr/bin",
            "All Files (*)"
        )
        
        if file_path:
            self.nuclei_path.setText(file_path)
    
    def browse_template_dir(self):
        """Browse for template directory"""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Template Directory",
            str(Path.home())
        )
        
        if dir_path:
            self.template_dir.setText(dir_path)
    
    def auto_detect_nuclei(self):
        """Auto-detect nuclei binary path"""
        # Try common locations
        common_paths = [
            '/usr/bin/nuclei',
            '/usr/local/bin/nuclei',
            str(Path.home() / 'go/bin/nuclei'),
            'nuclei'  # In PATH
        ]
        
        for path in common_paths:
            try:
                result = subprocess.run(
                    [path, '-version'],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.nuclei_path.setText(path)
                    self.statusBar().showMessage(f"Found nuclei at: {path}")
                    return
            except:
                continue
        
        QMessageBox.warning(
            self,
            "Not Found",
            "Could not auto-detect nuclei binary.\nPlease set the path manually."
        )
    
    def zoom_in(self):
        """Increase font size"""
        current_size = self.font_size.value()
        self.font_size.setValue(min(current_size + 1, 24))
    
    def zoom_out(self):
        """Decrease font size"""
        current_size = self.font_size.value()
        self.font_size.setValue(max(current_size - 1, 8))
    
    def change_font_size(self, size):
        """Change editor font size"""
        font = QFont("Courier New", size)
        self.template_editor.editor.setFont(font)
        self.output_text.setFont(font)
    
    def change_theme(self, theme):
        """Change application theme"""
        if theme == 'Dark':
            self.set_dark_theme()
        else:
            self.set_light_theme()
    
    def set_dark_theme(self):
        """Apply dark theme"""
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e1e;
                color: #d4d4d4;
            }
            QTextEdit, QLineEdit, QComboBox, QSpinBox {
                background-color: #252526;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                padding: 5px;
                border-radius: 3px;
            }
            QListWidget {
                background-color: #252526;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
            }
            QGroupBox {
                border: 1px solid #3e3e42;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #0e639c;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
            QPushButton:pressed {
                background-color: #0d5689;
            }
            QTabWidget::pane {
                border: 1px solid #3e3e42;
                background-color: #1e1e1e;
            }
            QTabBar::tab {
                background-color: #2d2d30;
                color: #d4d4d4;
                padding: 8px 15px;
                border: 1px solid #3e3e42;
            }
            QTabBar::tab:selected {
                background-color: #1e1e1e;
                border-bottom: 2px solid #0e639c;
            }
            QMenuBar {
                background-color: #2d2d30;
                color: #d4d4d4;
            }
            QMenuBar::item:selected {
                background-color: #3e3e42;
            }
            QMenu {
                background-color: #252526;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
            }
            QMenu::item:selected {
                background-color: #0e639c;
            }
            QToolBar {
                background-color: #2d2d30;
                border: none;
                spacing: 5px;
            }
            QStatusBar {
                background-color: #007acc;
                color: white;
            }
        """)
    
    def set_light_theme(self):
        """Apply light theme"""
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #ffffff;
                color: #000000;
            }
            QTextEdit, QLineEdit, QComboBox, QSpinBox {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
                padding: 5px;
                border-radius: 3px;
            }
            QListWidget {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
            }
            QGroupBox {
                border: 1px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
            }
            QTabBar::tab {
                background-color: #f3f3f3;
                color: #000000;
                padding: 8px 15px;
                border: 1px solid #cccccc;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                border-bottom: 2px solid #0078d4;
            }
        """)
    
    def open_documentation(self):
        """Open nuclei documentation"""
        import webbrowser
        webbrowser.open('https://docs.projectdiscovery.io/tools/nuclei/overview')
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About Nuclei Template Generator",
            """
            <h2>Nuclei Template Generator</h2>
            <p>Python Edition v1.0</p>
            <p>A standalone application for generating Nuclei templates 
            with HTTP request/response analysis.</p>
            <p><b>Features:</b></p>
            <ul>
                <li>Visual template creation</li>
                <li>Multiple matcher types</li>
                <li>Direct template execution</li>
                <li>Syntax highlighting</li>
                <li>CVE classification support</li>
                <li>Command history</li>
            </ul>
            <p>Based on the original Burp Suite plugin by PortSwigger</p>
            <p>Nuclei by ProjectDiscovery</p>
            """
        )
    
    def close_tab(self, index):
        """Close a tab"""
        if index > 2:  # Don't close main tabs
            self.tab_widget.removeTab(index)
    
    def save_settings(self):
        """Save application settings"""
        self.settings.setValue('nuclei_path', self.nuclei_path.text())
        self.settings.setValue('template_dir', self.template_dir.text())
        self.settings.setValue('theme', self.theme_combo.currentText())
        self.settings.setValue('font_size', self.font_size.value())
        
        self.statusBar().showMessage("Settings saved")
        QMessageBox.information(self, "Success", "Settings saved successfully!")
    
    def load_settings(self):
        """Load application settings"""
        nuclei_path = self.settings.value('nuclei_path', '')
        if nuclei_path:
            self.nuclei_path.setText(nuclei_path)
        else:
            self.auto_detect_nuclei()
        
        template_dir = self.settings.value(
            'template_dir',
            str(Path.home() / '.config/nuclei/templates')
        )
        self.template_dir.setText(template_dir)
        
        theme = self.settings.value('theme', 'Dark')
        self.theme_combo.setCurrentText(theme)
        self.change_theme(theme)
        
        font_size = int(self.settings.value('font_size', 10))
        self.font_size.setValue(font_size)
        self.change_font_size(font_size)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Nuclei Template Generator")
    app.setOrganizationName("NucleiGenerator")
    
    window = NucleiTemplateGenerator()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()