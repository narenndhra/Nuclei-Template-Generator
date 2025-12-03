"""
Nuclei Template Generator v2.0 - Professional Edition
Generates proper Nuclei templates with raw HTTP request format
Modern UI with advanced features - Final Version
"""

import sys
import os
import re
import yaml
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
import getpass

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel, QFileDialog,
    QTabWidget, QSplitter, QMessageBox, QComboBox, QCheckBox,
    QFrame, QDialog, QSpinBox, QTableWidget, QTableWidgetItem, 
    QHeaderView, QAbstractItemView, QListWidget, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QSettings
from PyQt6.QtGui import (
    QFont, QTextCharFormat, QColor, QSyntaxHighlighter, QAction, QKeySequence
)


# ============================================================================
# YAML Syntax Highlighter
# ============================================================================
class YAMLHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#61AFEF"))
        keyword_format.setFontWeight(700)
        keywords = [
            'id', 'info', 'name', 'author', 'severity', 'description', 
            'reference', 'classification', 'metadata', 'tags', 'http',
            'matchers', 'extractors', 'raw', 'method', 'path', 'headers', 'body',
            'matchers-condition', 'words', 'regex', 'status', 'dsl', 'binary',
            'condition', 'part', 'type', 'case-insensitive', 'cve-id',
            'cvss-metrics', 'cvss-score', 'cwe-id', 'payloads', 'attack'
        ]
        
        for word in keywords:
            pattern = f"^\\s*{word}:"
            self.highlighting_rules.append((re.compile(pattern, re.MULTILINE), keyword_format))
        
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#98C379"))
        self.highlighting_rules.append((re.compile(r'"[^"]*"'), string_format))
        self.highlighting_rules.append((re.compile(r"'[^']*'"), string_format))
        
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#5C6370"))
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((re.compile(r'#[^\n]*'), comment_format))
        
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#D19A66"))
        self.highlighting_rules.append((re.compile(r'\b\d+\.?\d*\b'), number_format))
        
        variable_format = QTextCharFormat()
        variable_format.setForeground(QColor("#E06C75"))
        variable_format.setFontWeight(700)
        self.highlighting_rules.append((re.compile(r'\{\{[^}]+\}\}'), variable_format))
        
        method_format = QTextCharFormat()
        method_format.setForeground(QColor("#C678DD"))
        method_format.setFontWeight(700)
        self.highlighting_rules.append((re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b'), method_format))
    
    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


# ============================================================================
# Custom Widgets
# ============================================================================
class ModernButton(QPushButton):
    def __init__(self, text: str, variant: str = "primary", parent=None):
        super().__init__(text, parent)
        self.variant = variant
        self.setObjectName(f"btn_{variant}")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(32)


class ModernLineEdit(QLineEdit):
    def __init__(self, placeholder: str = "", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setMinimumHeight(32)


class ModernTextEdit(QTextEdit):
    def __init__(self, placeholder: str = "", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)


class SeverityBadge(QLabel):
    COLORS = {
        'critical': ('#FF5555', '#fff'),
        'high': ('#FFB86C', '#000'),
        'medium': ('#F1FA8C', '#000'),
        'low': ('#8BE9FD', '#000'),
        'info': ('#BD93F9', '#fff')
    }
    
    def __init__(self, severity: str = "medium", parent=None):
        super().__init__(parent)
        self.set_severity(severity)
    
    def set_severity(self, severity: str):
        bg, fg = self.COLORS.get(severity.lower(), self.COLORS['medium'])
        self.setText(severity.upper())
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                padding: 4px 12px;
                border-radius: 10px;
                font-weight: bold;
                font-size: 10px;
            }}
        """)


# ============================================================================
# HTTP Request Parser
# ============================================================================
class HTTPRequestParser:
    @staticmethod
    def parse_raw_request(raw_request: str) -> Dict:
        lines = raw_request.strip().split('\n')
        if not lines:
            return {}
        
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        method = parts[0] if parts else 'GET'
        path = parts[1] if len(parts) > 1 else '/'
        protocol = parts[2] if len(parts) > 2 else 'HTTP/1.1'
        
        headers = {}
        body_start = -1
        host = ''
        
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
                if key.strip().lower() == 'host':
                    host = value.strip()
        
        body = ''
        if body_start > 0 and body_start < len(lines):
            body = '\n'.join(lines[body_start:])
        
        return {
            'method': method, 'path': path, 'protocol': protocol,
            'host': host, 'headers': headers, 'body': body.strip()
        }
    
    @staticmethod
    def format_raw_request(request_data: Dict, use_hostname_variable: bool = True) -> str:
        method = request_data.get('method', 'GET')
        path = request_data.get('path', '/')
        protocol = request_data.get('protocol', 'HTTP/1.1')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        lines = [f"{method} {path} {protocol}"]
        
        if use_hostname_variable:
            lines.append("Host: {{Hostname}}")
        elif 'Host' in headers:
            lines.append(f"Host: {headers['Host']}")
        
        for key, value in headers.items():
            if key.lower() != 'host':
                lines.append(f"{key}: {value}")
        
        if body:
            lines.append('')
            lines.append(body)
        
        return '\n'.join(lines)
    
    @staticmethod
    def extract_status_code(response: str) -> Optional[int]:
        match = re.search(r'HTTP/[\d.]+\s+(\d{3})', response)
        return int(match.group(1)) if match else None


# ============================================================================
# Dialogs
# ============================================================================
class CVEDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add CVE Classification")
        self.setModal(True)
        self.setMinimumWidth(400)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        layout.addWidget(QLabel("CVE ID:"))
        self.cve_input = ModernLineEdit("CVE-2024-XXXXX")
        layout.addWidget(self.cve_input)
        
        layout.addWidget(QLabel("CWE ID:"))
        self.cwe_input = ModernLineEdit("CWE-79")
        layout.addWidget(self.cwe_input)
        
        layout.addWidget(QLabel("CVSS Score:"))
        self.cvss_score = ModernLineEdit("7.5")
        layout.addWidget(self.cvss_score)
        
        layout.addWidget(QLabel("CVSS Vector:"))
        self.cvss_metrics = ModernLineEdit("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        layout.addWidget(self.cvss_metrics)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        cancel_btn = ModernButton("Cancel", "secondary")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        ok_btn = ModernButton("Add", "primary")
        ok_btn.clicked.connect(self.accept)
        btn_layout.addWidget(ok_btn)
        
        layout.addLayout(btn_layout)
    
    def get_data(self) -> Dict:
        data = {}
        if self.cve_input.text().strip():
            data['cve-id'] = self.cve_input.text().strip()
        if self.cwe_input.text().strip():
            data['cwe-id'] = self.cwe_input.text().strip()
        if self.cvss_score.text().strip():
            data['cvss-score'] = float(self.cvss_score.text())
        if self.cvss_metrics.text().strip():
            data['cvss-metrics'] = self.cvss_metrics.text().strip()
        return data


class MatcherDialog(QDialog):
    def __init__(self, matcher_type: str = "word", parent=None):
        super().__init__(parent)
        self.matcher_type = matcher_type
        self.setWindowTitle(f"Add {matcher_type.capitalize()} Matcher")
        self.setModal(True)
        self.setMinimumWidth(400)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Part selection
        part_layout = QHBoxLayout()
        part_layout.addWidget(QLabel("Match in:"))
        self.part_combo = QComboBox()
        self.part_combo.addItems(['body', 'header', 'all', 'raw'])
        part_layout.addWidget(self.part_combo)
        part_layout.addStretch()
        layout.addLayout(part_layout)
        
        # Content input
        if self.matcher_type == 'status':
            layout.addWidget(QLabel("Status Codes (comma-separated):"))
            self.content_input = ModernLineEdit("200, 201, 204")
            layout.addWidget(self.content_input)
        else:
            layout.addWidget(QLabel("Patterns (one per line):"))
            self.content_input = ModernTextEdit(
                "success\nadmin\nlogged in" if self.matcher_type == 'word' 
                else r"admin.*panel"
            )
            self.content_input.setMinimumHeight(100)
            layout.addWidget(self.content_input)
        
        # Options
        if self.matcher_type in ['word', 'regex']:
            self.case_insensitive = QCheckBox("Case Insensitive")
            layout.addWidget(self.case_insensitive)
            
            self.negative = QCheckBox("Negative Match")
            layout.addWidget(self.negative)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        cancel_btn = ModernButton("Cancel", "secondary")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        add_btn = ModernButton("Add Matcher", "primary")
        add_btn.clicked.connect(self.accept)
        btn_layout.addWidget(add_btn)
        
        layout.addLayout(btn_layout)
    
    def get_matcher(self) -> Dict:
        matcher = {'type': self.matcher_type}
        
        if self.matcher_type != 'status':
            matcher['part'] = self.part_combo.currentText()
        
        if self.matcher_type == 'status':
            codes = [int(s.strip()) for s in self.content_input.text().split(',') if s.strip().isdigit()]
            matcher['status'] = codes
        elif self.matcher_type == 'word':
            words = [line.strip() for line in self.content_input.toPlainText().split('\n') if line.strip()]
            matcher['words'] = words
        elif self.matcher_type == 'regex':
            patterns = [line.strip() for line in self.content_input.toPlainText().split('\n') if line.strip()]
            matcher['regex'] = patterns
        elif self.matcher_type == 'dsl':
            expressions = [line.strip() for line in self.content_input.toPlainText().split('\n') if line.strip()]
            matcher['dsl'] = expressions
        
        if hasattr(self, 'case_insensitive') and self.case_insensitive.isChecked():
            matcher['case-insensitive'] = True
        if hasattr(self, 'negative') and self.negative.isChecked():
            matcher['negative'] = True
        
        return matcher


# ============================================================================
# HTTP Panel
# ============================================================================
class HTTPPanel(QWidget):
    request_parsed = pyqtSignal(dict)
    matcher_added = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Header
        header = QHBoxLayout()
        title = QLabel("📡 HTTP Request/Response")
        title.setObjectName("sectionTitle")
        header.addWidget(title)
        header.addStretch()
        
        self.import_btn = ModernButton("Import", "secondary")
        self.import_btn.clicked.connect(self.import_from_file)
        header.addWidget(self.import_btn)
        layout.addLayout(header)
        
        # Splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        # Request
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(4)
        
        req_title = QLabel("📤 HTTP Request")
        req_title.setObjectName("cardTitle")
        req_layout.addWidget(req_title)
        self.request_text = ModernTextEdit("Paste HTTP request here...")
        self.request_text.setFont(QFont("JetBrains Mono", 11))
        req_layout.addWidget(self.request_text, 1)
        
        req_btn = QHBoxLayout()
        self.parse_btn = ModernButton("🔍 Parse Request", "primary")
        self.parse_btn.clicked.connect(self.parse_request)
        req_btn.addWidget(self.parse_btn)
        req_btn.addStretch()
        req_layout.addLayout(req_btn)
        
        splitter.addWidget(req_widget)
        
        # Response
        resp_widget = QWidget()
        resp_layout = QVBoxLayout(resp_widget)
        resp_layout.setContentsMargins(0, 0, 0, 0)
        resp_layout.setSpacing(4)
        
        resp_title = QLabel("📥 HTTP Response")
        resp_title.setObjectName("cardTitle")
        resp_layout.addWidget(resp_title)
        self.response_text = ModernTextEdit("Paste HTTP response here...")
        self.response_text.setFont(QFont("JetBrains Mono", 11))
        resp_layout.addWidget(self.response_text, 1)
        
        resp_btn = QHBoxLayout()
        self.add_word_btn = ModernButton("+ Word Matcher", "success")
        self.add_word_btn.clicked.connect(lambda: self.add_matcher_from_selection('word'))
        resp_btn.addWidget(self.add_word_btn)
        
        self.add_regex_btn = ModernButton("+ Regex Matcher", "success")
        self.add_regex_btn.clicked.connect(lambda: self.add_matcher_from_selection('regex'))
        resp_btn.addWidget(self.add_regex_btn)
        
        resp_btn.addStretch()
        
        self.status_label = QLabel("")
        resp_btn.addWidget(self.status_label)
        resp_layout.addLayout(resp_btn)
        
        splitter.addWidget(resp_widget)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter, 1)
        
        self.response_text.textChanged.connect(self.on_response_changed)
    
    def on_response_changed(self):
        response = self.response_text.toPlainText()
        status_code = HTTPRequestParser.extract_status_code(response)
        if status_code:
            color = "#4CAF50" if status_code < 400 else "#FF9800" if status_code < 500 else "#F44336"
            self.status_label.setText(f"Status: {status_code}")
            self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
    
    def parse_request(self):
        raw_request = self.request_text.toPlainText()
        if not raw_request.strip():
            QMessageBox.warning(self, "Warning", "Please enter an HTTP request")
            return
        
        parsed = HTTPRequestParser.parse_raw_request(raw_request)
        self.request_parsed.emit(parsed)
        QMessageBox.information(self, "Parsed", f"Method: {parsed.get('method')}\nPath: {parsed.get('path')}")
    
    def add_matcher_from_selection(self, matcher_type: str):
        cursor = self.response_text.textCursor()
        selected_text = cursor.selectedText()
        
        if not selected_text:
            dialog = MatcherDialog(matcher_type, self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.matcher_added.emit(dialog.get_matcher())
            return
        
        matcher = {'type': matcher_type, 'part': 'body'}
        if matcher_type == 'word':
            matcher['words'] = [line.strip() for line in selected_text.split('\n') if line.strip()]
        elif matcher_type == 'regex':
            matcher['regex'] = [re.escape(selected_text)]
        
        self.matcher_added.emit(matcher)
    
    def import_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Request", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            with open(file_path, 'r') as f:
                self.request_text.setText(f.read())
    
    def get_raw_request(self, use_hostname_variable: bool = True) -> str:
        raw_request = self.request_text.toPlainText()
        if not raw_request.strip():
            return ""
        parsed = HTTPRequestParser.parse_raw_request(raw_request)
        return HTTPRequestParser.format_raw_request(parsed, use_hostname_variable)
    
    def clear(self):
        self.request_text.clear()
        self.response_text.clear()
        self.status_label.clear()


# ============================================================================
# Template Editor Panel
# ============================================================================
class TemplateEditorPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_file = None
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        
        # Header
        header_title = QLabel("📝 Template Editor")
        header_title.setObjectName("sectionTitle")
        layout.addWidget(header_title)
        
        # Metadata section title
        meta_title = QLabel("📋 Template Info")
        meta_title.setObjectName("cardTitle")
        layout.addWidget(meta_title)
        
        # Metadata - compact
        meta_widget = QWidget()
        meta_layout = QVBoxLayout(meta_widget)
        meta_layout.setContentsMargins(0, 0, 0, 0)
        meta_layout.setSpacing(4)
        
        # Row 1
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("ID:"))
        self.template_id = ModernLineEdit("my-template")
        row1.addWidget(self.template_id, 2)
        row1.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(['info', 'low', 'medium', 'high', 'critical'])
        self.severity_combo.setCurrentText('medium')
        self.severity_combo.currentTextChanged.connect(self.update_severity_badge)
        row1.addWidget(self.severity_combo)
        self.severity_badge = SeverityBadge("medium")
        row1.addWidget(self.severity_badge)
        meta_layout.addLayout(row1)
        
        # Row 2
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Name:"))
        self.template_name = ModernLineEdit("Vulnerability Name")
        row2.addWidget(self.template_name, 2)
        row2.addWidget(QLabel("Author:"))
        self.author = ModernLineEdit(getpass.getuser())
        row2.addWidget(self.author)
        meta_layout.addLayout(row2)
        
        # Row 3
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Tags:"))
        self.tags = ModernLineEdit("cve,xss,sqli")
        row3.addWidget(self.tags, 2)
        row3.addWidget(QLabel("Reference:"))
        self.reference = ModernLineEdit("https://example.com")
        row3.addWidget(self.reference)
        meta_layout.addLayout(row3)
        
        # Description
        row4 = QHBoxLayout()
        row4.addWidget(QLabel("Description:"))
        self.description = ModernLineEdit("Description of the vulnerability")
        row4.addWidget(self.description)
        meta_layout.addLayout(row4)
        
        layout.addWidget(meta_widget)
        
        # YAML Editor title
        yaml_title = QLabel("📄 Generated YAML")
        yaml_title.setObjectName("cardTitle")
        layout.addWidget(yaml_title)
        
        self.yaml_editor = ModernTextEdit("# Template will be generated here...")
        self.yaml_editor.setFont(QFont("JetBrains Mono", 11))
        self.yaml_editor.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.highlighter = YAMLHighlighter(self.yaml_editor.document())
        layout.addWidget(self.yaml_editor, 1)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.copy_btn = ModernButton("📋 Copy to Clipboard", "secondary")
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        btn_layout.addWidget(self.copy_btn)
        
        self.validate_btn = ModernButton("✓ Validate YAML", "secondary")
        self.validate_btn.clicked.connect(self.validate_yaml)
        btn_layout.addWidget(self.validate_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
    
    def update_severity_badge(self, severity: str):
        self.severity_badge.set_severity(severity)
    
    def copy_to_clipboard(self):
        QApplication.clipboard().setText(self.yaml_editor.toPlainText())
        QMessageBox.information(self, "Copied", "Template copied to clipboard!")
    
    def validate_yaml(self):
        try:
            yaml.safe_load(self.yaml_editor.toPlainText())
            QMessageBox.information(self, "Valid", "✓ YAML syntax is valid!")
        except yaml.YAMLError as e:
            QMessageBox.warning(self, "Invalid YAML", f"Error:\n{str(e)}")
    
    def get_template_yaml(self) -> str:
        return self.yaml_editor.toPlainText()
    
    def set_template_yaml(self, content: str):
        self.yaml_editor.setText(content)


# ============================================================================
# Matchers Panel
# ============================================================================
class MatchersPanel(QWidget):
    matchers_changed = pyqtSignal(list)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.matchers = []
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumHeight(220)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        
        # Header
        header = QHBoxLayout()
        title = QLabel("🎯 Matchers")
        title.setObjectName("sectionTitle")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(QLabel("Condition:"))
        self.condition_combo = QComboBox()
        self.condition_combo.addItems(['and', 'or'])
        header.addWidget(self.condition_combo)
        layout.addLayout(header)
        
        # Table title
        table_title = QLabel("📋 Added Matchers")
        table_title.setObjectName("cardTitle")
        layout.addWidget(table_title)
        
        # Table
        self.matcher_table = QTableWidget()
        self.matcher_table.setColumnCount(4)
        self.matcher_table.setHorizontalHeaderLabels(['Type', 'Part', 'Value', 'Del'])
        self.matcher_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.matcher_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.matcher_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.matcher_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.matcher_table.horizontalHeader().resizeSection(3, 50)
        self.matcher_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.matcher_table.setAlternatingRowColors(True)
        self.matcher_table.verticalHeader().setVisible(False)
        self.matcher_table.setMinimumHeight(100)
        self.matcher_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(self.matcher_table, 1)
        
        # Buttons
        btn_layout = QHBoxLayout()
        for label, mtype in [("+ Word", "word"), ("+ Regex", "regex"), ("+ Status", "status"), ("+ DSL", "dsl")]:
            btn = ModernButton(label, "secondary")
            btn.setMaximumWidth(90)
            btn.clicked.connect(lambda checked, t=mtype: self.add_matcher(t))
            btn_layout.addWidget(btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
    
    def add_matcher(self, matcher_type: str):
        dialog = MatcherDialog(matcher_type, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            matcher = dialog.get_matcher()
            self.matchers.append(matcher)
            self.update_table()
            self.matchers_changed.emit(self.matchers)
    
    def add_matcher_direct(self, matcher: Dict):
        self.matchers.append(matcher)
        self.update_table()
        self.matchers_changed.emit(self.matchers)
    
    def update_table(self):
        self.matcher_table.setRowCount(len(self.matchers))
        
        for i, matcher in enumerate(self.matchers):
            self.matcher_table.setRowHeight(i, 36)
            
            type_item = QTableWidgetItem(matcher.get('type', 'unknown'))
            type_item.setForeground(QColor("#61AFEF"))
            self.matcher_table.setItem(i, 0, type_item)
            
            part_item = QTableWidgetItem(matcher.get('part', '-'))
            self.matcher_table.setItem(i, 1, part_item)
            
            value = ''
            if 'words' in matcher:
                value = ', '.join(matcher['words'][:3]) + ('...' if len(matcher['words']) > 3 else '')
            elif 'regex' in matcher:
                value = ', '.join(matcher['regex'][:2])
            elif 'status' in matcher:
                value = ', '.join(map(str, matcher['status']))
            elif 'dsl' in matcher:
                value = ', '.join(matcher['dsl'][:2])
            
            self.matcher_table.setItem(i, 2, QTableWidgetItem(value))
            
            del_btn = QPushButton("🗑")
            del_btn.setStyleSheet("QPushButton { background: #FF5252; border: none; border-radius: 4px; padding: 4px; } QPushButton:hover { background: #FF1744; }")
            del_btn.clicked.connect(lambda checked, row=i: self.remove_matcher(row))
            self.matcher_table.setCellWidget(i, 3, del_btn)
    
    def remove_matcher(self, index: int):
        if 0 <= index < len(self.matchers):
            del self.matchers[index]
            self.update_table()
            self.matchers_changed.emit(self.matchers)
    
    def get_matchers(self) -> List[Dict]:
        return self.matchers
    
    def get_condition(self) -> str:
        return self.condition_combo.currentText()
    
    def clear(self):
        self.matchers = []
        self.update_table()


# ============================================================================
# Execution Panel
# ============================================================================
class ExecutionPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.command_history = []
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Target section title
        target_title = QLabel("🎯 Target Configuration")
        target_title.setObjectName("cardTitle")
        layout.addWidget(target_title)
        
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Target URL:"))
        self.target_input = ModernLineEdit("https://example.com")
        row1.addWidget(self.target_input)
        layout.addLayout(row1)
        
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("CLI Flags:"))
        self.cli_flags = ModernLineEdit("-v -debug")
        row2.addWidget(self.cli_flags)
        layout.addLayout(row2)
        
        # Execute
        self.execute_btn = ModernButton("▶ Execute Template", "success")
        self.execute_btn.setMinimumHeight(45)
        self.execute_btn.setStyleSheet("""
            QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00C853, stop:1 #00E676); font-size: 14px; font-weight: bold; }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00E676, stop:1 #69F0AE); }
        """)
        layout.addWidget(self.execute_btn)
        
        # Output section title
        output_title = QLabel("📤 Execution Output")
        output_title.setObjectName("cardTitle")
        layout.addWidget(output_title)
        
        self.output_text = ModernTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("JetBrains Mono", 11))
        layout.addWidget(self.output_text, 1)
        
        # History section title
        history_title = QLabel("📜 Command History")
        history_title.setObjectName("cardTitle")
        layout.addWidget(history_title)
        
        self.history_list = QListWidget()
        self.history_list.setMaximumHeight(100)
        layout.addWidget(self.history_list)
    
    def add_to_history(self, command: str):
        if command not in self.command_history:
            self.command_history.append(command)
            self.history_list.addItem(command)
    
    def set_output(self, text: str):
        self.output_text.setText(text)
    
    def append_output(self, text: str):
        self.output_text.append(text)


# ============================================================================
# Main Application
# ============================================================================
class NucleiTemplateGenerator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings('NucleiGenerator', 'App')
        self.current_template_data = {}
        self.init_ui()
        self.load_settings()
        self.apply_styles()
    
    def init_ui(self):
        self.setWindowTitle("🔬 Nuclei Template Generator Pro")
        
        # Screen-based sizing
        screen = QApplication.primaryScreen().availableGeometry()
        w, h = int(screen.width() * 0.9), int(screen.height() * 0.9)
        self.setGeometry((screen.width() - w) // 2, (screen.height() - h) // 2, w, h)
        self.setMinimumSize(900, 600)
        
        self.create_menu_bar()
        
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setChildrenCollapsible(False)
        
        # Left - HTTP Panel
        self.http_panel = HTTPPanel()
        self.http_panel.request_parsed.connect(self.on_request_parsed)
        self.http_panel.matcher_added.connect(self.on_matcher_added)
        main_splitter.addWidget(self.http_panel)
        
        # Right - Tabs
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        self.tab_widget = QTabWidget()
        
        # Generator Tab
        gen_widget = QWidget()
        gen_layout = QVBoxLayout(gen_widget)
        gen_layout.setContentsMargins(8, 8, 8, 8)
        gen_layout.setSpacing(8)
        
        # Splitter for editor and matchers
        gen_splitter = QSplitter(Qt.Orientation.Vertical)
        gen_splitter.setChildrenCollapsible(False)
        
        self.template_editor = TemplateEditorPanel()
        gen_splitter.addWidget(self.template_editor)
        
        self.matchers_panel = MatchersPanel()
        self.matchers_panel.matchers_changed.connect(self.on_matchers_changed)
        gen_splitter.addWidget(self.matchers_panel)
        
        gen_splitter.setStretchFactor(0, 6)
        gen_splitter.setStretchFactor(1, 4)
        
        gen_layout.addWidget(gen_splitter, 1)
        
        # Generate button
        self.generate_btn = ModernButton("⚡ Generate Nuclei Template", "primary")
        self.generate_btn.setMinimumHeight(45)
        self.generate_btn.clicked.connect(self.generate_template)
        self.generate_btn.setStyleSheet("""
            QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #667eea, stop:1 #764ba2); font-size: 14px; font-weight: bold; }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #764ba2, stop:1 #667eea); }
        """)
        gen_layout.addWidget(self.generate_btn)
        
        self.tab_widget.addTab(gen_widget, "📝 Generator")
        
        # Execute Tab
        self.execution_panel = ExecutionPanel()
        self.execution_panel.execute_btn.clicked.connect(self.execute_template)
        self.tab_widget.addTab(self.execution_panel, "▶ Execute")
        
        # Settings Tab
        self.tab_widget.addTab(self.create_settings_tab(), "⚙️ Settings")
        
        right_layout.addWidget(self.tab_widget)
        main_splitter.addWidget(right_widget)
        
        main_splitter.setStretchFactor(0, 35)
        main_splitter.setStretchFactor(1, 65)
        
        main_layout.addWidget(main_splitter)
        
        self.statusBar().showMessage("Ready")
    
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("&File")
        file_menu.addAction(QAction("&New", self, shortcut=QKeySequence.StandardKey.New, triggered=self.new_template))
        file_menu.addAction(QAction("&Open", self, shortcut=QKeySequence.StandardKey.Open, triggered=self.open_template))
        file_menu.addAction(QAction("&Save", self, shortcut=QKeySequence.StandardKey.Save, triggered=self.save_template))
        file_menu.addSeparator()
        file_menu.addAction(QAction("&Quit", self, shortcut="Ctrl+Q", triggered=self.close))
        
        edit_menu = menubar.addMenu("&Edit")
        edit_menu.addAction(QAction("Add &CVE", self, triggered=self.add_cve_classification))
        
        help_menu = menubar.addMenu("&Help")
        help_menu.addAction(QAction("&Documentation", self, triggered=lambda: __import__('webbrowser').open('https://docs.projectdiscovery.io/tools/nuclei/overview')))
        help_menu.addAction(QAction("&About", self, triggered=self.show_about))
    
    def create_settings_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)
        
        # Nuclei Configuration
        nuclei_title = QLabel("🔧 Nuclei Configuration")
        nuclei_title.setObjectName("settingsTitle")
        layout.addWidget(nuclei_title)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Binary Path:"))
        self.nuclei_path = ModernLineEdit("/usr/bin/nuclei")
        path_layout.addWidget(self.nuclei_path)
        browse_btn = ModernButton("Browse", "secondary")
        browse_btn.clicked.connect(self.browse_nuclei_path)
        path_layout.addWidget(browse_btn)
        detect_btn = ModernButton("Auto-detect", "secondary")
        detect_btn.clicked.connect(self.auto_detect_nuclei)
        path_layout.addWidget(detect_btn)
        layout.addLayout(path_layout)
        
        tmpl_layout = QHBoxLayout()
        tmpl_layout.addWidget(QLabel("Template Directory:"))
        self.template_dir = ModernLineEdit(str(Path.home() / ".nuclei-templates"))
        tmpl_layout.addWidget(self.template_dir)
        browse_tmpl_btn = ModernButton("Browse", "secondary")
        browse_tmpl_btn.clicked.connect(self.browse_template_dir)
        tmpl_layout.addWidget(browse_tmpl_btn)
        layout.addLayout(tmpl_layout)
        
        # Editor Settings
        editor_title = QLabel("✏️ Editor Settings")
        editor_title.setObjectName("settingsTitle")
        layout.addWidget(editor_title)
        
        font_layout = QHBoxLayout()
        font_layout.addWidget(QLabel("Font Size:"))
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        self.font_size_spin.setValue(11)
        self.font_size_spin.setMinimumWidth(80)
        self.font_size_spin.valueChanged.connect(self.change_font_size)
        font_layout.addWidget(self.font_size_spin)
        font_layout.addStretch()
        layout.addLayout(font_layout)
        
        # Theme info
        theme_title = QLabel("🎨 Theme")
        theme_title.setObjectName("settingsTitle")
        layout.addWidget(theme_title)
        
        theme_info = QLabel("Current: Dark Theme (Professional)")
        theme_info.setStyleSheet("color: #64ffda;")
        layout.addWidget(theme_info)
        
        layout.addStretch()
        
        save_btn = ModernButton("💾 Save Settings", "primary")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        return widget
    
    def browse_nuclei_path(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Nuclei Binary")
        if path:
            self.nuclei_path.setText(path)
    
    def browse_template_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Select Template Directory")
        if path:
            self.template_dir.setText(path)
    
    def change_font_size(self, size: int):
        font = QFont("JetBrains Mono", size)
        self.template_editor.yaml_editor.setFont(font)
        self.http_panel.request_text.setFont(font)
        self.http_panel.response_text.setFont(font)
        self.execution_panel.output_text.setFont(font)
    
    def on_request_parsed(self, data: Dict):
        self.current_template_data['request'] = data
        self.statusBar().showMessage("Request parsed")
    
    def on_matcher_added(self, matcher: Dict):
        self.matchers_panel.add_matcher_direct(matcher)
        self.statusBar().showMessage(f"Added {matcher.get('type')} matcher")
    
    def on_matchers_changed(self, matchers: List[Dict]):
        self.current_template_data['matchers'] = matchers
    
    def generate_template(self):
        raw_request = self.http_panel.get_raw_request(use_hostname_variable=True)
        if not raw_request.strip():
            QMessageBox.warning(self, "Warning", "Please enter an HTTP request")
            return
        
        template_id = re.sub(r'[^a-zA-Z0-9_-]', '-', self.template_editor.template_id.text().strip() or 'custom-template')
        
        template = {
            'id': template_id,
            'info': {
                'name': self.template_editor.template_name.text().strip() or template_id,
                'author': self.template_editor.author.text().strip() or getpass.getuser(),
                'severity': self.template_editor.severity_combo.currentText(),
                'description': self.template_editor.description.text().strip() or 'description',
            }
        }
        
        ref = self.template_editor.reference.text().strip()
        if ref:
            template['info']['reference'] = [ref]
        
        tags = self.template_editor.tags.text().strip()
        if tags:
            template['info']['tags'] = tags
        
        if 'classification' in self.current_template_data:
            template['info']['classification'] = self.current_template_data['classification']
        
        http_section = {'raw': [raw_request]}
        
        matchers = self.matchers_panel.get_matchers()
        if matchers:
            http_section['matchers'] = matchers
            if len(matchers) > 1:
                http_section['matchers-condition'] = self.matchers_panel.get_condition()
        
        template['http'] = [http_section]
        
        yaml_content = self.format_nuclei_yaml(template)
        self.template_editor.set_template_yaml(yaml_content)
        self.statusBar().showMessage("✓ Template generated!")
        QMessageBox.information(self, "Generated", f"Template '{template_id}' generated successfully!")
    
    def format_nuclei_yaml(self, template: Dict) -> str:
        lines = [f"id: {template['id']}", "info:"]
        info = template['info']
        lines.extend([f"  name: {info['name']}", f"  author: {info['author']}", f"  severity: {info['severity']}", f"  description: {info['description']}"])
        
        if 'reference' in info:
            lines.append("  reference:")
            for ref in info['reference']:
                lines.append(f"    - {ref}")
        
        if 'tags' in info:
            lines.append(f"  tags: {info['tags']}")
        
        if 'classification' in info:
            lines.append("  classification:")
            for k, v in info['classification'].items():
                lines.append(f"    {k}: {v}")
        
        lines.append("http:")
        for http_item in template['http']:
            lines.append("  - raw:")
            lines.append("      - |+")
            for req_line in http_item['raw'][0].split('\n'):
                lines.append(f"        {req_line}")
            lines.append("")
            
            if 'matchers-condition' in http_item:
                lines.append(f"    matchers-condition: {http_item['matchers-condition']}")
            
            if 'matchers' in http_item:
                lines.append("    matchers:")
                for matcher in http_item['matchers']:
                    lines.append(f"      - type: {matcher['type']}")
                    if 'part' in matcher:
                        lines.append(f"        part: {matcher['part']}")
                    for key in ['words', 'regex', 'status', 'dsl']:
                        if key in matcher:
                            lines.append(f"        {key}:")
                            for val in matcher[key]:
                                lines.append(f"          - {val}")
                    if matcher.get('case-insensitive'):
                        lines.append("        case-insensitive: true")
                    if matcher.get('negative'):
                        lines.append("        negative: true")
        
        return '\n'.join(lines)
    
    def execute_template(self):
        nuclei_path = self.nuclei_path.text() or 'nuclei'
        target = self.execution_panel.target_input.text()
        
        if not target:
            QMessageBox.warning(self, "Warning", "Enter a target URL")
            return
        
        yaml_content = self.template_editor.get_template_yaml()
        if not yaml_content.strip() or yaml_content.startswith('#'):
            QMessageBox.warning(self, "Warning", "Generate a template first")
            return
        
        temp_dir = Path.home() / '.nuclei-generator-temp'
        temp_dir.mkdir(exist_ok=True)
        template_file = temp_dir / f"{re.sub(r'[^a-zA-Z0-9_-]', '-', self.template_editor.template_id.text() or 'temp')}.yaml"
        
        with open(template_file, 'w') as f:
            f.write(yaml_content)
        
        cli_flags = self.execution_panel.cli_flags.text().split()
        command = [nuclei_path, '-t', str(template_file), '-u', target] + cli_flags
        
        self.execution_panel.add_to_history(' '.join(command))
        self.execution_panel.set_output(f"$ {' '.join(command)}\n\n{'='*50}\n\n")
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            self.execution_panel.append_output(result.stdout + ("\n\nSTDERR:\n" + result.stderr if result.stderr else ""))
            self.statusBar().showMessage("Execution completed")
        except subprocess.TimeoutExpired:
            self.execution_panel.append_output("\n⚠️ Timeout after 120s")
        except FileNotFoundError:
            self.execution_panel.append_output(f"\n❌ Nuclei not found at '{nuclei_path}'")
        except Exception as e:
            self.execution_panel.append_output(f"\n❌ Error: {e}")
    
    def new_template(self):
        self.http_panel.clear()
        self.matchers_panel.clear()
        self.template_editor.template_id.clear()
        self.template_editor.template_name.clear()
        self.template_editor.description.clear()
        self.template_editor.reference.clear()
        self.template_editor.tags.clear()
        self.template_editor.yaml_editor.clear()
        self.current_template_data = {}
        self.statusBar().showMessage("New template")
    
    def open_template(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open", "", "YAML (*.yaml *.yml)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    template = yaml.safe_load(content)
                
                if 'id' in template:
                    self.template_editor.template_id.setText(template['id'])
                if 'info' in template:
                    info = template['info']
                    self.template_editor.template_name.setText(info.get('name', ''))
                    self.template_editor.author.setText(info.get('author', ''))
                    self.template_editor.severity_combo.setCurrentText(info.get('severity', 'medium'))
                    self.template_editor.description.setText(info.get('description', ''))
                    if 'reference' in info:
                        self.template_editor.reference.setText(info['reference'][0] if isinstance(info['reference'], list) else info['reference'])
                    if 'tags' in info:
                        self.template_editor.tags.setText(info['tags'] if isinstance(info['tags'], str) else ', '.join(info['tags']))
                
                if 'http' in template and template['http']:
                    http_section = template['http'][0]
                    if 'matchers' in http_section:
                        for matcher in http_section['matchers']:
                            self.matchers_panel.add_matcher_direct(matcher)
                    if 'raw' in http_section and http_section['raw']:
                        self.http_panel.request_text.setText(http_section['raw'][0])
                
                self.template_editor.set_template_yaml(content)
                self.statusBar().showMessage(f"Opened: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed: {e}")
    
    def save_template(self):
        default_name = f"{self.template_editor.template_id.text() or 'template'}.yaml"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save", default_name, "YAML (*.yaml *.yml)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.template_editor.get_template_yaml())
                self.statusBar().showMessage(f"Saved: {file_path}")
                QMessageBox.information(self, "Saved", f"Saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed: {e}")
    
    def add_cve_classification(self):
        dialog = CVEDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.current_template_data['classification'] = dialog.get_data()
            self.statusBar().showMessage("CVE classification added")
    
    def auto_detect_nuclei(self):
        for path in ['/usr/bin/nuclei', '/usr/local/bin/nuclei', str(Path.home() / 'go/bin/nuclei'), 'nuclei']:
            try:
                if subprocess.run([path, '-version'], capture_output=True, timeout=5).returncode == 0:
                    self.nuclei_path.setText(path)
                    self.statusBar().showMessage(f"Found: {path}")
                    return
            except:
                continue
        QMessageBox.warning(self, "Not Found", "Could not find nuclei")
    
    def save_settings(self):
        self.settings.setValue('nuclei_path', self.nuclei_path.text())
        self.settings.setValue('template_dir', self.template_dir.text())
        self.settings.setValue('font_size', self.font_size_spin.value())
        QMessageBox.information(self, "Saved", "Settings saved successfully!")
    
    def load_settings(self):
        self.nuclei_path.setText(self.settings.value('nuclei_path', ''))
        self.template_dir.setText(self.settings.value('template_dir', str(Path.home() / '.nuclei-templates')))
        font_size = int(self.settings.value('font_size', 11))
        self.font_size_spin.setValue(font_size)
        self.change_font_size(font_size)
        if not self.nuclei_path.text():
            self.auto_detect_nuclei()
    
    def show_about(self):
        QMessageBox.about(self, "About", "<h2>Nuclei Template Generator Pro</h2><p>v2.0 - Professional tool for Nuclei templates</p>")
    
    def apply_styles(self):
        self.setStyleSheet("""
            * { font-family: 'SF Pro Display', 'Segoe UI', -apple-system, sans-serif; font-size: 13px; }
            QMainWindow, QWidget { background: #0f0f23; color: #e0e0e0; }
            QLabel { color: #b0b0b0; font-size: 13px; }
            #sectionTitle { color: #64ffda; font-size: 16px; font-weight: bold; }
            #settingsTitle { color: #64ffda; font-size: 15px; font-weight: bold; margin-top: 10px; }
            #cardTitle { color: #61AFEF; font-size: 14px; font-weight: bold; }
            
            QLineEdit, QTextEdit { background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 6px; padding: 8px 10px; color: #fff; font-size: 13px; }
            QLineEdit:focus, QTextEdit:focus { border-color: #667eea; }
            
            QPushButton { background: #667eea; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; font-size: 13px; }
            QPushButton:hover { background: #764ba2; }
            #btn_secondary { background: #2a2a4a; }
            #btn_secondary:hover { background: #3a3a5a; }
            #btn_success { background: #00C853; }
            #btn_success:hover { background: #00E676; }
            
            QComboBox { background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 6px; padding: 8px; color: #fff; min-width: 80px; font-size: 13px; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background: #1a1a2e; border: 1px solid #2a2a4a; selection-background-color: #667eea; }
            
            QSpinBox { background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 6px; padding: 6px; color: #fff; font-size: 13px; }
            
            QTabWidget::pane { background: #0f0f23; border: 1px solid #2a2a4a; border-radius: 8px; }
            QTabBar::tab { background: #1a1a2e; color: #888; padding: 12px 24px; margin-right: 2px; border-top-left-radius: 6px; border-top-right-radius: 6px; font-size: 13px; font-weight: 600; }
            QTabBar::tab:selected { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #667eea, stop:1 #764ba2); color: white; }
            QTabBar::tab:hover:!selected { background: #2a2a4a; color: #fff; }
            
            QTableWidget { background: #0d0d1a; border: 1px solid #2a2a4a; border-radius: 6px; gridline-color: #2a2a4a; alternate-background-color: #151528; font-size: 13px; }
            QHeaderView::section { background: #1a1a2e; color: #64ffda; padding: 10px; border: none; font-weight: bold; font-size: 13px; }
            QTableWidget::item { padding: 8px; }
            QTableWidget::item:selected { background: #667eea; }
            
            QListWidget { background: #0d0d1a; border: 1px solid #2a2a4a; border-radius: 6px; font-size: 13px; }
            QListWidget::item { padding: 8px; }
            QListWidget::item:selected { background: #667eea; }
            
            QCheckBox { color: #e0e0e0; font-size: 13px; }
            QCheckBox::indicator { width: 18px; height: 18px; border-radius: 4px; border: 1px solid #2a2a4a; background: #1a1a2e; }
            QCheckBox::indicator:checked { background: #667eea; border-color: #667eea; }
            
            QSplitter::handle { background: #2a2a4a; }
            QSplitter::handle:hover { background: #667eea; }
            QSplitter::handle:horizontal { width: 5px; }
            QSplitter::handle:vertical { height: 5px; }
            
            QMenuBar { background: #0f0f23; color: #e0e0e0; font-size: 13px; }
            QMenuBar::item { padding: 8px 14px; border-radius: 4px; }
            QMenuBar::item:selected { background: #2a2a4a; }
            QMenu { background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 6px; padding: 6px; }
            QMenu::item { padding: 8px 24px; border-radius: 4px; font-size: 13px; }
            QMenu::item:selected { background: #667eea; }
            
            QScrollBar:vertical { background: #0f0f23; width: 10px; }
            QScrollBar::handle:vertical { background: #2a2a4a; border-radius: 5px; min-height: 20px; }
            QScrollBar::handle:vertical:hover { background: #667eea; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
            QScrollBar:horizontal { background: #0f0f23; height: 10px; }
            QScrollBar::handle:horizontal { background: #2a2a4a; border-radius: 5px; min-width: 20px; }
            QScrollBar::handle:horizontal:hover { background: #667eea; }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
            
            QStatusBar { background: #1a1a2e; color: #64ffda; padding: 6px; font-size: 12px; }
            QMessageBox, QDialog { background: #0f0f23; }
            QMessageBox QLabel { font-size: 13px; }
        """)


def main():
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    app = QApplication(sys.argv)
    app.setApplicationName("Nuclei Template Generator Pro")
    
    # Set larger default font based on platform
    if sys.platform == "darwin":
        font = QFont("SF Pro Display", 13)
    elif sys.platform.startswith("linux"):
        font = QFont("Ubuntu", 12)
    else:
        font = QFont("Segoe UI", 11)
    app.setFont(font)
    
    window = NucleiTemplateGenerator()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
