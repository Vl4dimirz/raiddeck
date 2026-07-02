"""Modern dark dashboard theme. Vibrant, easy to scan: an indigo accent for
actions, and bold, distinct severity colours (this is a security tool — colour
by severity is the whole point of the UI)."""

ACCENT = "#6366f1"        # indigo
ACCENT_HOVER = "#7c7ff5"
ACCENT_PRESS = "#565ae0"

QSS = f"""
* {{ font-family: "Segoe UI", Arial, sans-serif; font-size: 14px; }}

QMainWindow, QWidget {{ background: #0f1117; color: #e8eaf0; }}

QMenuBar {{ background: #0f1117; color: #b9bdca; border-bottom: 1px solid #232634; }}
QMenuBar::item {{ padding: 7px 12px; background: transparent; }}
QMenuBar::item:selected {{ background: #1d2130; border-radius: 6px; }}
QMenu {{ background: #171a24; color: #e8eaf0; border: 1px solid #2a2e3e; padding: 6px; }}
QMenu::item {{ padding: 7px 26px; border-radius: 6px; }}
QMenu::item:selected {{ background: #2a2e42; }}

QLineEdit {{
    background: #181b24; border: 1px solid #2c303e; border-radius: 10px;
    padding: 10px 14px; color: #e8eaf0; selection-background-color: {ACCENT};
}}
QLineEdit:focus {{ border: 1px solid {ACCENT}; }}

QPushButton {{
    background: #1e2230; color: #e8eaf0; border: 1px solid #303546;
    border-radius: 10px; padding: 9px 18px;
}}
QPushButton:hover {{ background: #262b3b; }}
QPushButton:pressed {{ background: #2d3346; }}
QPushButton:disabled {{ color: #6b6f7d; background: #191c26; border-color: #262a37; }}

QPushButton#primary {{ background: {ACCENT}; color: #ffffff; font-weight: 700; border: none; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#primary:pressed {{ background: {ACCENT_PRESS}; }}
QPushButton#primary:disabled {{ background: #3a3d5c; color: #9a9db0; }}

QCheckBox {{ color: #c6c9d4; spacing: 9px; }}
QCheckBox::indicator {{
    width: 18px; height: 18px; border-radius: 5px;
    border: 1px solid #3c4152; background: #181b24;
}}
QCheckBox::indicator:hover {{ border: 1px solid {ACCENT}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border: 1px solid {ACCENT}; }}

QListWidget {{
    background: #141721; border: 1px solid #232634; border-radius: 12px; padding: 6px; outline: 0;
}}
QListWidget::item {{ padding: 10px 11px; border-radius: 9px; color: #b9bdca; margin-bottom: 3px; }}
QListWidget::item:hover {{ background: #1c2030; }}
QListWidget::item:selected {{ background: #262a45; color: #ffffff; border: 1px solid {ACCENT}; }}

QTableWidget {{
    background: #141721; border: 1px solid #232634; border-radius: 12px;
    color: #d9dbe4; alternate-background-color: #171a25; outline: 0;
}}
QTableWidget::item {{ padding: 9px 10px; }}
QTableWidget::item:selected {{ background: #262a45; color: #ffffff; }}
QHeaderView::section {{
    background: #181b26; color: #9498a6; padding: 12px 10px; border: none;
    border-bottom: 1px solid #2a2e3e; font-weight: 600;
}}
QTableCornerButton::section {{ background: #181b26; border: none; }}

QScrollBar:vertical {{ background: transparent; width: 11px; margin: 3px; }}
QScrollBar::handle:vertical {{ background: #333850; border-radius: 5px; min-height: 32px; }}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QSplitter::handle {{ background: transparent; }}
QToolTip {{ background: #181b24; color: #e8eaf0; border: 1px solid #2c303e; padding: 6px; border-radius: 6px; }}
QDialog, QMessageBox, QInputDialog {{ background: #0f1117; }}
"""

# Bold, distinct severity colours (Tailwind-ish) — the usable heart of the UI.
SEV_BG = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
    "LOW": "#3b82f6", "INFO": "#6b7280",
}
SEV_FG = {
    "CRITICAL": "#ffffff", "HIGH": "#ffffff", "MEDIUM": "#1c1500",
    "LOW": "#ffffff", "INFO": "#ffffff",
}
