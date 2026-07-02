"""Render RaidDeck with sample findings + a history entry, screenshot, and
verify the HTML export renders."""
import sys
from datetime import datetime, timezone

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication

from raiddeck import history, reporting, theme
from raiddeck.app import MainWindow
from raidkit.report import Finding, Severity

app = QApplication(sys.argv)
app.setStyle("Fusion")
app.setStyleSheet(theme.QSS)
w = MainWindow()
w.target.setText("http://localhost:8046/")
w.authorized.setChecked(True)

sample = [
    Finding("cors", "CORS reflects ANY origin AND allows credentials", Severity.CRITICAL,
            evidence="ACAO echoed, Allow-Credentials: true", remediation="Allowlist specific origins."),
    Finding("exposure", "Environment file (.env) is publicly served", Severity.HIGH,
            evidence="200 http://localhost:8046/.env", remediation="Block dotfiles at the web server."),
    Finding("headers", "Missing Content-Security-Policy", Severity.MEDIUM,
            remediation="Add a CSP to constrain script/style sources."),
    Finding("discovery", "API docs (Swagger UI) reachable: /docs", Severity.MEDIUM,
            evidence="200 http://localhost:8046/docs", remediation="Disable docs in production."),
    Finding("transport", "Cookie 'session' missing HttpOnly, Secure", Severity.LOW,
            evidence="set-cookie: session=abc", remediation="Set Secure + HttpOnly + SameSite."),
    Finding("discovery", "Health check reachable: /health", Severity.INFO,
            evidence="200 http://localhost:8046/health"),
]
now = datetime.now(timezone.utc).isoformat()
recs = [
    history.ScanRecord("http://localhost:8046/", now, sample),
    history.ScanRecord("http://127.0.0.1:3000/", now, sample[:3]),
]
w._records = recs
w._refresh_history()
w.history_list.setCurrentRow(0)
w._show_record(recs[0])

# verify HTML export renders without error
with open("C:/Users/Phisi/raiddeck/_sample_report.html", "w", encoding="utf-8") as f:
    f.write(reporting.to_html(recs[0].target, sample, datetime.now(timezone.utc)))

w.show()


def snap():
    w.grab().save("C:/Users/Phisi/raiddeck/preview.png")
    app.quit()


QTimer.singleShot(500, snap)
app.exec()
print("saved preview.png + _sample_report.html")
