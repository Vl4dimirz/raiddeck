"""RaidDeck main window — GUI over the raidkit engine, scope-gated white-hat.

Features: authorized-only scanning, background scans, color-coded findings,
scan history, report export (JSON/Markdown/HTML), a target manager, and
per-check selection.
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from raidkit.checks import cors, discovery, exposure, headers, openredirect, transport, xss
from raidkit.http import make_client
from raidkit.report import Finding, Severity

from raiddeck import __version__, history, reporting, scope, theme
from raiddeck.dialogs import TargetsDialog

AVAILABLE_CHECKS = [
    ("headers", headers), ("transport", transport), ("exposure", exposure),
    ("discovery", discovery), ("cors", cors), ("openredirect", openredirect), ("xss", xss),
]


async def _run(url: str, modules) -> list[Finding]:
    findings: list[Finding] = []
    async with make_client() as client:
        for m in modules:
            findings += await m.run(client, url)
    return findings


class ScanThread(QThread):
    done = Signal(list)
    failed = Signal(str)

    def __init__(self, url: str, modules):
        super().__init__()
        self.url = url
        self.modules = modules

    def run(self) -> None:
        try:
            self.done.emit(asyncio.run(_run(self.url, self.modules)))
        except Exception as e:
            self.failed.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"RaidDeck {__version__} — White-Hat Security Toolkit")
        self.resize(1120, 720)
        self._thread: ScanThread | None = None
        self._records: list[history.ScanRecord] = history.load()
        self._current: history.ScanRecord | None = None
        self._enabled = {name for name, _ in AVAILABLE_CHECKS}

        self._build_menu()

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(22, 18, 22, 16)
        layout.setSpacing(14)

        # header — wordmark + subtitle
        header = QHBoxLayout()
        title = QLabel("Raid<span style='color:#818cf8'>Deck</span>")
        title.setTextFormat(Qt.RichText)
        title.setStyleSheet("font-size:26px; font-weight:800; letter-spacing:0.5px;")
        subtitle = QLabel("White-Hat Security Toolkit")
        subtitle.setStyleSheet("color:#7d808a; font-size:13px; padding-bottom:3px;")
        header.addWidget(title)
        header.addSpacing(12)
        header.addWidget(subtitle, 0, Qt.AlignBottom)
        header.addStretch(1)
        layout.addLayout(header)

        banner = QLabel(
            "<b style='color:#e2b23a'>WHITE-HAT MODE</b>  &nbsp;RaidDeck only scans "
            "local/private hosts or your Authorized Targets, read-only. Never use it "
            "on systems you don't own or aren't permitted to test."
        )
        banner.setWordWrap(True)
        banner.setStyleSheet(
            "background:#17140c; color:#b9bcc4; border:1px solid #3a3016;"
            "border-left:3px solid #e2b23a; border-radius:8px; padding:11px 14px;"
        )
        layout.addWidget(banner)

        row = QHBoxLayout()
        row.setSpacing(12)
        self.target = QLineEdit()
        self.target.setPlaceholderText("https://localhost:8000/")
        self.target.setMinimumHeight(40)
        self.authorized = QCheckBox("I'm authorized to test this target")
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setMinimumHeight(40)
        self.scan_btn.setMinimumWidth(120)
        self.scan_btn.setCursor(Qt.PointingHandCursor)
        row.addWidget(self.target, 1)
        row.addWidget(self.authorized)
        row.addWidget(self.scan_btn)
        layout.addLayout(row)

        splitter = QSplitter(Qt.Horizontal)
        self.history_list = QListWidget()
        self.history_list.setMaximumWidth(260)
        self.history_list.itemClicked.connect(self._open_record)
        splitter.addWidget(self.history_list)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Severity", "Check", "Finding", "Evidence", "Fix"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        h = self.table.horizontalHeader()
        for col, mode in ((0, QHeaderView.ResizeToContents), (1, QHeaderView.ResizeToContents),
                          (2, QHeaderView.Stretch), (3, QHeaderView.ResizeToContents),
                          (4, QHeaderView.Stretch)):
            h.setSectionResizeMode(col, mode)
        splitter.addWidget(self.table)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        self.status = QLabel("Ready. Enter a target you own, tick authorized, and scan.")
        self.status.setStyleSheet("color:#888;")
        layout.addWidget(self.status)

        self.scan_btn.clicked.connect(self._on_scan)
        self.target.returnPressed.connect(self._on_scan)
        self._refresh_history()

    # ---- menu ----
    def _build_menu(self) -> None:
        bar = self.menuBar()
        filemenu = bar.addMenu("&File")
        self.act_json = QAction("Export JSON…", self, triggered=lambda: self._export("json"))
        self.act_md = QAction("Export Markdown…", self, triggered=lambda: self._export("md"))
        self.act_html = QAction("Export HTML…", self, triggered=lambda: self._export("html"))
        for a in (self.act_json, self.act_md, self.act_html):
            a.setEnabled(False)
            filemenu.addAction(a)
        filemenu.addSeparator()
        filemenu.addAction(QAction("Exit", self, triggered=self.close))

        tmenu = bar.addMenu("&Targets")
        tmenu.addAction(QAction("Manage authorized targets…", self, triggered=self._manage))

        cmenu = bar.addMenu("&Checks")
        for name, _ in AVAILABLE_CHECKS:
            act = QAction(name, self, checkable=True, checked=True)
            act.toggled.connect(lambda on, n=name: self._toggle_check(n, on))
            cmenu.addAction(act)

    def _toggle_check(self, name: str, on: bool) -> None:
        (self._enabled.add if on else self._enabled.discard)(name)

    # ---- scanning ----
    def _on_scan(self) -> None:
        url = self.target.text().strip()
        if not url:
            return
        if not self.authorized.isChecked():
            QMessageBox.warning(self, "Authorization required",
                                "Tick 'I'm authorized to test this target' first.")
            return
        allowed, reason = scope.check(url)
        if not allowed:
            QMessageBox.warning(self, "Out of scope",
                                reason + "\n\nUse Targets → Manage to add a host you own.")
            return
        modules = [m for n, m in AVAILABLE_CHECKS if n in self._enabled]
        if not modules:
            QMessageBox.information(self, "No checks", "Enable at least one check in the Checks menu.")
            return

        self._set_scanning(True)
        self.status.setText(f"Scanning {url}  ({reason})…")
        self._thread = ScanThread(url, modules)
        self._thread.done.connect(lambda f, u=url: self._on_done(u, f))
        self._thread.failed.connect(self._on_failed)
        self._thread.start()

    def _on_done(self, url: str, findings: list[Finding]) -> None:
        record = history.ScanRecord(url, datetime.now(timezone.utc).isoformat(), findings)
        self._records.append(record)
        history.save(self._records)
        self._refresh_history()
        self.history_list.setCurrentRow(0)
        self._show_record(record)
        self._set_scanning(False)

    def _on_failed(self, msg: str) -> None:
        self._set_scanning(False)
        self.status.setText(f"Scan failed: {msg}")

    def _set_scanning(self, scanning: bool) -> None:
        self.scan_btn.setEnabled(not scanning)
        self.scan_btn.setText("Scanning…" if scanning else "Scan")

    # ---- history + display ----
    def _refresh_history(self) -> None:
        self.history_list.clear()
        for rec in reversed(self._records):  # newest first
            when = rec.when[11:16] if len(rec.when) > 16 else rec.when
            item = QListWidgetItem(f"{when}  {rec.target}\n   {len(rec.findings)} findings")
            item.setData(Qt.UserRole, rec)
            self.history_list.addItem(item)

    def _open_record(self, item: QListWidgetItem) -> None:
        self._show_record(item.data(Qt.UserRole))

    def _sev_pill(self, name: str) -> QWidget:
        lbl = QLabel(name)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setFixedSize(86, 24)
        lbl.setStyleSheet(
            f"background:{theme.SEV_BG[name]}; color:{theme.SEV_FG[name]};"
            "border-radius:12px; font-weight:800; font-size:11px; letter-spacing:0.5px;"
        )
        holder = QWidget()
        holder.setStyleSheet("background:transparent;")
        lay = QHBoxLayout(holder)
        lay.setContentsMargins(10, 5, 10, 5)
        lay.addWidget(lbl)
        lay.setAlignment(Qt.AlignCenter)
        return holder

    def _show_record(self, record: history.ScanRecord) -> None:
        self._current = record
        for a in (self.act_json, self.act_md, self.act_html):
            a.setEnabled(True)
        findings = sorted(record.findings, key=lambda f: f.severity, reverse=True)
        self.table.setRowCount(len(findings))
        for i, f in enumerate(findings):
            self.table.setCellWidget(i, 0, self._sev_pill(f.severity.name))
            self.table.setItem(i, 1, QTableWidgetItem(f.check))
            self.table.setItem(i, 2, QTableWidgetItem(f.title))
            self.table.setItem(i, 3, QTableWidgetItem(f.evidence))
            self.table.setItem(i, 4, QTableWidgetItem(f.remediation))
        self.table.resizeRowsToContents()
        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = "   ".join(f"{s.name}: {counts.get(s, 0)}" for s in reversed(Severity))
        self.status.setText(f"{record.target} — {len(findings)} findings.   {summary}")

    # ---- export ----
    def _export(self, fmt: str) -> None:
        if self._current is None:
            return
        rec = self._current
        host = rec.target.split("//")[-1].split("/")[0].split(":")[0] or "scan"
        default = f"raiddeck-{host}-{rec.when[:10]}.{fmt}"
        filters = {"json": "JSON (*.json)", "md": "Markdown (*.md)", "html": "HTML (*.html)"}
        path, _ = QFileDialog.getSaveFileName(self, "Export report", default, filters[fmt])
        if not path:
            return
        when = datetime.fromisoformat(rec.when)
        text = {
            "json": reporting.to_json, "md": reporting.to_markdown, "html": reporting.to_html,
        }[fmt](rec.target, rec.findings, when)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.status.setText(f"Wrote {path}")

    def _manage(self) -> None:
        TargetsDialog(self).exec()


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(theme.QSS)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
