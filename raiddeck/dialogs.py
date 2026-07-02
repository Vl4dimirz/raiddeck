"""Authorized Targets manager dialog."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from raiddeck import scope


class TargetsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authorized Targets")
        self.resize(460, 360)
        layout = QVBoxLayout(self)

        note = QLabel(
            "Only add hosts you OWN or have written permission to test. "
            "RaidDeck will only scan these (plus local/private addresses)."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color:#666;")
        layout.addWidget(note)

        self.list = QListWidget()
        layout.addWidget(self.list, 1)

        row = QHBoxLayout()
        add = QPushButton("Add…")
        remove = QPushButton("Remove")
        close = QPushButton("Close")
        add.clicked.connect(self._add)
        remove.clicked.connect(self._remove)
        close.clicked.connect(self.accept)
        row.addWidget(add)
        row.addWidget(remove)
        row.addStretch(1)
        row.addWidget(close)
        layout.addLayout(row)

        self._refresh()

    def _refresh(self) -> None:
        self.list.clear()
        self.list.addItems(scope.authorized_hosts())

    def _add(self) -> None:
        host, ok = QInputDialog.getText(
            self, "Add authorized target",
            "Host you own / are permitted to test (e.g. myapp.example.com):",
        )
        host = host.strip().lower()
        if ok and host:
            # store a bare host; strip any scheme/path the user pasted
            host = host.split("//")[-1].split("/")[0]
            scope.add_authorized(host)
            self._refresh()

    def _remove(self) -> None:
        item = self.list.currentItem()
        if item is None:
            return
        if QMessageBox.question(self, "Remove", f"Remove '{item.text()}'?") == QMessageBox.Yes:
            scope.remove_authorized(item.text())
            self._refresh()
