from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import BodyLabel, PlainTextEdit, PrimaryPushButton, PushButton, SearchLineEdit, SubtitleLabel


class LogsPage(QWidget):
    clear_requested = pyqtSignal()
    export_diag_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("logs")
        self._lines: list[str] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("Логи и диагностика", self))

        toolbar = QHBoxLayout()
        self.search = SearchLineEdit(self)
        self.search.setPlaceholderText("Фильтр логов")
        self.clear_btn = PushButton("Очистить", self)
        self.export_btn = PrimaryPushButton("Экспорт диагностики", self)

        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.clear_btn)
        toolbar.addWidget(self.export_btn)
        root.addLayout(toolbar)

        root.addWidget(BodyLabel("Логи работы", self))
        self.log_edit = PlainTextEdit(self)
        self.log_edit.setReadOnly(True)
        root.addWidget(self.log_edit, 1)

        self.search.textChanged.connect(self._refresh)
        self.clear_btn.clicked.connect(self.clear_requested)
        self.export_btn.clicked.connect(self.export_diag_requested)

    def append_line(self, line: str) -> None:
        self._lines.append(line)
        if len(self._lines) > 5000:
            self._lines = self._lines[-5000:]
        self._refresh()

    def set_lines(self, lines: list[str]) -> None:
        self._lines = list(lines)
        self._refresh()

    def clear_view(self) -> None:
        self._lines = []
        self.log_edit.clear()

    def _refresh(self) -> None:
        query = self.search.text().strip().lower()
        if not query:
            data = self._lines
        else:
            data = [line for line in self._lines if query in line.lower()]
        self.log_edit.setPlainText("\n".join(data[-2000:]))
        vbar = self.log_edit.verticalScrollBar()
        vbar.setValue(vbar.maximum())
