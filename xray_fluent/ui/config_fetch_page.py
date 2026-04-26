"""config_fetch_page.py — страница управления автозагрузкой VPN-конфигов."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QPlainTextEdit,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    FluentIcon as FIF,
    IndeterminateProgressBar,
    PrimaryPushButton,
    ProgressBar,
    PushButton,
    SpinBox,
    SubtitleLabel,
    SwitchButton,
    TitleLabel,
)

from ..config_fetcher import URLS_BASE


class ConfigFetchPage(QWidget):
    """Страница «Авто-загрузка конфигов»."""

    # Сигналы, которые обрабатывает main_window → controller
    fetch_now_requested = pyqtSignal()
    stop_fetch_requested = pyqtSignal()
    settings_changed = pyqtSignal(dict)   # {enabled, interval_min, workers, filter, dedup, extra_urls}

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("config_fetch")

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 28, 36, 28)
        root.setSpacing(20)

        # ── Заголовок ──
        title = SubtitleLabel("Авто-загрузка конфигов", self)
        root.addWidget(title)

        desc = CaptionLabel(
            f"Загружает VPN-конфиги из {len(URLS_BASE)} публичных источников "
            "(GitHub-репозитории). Фильтрует серверы РФ/Европы и автоматически "
            "добавляет новые ноды в список серверов.",
            self,
        )
        desc.setWordWrap(True)
        root.addWidget(desc)

        # ── Включить авто-обновление ──
        auto_row = QHBoxLayout()
        auto_label = BodyLabel("Автоматическое обновление", self)
        self._auto_switch = SwitchButton(self)
        self._auto_switch.setChecked(False)
        self._auto_switch.checkedChanged.connect(self._on_any_change)
        auto_row.addWidget(auto_label)
        auto_row.addStretch()
        auto_row.addWidget(self._auto_switch)
        root.addLayout(auto_row)

        # ── Интервал ──
        interval_row = QHBoxLayout()
        interval_label = BodyLabel("Интервал обновления (мин)", self)
        self._interval_spin = SpinBox(self)
        self._interval_spin.setRange(5, 1440)
        self._interval_spin.setValue(60)
        self._interval_spin.setFixedWidth(100)
        self._interval_spin.valueChanged.connect(self._on_any_change)
        interval_row.addWidget(interval_label)
        interval_row.addStretch()
        interval_row.addWidget(self._interval_spin)
        root.addLayout(interval_row)

        # ── Кол-во потоков ──
        workers_row = QHBoxLayout()
        workers_label = BodyLabel("Параллельных потоков загрузки", self)
        self._workers_spin = SpinBox(self)
        self._workers_spin.setRange(1, 50)
        self._workers_spin.setValue(20)
        self._workers_spin.setFixedWidth(100)
        self._workers_spin.valueChanged.connect(self._on_any_change)
        workers_row.addWidget(workers_label)
        workers_row.addStretch()
        workers_row.addWidget(self._workers_spin)
        root.addLayout(workers_row)

        # ── Фильтр РФ/Европа ──
        filter_row = QHBoxLayout()
        filter_label = BodyLabel("Фильтр: только Россия и Европа", self)
        filter_caption = CaptionLabel("Отсеивает серверы из других регионов", self)
        filter_label_box = QVBoxLayout()
        filter_label_box.setSpacing(2)
        filter_label_box.addWidget(filter_label)
        filter_label_box.addWidget(filter_caption)
        self._filter_switch = SwitchButton(self)
        self._filter_switch.setChecked(True)
        self._filter_switch.checkedChanged.connect(self._on_any_change)
        filter_row.addLayout(filter_label_box)
        filter_row.addStretch()
        filter_row.addWidget(self._filter_switch)
        root.addLayout(filter_row)

        # ── Дедупликация ──
        dedup_row = QHBoxLayout()
        dedup_label = BodyLabel("Дедупликация по IP:port:protocol", self)
        dedup_caption = CaptionLabel("Убирает дубликаты с одинаковым адресом", self)
        dedup_label_box = QVBoxLayout()
        dedup_label_box.setSpacing(2)
        dedup_label_box.addWidget(dedup_label)
        dedup_label_box.addWidget(dedup_caption)
        self._dedup_switch = SwitchButton(self)
        self._dedup_switch.setChecked(True)
        self._dedup_switch.checkedChanged.connect(self._on_any_change)
        dedup_row.addLayout(dedup_label_box)
        dedup_row.addStretch()
        dedup_row.addWidget(self._dedup_switch)
        root.addLayout(dedup_row)

        # ── Дополнительные URL ──
        extra_label = BodyLabel("Дополнительные URL подписок (по одному на строку)", self)
        root.addWidget(extra_label)
        self._extra_urls_edit = QPlainTextEdit(self)
        self._extra_urls_edit.setPlaceholderText(
            "https://example.com/sub.txt\nhttps://another.example/vmess"
        )
        self._extra_urls_edit.setFixedHeight(90)
        self._extra_urls_edit.textChanged.connect(self._on_any_change)
        root.addWidget(self._extra_urls_edit)

        # ── Кнопки запуска / остановки ──
        btn_row = QHBoxLayout()
        self._fetch_btn = PrimaryPushButton(FIF.DOWNLOAD, "Загрузить сейчас", self)
        self._fetch_btn.clicked.connect(self._on_fetch_now)
        self._stop_btn = PushButton(FIF.CLOSE, "Остановить", self)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self.stop_fetch_requested)
        btn_row.addWidget(self._fetch_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # ── Прогресс ──
        self._spinner = IndeterminateProgressBar(self)
        self._spinner.setFixedHeight(4)
        self._spinner.hide()
        root.addWidget(self._spinner)

        self._progress_bar = ProgressBar(self)
        self._progress_bar.setFixedHeight(8)
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.hide()
        root.addWidget(self._progress_bar)

        self._status_label = CaptionLabel("", self)
        self._status_label.setWordWrap(True)
        root.addWidget(self._status_label)

        root.addStretch()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_settings(
        self,
        enabled: bool,
        interval_min: int,
        workers: int,
        filter_on: bool,
        dedup: bool,
        extra_urls: list[str],
    ) -> None:
        """Загрузить текущие настройки из AppSettings."""
        self._auto_switch.setChecked(enabled)
        self._interval_spin.setValue(interval_min)
        self._workers_spin.setValue(workers)
        self._filter_switch.setChecked(filter_on)
        self._dedup_switch.setChecked(dedup)
        self._extra_urls_edit.setPlainText("\n".join(extra_urls))

    def on_fetch_started(self) -> None:
        self._fetch_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._spinner.show()
        self._progress_bar.show()
        self._progress_bar.setValue(0)
        self._status_label.setText("Загрузка конфигов...")

    def on_fetch_progress(self, done: int, total: int, added: int) -> None:
        if total > 0:
            self._progress_bar.setValue(int(done / total * 100))
        self._status_label.setText(
            f"Обработано: {done}/{total} источников, получено конфигов: {added}"
        )

    def on_fetch_finished(self, imported: int, total_configs: int, errors: int) -> None:
        self._fetch_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._spinner.hide()
        self._progress_bar.setValue(100)
        err_txt = f", ошибок: {errors}" if errors else ""
        self._status_label.setText(
            f"✅ Готово! Конфигов найдено: {total_configs}, "
            f"добавлено нод: {imported}{err_txt}"
        )

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _on_fetch_now(self) -> None:
        self._emit_settings()
        self.fetch_now_requested.emit()

    def _on_any_change(self) -> None:
        self._emit_settings()

    def _emit_settings(self) -> None:
        extra_raw = self._extra_urls_edit.toPlainText().strip()
        extra_urls = [u.strip() for u in extra_raw.splitlines() if u.strip()]
        self.settings_changed.emit({
            "enabled": self._auto_switch.isChecked(),
            "interval_min": self._interval_spin.value(),
            "workers": self._workers_spin.value(),
            "filter": self._filter_switch.isChecked(),
            "dedup": self._dedup_switch.isChecked(),
            "extra_urls": extra_urls,
        })
