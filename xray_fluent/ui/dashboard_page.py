from __future__ import annotations

import socket
import threading
from collections import deque

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QStackedWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    BreadcrumbBar,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon as FIF,
    PrimaryPushButton,
    PushButton,
    SmoothScrollArea,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TableWidget,
    TransparentToolButton,
)

from ..models import AppSettings, Node, RoutingSettings
from .traffic_graph import DetailTrafficGraphWidget, TrafficGraphWidget


def _format_speed(value_bps: float) -> str:
    value = max(0.0, value_bps)
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    unit_index = 0
    while value >= 1024.0 and unit_index < len(units) - 1:
        value /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.2f} {units[unit_index]}"


def _format_latency(value_ms: int | None) -> str:
    if value_ms is None:
        return "--"
    return f"{value_ms} ms"


def _mode_title(mode: str) -> str:
    mapping = {
        "global": "Глобальный",
        "rule": "Правила",
        "direct": "Прямой",
    }
    return mapping.get(mode, mode.title() or "Неизвестно")


def _detect_my_country() -> str:
    """
    Определяем страну пользователя через ip-api.com.
    Возвращает двухбуквенный код (например 'RU') или '' при ошибке.
    Вызывать только из фонового потока.
    """
    try:
        import urllib.request, json
        with urllib.request.urlopen("http://ip-api.com/json/?fields=countryCode", timeout=5) as r:
            data = json.loads(r.read())
            return data.get("countryCode", "")
    except Exception:
        return ""


class DashboardPage(QWidget):
    toggle_connection_requested = pyqtSignal()
    # Сигнал подключения к конкретному узлу (для "Подключиться к самому быстрому")
    connect_fastest_requested   = pyqtSignal()
    node_selected  = pyqtSignal(str)
    mode_changed   = pyqtSignal(str)
    tun_toggled    = pyqtSignal(bool)
    proxy_toggled  = pyqtSignal(bool)
    # Zapret-управление с дашборда
    zapret_start_requested = pyqtSignal(str)   # preset_name
    zapret_stop_requested  = pyqtSignal()
    # Smart-connection toggles (напрямую меняют AppSettings)
    dpi_fragment_toggled   = pyqtSignal(bool)
    dpi_mux_toggled        = pyqtSignal(bool)
    dpi_noise_toggled      = pyqtSignal(bool)
    auto_switch_toggled    = pyqtSignal(bool)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("dashboard")

        self._nodes: list[Node] = []
        self._node_ids: list[str] = []
        self._selected_node: Node | None = None
        self._connected = False
        self._mode = "rule"
        self._settings = AppSettings()
        self._routing = RoutingSettings()
        self._selected_latency_ms: int | None = None
        self._live_rtt_ms: int | None = None
        self._last_down_bps = 0.0
        self._last_up_bps = 0.0
        self._peak_bps = 0.0
        self._down_history: deque[float] = deque(maxlen=300)
        self._up_history: deque[float] = deque(maxlen=300)
        self._last_process_stats: list | None = None

        # Zapret state
        self._zapret_running  = False
        self._zapret_preset   = ""
        self._zapret_presets: list[str] = []

        # My country (resolved async once)
        self._my_country: str = ""
        self._my_country_resolved = False

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(30)
        self._refresh_timer.timeout.connect(self._do_refresh_dashboard)

        # ── Outer layout with QStackedWidget ──────────────────
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._stack = QStackedWidget(self)
        outer.addWidget(self._stack)

        # ── Page 0: main dashboard ────────────────────────────
        main_page = QWidget()
        main_page.setStyleSheet("QWidget { background: transparent; }")
        self._stack.addWidget(main_page)

        main_outer = QVBoxLayout(main_page)
        main_outer.setContentsMargins(0, 0, 0, 0)

        self._scroll = SmoothScrollArea(main_page)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        main_outer.addWidget(self._scroll)

        container = QWidget()
        container.setStyleSheet("QWidget { background: transparent; }")
        self._scroll.setWidget(container)

        root = QVBoxLayout(container)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("Панель управления", container))
        self.summary_label = CaptionLabel("Краткий обзор подключения, профиля, трафика и маршрутизации.", self)
        self.summary_label.setWordWrap(True)
        root.addWidget(self.summary_label)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        # ── Connection card (задача 4: переименован в «Подключение к VPN») ──
        self.connection_card = CardWidget(self)
        connection_layout = QVBoxLayout(self.connection_card)
        connection_layout.setContentsMargins(18, 16, 18, 16)
        connection_layout.setSpacing(6)
        connection_layout.addWidget(StrongBodyLabel("Подключение к VPN", self.connection_card))
        self.connection_state_label = SubtitleLabel("Ожидание", self.connection_card)
        self.connection_engine_label = BodyLabel("Системный прокси", self.connection_card)
        self.connection_status_label = CaptionLabel("Прокси остановлен", self.connection_card)
        self.connection_target_label = CaptionLabel("Активный профиль не выбран", self.connection_card)
        self.connection_target_label.setWordWrap(True)
        connection_layout.addWidget(self.connection_state_label)
        connection_layout.addWidget(self.connection_engine_label)

        switches_row = QHBoxLayout()
        switches_row.setSpacing(20)
        tun_label = CaptionLabel("VPN (TUN)", self.connection_card)
        self.tun_switch = SwitchButton(self.connection_card)
        self.tun_switch.setOnText("Вкл")
        self.tun_switch.setOffText("Выкл")
        switches_row.addWidget(tun_label)
        switches_row.addWidget(self.tun_switch)
        switches_row.addSpacing(12)
        proxy_label = CaptionLabel("Сист. прокси", self.connection_card)
        self.proxy_switch = SwitchButton(self.connection_card)
        self.proxy_switch.setOnText("Вкл")
        self.proxy_switch.setOffText("Выкл")
        switches_row.addWidget(proxy_label)
        switches_row.addWidget(self.proxy_switch)
        switches_row.addStretch(1)
        connection_layout.addLayout(switches_row)

        # Задача 1: кнопка «Подключиться к лучшему» (другая страна)
        self.fastest_btn = PrimaryPushButton(FIF.PLAY_SOLID, "Подключиться к лучшему", self.connection_card)
        self.fastest_btn.setToolTip("Подключиться к самому быстрому серверу другой страны")
        connection_layout.addWidget(self.fastest_btn)

        # Обычная кнопка запуска/остановки (без auto-select)
        self.toggle_btn = PushButton(FIF.PLAY_SOLID, "Запустить прокси", self.connection_card)
        connection_layout.addWidget(self.toggle_btn)

        # Hidden node combo (keeps selection logic intact, UI on nodes page)
        self.node_combo = ComboBox(self.connection_card)
        self.node_combo.setVisible(False)

        connection_layout.addStretch(1)
        self.connection_status_label.setWordWrap(True)
        connection_layout.addWidget(self.connection_status_label)
        self.connection_target_label.setWordWrap(True)
        connection_layout.addWidget(self.connection_target_label)

        # Profile info labels (read-only, hidden)
        self.profile_name_label = BodyLabel("", self)
        self.profile_name_label.setVisible(False)
        self.profile_endpoint_label = CaptionLabel("", self)
        self.profile_endpoint_label.setVisible(False)
        self.profile_group_label = CaptionLabel("", self)
        self.profile_group_label.setVisible(False)
        self.profile_latency_label = CaptionLabel("", self)
        self.profile_latency_label.setVisible(False)

        # ── Zapret card (задача 5: вместо routing на месте [0,1]) ──
        self.zapret_card = CardWidget(self)
        zapret_layout = QVBoxLayout(self.zapret_card)
        zapret_layout.setContentsMargins(18, 16, 18, 16)
        zapret_layout.setSpacing(8)
        zapret_layout.addWidget(StrongBodyLabel("Управление Zapret", self.zapret_card))

        self._zapret_state_label = BodyLabel("Остановлен", self.zapret_card)
        zapret_layout.addWidget(self._zapret_state_label)

        self._zapret_preset_combo = ComboBox(self.zapret_card)
        self._zapret_preset_combo.setPlaceholderText("Выберите пресет...")
        zapret_layout.addWidget(self._zapret_preset_combo)

        zapret_btn_row = QHBoxLayout()
        self._zapret_start_btn = PrimaryPushButton(FIF.PLAY_SOLID, "Запустить", self.zapret_card)
        self._zapret_stop_btn  = PushButton(FIF.CLOSE, "Остановить", self.zapret_card)
        self._zapret_stop_btn.setEnabled(False)
        zapret_btn_row.addWidget(self._zapret_start_btn)
        zapret_btn_row.addWidget(self._zapret_stop_btn)
        zapret_btn_row.addStretch(1)
        zapret_layout.addLayout(zapret_btn_row)

        self._zapret_error_label = CaptionLabel("", self.zapret_card)
        self._zapret_error_label.setWordWrap(True)
        self._zapret_error_label.setVisible(False)
        zapret_layout.addWidget(self._zapret_error_label)
        zapret_layout.addStretch(1)

        # ── Traffic card ──────────────────────────────────────
        self.traffic_card = CardWidget(self)
        traffic_layout = QVBoxLayout(self.traffic_card)
        traffic_layout.setContentsMargins(18, 16, 18, 16)
        traffic_layout.setSpacing(6)
        traffic_layout.addWidget(StrongBodyLabel("Трафик", self.traffic_card))
        self.traffic_down_label = BodyLabel("Загрузка: 0 B/s", self.traffic_card)
        self.traffic_up_label = BodyLabel("Выгрузка: 0 B/s", self.traffic_card)
        self.traffic_rtt_label = BodyLabel("RTT: --", self.traffic_card)
        self.traffic_graph = TrafficGraphWidget(self.traffic_card)
        self.traffic_graph.clicked.connect(self._show_traffic_page)
        self.traffic_peak_label = CaptionLabel("Пик: 0 B/s", self.traffic_card)
        traffic_layout.addWidget(self.traffic_down_label)
        traffic_layout.addWidget(self.traffic_up_label)
        traffic_layout.addWidget(self.traffic_rtt_label)
        traffic_layout.addWidget(self.traffic_graph, 1)
        traffic_layout.addWidget(self.traffic_peak_label)

        # ── Process traffic table (TUN mode only) ────────────
        self._proc_traffic_card = CardWidget(self)
        proc_layout = QVBoxLayout(self._proc_traffic_card)
        proc_layout.setContentsMargins(18, 16, 18, 16)
        proc_layout.setSpacing(6)
        proc_header = QHBoxLayout()
        proc_header.addWidget(StrongBodyLabel("Трафик по процессам", self._proc_traffic_card))
        proc_header.addStretch(1)
        from qfluentwidgets import TransparentToolButton
        self._proc_detail_btn = TransparentToolButton(FIF.CHEVRON_RIGHT_MED, self._proc_traffic_card)
        self._proc_detail_btn.setFixedSize(32, 32)
        self._proc_detail_btn.setToolTip("Развернуть на весь экран")
        self._proc_detail_btn.clicked.connect(self._show_proc_page)
        proc_header.addWidget(self._proc_detail_btn)
        proc_layout.addLayout(proc_header)

        self._proc_traffic_table = TableWidget(self._proc_traffic_card)
        self._proc_traffic_table.setColumnCount(7)
        self._proc_traffic_table.setHorizontalHeaderLabels(
            ["Процесс", "Скорость", "VPN", "Прямой", "Соед.", "Хост", "Всего"]
        )
        _col_tooltips = [
            "Имя исполняемого файла приложения",
            "Текущая скорость загрузки/выгрузки",
            "Объём трафика через VPN (зашифрованный, через прокси-сервер)",
            "Объём трафика напрямую (без VPN, к серверу напрямую)",
            "Активные соединения (всего за сессию)",
            "Домен или IP с наибольшим трафиком",
            "Общий объём трафика за сессию",
        ]
        for col, tip in enumerate(_col_tooltips):
            item = self._proc_traffic_table.horizontalHeaderItem(col)
            if item:
                item.setToolTip(tip)
        self._proc_traffic_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Interactive
        )
        self._proc_traffic_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        for col in (1, 2, 3, 4, 6):
            self._proc_traffic_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._proc_traffic_table.verticalHeader().setVisible(False)
        self._proc_traffic_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._proc_traffic_table.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection
        )
        self._proc_traffic_table.setMinimumHeight(150)
        proc_layout.addWidget(self._proc_traffic_table, 1)

        # ── Routing card (задача 3: перенесена вниз, под Подключение) ──
        self.routing_card = CardWidget(self)
        routing_layout = QVBoxLayout(self.routing_card)
        routing_layout.setContentsMargins(18, 16, 18, 16)
        routing_layout.setSpacing(8)
        routing_layout.addWidget(StrongBodyLabel("Маршрутизация", self.routing_card))
        self.mode_combo = ComboBox(self.routing_card)
        self.mode_combo.addItem("Глобальный", userData="global")
        self.mode_combo.addItem("Правила", userData="rule")
        self.mode_combo.addItem("Прямой", userData="direct")
        routing_layout.addWidget(self.mode_combo)
        self.routing_mode_label = BodyLabel("Правила", self.routing_card)
        self.routing_dns_label = CaptionLabel("DNS: Системный", self.routing_card)
        self.routing_rules_label = CaptionLabel("Прямые: 0   Прокси: 0   Блок: 0", self.routing_card)
        self.routing_bypass_label = CaptionLabel("Обход LAN: включён", self.routing_card)
        self.routing_bypass_label.setWordWrap(True)
        routing_layout.addWidget(self.routing_mode_label)
        routing_layout.addStretch(1)
        routing_layout.addWidget(self.routing_dns_label)
        routing_layout.addWidget(self.routing_rules_label)
        routing_layout.addWidget(self.routing_bypass_label)

        # ── Grid layout:
        #   [0,0] Подключение к VPN   [0,1] Zapret (быстрое управление)
        #   [1,0..1] Умное подключение (авто-переключение + анти-DPI)
        # ── Routing card идёт полной строкой ниже grid

        # ── Smart Connection card ─────────────────────────────
        self.smart_card = CardWidget(self)
        smart_layout = QVBoxLayout(self.smart_card)
        smart_layout.setContentsMargins(18, 14, 18, 14)
        smart_layout.setSpacing(6)

        smart_header = QHBoxLayout()
        smart_header.addWidget(StrongBodyLabel("Умное подключение", self.smart_card))
        smart_header.addStretch(1)
        self._smart_status_label = CaptionLabel("", self.smart_card)
        smart_header.addWidget(self._smart_status_label)
        smart_layout.addLayout(smart_header)

        # Row 1: авто-переключение
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        _as_label = BodyLabel("Авто-переключение на лучший сервер", self.smart_card)
        row1.addWidget(_as_label)
        row1.addStretch(1)
        self._auto_switch_switch = SwitchButton(self.smart_card)
        self._auto_switch_switch.setToolTip(
            "При падении скорости автоматически переключаться на более быстрый сервер.\n"
            "Настройки порога и стратегии — в разделе Настройки."
        )
        row1.addWidget(self._auto_switch_switch)
        smart_layout.addLayout(row1)

        # Row 2: фрагментация DPI
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        _frag_label = BodyLabel("Анти-DPI фрагментация TLS", self.smart_card)
        _frag_label.setToolTip("Разбивает TLS-хендшейк на части — обходит ТСПУ РКН")
        row2.addWidget(_frag_label)
        row2.addStretch(1)
        self._dpi_fragment_switch = SwitchButton(self.smart_card)
        row2.addWidget(self._dpi_fragment_switch)
        smart_layout.addLayout(row2)

        # Row 3: Mux
        row3 = QHBoxLayout()
        row3.setSpacing(8)
        _mux_label = BodyLabel("Мультиплексирование (Mux)", self.smart_card)
        _mux_label.setToolTip("Несколько потоков в одном TCP — меньше хендшейков, меньше сигнатур")
        row3.addWidget(_mux_label)
        row3.addStretch(1)
        self._dpi_mux_switch = SwitchButton(self.smart_card)
        row3.addWidget(self._dpi_mux_switch)
        smart_layout.addLayout(row3)

        # Row 4: Noise
        row4 = QHBoxLayout()
        row4.setSpacing(8)
        _noise_label = BodyLabel("Шумовое маскирование трафика", self.smart_card)
        _noise_label.setToolTip("Паддинг-пакеты имитируют обычный HTTPS-трафик")
        row4.addWidget(_noise_label)
        row4.addStretch(1)
        self._dpi_noise_switch = SwitchButton(self.smart_card)
        row4.addWidget(self._dpi_noise_switch)
        smart_layout.addLayout(row4)

        # Note: DPI changes apply on next connect
        _dpi_hint = CaptionLabel("⚡ Изменения DPI применяются при следующем подключении", self.smart_card)
        _dpi_hint.setWordWrap(True)
        smart_layout.addWidget(_dpi_hint)

        grid.addWidget(self.connection_card, 0, 0)
        grid.addWidget(self.zapret_card,     0, 1)
        grid.addWidget(self.smart_card,      1, 0, 1, 2)  # полная строка
        root.addLayout(grid)
        root.addWidget(self.routing_card)       # задача 3: под Подключением
        root.addWidget(self.traffic_card)
        root.addWidget(self._proc_traffic_card)
        root.addStretch(1)

        # ── Page 1: traffic detail subpage ────────────────────
        self._traffic_detail_page = QWidget()
        self._traffic_detail_page.setStyleSheet("QWidget { background: transparent; }")
        self._stack.addWidget(self._traffic_detail_page)

        detail_layout = QVBoxLayout(self._traffic_detail_page)
        detail_layout.setContentsMargins(24, 20, 24, 20)
        detail_layout.setSpacing(12)

        self._traffic_breadcrumb = BreadcrumbBar(self._traffic_detail_page)
        self._traffic_breadcrumb.addItem("dashboard", "Панель управления")
        self._traffic_breadcrumb.addItem("traffic", "Трафик")
        self._traffic_breadcrumb.currentItemChanged.connect(self._on_traffic_breadcrumb)
        detail_layout.addWidget(self._traffic_breadcrumb)

        self._detail_graph = DetailTrafficGraphWidget(self._traffic_detail_page)
        detail_layout.addWidget(self._detail_graph, 1)

        detail_stats_row = QHBoxLayout()
        detail_stats_row.setSpacing(16)
        self._detail_down_label = BodyLabel("Загрузка: 0 B/s", self._traffic_detail_page)
        self._detail_up_label = BodyLabel("Выгрузка: 0 B/s", self._traffic_detail_page)
        self._detail_rtt_label = BodyLabel("RTT: --", self._traffic_detail_page)
        self._detail_peak_label = BodyLabel("Пик: 0 B/s", self._traffic_detail_page)
        detail_stats_row.addWidget(self._detail_down_label)
        detail_stats_row.addWidget(self._detail_up_label)
        detail_stats_row.addWidget(self._detail_rtt_label)
        detail_stats_row.addWidget(self._detail_peak_label)
        detail_stats_row.addStretch(1)
        detail_layout.addLayout(detail_stats_row)

        # ── Page 2: process traffic detail subpage ─────────────
        self._proc_detail_page = QWidget()
        self._proc_detail_page.setStyleSheet("QWidget { background: transparent; }")
        self._stack.addWidget(self._proc_detail_page)

        proc_detail_layout = QVBoxLayout(self._proc_detail_page)
        proc_detail_layout.setContentsMargins(24, 20, 24, 20)
        proc_detail_layout.setSpacing(12)

        self._proc_breadcrumb = BreadcrumbBar(self._proc_detail_page)
        self._proc_breadcrumb.addItem("dashboard", "Панель управления")
        self._proc_breadcrumb.addItem("processes", "Трафик по процессам")
        self._proc_breadcrumb.currentItemChanged.connect(self._on_proc_breadcrumb)
        proc_detail_layout.addWidget(self._proc_breadcrumb)

        self._proc_detail_table = TableWidget(self._proc_detail_page)
        self._proc_detail_table.setColumnCount(7)
        self._proc_detail_table.setHorizontalHeaderLabels(
            ["Процесс", "Скорость", "VPN", "Прямой", "Соединения", "Основной хост", "Всего"]
        )
        self._proc_detail_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Interactive
        )
        self._proc_detail_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        for col in (1, 2, 3, 4, 6):
            self._proc_detail_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        for col, tip in enumerate(_col_tooltips):
            item = self._proc_detail_table.horizontalHeaderItem(col)
            if item:
                item.setToolTip(tip)
        self._proc_detail_table.verticalHeader().setVisible(False)
        self._proc_detail_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._proc_detail_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._proc_detail_table.setMinimumHeight(400)
        proc_detail_layout.addWidget(self._proc_detail_table, 1)

        # ── Signal connections ────────────────────────────────
        self.node_combo.currentIndexChanged.connect(self._on_node_changed)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.tun_switch.checkedChanged.connect(self._on_tun_toggled)
        self.proxy_switch.checkedChanged.connect(self._on_proxy_toggled)
        self.toggle_btn.clicked.connect(self.toggle_connection_requested)
        self.fastest_btn.clicked.connect(self._on_fastest_clicked)
        self._zapret_start_btn.clicked.connect(self._on_zapret_start_clicked)
        self._zapret_stop_btn.clicked.connect(self.zapret_stop_requested)
        self._auto_switch_switch.checkedChanged.connect(self.auto_switch_toggled)
        self._dpi_fragment_switch.checkedChanged.connect(self.dpi_fragment_toggled)
        self._dpi_mux_switch.checkedChanged.connect(self.dpi_mux_toggled)
        self._dpi_noise_switch.checkedChanged.connect(self.dpi_noise_toggled)

        self._stack.setCurrentIndex(0)
        self._refresh_dashboard()

        # Определяем страну пользователя в фоне (один раз)
        threading.Thread(target=self._resolve_my_country, daemon=True).start()

    # ── Public API ────────────────────────────────────────────

    def set_nodes(self, nodes: list[Node], selected_node_id: str | None) -> None:
        self._nodes = list(nodes)
        self._node_ids = []

        self.node_combo.blockSignals(True)
        self.node_combo.clear()

        selected_index = 0
        for index, node in enumerate(self._nodes):
            self.node_combo.addItem(self._node_title(node))
            self._node_ids.append(node.id)
            if selected_node_id and selected_node_id == node.id:
                selected_index = index

        if self._nodes:
            self.node_combo.setEnabled(True)
            self.node_combo.setCurrentIndex(selected_index)
            self._selected_node = self._nodes[selected_index]
        else:
            self.node_combo.addItem("Профили не импортированы")
            self.node_combo.setEnabled(False)
            self._selected_node = None

        self.node_combo.blockSignals(False)
        self._refresh_dashboard()

    def set_selected_node(self, node: Node | None) -> None:
        self._selected_node = node
        if node is not None and node.id in self._node_ids:
            self.node_combo.blockSignals(True)
            self.node_combo.setCurrentIndex(self._node_ids.index(node.id))
            self.node_combo.blockSignals(False)
        self._refresh_dashboard()

    def set_connection(self, connected: bool) -> None:
        self._connected = connected
        if not connected:
            self._last_down_bps = 0.0
            self._last_up_bps = 0.0
            self._live_rtt_ms = None
            self._peak_bps = 0.0
            self._down_history.clear()
            self._up_history.clear()
            self.traffic_graph.clear_data()
            self._proc_traffic_table.setRowCount(0)
            self._last_process_stats = None
        self._refresh_dashboard()

    def set_mode(self, mode: str) -> None:
        self._mode = mode
        self._routing.mode = mode
        self.mode_combo.blockSignals(True)
        for index in range(self.mode_combo.count()):
            if self.mode_combo.itemData(index) == mode:
                self.mode_combo.setCurrentIndex(index)
                break
        self.mode_combo.blockSignals(False)
        self._refresh_dashboard()

    def set_proxy_ports(self, socks_port: int, http_port: int) -> None:
        self._settings.socks_port = socks_port
        self._settings.http_port = http_port
        self._settings.tun_mode = False
        self._refresh_dashboard()

    def set_tun_mode(self, enabled: bool) -> None:
        self._settings.tun_mode = enabled
        self._refresh_dashboard()

    def set_settings_snapshot(self, settings: AppSettings) -> None:
        self._settings = settings
        self._sync_switches()
        self._refresh_dashboard()

    def set_routing_snapshot(self, routing: RoutingSettings) -> None:
        self._routing = routing
        self.set_mode(routing.mode)

    def set_selected_latency(self, value: int | None) -> None:
        self._selected_latency_ms = value
        if self._selected_node is not None:
            self._selected_node.ping_ms = value
        self._refresh_dashboard()

    def set_live_metrics(self, down_bps: float, up_bps: float, latency_ms: int | None) -> None:
        self._last_down_bps = max(0.0, down_bps)
        self._last_up_bps = max(0.0, up_bps)
        self._live_rtt_ms = latency_ms
        self._peak_bps = max(self._peak_bps, self._last_down_bps, self._last_up_bps)
        self._down_history.append(self._last_down_bps)
        self._up_history.append(self._last_up_bps)
        self.traffic_graph.add_point(self._last_down_bps, self._last_up_bps)
        if self._stack.currentIndex() == 1:
            self._detail_graph.add_point(self._last_down_bps, self._last_up_bps)
        self._refresh_dashboard()

    def set_process_stats(self, stats: list | None) -> None:
        if stats is None:
            return
        self._proc_traffic_table.setRowCount(len(stats))
        for row, ps in enumerate(stats):
            self._proc_traffic_table.setItem(row, 0, QTableWidgetItem(ps.exe))
            speed = f"↓{_format_speed(ps.down_speed)}  ↑{_format_speed(ps.up_speed)}"
            self._proc_traffic_table.setItem(row, 1, QTableWidgetItem(speed))
            vpn_item = QTableWidgetItem(self._format_bytes(ps.proxy_bytes))
            if ps.proxy_bytes > 0:
                vpn_item.setForeground(QColor("#2ecc71"))
            self._proc_traffic_table.setItem(row, 2, vpn_item)
            self._proc_traffic_table.setItem(row, 3, QTableWidgetItem(self._format_bytes(ps.direct_bytes)))
            conn_text = f"{ps.connections} ({ps.total_connections})" if ps.total_connections > ps.connections else str(ps.connections)
            self._proc_traffic_table.setItem(row, 4, QTableWidgetItem(conn_text))
            host = ps.top_host
            if len(host) > 30:
                host = host[:27] + "..."
            self._proc_traffic_table.setItem(row, 5, QTableWidgetItem(host))
            total = ps.upload + ps.download
            self._proc_traffic_table.setItem(row, 6, QTableWidgetItem(self._format_bytes(total)))
        if self._stack.currentIndex() == 2:
            self._update_proc_detail_table()

    # ── Zapret public API ─────────────────────────────────────

    def set_zapret_presets(self, presets: list[str], active: str = "") -> None:
        """Загрузить список пресетов в combo."""
        self._zapret_presets = list(presets)
        self._zapret_preset_combo.blockSignals(True)
        self._zapret_preset_combo.clear()
        for p in presets:
            self._zapret_preset_combo.addItem(p)
        if active and active in presets:
            self._zapret_preset_combo.setCurrentIndex(presets.index(active))
        self._zapret_preset_combo.blockSignals(False)
        self._refresh_zapret_card()

    def set_zapret_running(self, running: bool, preset_name: str = "") -> None:
        self._zapret_running = running
        if running:
            self._zapret_preset = preset_name
        else:
            self._zapret_preset = ""
        self._zapret_error_label.setVisible(False)
        self._refresh_zapret_card()

    def set_zapret_error(self, message: str) -> None:
        self._zapret_error_label.setText(f"⚠️  {message}")
        self._zapret_error_label.setVisible(True)
        self._refresh_zapret_card()

    @staticmethod
    def _format_bytes(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 * 1024 * 1024:
            return f"{b / 1024 / 1024:.1f} MB"
        else:
            return f"{b / 1024 / 1024 / 1024:.2f} GB"

    # ── Refresh logic ─────────────────────────────────────────

    def _refresh_dashboard(self) -> None:
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def _do_refresh_dashboard(self) -> None:
        self._refresh_connection_card()
        self._refresh_profile_card()
        self._refresh_traffic_card()
        self._refresh_routing_card()
        self._refresh_zapret_card()
        has_profiles = bool(self._nodes)
        self.toggle_btn.setEnabled(has_profiles)
        self.fastest_btn.setEnabled(has_profiles)
        if self._stack.currentIndex() == 1:
            self._refresh_detail_stats()

    def _refresh_connection_card(self) -> None:
        action = "VPN" if self._settings.tun_mode else "Прокси"
        self.connection_state_label.setText("Подключено" if self._connected else "Ожидание")
        self.connection_engine_label.setText(self._route_engine_label())
        self.connection_status_label.setText(f"{action} {'работает' if self._connected else 'остановлен'}")
        self.connection_target_label.setText(self._selected_node_summary())
        self.toggle_btn.setText(self._toggle_action_text())
        self.toggle_btn.setIcon(FIF.PAUSE_BOLD if self._connected else FIF.PLAY_SOLID)
        # Кнопка «Подключиться к лучшему»
        if self._connected:
            self.fastest_btn.setText("Переключить на лучший")
            self.fastest_btn.setIcon(FIF.SYNC)
        else:
            self.fastest_btn.setText("Подключиться к лучшему")
            self.fastest_btn.setIcon(FIF.PLAY_SOLID)
        self.summary_label.setText(self._summary_text())

    def _refresh_profile_card(self) -> None:
        selected = self._selected_node
        if selected is None:
            self.profile_name_label.setText("Профиль не выбран")
            self.profile_endpoint_label.setText("Сначала импортируйте или выберите узел")
            self.profile_group_label.setText(f"Профилей: {len(self._nodes)}")
            self.profile_latency_label.setText("Задержка: --")
            return
        self.profile_name_label.setText(selected.name or "Безымянный профиль")
        scheme = selected.scheme.upper() if selected.scheme else "NODE"
        self.profile_endpoint_label.setText(f"{selected.server or '--'}:{selected.port or '--'}  ({scheme})")
        self.profile_group_label.setText(f"Группа: {selected.group or 'По умолчанию'}")
        self.profile_latency_label.setText(f"Задержка: {_format_latency(self._effective_latency())}")

    def _refresh_traffic_card(self) -> None:
        self.traffic_down_label.setText(f"Загрузка: {_format_speed(self._last_down_bps)}")
        self.traffic_up_label.setText(f"Выгрузка: {_format_speed(self._last_up_bps)}")
        self.traffic_rtt_label.setText(f"RTT: {_format_latency(self._effective_latency())}")
        self.traffic_peak_label.setText(f"Пик: {_format_speed(self._peak_bps)}")

    def _refresh_routing_card(self) -> None:
        self.routing_mode_label.setText(_mode_title(self._routing.mode))
        self.routing_dns_label.setText(f"DNS: {self._routing.dns_mode.title()}")
        self.routing_rules_label.setText(
            f"Прямые: {len(self._routing.direct_domains)}   Прокси: {len(self._routing.proxy_domains)}   Блок: {len(self._routing.block_domains)}"
        )
        bypass = "включён" if self._routing.bypass_lan else "выключен"
        self.routing_bypass_label.setText(f"Обход LAN: {bypass}")

    def _refresh_zapret_card(self) -> None:
        if self._zapret_running:
            preset = self._zapret_preset or "?"
            self._zapret_state_label.setText(f"✅  Работает: {preset}")
            self._zapret_start_btn.setEnabled(False)
            self._zapret_stop_btn.setEnabled(True)
            self._zapret_preset_combo.setEnabled(False)
        else:
            self._zapret_state_label.setText("⏹  Остановлен")
            has_presets = bool(self._zapret_presets)
            self._zapret_start_btn.setEnabled(has_presets)
            self._zapret_stop_btn.setEnabled(False)
            self._zapret_preset_combo.setEnabled(has_presets)

    def _refresh_detail_stats(self) -> None:
        self._detail_down_label.setText(f"Загрузка: {_format_speed(self._last_down_bps)}")
        self._detail_up_label.setText(f"Выгрузка: {_format_speed(self._last_up_bps)}")
        self._detail_rtt_label.setText(f"RTT: {_format_latency(self._effective_latency())}")
        self._detail_peak_label.setText(f"Пик: {_format_speed(self._peak_bps)}")

    # ── Traffic subpage navigation ────────────────────────────

    def _show_traffic_page(self) -> None:
        self._detail_graph.set_data(self._down_history, self._up_history)
        self._refresh_detail_stats()
        self._reset_traffic_breadcrumb()
        self._stack.setCurrentIndex(1)

    def _show_main_page(self) -> None:
        self._stack.setCurrentIndex(0)

    def _on_traffic_breadcrumb(self, routeKey: str) -> None:
        if routeKey == "dashboard":
            self._show_main_page()

    def _reset_traffic_breadcrumb(self) -> None:
        self._traffic_breadcrumb.blockSignals(True)
        self._traffic_breadcrumb.clear()
        self._traffic_breadcrumb.addItem("dashboard", "Панель управления")
        self._traffic_breadcrumb.addItem("traffic", "Трафик")
        self._traffic_breadcrumb.blockSignals(False)

    # ── Process subpage navigation ──────────────────────────

    def _show_proc_page(self) -> None:
        self._update_proc_detail_table()
        self._reset_proc_breadcrumb()
        self._stack.setCurrentIndex(2)

    def _on_proc_breadcrumb(self, routeKey: str) -> None:
        if routeKey == "dashboard":
            self._show_main_page()

    def _reset_proc_breadcrumb(self) -> None:
        self._proc_breadcrumb.blockSignals(True)
        self._proc_breadcrumb.clear()
        self._proc_breadcrumb.addItem("dashboard", "Панель управления")
        self._proc_breadcrumb.addItem("processes", "Трафик по процессам")
        self._proc_breadcrumb.blockSignals(False)

    def _update_proc_detail_table(self) -> None:
        src = self._proc_traffic_table
        dst = self._proc_detail_table
        rows = src.rowCount()
        dst.setRowCount(rows)
        for r in range(rows):
            for c in range(7):
                item = src.item(r, c)
                if item:
                    new_item = QTableWidgetItem(item.text())
                    new_item.setForeground(item.foreground())
                    dst.setItem(r, c, new_item)

    # ── Helpers ───────────────────────────────────────────────

    def _effective_latency(self) -> int | None:
        return self._live_rtt_ms if self._live_rtt_ms is not None else self._selected_latency_ms

    def _route_engine_label(self) -> str:
        if self._settings.tun_mode:
            return "Режим VPN (TUN)"
        if self._settings.enable_system_proxy:
            return f"Системный прокси  HTTP {self._settings.http_port} / SOCKS {self._settings.socks_port}"
        return f"Локальный прокси  HTTP {self._settings.http_port} / SOCKS {self._settings.socks_port}"

    def _toggle_action_text(self) -> str:
        if self._settings.tun_mode:
            return "Остановить VPN" if self._connected else "Запустить VPN"
        return "Остановить прокси" if self._connected else "Запустить прокси"

    def _selected_node_summary(self) -> str:
        if self._selected_node is None:
            return "Активный профиль не выбран"
        group = self._selected_node.group or "По умолчанию"
        scheme = self._selected_node.scheme.upper() if self._selected_node.scheme else "NODE"
        server = self._selected_node.server or "unknown-host"
        port = self._selected_node.port or "--"
        return f"{group}  {scheme}  {server}:{port}"

    def _summary_text(self) -> str:
        if self._selected_node is None:
            return "Выберите узел, чтобы запустить прокси или VPN и просмотреть состояние сеанса."
        if self._connected:
            return f"Активный сеанс: {self._selected_node_summary()}"
        return f"Готов к запуску: {self._selected_node_summary()}"

    def _node_title(self, node: Node) -> str:
        name = node.name or node.server or "Безымянный"
        scheme = node.scheme.upper() if node.scheme else "NODE"
        return f"{name} ({scheme})"

    def _get_fastest_foreign_node(self) -> Node | None:
        """
        Задача 1: выбрать самый быстрый сервер страны, отличной от страны пользователя.
        Приоритет: speed_mbps > ping_ms. Живые (is_alive=True) предпочтительнее.
        """
        my_cc = self._my_country.upper()

        candidates = [
            n for n in self._nodes
            if (not my_cc or (n.country_code or "").upper() != my_cc)
        ]
        if not candidates:
            # Если страна не определена или все узлы одной страны — берём из всех
            candidates = list(self._nodes)
        if not candidates:
            return None

        alive = [n for n in candidates if n.is_alive is True]
        pool = alive if alive else candidates

        with_speed = [n for n in pool if n.speed_mbps is not None and n.speed_mbps > 0]
        if with_speed:
            return max(with_speed, key=lambda n: n.speed_mbps)

        with_ping = [n for n in pool if n.ping_ms is not None]
        if with_ping:
            return min(with_ping, key=lambda n: n.ping_ms)

        return pool[0]

    def _resolve_my_country(self) -> None:
        """Фоновый поток: определить страну пользователя один раз."""
        if self._my_country_resolved:
            return
        self._my_country_resolved = True
        cc = _detect_my_country()
        self._my_country = cc

    # ── Signal handlers ───────────────────────────────────────

    def _on_node_changed(self, index: int) -> None:
        if 0 <= index < len(self._node_ids):
            self.node_selected.emit(self._node_ids[index])

    def _on_mode_changed(self, index: int) -> None:
        value = self.mode_combo.itemData(index)
        if value:
            self.mode_changed.emit(str(value))

    def _on_tun_toggled(self, checked: bool) -> None:
        self.proxy_switch.setEnabled(not checked)
        self.tun_toggled.emit(checked)

    def _on_proxy_toggled(self, checked: bool) -> None:
        self.proxy_toggled.emit(checked)

    def _on_fastest_clicked(self) -> None:
        """
        Задача 1: при клике на «Подключиться к лучшему» выбрать самый быстрый
        сервер другой страны и инициировать подключение.
        """
        node = self._get_fastest_foreign_node()
        if node is not None:
            self.node_selected.emit(node.id)
            # Небольшая задержка чтобы set_selected_node обработался
            QTimer.singleShot(50, self.connect_fastest_requested)

    def _on_zapret_start_clicked(self) -> None:
        idx = self._zapret_preset_combo.currentIndex()
        if 0 <= idx < len(self._zapret_presets):
            self._zapret_error_label.setVisible(False)
            self.zapret_start_requested.emit(self._zapret_presets[idx])

    def _sync_switches(self) -> None:
        self.tun_switch.blockSignals(True)
        self.tun_switch.setChecked(self._settings.tun_mode)
        self.tun_switch.setText("Вкл" if self._settings.tun_mode else "Выкл")
        self.tun_switch.blockSignals(False)

        self.proxy_switch.blockSignals(True)
        self.proxy_switch.setChecked(self._settings.enable_system_proxy)
        self.proxy_switch.setText("Вкл" if self._settings.enable_system_proxy else "Выкл")
        self.proxy_switch.setEnabled(not self._settings.tun_mode)
        self.proxy_switch.blockSignals(False)

        # Smart card switches
        self._auto_switch_switch.blockSignals(True)
        self._auto_switch_switch.setChecked(self._settings.auto_switch_enabled)
        self._auto_switch_switch.blockSignals(False)

        self._dpi_fragment_switch.blockSignals(True)
        self._dpi_fragment_switch.setChecked(self._settings.dpi_fragment_enabled)
        self._dpi_fragment_switch.blockSignals(False)

        self._dpi_mux_switch.blockSignals(True)
        self._dpi_mux_switch.setChecked(self._settings.dpi_mux_enabled)
        self._dpi_mux_switch.blockSignals(False)

        self._dpi_noise_switch.blockSignals(True)
        self._dpi_noise_switch.setChecked(self._settings.dpi_noise_enabled)
        self._dpi_noise_switch.blockSignals(False)

        # Update smart status label
        active_features: list[str] = []
        if self._settings.auto_switch_enabled:
            strategy_map = {"speed": "по скорости", "ping": "по пингу", "roundrobin": "по порядку"}
            active_features.append(f"Авто-переключение ({strategy_map.get(self._settings.auto_switch_strategy, '')})")
        if self._settings.dpi_fragment_enabled:
            active_features.append("Фрагментация")
        if self._settings.dpi_mux_enabled:
            active_features.append("Mux")
        if self._settings.dpi_noise_enabled:
            active_features.append("Noise")
        if active_features:
            self._smart_status_label.setText("✓ " + ", ".join(active_features))
        else:
            self._smart_status_label.setText("Все функции отключены")
