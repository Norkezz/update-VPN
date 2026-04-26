from __future__ import annotations

from copy import deepcopy

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QFileDialog, QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    FluentIcon as FIF,
    LineEdit,
    PasswordLineEdit,
    PrimaryPushSettingCard,
    PushButton,
    PushSettingCard,
    SettingCard,
    SpinBox,
    SettingCardGroup,
    SmoothScrollArea,
    SubtitleLabel,
    SwitchSettingCard,
)
from qfluentwidgets.components.settings.setting_card import ColorPickerButton

from ..constants import SINGBOX_PATH_DEFAULT, XRAY_PATH_DEFAULT
from ..models import AppSettings, SecuritySettings
from ..path_utils import normalize_configured_path, resolve_configured_path


class _ComboCard(SettingCard):
    """Setting card with a combo box on the right."""

    def __init__(self, icon, title, content, items: list[tuple[str, str]], parent=None):
        super().__init__(icon, title, content, parent)
        self.combo = ComboBox(self)
        self.combo.setMinimumWidth(220)
        for text, data in items:
            self.combo.addItem(text, userData=data)
        self.hBoxLayout.addWidget(self.combo, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _SpinCard(SettingCard):
    """Setting card with a spin box on the right."""

    def __init__(self, icon, title, content, min_val=1, max_val=65535, parent=None):
        super().__init__(icon, title, content, parent)
        self.spin = SpinBox(self)
        self.spin.setRange(min_val, max_val)
        self.spin.setMinimumWidth(180)
        self.hBoxLayout.addWidget(self.spin, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _ColorCard(SettingCard):
    """Setting card with a color picker button on the right."""

    def __init__(self, icon, title, content, parent=None):
        super().__init__(icon, title, content, parent)
        self.picker = ColorPickerButton(QColor("#0078D4"), title, self)
        self.hBoxLayout.addWidget(self.picker, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _LineEditCard(SettingCard):
    """Setting card with a line edit on the right."""

    def __init__(self, icon, title, content, placeholder="", parent=None):
        super().__init__(icon, title, content, parent)
        self.edit = LineEdit(self)
        self.edit.setPlaceholderText(placeholder)
        self.edit.setMinimumWidth(420)
        self.hBoxLayout.addWidget(self.edit, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _BrowseCard(SettingCard):
    """Setting card with a line edit + browse button on the right."""

    def __init__(self, icon, title, content, parent=None):
        super().__init__(icon, title, content, parent)
        self.edit = LineEdit(self)
        self.edit.setMinimumWidth(380)
        self.btn = PushButton("Обзор", self)
        self.hBoxLayout.addWidget(self.edit, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(8)
        self.hBoxLayout.addWidget(self.btn, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _PasswordActionCard(SettingCard):
    """Setting card with a password edit and action buttons."""

    def __init__(self, icon, title, content, placeholder="", buttons: list[str] | None = None, parent=None):
        super().__init__(icon, title, content, parent)
        self.edit = PasswordLineEdit(self)
        self.edit.setPlaceholderText(placeholder)
        self.edit.setMinimumWidth(260)
        self.hBoxLayout.addWidget(self.edit, 0, Qt.AlignmentFlag.AlignRight)
        self.buttons: list[PushButton] = []
        for text in (buttons or []):
            self.hBoxLayout.addSpacing(8)
            btn = PushButton(text, self)
            self.hBoxLayout.addWidget(btn, 0, Qt.AlignmentFlag.AlignRight)
            self.buttons.append(btn)
        self.hBoxLayout.addSpacing(16)


class SettingsPage(QWidget):
    save_requested = pyqtSignal(object)
    auto_lock_minutes_changed = pyqtSignal(int)
    set_password_requested = pyqtSignal(str)
    disable_password_requested = pyqtSignal()
    lock_now_requested = pyqtSignal()
    # Update buttons moved to UpdatesPage
    export_backup_requested = pyqtSignal()
    import_backup_requested = pyqtSignal()
    set_encryption_requested = pyqtSignal(str)
    disable_encryption_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("settings")
        self._settings = AppSettings()
        self._security = SecuritySettings()
        self._loading = False

        # --- Outer layout with scroll area ---
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._scroll = SmoothScrollArea(self)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(self._scroll)

        container = QWidget()
        container.setStyleSheet("QWidget { background: transparent; }")
        self._scroll.setWidget(container)

        root = QVBoxLayout(container)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(4)

        root.addWidget(SubtitleLabel("Настройки", container))
        root.addSpacing(8)

        # ============================================================
        # Appearance
        # ============================================================
        appearance_group = SettingCardGroup("Внешний вид", container)

        self.theme_card = _ComboCard(
            FIF.BRUSH, "Тема", "Выберите светлую, тёмную или системную тему",
            [("Авто", "system"), ("Светлая", "light"), ("Тёмная", "dark")],
            parent=appearance_group,
        )
        self.accent_card = _ColorCard(
            FIF.PALETTE, "Цвет акцента", "Выберите цвет акцента для элементов интерфейса",
            parent=appearance_group,
        )

        appearance_group.addSettingCard(self.theme_card)
        appearance_group.addSettingCard(self.accent_card)
        root.addWidget(appearance_group)

        # ============================================================
        # Network
        # ============================================================
        network_group = SettingCardGroup("Сеть", container)

        self.socks_card = _SpinCard(
            FIF.CONNECT, "Порт SOCKS", "Локальный порт SOCKS5 прокси",
            parent=network_group,
        )
        self.http_card = _SpinCard(
            FIF.GLOBE, "Порт HTTP", "Локальный порт HTTP прокси",
            parent=network_group,
        )
        self.reconnect_card = SwitchSettingCard(
            FIF.SYNC, "Переподключение при смене сети",
            "Автоматически переподключаться при смене сетевого адаптера",
            parent=network_group,
        )

        network_group.addSettingCard(self.socks_card)
        network_group.addSettingCard(self.http_card)
        network_group.addSettingCard(self.reconnect_card)
        root.addWidget(network_group)

        # ============================================================
        # Auto-switch
        # ============================================================
        auto_switch_group = SettingCardGroup("Авто-переключение", container)

        self.auto_switch_card = SwitchSettingCard(
            FIF.SYNC, "Авто-переключение при падении скорости",
            "Автоматически переключаться на другой сервер при низкой скорости",
            parent=auto_switch_group,
        )
        self.auto_switch_threshold_card = _SpinCard(
            FIF.SPEED_HIGH, "Порог скорости (КБ/с)",
            "Минимальная скорость загрузки для срабатывания",
            min_val=1, max_val=10000, parent=auto_switch_group,
        )
        self.auto_switch_delay_card = _SpinCard(
            FIF.STOP_WATCH, "Задержка (секунды)",
            "Время ожидания перед переключением",
            min_val=5, max_val=300, parent=auto_switch_group,
        )
        self.auto_switch_cooldown_card = _SpinCard(
            FIF.HISTORY, "Кулдаун (секунды)",
            "Минимальный интервал между автопереключениями",
            min_val=10, max_val=600, parent=auto_switch_group,
        )

        auto_switch_group.addSettingCard(self.auto_switch_card)
        auto_switch_group.addSettingCard(self.auto_switch_threshold_card)
        auto_switch_group.addSettingCard(self.auto_switch_delay_card)
        auto_switch_group.addSettingCard(self.auto_switch_cooldown_card)

        self.auto_switch_strategy_card = _ComboCard(
            FIF.SYNC, "Стратегия выбора сервера",
            "Как выбирается следующий сервер при авто-переключении",
            items=[
                ("По скорости (рекомендуется)", "speed"),
                ("По пингу (минимальная задержка)", "ping"),
                ("По порядку (Round-Robin)", "roundrobin"),
            ],
            parent=auto_switch_group,
        )
        auto_switch_group.addSettingCard(self.auto_switch_strategy_card)
        root.addWidget(auto_switch_group)

        # ============================================================
        # Stability (keepalive + backoff)
        # ============================================================
        stability_group = SettingCardGroup("Стабильность соединения", container)

        self.keepalive_card = SwitchSettingCard(
            FIF.WIFI, "Keepalive-мониторинг",
            "Проверять соединение и автоматически переподключаться при обрыве",
            parent=stability_group,
        )
        self.keepalive_interval_card = _SpinCard(
            FIF.STOP_WATCH, "Интервал проверки (сек)",
            "Как часто проверять доступность прокси",
            min_val=10, max_val=300, parent=stability_group,
        )
        self.keepalive_fails_card = _SpinCard(
            FIF.CANCEL, "Ошибок до переподключения",
            "Сколько подряд неудачных проверок инициируют переподключение",
            min_val=1, max_val=20, parent=stability_group,
        )
        self.backoff_card = SwitchSettingCard(
            FIF.HISTORY, "Экспоненциальный backoff",
            "Увеличивать интервал между попытками переподключения (2 → 5 → 10 → 60 сек)",
            parent=stability_group,
        )
        stability_group.addSettingCard(self.keepalive_card)
        stability_group.addSettingCard(self.keepalive_interval_card)
        stability_group.addSettingCard(self.keepalive_fails_card)
        stability_group.addSettingCard(self.backoff_card)
        root.addWidget(stability_group)

        # ============================================================
        # DPI Anti-block
        # ============================================================
        dpi_group = SettingCardGroup("Анти-блокировки DPI", container)

        self.dpi_fragment_card = SwitchSettingCard(
            FIF.TILES, "Фрагментация TLS ClientHello",
            "Разбивает первый TLS-пакет на части — обходит большинство DPI (ТСПУ РКН, Роскомнадзор)",
            parent=dpi_group,
        )
        self.dpi_fragment_packets_card = _SpinCard(
            FIF.LAYOUT, "Количество фрагментов",
            "На сколько частей разбивать ClientHello (2–5 оптимально)",
            min_val=1, max_val=10, parent=dpi_group,
        )
        self.dpi_fragment_length_card = _SpinCard(
            FIF.CODE, "Макс. размер фрагмента (байт)",
            "Максимальный размер одного фрагмента пакета",
            min_val=10, max_val=500, parent=dpi_group,
        )
        self.dpi_fragment_interval_card = _SpinCard(
            FIF.PAUSE, "Интервал между фрагментами (мс)",
            "Задержка между отправкой фрагментов (1–50 мс)",
            min_val=1, max_val=200, parent=dpi_group,
        )
        self.dpi_mux_card = SwitchSettingCard(
            FIF.CONNECT, "Мультиплексирование (Mux)",
            "Несколько потоков в одном TCP-соединении — снижает число новых хендшейков",
            parent=dpi_group,
        )
        self.dpi_mux_concurrency_card = _SpinCard(
            FIF.SPEED_HIGH, "Параллельных потоков Mux",
            "Количество одновременных логических потоков",
            min_val=1, max_val=64, parent=dpi_group,
        )
        self.dpi_noise_card = SwitchSettingCard(
            FIF.QUIET_HOURS, "Шумовое маскирование (Noise)",
            "Добавляет случайные паддинг-пакеты для имитации обычного HTTPS-трафика",
            parent=dpi_group,
        )
        dpi_group.addSettingCard(self.dpi_fragment_card)
        dpi_group.addSettingCard(self.dpi_fragment_packets_card)
        dpi_group.addSettingCard(self.dpi_fragment_length_card)
        dpi_group.addSettingCard(self.dpi_fragment_interval_card)
        dpi_group.addSettingCard(self.dpi_mux_card)
        dpi_group.addSettingCard(self.dpi_mux_concurrency_card)
        dpi_group.addSettingCard(self.dpi_noise_card)
        root.addWidget(dpi_group)

        # ============================================================
        # Core paths
        # ============================================================
        paths_group = SettingCardGroup("Пути к ядрам", container)

        self.xray_path_card = _BrowseCard(
            FIF.COMMAND_PROMPT, "Путь к Xray", "Относительные пути разрешаются от папки приложения",
            parent=paths_group,
        )
        self.singbox_path_card = _BrowseCard(
            FIF.COMMAND_PROMPT, "Путь к sing-box", "Необязательно; относительные пути разрешаются от папки приложения",
            parent=paths_group,
        )

        self.tun_engine_card = _ComboCard(
            FIF.DEVELOPER_TOOLS, "Движок TUN",
            "sing-box — маршрутизация по процессам, мониторинг трафика; tun2socks — запасной",
            [
                ("sing-box (рекомендуемый)", "singbox"),
                ("tun2socks (запасной)", "tun2socks"),
            ],
            parent=paths_group,
        )

        paths_group.addSettingCard(self.xray_path_card)
        paths_group.addSettingCard(self.singbox_path_card)
        paths_group.addSettingCard(self.tun_engine_card)
        root.addWidget(paths_group)

        # ============================================================
        # Startup
        # ============================================================
        startup_group = SettingCardGroup("Запуск", container)

        self.start_min_card = SwitchSettingCard(
            FIF.MINIMIZE, "Запуск в свёрнутом виде",
            "Запускать приложение свёрнутым в системный трей",
            parent=startup_group,
        )
        self.launch_card = SwitchSettingCard(
            FIF.POWER_BUTTON, "Запуск при старте Windows",
            "Автоматически запускать приложение при входе в систему",
            parent=startup_group,
        )

        startup_group.addSettingCard(self.start_min_card)
        startup_group.addSettingCard(self.launch_card)
        root.addWidget(startup_group)

        # ============================================================
        # Updates
        # ============================================================
        updates_group = SettingCardGroup("Обновления", container)

        self.check_updates_card = SwitchSettingCard(
            FIF.UPDATE, "Проверять обновления",
            "Периодически проверять наличие новых версий при запуске",
            parent=updates_group,
        )
        self.allow_updates_card = SwitchSettingCard(
            FIF.DOWNLOAD, "Разрешить обновления",
            "Разрешить загрузку и установку обновлений приложения",
            parent=updates_group,
        )
        self.xray_auto_update_card = SwitchSettingCard(
            FIF.CLOUD_DOWNLOAD, "Автообновление ядра Xray",
            "Автоматически обновлять ядро Xray при запуске",
            parent=updates_group,
        )

        updates_group.addSettingCard(self.check_updates_card)
        updates_group.addSettingCard(self.allow_updates_card)
        updates_group.addSettingCard(self.xray_auto_update_card)
        root.addWidget(updates_group)

        # ============================================================
        # Data
        # ============================================================
        data_group = SettingCardGroup("Данные", container)

        self.encryption_card = _PasswordActionCard(
            FIF.FINGERPRINT, "Пароль шифрования",
            "Защитить файл состояния паролем",
            placeholder="Введите пароль",
            buttons=["Включить шифрование", "Отключить шифрование"],
            parent=data_group,
        )
        self.export_backup_card = PushSettingCard(
            "Экспорт", FIF.SAVE, "Экспорт резервной копии",
            "Экспортировать полное состояние приложения в файл",
            parent=data_group,
        )
        self.import_backup_card = PushSettingCard(
            "Импорт", FIF.FOLDER, "Импорт резервной копии",
            "Восстановить состояние приложения из резервной копии",
            parent=data_group,
        )

        data_group.addSettingCard(self.encryption_card)
        data_group.addSettingCard(self.export_backup_card)
        data_group.addSettingCard(self.import_backup_card)
        root.addWidget(data_group)

        # ============================================================
        # Security
        # ============================================================
        security_group = SettingCardGroup("Безопасность", container)

        self.password_card = _PasswordActionCard(
            FIF.CERTIFICATE, "Мастер-пароль",
            "Установите пароль для блокировки приложения",
            placeholder="Введите новый пароль",
            buttons=["Установить пароль", "Отключить пароль", "Заблокировать"],
            parent=security_group,
        )
        self.auto_lock_card = _SpinCard(
            FIF.STOP_WATCH, "Автоблокировка (минуты)",
            "Блокировать приложение после периода бездействия",
            min_val=1, max_val=120, parent=security_group,
        )

        security_group.addSettingCard(self.password_card)
        security_group.addSettingCard(self.auto_lock_card)
        root.addWidget(security_group)

        root.addStretch(1)

        # ============================================================
        # Signal connections
        # ============================================================

        # Browse buttons
        self.xray_path_card.btn.clicked.connect(self._choose_xray_path)
        self.singbox_path_card.btn.clicked.connect(self._choose_singbox_path)

        # Password / encryption / backup buttons
        self.password_card.buttons[0].clicked.connect(self._emit_password)       # Set password
        self.password_card.buttons[1].clicked.connect(self.disable_password_requested)  # Disable password
        self.password_card.buttons[2].clicked.connect(self.lock_now_requested)    # Lock now

        self.encryption_card.buttons[0].clicked.connect(self._emit_set_encryption)  # Set encryption
        self.encryption_card.buttons[1].clicked.connect(self.disable_encryption_requested)  # Disable encryption

        self.export_backup_card.clicked.connect(self.export_backup_requested)
        self.import_backup_card.clicked.connect(self.import_backup_requested)

        # Update action buttons
        # Update buttons moved to UpdatesPage

        # --- Auto-save connections ---
        self.theme_card.combo.currentIndexChanged.connect(self._auto_save)
        self.accent_card.picker.colorChanged.connect(self._auto_save)
        self.socks_card.spin.valueChanged.connect(self._auto_save)
        self.http_card.spin.valueChanged.connect(self._auto_save)
        self.xray_path_card.edit.editingFinished.connect(self._auto_save)
        self.singbox_path_card.edit.editingFinished.connect(self._auto_save)
        self.tun_engine_card.combo.currentIndexChanged.connect(self._auto_save)

        self.start_min_card.checkedChanged.connect(self._auto_save)
        self.launch_card.checkedChanged.connect(self._auto_save)
        self.reconnect_card.checkedChanged.connect(self._auto_save)
        self.check_updates_card.checkedChanged.connect(self._auto_save)
        self.allow_updates_card.checkedChanged.connect(self._auto_save)
        self.xray_auto_update_card.checkedChanged.connect(self._auto_save)

        self.auto_switch_card.checkedChanged.connect(self._auto_save)
        self.auto_switch_threshold_card.spin.valueChanged.connect(self._auto_save)
        self.auto_switch_delay_card.spin.valueChanged.connect(self._auto_save)
        self.auto_switch_cooldown_card.spin.valueChanged.connect(self._auto_save)
        self.auto_switch_strategy_card.combo.currentIndexChanged.connect(self._auto_save)

        self.keepalive_card.checkedChanged.connect(self._auto_save)
        self.keepalive_interval_card.spin.valueChanged.connect(self._auto_save)
        self.keepalive_fails_card.spin.valueChanged.connect(self._auto_save)
        self.backoff_card.checkedChanged.connect(self._auto_save)

        self.dpi_fragment_card.checkedChanged.connect(self._auto_save)
        self.dpi_fragment_packets_card.spin.valueChanged.connect(self._auto_save)
        self.dpi_fragment_length_card.spin.valueChanged.connect(self._auto_save)
        self.dpi_fragment_interval_card.spin.valueChanged.connect(self._auto_save)
        self.dpi_mux_card.checkedChanged.connect(self._auto_save)
        self.dpi_mux_concurrency_card.spin.valueChanged.connect(self._auto_save)
        self.dpi_noise_card.checkedChanged.connect(self._auto_save)

        self.auto_lock_card.spin.valueChanged.connect(self._auto_save)

    # ================================================================
    # Public API
    # ================================================================

    def set_values(self, settings: AppSettings, security: SecuritySettings) -> None:
        self._loading = True
        self._settings = deepcopy(settings)
        self._security = deepcopy(security)

        self._select_combo_data(self.theme_card.combo, settings.theme)
        self.accent_card.picker.setColor(QColor(settings.accent_color or "#0078D4"))
        self.socks_card.spin.setValue(settings.socks_port)
        self.http_card.spin.setValue(settings.http_port)
        self.xray_path_card.edit.setText(
            normalize_configured_path(
                settings.xray_path,
                default_path=XRAY_PATH_DEFAULT,
                use_default_if_empty=True,
                migrate_default_location=True,
            )
        )
        self.singbox_path_card.edit.setText(
            normalize_configured_path(
                settings.singbox_path,
                default_path=SINGBOX_PATH_DEFAULT,
                use_default_if_empty=True,
                migrate_default_location=True,
            )
        )
        self._select_combo_data(self.tun_engine_card.combo, settings.tun_engine)
        self.start_min_card.setChecked(settings.start_minimized)
        self.launch_card.setChecked(settings.launch_on_startup)
        self.reconnect_card.setChecked(settings.reconnect_on_network_change)
        self.check_updates_card.setChecked(settings.check_updates)
        self.allow_updates_card.setChecked(settings.allow_updates)
        self.xray_auto_update_card.setChecked(settings.xray_auto_update)

        self.auto_switch_card.setChecked(settings.auto_switch_enabled)
        self.auto_switch_threshold_card.spin.setValue(settings.auto_switch_threshold_kbps)
        self.auto_switch_delay_card.spin.setValue(settings.auto_switch_delay_sec)
        self.auto_switch_cooldown_card.spin.setValue(settings.auto_switch_cooldown_sec)
        self._select_combo_data(self.auto_switch_strategy_card.combo, settings.auto_switch_strategy)

        self.keepalive_card.setChecked(settings.stability_keepalive_enabled)
        self.keepalive_interval_card.spin.setValue(settings.stability_keepalive_interval_sec)
        self.keepalive_fails_card.spin.setValue(settings.stability_keepalive_fails_before_reconnect)
        self.backoff_card.setChecked(settings.stability_backoff_enabled)

        self.dpi_fragment_card.setChecked(settings.dpi_fragment_enabled)
        self.dpi_fragment_packets_card.spin.setValue(settings.dpi_fragment_packets)
        self.dpi_fragment_length_card.spin.setValue(settings.dpi_fragment_length)
        self.dpi_fragment_interval_card.spin.setValue(settings.dpi_fragment_interval_ms)
        self.dpi_mux_card.setChecked(settings.dpi_mux_enabled)
        self.dpi_mux_concurrency_card.spin.setValue(settings.dpi_mux_concurrency)
        self.dpi_noise_card.setChecked(settings.dpi_noise_enabled)

        self.auto_lock_card.spin.setValue(security.auto_lock_minutes)
        self.password_card.edit.clear()
        self._loading = False

    def set_encryption_active(self, active: bool) -> None:
        self.encryption_card.buttons[1].setEnabled(active)  # Disable encryption btn

    # ================================================================
    # Private slots
    # ================================================================

    def _choose_xray_path(self) -> None:
        current_path = resolve_configured_path(
            self.xray_path_card.edit.text(),
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите xray.exe",
            str(current_path or XRAY_PATH_DEFAULT),
            "xray.exe (xray.exe)",
        )
        if file_path:
            self.xray_path_card.edit.setText(
                normalize_configured_path(
                    file_path,
                    default_path=XRAY_PATH_DEFAULT,
                    use_default_if_empty=True,
                    migrate_default_location=True,
                )
            )
            self._auto_save()

    def _choose_singbox_path(self) -> None:
        current_path = resolve_configured_path(
            self.singbox_path_card.edit.text(),
            default_path=SINGBOX_PATH_DEFAULT,
            migrate_default_location=True,
        )
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите sing-box.exe",
            str(current_path or SINGBOX_PATH_DEFAULT),
            "sing-box.exe (sing-box.exe)",
        )
        if file_path:
            self.singbox_path_card.edit.setText(
                normalize_configured_path(
                    file_path,
                    default_path=SINGBOX_PATH_DEFAULT,
                    migrate_default_location=True,
                )
            )
            self._auto_save()

    def _auto_save(self) -> None:
        if self._loading:
            return
        data = deepcopy(self._settings)
        data.theme = str(self.theme_card.combo.currentData() or "system")
        data.accent_color = self.accent_card.picker.color.name() or "#0078D4"
        data.socks_port = int(self.socks_card.spin.value())
        data.http_port = int(self.http_card.spin.value())
        data.xray_path = normalize_configured_path(
            self.xray_path_card.edit.text(),
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        data.singbox_path = normalize_configured_path(
            self.singbox_path_card.edit.text(),
            default_path=SINGBOX_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        self.xray_path_card.edit.setText(data.xray_path)
        self.singbox_path_card.edit.setText(data.singbox_path)
        data.tun_engine = self.tun_engine_card.combo.currentData() or "singbox"
        data.start_minimized = self.start_min_card.isChecked()
        data.launch_on_startup = self.launch_card.isChecked()
        data.reconnect_on_network_change = self.reconnect_card.isChecked()
        data.check_updates = self.check_updates_card.isChecked()
        data.allow_updates = self.allow_updates_card.isChecked()
        data.xray_auto_update = self.xray_auto_update_card.isChecked()
        data.auto_switch_enabled = self.auto_switch_card.isChecked()
        data.auto_switch_threshold_kbps = int(self.auto_switch_threshold_card.spin.value())
        data.auto_switch_delay_sec = int(self.auto_switch_delay_card.spin.value())
        data.auto_switch_cooldown_sec = int(self.auto_switch_cooldown_card.spin.value())
        data.auto_switch_strategy = self.auto_switch_strategy_card.combo.currentData() or "speed"

        data.stability_keepalive_enabled = self.keepalive_card.isChecked()
        data.stability_keepalive_interval_sec = int(self.keepalive_interval_card.spin.value())
        data.stability_keepalive_fails_before_reconnect = int(self.keepalive_fails_card.spin.value())
        data.stability_backoff_enabled = self.backoff_card.isChecked()

        data.dpi_fragment_enabled = self.dpi_fragment_card.isChecked()
        data.dpi_fragment_packets = int(self.dpi_fragment_packets_card.spin.value())
        data.dpi_fragment_length = int(self.dpi_fragment_length_card.spin.value())
        data.dpi_fragment_interval_ms = int(self.dpi_fragment_interval_card.spin.value())
        data.dpi_mux_enabled = self.dpi_mux_card.isChecked()
        data.dpi_mux_concurrency = int(self.dpi_mux_concurrency_card.spin.value())
        data.dpi_noise_enabled = self.dpi_noise_card.isChecked()
        self.save_requested.emit(data)
        self.auto_lock_minutes_changed.emit(int(self.auto_lock_card.spin.value()))

    def _emit_set_encryption(self) -> None:
        value = self.encryption_card.edit.text().strip()
        if value:
            self.set_encryption_requested.emit(value)
            self.encryption_card.edit.clear()

    def _emit_password(self) -> None:
        value = self.password_card.edit.text().strip()
        if value:
            self.set_password_requested.emit(value)
            self.password_card.edit.clear()

    @staticmethod
    def _select_combo_data(combo: ComboBox, value: str) -> None:
        for index in range(combo.count()):
            if combo.itemData(index) == value:
                combo.setCurrentIndex(index)
                return
