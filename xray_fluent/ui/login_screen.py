"""login_screen.py — AegisNET форма входа (показывается до Splash).

Проверка:  логин + пароль + Device ID.
Device ID = CRC32(CPU name) → MD5 → SHA-256 → CRC32  (hex-строка).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import zlib
from pathlib import Path

from PyQt6.QtCore import (
    Qt, QTimer, pyqtSignal, QPoint, QThread,
)
from PyQt6.QtGui import (
    QColor, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap,
    QGuiApplication,
)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QCheckBox,
    QVBoxLayout, QHBoxLayout,
)


# ─── Хранилище сессий ──────────────────────────────────────────────────────
def _data_dir() -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS).parent
    return Path(__file__).resolve().parents[2]


_SESSION_FILE = _data_dir() / "data" / "session.json"


def _save_session(username: str) -> None:
    _SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SESSION_FILE.write_text(json.dumps({"user": username}), encoding="utf-8")


def _load_session() -> str | None:
    try:
        if _SESSION_FILE.exists():
            data = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
            return data.get("user")
    except Exception:
        pass
    return None


def _clear_session() -> None:
    try:
        if _SESSION_FILE.exists():
            _SESSION_FILE.unlink()
    except Exception:
        pass


# ─── Device ID ─────────────────────────────────────────────────────────────

def _crc32_hex(data: bytes) -> str:
    val = zlib.crc32(data) & 0xFFFFFFFF
    return format(val, "08x")


def _get_cpu_name() -> str:
    try:
        import platform
        cpu = platform.processor()
        if cpu:
            return cpu
    except Exception:
        pass
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        )
        val, _ = winreg.QueryValueEx(key, "ProcessorNameString")
        winreg.CloseKey(key)
        return str(val).strip()
    except Exception:
        pass
    return "Unknown CPU"


def compute_device_id() -> str:
    """CRC32(cpu) → MD5 → SHA-256 → CRC32 (hex)."""
    cpu = _get_cpu_name().encode("utf-8")
    step1 = _crc32_hex(cpu)
    step2 = hashlib.md5(step1.encode()).hexdigest()
    step3 = hashlib.sha256(step2.encode()).hexdigest()
    step4 = _crc32_hex(step3.encode())
    return step4.upper()


# ─── Цвета ─────────────────────────────────────────────────────────────────
_RADIUS = 14


def _resource_path(filename: str) -> str:
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), filename)


# ─── Zapret для логина ──────────────────────────────────────────────────────
# Список пресетов, которые пробуем при входе (по приоритету).
# Первый существующий будет использован.
_LOGIN_ZAPRET_PRESETS = [
    "Default",
    "Default v5",
    "Default multisplit_sni",
    "general FAKE TLS AUTO",
]

_TELEGRAM_HOSTS = [
    "149.154.160.0/20",   # Telegram DC1-DC5
    "91.108.4.0/22",
    "91.108.8.0/21",
    "91.108.16.0/21",
    "91.108.56.0/22",
    "95.161.64.0/20",
    "149.154.164.0/22",
    "2001:b28:f23d::/48",
    "2001:b28:f23f::/48",
]


class _LoginZapretHelper:
    """
    Запускает winws2.exe в subprocess (без Qt-зависимостей) на время логина.
    Используется только для доступа к api.telegram.org при проверке лицензии.
    """

    def __init__(self) -> None:
        import subprocess as _sp
        self._sp = _sp
        self._proc: "_sp.Popen | None" = None

    def _find_preset(self) -> "Path | None":
        from ..zapret_manager import _presets_dir
        presets = _presets_dir()
        for name in _LOGIN_ZAPRET_PRESETS:
            p = presets / f"{name}.txt"
            if p.exists():
                return p
        # Берём первый доступный пресет
        if presets.is_dir():
            for p in sorted(presets.iterdir()):
                if p.suffix == ".txt" and not p.name.startswith("_"):
                    return p
        return None

    def _build_args(self, preset: "Path") -> "list[str]":
        """Читаем пресет и добавляем фильтр только на Telegram-хосты."""
        args: list[str] = []
        text = preset.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                args.append(s)

        # Если пресет не содержит ipset/hostlist — добавляем фильтр по IP Telegram
        has_filter = any("ipset" in a or "hostlist" in a for a in args)
        if not has_filter:
            # Пишем временный ipset файл с IP Telegram
            import tempfile, os as _os
            fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="tg_login_")
            _os.close(fd)
            Path(tmp).write_text("\n".join(_TELEGRAM_HOSTS) + "\n", encoding="utf-8")
            self._tmp_ipset = tmp
            args.append(f"--ipset={tmp}")

        return args

    def start(self) -> bool:
        """Запускает zapret. Возвращает True если процесс стартовал."""
        try:
            from ..zapret_manager import _winws2_exe, _zapret_dir
            winws2 = _winws2_exe()
            zapret_dir = _zapret_dir()
            if not winws2.exists():
                return False

            preset = self._find_preset()
            if preset is None:
                return False

            args = self._build_args(preset)
            if not args:
                return False

            cmd = [str(winws2)] + args
            CREATE_NO_WINDOW = 0x08000000
            self._proc = self._sp.Popen(
                cmd,
                cwd=str(zapret_dir),
                stdout=self._sp.DEVNULL,
                stderr=self._sp.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
            return True
        except Exception:
            return False

    def stop(self) -> None:
        """Останавливает процесс zapret."""
        if self._proc is not None:
            try:
                self._proc.kill()
                self._proc.wait(timeout=3)
            except Exception:
                pass
            self._proc = None
        # Удаляем временный ipset если создавали
        tmp = getattr(self, "_tmp_ipset", None)
        if tmp:
            try:
                Path(tmp).unlink(missing_ok=True)
            except Exception:
                pass
            self._tmp_ipset = None


# ─── Виджеты ───────────────────────────────────────────────────────────────

class _ExitButton(QPushButton):
    def __init__(self, parent=None):
        super().__init__("✕", parent)
        self.setFixedSize(28, 28)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            QPushButton {
                background: rgba(255,80,80,0.18); color: rgba(200,80,80,0.85);
                border: 1px solid rgba(200,80,80,0.3); border-radius: 14px;
                font-size: 13px; font-weight: bold;
            }
            QPushButton:hover { background: rgba(255,80,80,0.35); color: rgb(255,100,100); }
        """)


class _EyeButton(QPushButton):
    """Кнопка переключения видимости пароля (👁 / 🙈)."""
    def __init__(self, parent=None):
        super().__init__("👁", parent)
        self.setFixedSize(34, 34)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setCheckable(True)
        self.setToolTip("Показать пароль")
        self.setStyleSheet("""
            QPushButton {
                background: transparent; color: rgba(100,140,190,0.7);
                border: none; font-size: 15px; border-radius: 6px;
            }
            QPushButton:hover { color: rgb(0,168,255); background: rgba(0,100,180,0.15); }
            QPushButton:checked { color: rgb(0,168,255); }
            QPushButton:disabled { color: rgba(100,140,190,0.3); }
        """)


class _LicenseThread(QThread):
    """Проверяем лицензию в фоне, чтобы не блокировать UI."""
    done = pyqtSignal(object)

    def __init__(self, device_id: str, username: str, password: str, parent=None):
        super().__init__(parent)
        self._did  = device_id
        self._user = username
        self._pass = password

    def run(self) -> None:
        try:
            from ..license_check import check_license
            result = check_license(self._did, self._user, self._pass)
        except Exception as e:
            from ..license_check import LicenseResult
            result = LicenseResult(ok=False, message=f"Ошибка проверки лицензии:\n{e}")
        self.done.emit(result)


# ─── LoginScreen ───────────────────────────────────────────────────────────
class LoginScreen(QWidget):
    """Форма входа."""

    login_ok = pyqtSignal(str)
    exit_app = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(
            parent,
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowMinimizeButtonHint,
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        self._bg_pixmap: QPixmap | None = None
        _bg = _resource_path("splash_bg.png")
        if os.path.exists(_bg):
            self._bg_pixmap = QPixmap(_bg)

        self._device_id = compute_device_id()
        self._drag_pos: QPoint | None = None

        # ── Zapret для доступа к Telegram во время логина ──────────────────
        self._zapret = _LoginZapretHelper()
        _zapret_started = self._zapret.start()
        # Даём winws2 секунду подняться перед первым запросом
        if _zapret_started:
            from PyQt6.QtCore import QThread as _QThread
            _QThread.msleep(1000)

        self.resize(430, 530)
        self._center_on_screen()
        self._build_ui()

        saved_user = _load_session()
        if saved_user:
            self._user_edit.setText(saved_user)
            self._remember_cb.setChecked(True)

    # ── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        inner = QWidget(self)
        inner.setStyleSheet("background: transparent;")
        root.addWidget(inner)

        layout = QVBoxLayout(inner)
        layout.setContentsMargins(48, 36, 48, 32)
        layout.setSpacing(0)

        # Кнопка выхода
        top_bar = QHBoxLayout()
        top_bar.addStretch()
        self._exit_btn = _ExitButton(inner)
        self._exit_btn.clicked.connect(self._on_exit)
        top_bar.addWidget(self._exit_btn)
        layout.addLayout(top_bar)

        layout.addSpacing(8)

        # Заголовок
        title = QLabel("AegisNET", inner)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: rgb(0,168,255); font: bold 28px 'Segoe UI'; background: transparent;")
        layout.addWidget(title)

        sub = QLabel("Безопасный вход", inner)
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("color: rgb(100,130,170); font: 11px 'Segoe UI'; background: transparent;")
        layout.addWidget(sub)

        layout.addSpacing(28)

        # Логин
        lbl_user = QLabel("Логин", inner)
        lbl_user.setStyleSheet("color: rgb(160,180,210); font: 10px 'Segoe UI'; background: transparent;")
        layout.addWidget(lbl_user)
        layout.addSpacing(4)

        self._user_edit = QLineEdit(inner)
        self._user_edit.setPlaceholderText("Введите логин")
        self._user_edit.setFixedHeight(38)
        self._user_edit.setStyleSheet(self._field_style())
        layout.addWidget(self._user_edit)

        layout.addSpacing(14)

        # Пароль с кнопкой-глазом
        lbl_pass = QLabel("Пароль", inner)
        lbl_pass.setStyleSheet("color: rgb(160,180,210); font: 10px 'Segoe UI'; background: transparent;")
        layout.addWidget(lbl_pass)
        layout.addSpacing(4)

        pass_row = QHBoxLayout()
        pass_row.setContentsMargins(0, 0, 0, 0)
        pass_row.setSpacing(5)

        self._pass_edit = QLineEdit(inner)
        self._pass_edit.setPlaceholderText("Введите пароль")
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setFixedHeight(38)
        self._pass_edit.setStyleSheet(self._field_style())
        self._pass_edit.returnPressed.connect(self._on_login)
        pass_row.addWidget(self._pass_edit)

        self._eye_btn = _EyeButton(inner)
        self._eye_btn.clicked.connect(self._toggle_pass_visibility)
        pass_row.addWidget(self._eye_btn)

        layout.addLayout(pass_row)

        layout.addSpacing(12)

        # «Запомнить меня»
        self._remember_cb = QCheckBox("Запомнить меня", inner)
        self._remember_cb.setStyleSheet("""
            QCheckBox { color: rgb(130,155,190); font: 10px 'Segoe UI'; background: transparent; }
            QCheckBox::indicator { width: 14px; height: 14px; border-radius: 3px;
                border: 1px solid rgb(60,90,140); background: rgba(0,0,0,0.3); }
            QCheckBox::indicator:checked { background: rgb(0,140,220); border: 1px solid rgb(0,168,255); }
        """)
        layout.addWidget(self._remember_cb)

        layout.addSpacing(20)

        # Кнопка входа
        self._login_btn = QPushButton("Войти", inner)
        self._login_btn.setFixedHeight(42)
        self._login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._login_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 rgb(0,100,200), stop:1 rgb(0,168,255));
                color: white; border-radius: 8px; font: bold 13px 'Segoe UI';
            }
            QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 rgb(0,120,220), stop:1 rgb(30,185,255)); }
            QPushButton:pressed { background: rgb(0,80,160); }
            QPushButton:disabled { background: rgba(0,80,140,0.5); color: rgba(255,255,255,0.5); }
        """)
        self._login_btn.clicked.connect(self._on_login)
        layout.addWidget(self._login_btn)

        layout.addSpacing(10)

        # Ошибка
        self._err_label = QLabel("", inner)
        self._err_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._err_label.setWordWrap(True)
        self._err_label.setStyleSheet(
            "color: rgb(255,80,80); font: 10px 'Segoe UI'; background: transparent;"
        )
        layout.addWidget(self._err_label)

        layout.addStretch()

        # Device ID
        did_lbl = QLabel("ID устройства:", inner)
        did_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        did_lbl.setStyleSheet("color: rgb(70,95,135); font: 9px 'Segoe UI'; background: transparent;")
        layout.addWidget(did_lbl)
        layout.addSpacing(2)

        self._did_btn = QPushButton(self._device_id, inner)
        self._did_btn.setFixedHeight(26)
        self._did_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._did_btn.setToolTip("Нажмите, чтобы скопировать ID устройства")
        self._did_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0,80,140,0.25); color: rgb(80,130,190);
                border: 1px solid rgba(0,100,180,0.3); border-radius: 6px;
                font: 9px 'Consolas'; letter-spacing: 2px;
            }
            QPushButton:hover { background: rgba(0,100,180,0.4); color: rgb(120,180,240); }
        """)
        self._did_btn.clicked.connect(self._copy_device_id)
        layout.addWidget(self._did_btn)

        # Overlay «Скопировано»
        self._overlay = QLabel("✓  ID скопирован", self)
        self._overlay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._overlay.setFixedSize(200, 36)
        self._overlay.setStyleSheet("""
            background: rgba(0,168,255,0.85); color: white;
            border-radius: 10px; font: bold 10px 'Segoe UI';
        """)
        self._overlay.hide()

        self._overlay_timer = QTimer(self)
        self._overlay_timer.setSingleShot(True)
        self._overlay_timer.timeout.connect(self._overlay.hide)

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _field_style() -> str:
        return """
            QLineEdit {
                background: rgba(10,20,40,0.7); color: rgb(220,235,255);
                border: 1px solid rgba(0,100,180,0.45); border-radius: 7px;
                padding: 0 12px; font: 12px 'Segoe UI';
                selection-background-color: rgb(0,120,200);
            }
            QLineEdit:focus { border: 1px solid rgb(0,168,255); }
        """

    def _center_on_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen:
            sg = screen.availableGeometry()
            self.move(
                sg.x() + (sg.width()  - self.width())  // 2,
                sg.y() + (sg.height() - self.height()) // 2,
            )

    # ── Slots ────────────────────────────────────────────────────────────────

    def _toggle_pass_visibility(self, checked: bool) -> None:
        """Переключатель показа пароля."""
        if checked:
            self._pass_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self._eye_btn.setText("🙈")
            self._eye_btn.setToolTip("Скрыть пароль")
        else:
            self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self._eye_btn.setText("👁")
            self._eye_btn.setToolTip("Показать пароль")

    def _on_login(self) -> None:
        username = self._user_edit.text().strip()
        password = self._pass_edit.text()

        if not username or not password:
            self._err_label.setText("Введите логин и пароль")
            return

        # Скрываем пароль перед отправкой
        if self._eye_btn.isChecked():
            self._eye_btn.setChecked(False)
            self._toggle_pass_visibility(False)

        self._set_ui_busy(True)
        self._err_label.setText("Проверка лицензии...")

        self._lic_thread = _LicenseThread(self._device_id, username, password)
        self._lic_thread.done.connect(self._on_license_result)
        self._lic_thread.start()

    def _on_license_result(self, result) -> None:
        self._set_ui_busy(False)
        if result.ok:
            username = self._user_edit.text().strip()
            if self._remember_cb.isChecked():
                _save_session(username)
            else:
                _clear_session()
            self._err_label.setText("")
            # Останавливаем zapret — он больше не нужен, логин прошёл
            self._zapret.stop()
            self.login_ok.emit(username)
            self.close()
        else:
            self._err_label.setText(result.message)
            self._pass_edit.clear()
            self._pass_edit.setFocus()

    def _on_exit(self) -> None:
        """Останавливаем zapret и выходим из приложения."""
        self._zapret.stop()
        self.exit_app.emit()

    def _set_ui_busy(self, busy: bool) -> None:
        self._login_btn.setEnabled(not busy)
        self._user_edit.setEnabled(not busy)
        self._pass_edit.setEnabled(not busy)
        self._eye_btn.setEnabled(not busy)
        self._login_btn.setText("Проверка..." if busy else "Войти")

    def _copy_device_id(self) -> None:
        QGuiApplication.clipboard().setText(self._device_id)
        btn_pos = self._did_btn.mapTo(self, QPoint(0, 0))
        x = btn_pos.x() + (self._did_btn.width() - self._overlay.width()) // 2
        y = btn_pos.y() - self._overlay.height() - 6
        self._overlay.move(x, y)
        self._overlay.show()
        self._overlay.raise_()
        self._overlay_timer.start(1800)

    # ── Drag ─────────────────────────────────────────────────────────────────

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag_pos and e.buttons() == Qt.MouseButton.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None

    # ── Paint ────────────────────────────────────────────────────────────────

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()

        clip = QPainterPath()
        clip.addRoundedRect(0, 0, W, H, _RADIUS, _RADIUS)
        p.setClipPath(clip)

        if self._bg_pixmap and not self._bg_pixmap.isNull():
            scaled = self._bg_pixmap.scaled(
                W, H,
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            xo = (scaled.width()  - W) // 2
            yo = (scaled.height() - H) // 2
            p.drawPixmap(-xo, -yo, scaled)
        else:
            g = QLinearGradient(0, 0, 0, H)
            g.setColorAt(0, QColor(22, 28, 44))
            g.setColorAt(1, QColor(12, 16, 28))
            p.fillPath(clip, g)

        ov = QLinearGradient(0, 0, 0, H)
        ov.setColorAt(0, QColor(8, 12, 24, 170))
        ov.setColorAt(1, QColor(5, 8, 18, 200))
        p.fillPath(clip, ov)

        p.setClipping(False)
        p.setPen(QPen(QColor(40, 80, 140, 180), 1))
        p.drawPath(clip)
        p.end()
