"""splash_screen.py — AegisNET splash с загрузкой, пингом, speed-check и live-check."""

from __future__ import annotations

import os
import sys
import time
from collections import deque

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap,
)
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton

from ..config_fetcher import (
    ConfigFetchWorker, FetchSummary, URLS_BASE, MAX_PING_MS, MAX_CONFIGS, MAX_PER_COUNTRY,
    PING_WORKERS,
)


def _resource_path(filename: str) -> str:
    """Return path to a bundled resource (works both dev and PyInstaller)."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), filename)


# ── Цвета фирменного стиля AegisNET ──────────────────────────────
_ACCENT    = QColor(0, 168, 255)       # голубой — fetch
_ACCENT2   = QColor(0, 220, 130)       # зелёный — ping
_ACCENT3   = QColor(255, 180, 0)       # золотой — speed
_ACCENT4   = QColor(180, 80, 255)      # фиолетовый — live
_ACCENT5   = QColor(255, 120, 60)      # оранжевый — country
_TEXT      = QColor(230, 240, 255)
_SUBTEXT   = QColor(160, 180, 210)
_TRACK     = QColor(30, 40, 60, 180)
_RADIUS    = 14

_AVG_URL_SECONDS = 0.5   # асинхронный fetch быстрее


class _ExitSplashButton(QPushButton):
    """Кнопка ✕ — полное закрытие приложения со Splash."""
    def __init__(self, parent=None):
        super().__init__("✕", parent)
        self.setFixedSize(26, 26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            QPushButton {
                background: rgba(255,70,70,0.15);
                color: rgba(200,80,80,0.75);
                border: 1px solid rgba(200,60,60,0.25);
                border-radius: 13px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: rgba(255,70,70,0.35);
                color: rgb(255,100,100);
                border: 1px solid rgba(255,80,80,0.5);
            }
        """)


class _WindowButton(QPushButton):
    """Маленькая кнопка управления окном."""
    def __init__(self, text: str, parent=None, danger: bool = False):
        super().__init__(text, parent)
        self.setFixedSize(28, 28)
        self.setFlat(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        color = "#e05555" if danger else "#aaa"
        hover_bg = "rgba(200,50,50,0.7)" if danger else "rgba(255,255,255,0.18)"
        self.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {color};
                border: none; border-radius: 14px;
                font-size: 15px; font-weight: bold;
            }}
            QPushButton:hover {{ background: {hover_bg}; color: white; }}
        """)


class AppSplashScreen(QWidget):
    fetch_done = pyqtSignal(object)
    closed     = pyqtSignal()

    def __init__(
        self,
        workers: int = 50,
        filter_enabled: bool = True,
        extra_urls: list[str] | None = None,
        skip_fetch: bool = False,
        parent=None,
    ):
        super().__init__(
            parent,
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowMinimizeButtonHint,
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setMinimumSize(520, 300)

        # ── Кнопки управления окном ─────────────────────────────
        self._btn_minimize = _WindowButton("−", self)
        self._btn_minimize.setToolTip("Свернуть")
        self._btn_minimize.clicked.connect(self.showMinimized)

        self._btn_cancel = _WindowButton("✕", self, danger=True)
        self._btn_cancel.setToolTip("Отмена и выход")
        self._btn_cancel.clicked.connect(self._on_cancel)

        # ── Фоновое изображение ─────────────────────────────────
        self._bg_pixmap: QPixmap | None = None
        _bg_path = _resource_path("splash_bg.png")
        if os.path.exists(_bg_path):
            self._bg_pixmap = QPixmap(_bg_path)

        self._skip_fetch  = skip_fetch
        self._total_urls  = len(URLS_BASE) + len(extra_urls or [])
        self._done_urls   = 0
        self._added_total = 0

        # Прогресс по этапам
        self._ping_done  = 0;  self._ping_total  = 0
        self._speed_done = 0;  self._speed_total = 0
        self._live_done  = 0;  self._live_total  = 0

        self._stage     = "Инициализация..."
        self._sub_stage = ""
        self._phase     = "init"   # init | fetch | ping | speed | live | country | done

        self._anim_value   = 0.0
        self._target_value = 0.0

        self._bar_color_l = QColor(0, 80, 180)
        self._bar_color_r = _ACCENT

        # ETA
        self._start_ts  = 0.0
        self._eta_sec   = self._total_urls * _AVG_URL_SECONDS
        self._phase_start_ts  = 0.0
        self._phase_done_prev = 0
        self._phase_total_cur = 1

        self._finished = False
        self._closing  = False

        self.resize(580, 380)
        self._center_on_screen()

        # ── Кнопка полного закрытия (выход из приложения) ───────────────
        self._exit_btn = _ExitSplashButton(self)
        self._exit_btn.move(self.width() - 36, 8)
        self._exit_btn.clicked.connect(self._on_exit_clicked)

        self._init_steps = [
            "Инициализация AegisNET...",
            "Загрузка настроек...",
            "Подготовка интерфейса...",
            "Подключение к источникам...",
        ]
        self._init_step_idx = 0

        self._worker: ConfigFetchWorker | None = None
        if not skip_fetch:
            self._worker = ConfigFetchWorker(
                workers=workers,
                filter_enabled=filter_enabled,
                extra_urls=extra_urls,
                parent=self,
            )
            self._worker.progress.connect(self._on_fetch_progress)
            self._worker.ping_progress.connect(self._on_ping_progress)
            self._worker.speed_progress.connect(self._on_speed_progress)
            self._worker.live_progress.connect(self._on_live_progress)
            self._worker.stage.connect(self._on_stage)
            self._worker.finished.connect(self._on_finished)
            self._worker.error.connect(self._on_error)

        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(16)
        self._anim_timer.timeout.connect(self._tick_anim)
        self._anim_timer.start()

        self._eta_timer = QTimer(self)
        self._eta_timer.setInterval(400)
        self._eta_timer.timeout.connect(self._recalc_eta)
        self._eta_timer.start()

        self._step_timer = QTimer(self)
        self._step_timer.setInterval(280)
        self._step_timer.timeout.connect(self._advance_init_step)
        self._step_timer.start()

    # ── Public ──────────────────────────────────────────────────

    def start_fetch(self) -> None:
        if self._worker and not self._worker.isRunning():
            self._start_ts = time.monotonic()
            self._worker.start()

    def finish(self) -> None:
        self._do_close()

    # ── Slots ────────────────────────────────────────────────────

    def _advance_init_step(self) -> None:
        if self._init_step_idx < len(self._init_steps):
            self._stage = self._init_steps[self._init_step_idx]
            self._init_step_idx += 1
            pct = self._init_step_idx / len(self._init_steps)
            self._target_value = pct * 12.0
            self.update()
        else:
            self._step_timer.stop()
            if self._skip_fetch:
                self._stage = "Загрузка пропущена"
                self._target_value = 100.0
                self.fetch_done.emit(FetchSummary())
                QTimer.singleShot(400, self._do_close)
            else:
                self._phase = "fetch"
                self._set_bar_color("fetch")
                self._phase_start_ts = time.monotonic()
                self._phase_total_cur = self._total_urls
                self.start_fetch()

    def _on_fetch_progress(self, done: int, total: int, url: str, added: int) -> None:
        self._done_urls    = done
        self._added_total += added
        self._phase_done_prev = done
        self._phase_total_cur = total
        short = url.split("/")[-1] if "/" in url else url
        self._sub_stage = short[:55] + "..." if len(short) > 55 else short
        # fetch: 12% → 55%
        self._target_value = 12.0 + (done / max(total, 1)) * 43.0
        self.update()

    def _on_ping_progress(self, done: int, total: int) -> None:
        if self._phase != "ping":
            self._phase = "ping"
            self._set_bar_color("ping")
            self._phase_start_ts = time.monotonic()
            self._phase_done_prev = 0
            self._phase_total_cur = total
        self._ping_done  = done
        self._ping_total = total
        self._phase_done_prev = done
        # ping: 55% → 72%
        self._target_value = 55.0 + (done / max(total, 1)) * 17.0
        self.update()

    def _on_speed_progress(self, done: int, total: int) -> None:
        if self._phase != "speed":
            self._phase = "speed"
            self._set_bar_color("speed")
            self._phase_start_ts = time.monotonic()
            self._phase_done_prev = 0
            self._phase_total_cur = total
        self._speed_done  = done
        self._speed_total = total
        self._phase_done_prev = done
        # speed: 72% → 87%
        self._target_value = 72.0 + (done / max(total, 1)) * 15.0
        self.update()

    def _on_live_progress(self, done: int, total: int) -> None:
        if self._phase != "live":
            self._phase = "live"
            self._set_bar_color("live")
            self._phase_start_ts = time.monotonic()
            self._phase_done_prev = 0
            self._phase_total_cur = total
        self._live_done  = done
        self._live_total = total
        self._phase_done_prev = done
        # live: 87% → 96%
        self._target_value = 87.0 + (done / max(total, 1)) * 9.0
        self.update()

    def _on_stage(self, text: str) -> None:
        self._stage = text
        if "пинг" in text.lower() or "📡" in text:
            self._phase = "ping"
            self._set_bar_color("ping")
            self._sub_stage = f"порог {MAX_PING_MS} мс  •  {PING_WORKERS} потоков"
        elif "скорост" in text.lower() or "⚡" in text:
            self._phase = "speed"
            self._set_bar_color("speed")
            self._sub_stage = "ya.ru → google.com → 100kb.txt"
        elif "live" in text.lower() or "🔍" in text or "работоспособн" in text.lower():
            self._phase = "live"
            self._set_bar_color("live")
            self._sub_stage = "проверка ya.ru/google/file через xray"
        elif "отбор" in text.lower() or "🌍" in text:
            self._phase = "country"
            self._set_bar_color("country")
            self._sub_stage = ""
        elif "готово" in text.lower() or "✅" in text:
            self._sub_stage = ""
        self.update()

    def _on_finished(self, summary: FetchSummary) -> None:
        self._finished = True
        self._phase = "done"
        self._sub_stage = ""
        self._stage = (
            f"✅  Готово!  Конфигов: {len(summary.links)}  •  "
            f"Пинг: -{summary.ping_filtered}  •  "
            f"Скорость: -{summary.speed_filtered}  •  "
            f"Live: -{summary.live_filtered}"
        )
        self._target_value = 100.0
        self.fetch_done.emit(summary)
        QTimer.singleShot(1200, self._do_close)

    def _on_error(self, msg: str) -> None:
        self._stage = f"⚠️  Ошибка: {msg}"
        self._sub_stage = ""
        self._target_value = 100.0
        self.fetch_done.emit(FetchSummary())
        QTimer.singleShot(1800, self._do_close)

    def _tick_anim(self) -> None:
        if abs(self._anim_value - self._target_value) < 0.1:
            self._anim_value = self._target_value
        else:
            self._anim_value += (self._target_value - self._anim_value) * 0.10
        self.update()

    def _recalc_eta(self) -> None:
        """Пересчитываем ETA на основе текущего этапа."""
        if self._phase_start_ts == 0.0 or self._finished:
            return
        elapsed = max(0.001, time.monotonic() - self._phase_start_ts)
        done = self._phase_done_prev
        total = self._phase_total_cur
        if done <= 0 or total <= 0:
            return
        rate = done / elapsed  # единиц/сек
        remaining = total - done
        self._eta_sec = remaining / max(rate, 0.001)

    def _on_exit_clicked(self) -> None:
        """Полное закрытие приложения из Splash."""
        import sys as _sys
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
        _sys.exit(0)

    def _do_close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._anim_timer.stop()
        self._eta_timer.stop()
        self._step_timer.stop()
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
        self.closed.emit()
        self.close()

    # ── Helpers ──────────────────────────────────────────────────

    def _set_bar_color(self, mode: str) -> None:
        colors = {
            "fetch":   (QColor(0, 80, 180),    _ACCENT),
            "ping":    (QColor(0, 160, 80),     _ACCENT2),
            "speed":   (QColor(180, 120, 0),    _ACCENT3),
            "live":    (QColor(120, 40, 200),   _ACCENT4),
            "country": (QColor(180, 80, 20),    _ACCENT5),
        }
        l, r = colors.get(mode, (QColor(0, 80, 180), _ACCENT))
        self._bar_color_l = l
        self._bar_color_r = r

    def _center_on_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen:
            sg = screen.availableGeometry()
            self.move(
                sg.x() + (sg.width()  - self.width())  // 2,
                sg.y() + (sg.height() - self.height()) // 2,
            )

    def _eta_str(self) -> str:
        eta = self._eta_sec
        if self._finished or self._phase in ("init", "done"):
            return ""
        if eta >= 3600:
            return f"~{int(eta // 3600)}ч {int((eta % 3600) // 60)}м"
        if eta >= 60:
            return f"~{int(eta // 60)} мин {int(eta % 60)} с"
        return f"~{max(1, int(eta))} с"

    # ── Paint ────────────────────────────────────────────────────

    def resizeEvent(self, e) -> None:
        super().resizeEvent(e)
        W = self.width()
        self._btn_cancel.move(W - 34, 6)
        self._btn_minimize.move(W - 66, 6)

    def _on_cancel(self) -> None:
        """Отмена: прерываем worker и завершаем программу."""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(800)
        self._do_close()
        from PyQt6.QtWidgets import QApplication
        QApplication.quit()

    def paintEvent(self, _) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()

        # ── Clip to rounded rect ────────────────────────────────
        clip_path = QPainterPath()
        clip_path.addRoundedRect(0, 0, W, H, _RADIUS, _RADIUS)
        p.setClipPath(clip_path)

        # ── Фон: изображение splash_bg.png ─────────────────────
        if self._bg_pixmap and not self._bg_pixmap.isNull():
            scaled = self._bg_pixmap.scaled(
                W, H,
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            x_off = (scaled.width() - W) // 2
            y_off = (scaled.height() - H) // 2
            p.drawPixmap(-x_off, -y_off, scaled)
        else:
            bg_grad = QLinearGradient(0, 0, 0, H)
            bg_grad.setColorAt(0, QColor(22, 28, 44))
            bg_grad.setColorAt(1, QColor(12, 16, 28))
            p.fillPath(clip_path, bg_grad)

        # ── Тёмный overlay внизу под прогресс/текст ────────────
        # Мягкий fade: прозрачный сверху → тёмный снизу (только 130px)
        text_area_grad = QLinearGradient(0, H - 130, 0, H)
        text_area_grad.setColorAt(0, QColor(10, 14, 26, 0))
        text_area_grad.setColorAt(0.5, QColor(10, 14, 26, 120))
        text_area_grad.setColorAt(1, QColor(10, 14, 26, 200))
        p.fillRect(0, H - 130, W, 130, text_area_grad)

        # ── Тонкая рамка окна ───────────────────────────────────
        p.setClipping(False)
        p.setPen(QPen(QColor(40, 80, 140, 180), 1))
        p.drawPath(clip_path)
        p.setClipPath(clip_path)

        # ── Прогрессбар ──
        bar_h  = 6
        bar_mx = 48
        bar_y  = H - 78
        bar_w  = W - bar_mx * 2
        bar_pct = max(0.0, min(1.0, self._anim_value / 100.0))

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(_TRACK)
        p.drawRoundedRect(bar_mx, bar_y, bar_w, bar_h, bar_h // 2, bar_h // 2)

        fill_w = max(bar_h, int(bar_w * bar_pct))
        grad = QLinearGradient(bar_mx, 0, bar_mx + fill_w, 0)
        grad.setColorAt(0, self._bar_color_l)
        grad.setColorAt(1, self._bar_color_r)
        p.setBrush(grad)
        p.drawRoundedRect(bar_mx, bar_y, fill_w, bar_h, bar_h // 2, bar_h // 2)

        # ── Процент ──
        p.setPen(QPen(_TEXT))
        p.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        p.drawText(0, bar_y - 22, W, 18, Qt.AlignmentFlag.AlignCenter, f"{int(self._anim_value)}%")

        # ── Основной этап ──
        stage_y = bar_y + bar_h + 8
        p.setPen(QPen(_SUBTEXT))
        p.setFont(QFont("Segoe UI", 8))
        p.drawText(bar_mx, stage_y, bar_w, 16,
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   self._stage)

        # ── ETA справа от этапа ──
        eta = self._eta_str()
        if eta:
            p.setPen(QPen(QColor(80, 110, 160)))
            p.setFont(QFont("Segoe UI", 8))
            p.drawText(bar_mx, stage_y, bar_w, 16,
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       eta)

        # ── Вторая строка (прогресс подэтапа или sub_stage) ──
        line2_y = stage_y + 17
        phase_text = ""
        phase_color = _SUBTEXT

        if not self._finished:
            if self._phase == "ping" and self._ping_total > 0:
                phase_text = f"📡  {self._ping_done}/{self._ping_total} конфигов"
                phase_color = QColor(80, 210, 130)
            elif self._phase == "speed" and self._speed_total > 0:
                phase_text = f"⚡  {self._speed_done}/{self._speed_total} конфигов"
                phase_color = QColor(255, 190, 40)
            elif self._phase == "live" and self._live_total > 0:
                phase_text = f"🔍  {self._live_done}/{self._live_total} конфигов"
                phase_color = QColor(180, 100, 255)
            elif self._sub_stage:
                phase_text = self._sub_stage
                phase_color = QColor(80, 100, 130)

        if phase_text:
            p.setPen(QPen(phase_color))
            p.setFont(QFont("Segoe UI", 8))
            p.drawText(bar_mx, line2_y, bar_w, 14,
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       phase_text)
        elif self._finished:
            p.setPen(QPen(QColor(60, 200, 100)))
            p.setFont(QFont("Segoe UI", 8))
            p.drawText(bar_mx, line2_y, bar_w, 14,
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       "✓ Готово")

        # ── Нижняя подпись + версия ─────────────────────────────
        from ..constants import APP_VERSION
        p.setPen(QPen(QColor(70, 90, 120)))
        p.setFont(QFont("Segoe UI", 7))
        p.drawText(0, H - 22, W, 12, Qt.AlignmentFlag.AlignCenter,
                   "Protected by AegisNET  •  Connecting you safely")
        p.setPen(QPen(QColor(80, 105, 145)))
        p.setFont(QFont("Segoe UI", 7))
        p.drawText(0, H - 10, W, 10, Qt.AlignmentFlag.AlignCenter,
                   f"v{APP_VERSION}")

        p.end()
