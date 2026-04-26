from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
import json
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from .country_flags import CountryResolver, detect_country
from .config_builder import build_xray_config
from .singbox_config_builder import build_singbox_config, build_xray_hybrid_config, needs_xray_hybrid, TunConfigBundle
from .connectivity_test import ConnectivityTestWorker
from .constants import APP_NAME, LOG_DIR, ROUTING_MODES, SINGBOX_CLASH_API_PORT, XRAY_STATS_API_PORT
from .diagnostics import export_diagnostics
from .link_parser import parse_links_text
from .live_metrics_worker import LiveMetricsWorker
from .models import AppSettings, AppState, Node, RoutingSettings
from .network_monitor import NetworkMonitor
from .ping_worker import PingWorker
from .speed_test_worker import SpeedTestWorker
from .proxy_manager import ProxyManager
from .security import create_password_hash, get_idle_seconds, verify_password
from .tun2socks_manager import Tun2SocksManager
from .singbox_manager import SingBoxManager, get_singbox_version
from .storage import PassphraseRequired, StateStorage
from .startup import build_startup_command, set_startup_enabled
from .xray_core_updater import XrayCoreUpdateResult, XrayCoreUpdateWorker
from .traffic_history import TrafficHistoryStorage
from .xray_manager import XrayManager, get_xray_version
from .zapret_manager import ZapretManager


class AppController(QObject):
    nodes_changed = pyqtSignal(object)
    selection_changed = pyqtSignal(object)
    connection_changed = pyqtSignal(bool)
    routing_changed = pyqtSignal(object)
    settings_changed = pyqtSignal(object)
    log_line = pyqtSignal(str)
    status = pyqtSignal(str, str)
    ping_updated = pyqtSignal(str, object)
    speed_updated = pyqtSignal(str, object, bool)  # node_id, speed_mbps, is_alive
    connectivity_test_done = pyqtSignal(bool, str, object)
    live_metrics_updated = pyqtSignal(object)
    xray_update_result = pyqtSignal(object)
    lock_state_changed = pyqtSignal(bool)
    passphrase_required = pyqtSignal()
    auto_switch_triggered = pyqtSignal(str)  # node name we're switching to
    config_fetch_started = pyqtSignal()
    config_fetch_progress = pyqtSignal(int, int, int)   # done, total, added_this_url
    config_fetch_finished = pyqtSignal(int, int, int)   # imported_nodes, total_configs, errors

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self.storage = StateStorage()
        self.xray = XrayManager(self)
        self.singbox = SingBoxManager(self)
        self.tun2socks = Tun2SocksManager(self)
        self.zapret = ZapretManager(self)
        self.proxy = ProxyManager()
        self.network_monitor = NetworkMonitor(parent=self)

        self.state = AppState()
        self.recent_logs: list[str] = []
        self.connected = False
        self.locked = False

        # --- File logger (5 MB × 3 rotated files in data/logs/) ---
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("xray_fluent")
        self._logger.setLevel(logging.DEBUG)
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                LOG_DIR / "app.log",
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
            self._logger.addHandler(handler)

        self._country_resolver: CountryResolver | None = None
        self._ping_worker: PingWorker | None = None
        self._speed_worker: SpeedTestWorker | None = None
        self._connectivity_worker: ConnectivityTestWorker | None = None
        self._metrics_worker: LiveMetricsWorker | None = None
        self._xray_update_worker: XrayCoreUpdateWorker | None = None
        self._xray_update_silent = False
        self._reconnect_after_xray_update = False
        self._reconnecting = False
        self._switching = False  # suppress intermediate UI updates during stop→start
        self._active_core: str = "xray"  # "xray" | "singbox" | "tun2socks"
        self._protect_ss_port: int = 0
        self._protect_ss_password: str = ""
        self._traffic_history = TrafficHistoryStorage()
        self._traffic_save_counter = 0

        # Заполняются из main.py после успешного логина
        self._current_username:  str = ""
        self._current_device_id: str = ""

        # --- Auto-switch state ---
        self._auto_switch_low_since: float = 0.0  # monotonic timestamp when speed first dropped
        self._auto_switch_last_switch: float = 0.0  # monotonic timestamp of last auto-switch
        self._auto_switch_high_ticks: int = 0  # consecutive readings above threshold
        self._auto_switch_active_download: bool = False  # True after sustained traffic

        # --- Health Monitor (стабильность как у платных VPN) ---
        self._health_dead_strikes: int = 0        # сколько мертвых тиков подряд
        self._health_warn_emitted: bool = False   # уже выдали предупреждение о пинге

        # --- Auto-ping таймер ---
        self._auto_ping_timer = QTimer(self)
        self._auto_ping_timer.timeout.connect(self._on_auto_ping_tick)

        # --- Stability: keepalive heartbeat ---
        self._keepalive_fail_count: int = 0
        self._keepalive_timer = QTimer(self)
        self._keepalive_timer.timeout.connect(self._check_keepalive)

        # --- Stability: exponential backoff for reconnect ---
        self._backoff_attempt: int = 0
        self._backoff_timer = QTimer(self)
        self._backoff_timer.setSingleShot(True)
        self._backoff_timer.timeout.connect(self._do_backoff_reconnect)

        self.xray.log_received.connect(self._on_xray_log)
        self.xray.error.connect(self._on_xray_error)
        self.xray.state_changed.connect(self._on_core_state_changed)

        self.singbox.log_received.connect(self._on_xray_log)
        self.singbox.error.connect(self._on_singbox_error)
        self.singbox.state_changed.connect(self._on_core_state_changed)

        self.tun2socks.log_received.connect(self._on_xray_log)
        self.tun2socks.error.connect(self._on_singbox_error)
        self.tun2socks.state_changed.connect(self._on_core_state_changed)

        self.network_monitor.network_changed.connect(self._on_network_changed)

        self._lock_timer = QTimer(self)
        self._lock_timer.setInterval(15_000)
        self._lock_timer.timeout.connect(self._check_auto_lock)

    def load(self) -> bool:
        # Если passphrase ещё не задан — устанавливаем авто-ключ из device_id.
        # Это гарантирует что первый же save() запишет зашифрованный файл.
        if not self.storage.passphrase:
            self.storage.passphrase = self._derive_auto_passphrase()
        try:
            self.state = self.storage.load()
        except PassphraseRequired:
            self.passphrase_required.emit()
            return False

        self._detect_countries_sync()
        self._migrate_sort_order()
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.routing_changed.emit(self.state.routing)
        self.settings_changed.emit(self.state.settings)
        QTimer.singleShot(500, self._start_country_ip_resolution)

        version = get_xray_version(self.state.settings.xray_path)
        if version:
            self._log(f"[core] {version}")
        else:
            self.status.emit("warning", "Не удалось прочитать версию Xray")

        sb_version = get_singbox_version(self.state.settings.singbox_path)
        if sb_version:
            self._log(f"[core] sing-box: {sb_version}")

        self.network_monitor.start()
        self._lock_timer.start()
        self._schedule_config_fetch()
        self._start_auto_ping_timer()
        return True

    def set_data_passphrase(self, passphrase: str) -> None:
        self.storage.passphrase = passphrase
        self.save()
        self.status.emit("success", "Шифрование данных включено")

    def clear_data_passphrase(self) -> None:
        """Отключает пользовательский пароль, переходя на авто-ключ из device_id.
        state.enc остаётся зашифрованным — plain-text на диске не допускается."""
        auto_pass = self._derive_auto_passphrase()
        self.storage.passphrase = auto_pass
        self.save()
        self.status.emit("info", "Пользовательский пароль снят (данные защищены авто-ключом)")

    def _derive_auto_passphrase(self) -> str:
        """Деривирует авто-passphrase из device_id (машинного идентификатора).
        Не требует ввода пользователя, но не является пустой строкой."""
        import hashlib
        did = getattr(self, "_current_device_id", "") or ""
        if not did:
            try:
                from .ui.login_screen import compute_device_id
                did = compute_device_id()
            except Exception:
                did = "AegisNET-fallback-device-key"
        return hashlib.sha256(f"aegis-auto:{did}".encode()).hexdigest()

    def is_data_encrypted(self) -> bool:
        return self.storage.is_encrypted()

    def save(self) -> None:
        self.storage.save(self.state)

    # ── Country detection helpers ──

    def _detect_countries_sync(self) -> None:
        changed = False
        for node in self.state.nodes:
            if not node.country_code:
                code = detect_country(node.name, node.server)
                if code:
                    node.country_code = code
                    changed = True
        if changed:
            self.save()

    def _start_country_ip_resolution(self) -> None:
        needs = [(n.id, n.server) for n in self.state.nodes if not n.country_code]
        if not needs:
            return
        self._country_resolver = CountryResolver(needs, parent=self)
        self._country_resolver.resolved.connect(self._on_countries_resolved)
        self._country_resolver.start()

    def _on_countries_resolved(self, results: dict[str, str]) -> None:
        if not results:
            return
        for node in self.state.nodes:
            if node.id in results:
                node.country_code = results[node.id]
        self.save()
        self.nodes_changed.emit(self.state.nodes)

    def shutdown(self) -> None:
        if self._country_resolver and self._country_resolver.isRunning():
            self._country_resolver.quit()
            self._country_resolver.wait(2000)
        if self._ping_worker and self._ping_worker.isRunning():
            self._ping_worker.cancel()
            self._ping_worker.wait(500)
        if self._connectivity_worker and self._connectivity_worker.isRunning():
            self._connectivity_worker.wait(1000)
        self._stop_metrics_worker()
        if self._speed_worker and self._speed_worker.isRunning():
            self._speed_worker.cancel()
            if not self._speed_worker.wait(3000):
                self._speed_worker.terminate()
                self._speed_worker.wait(1000)
        if self._xray_update_worker and self._xray_update_worker.isRunning():
            self._xray_update_worker.wait(1000)
        # Останавливаем GitHub-sync воркер
        gh_sync = getattr(self, "_github_sync_worker", None)
        if gh_sync and gh_sync.isRunning():
            gh_sync.cancel()
            gh_sync.quit()
            if not gh_sync.wait(2000):
                gh_sync.terminate()
                gh_sync.wait(1000)

        # Останавливаем ConfigFetchWorker (splash fetch)
        cf_worker = getattr(self, "_config_fetch_worker", None)
        if cf_worker and cf_worker.isRunning():
            cf_worker.cancel()
            cf_worker.quit()
            if not cf_worker.wait(2000):
                cf_worker.terminate()
                cf_worker.wait(1000)

        # Останавливаем фоновый воркер обновления конфигов
        bg = getattr(self, "_bg_refresh_worker", None)
        if bg and bg.isRunning():
            bg.stop()
            if not bg.wait(2000):
                bg.terminate()
                bg.wait(1000)

        self.disconnect_current()
        # Ensure all cores are stopped
        if self.tun2socks.is_running:
            self.tun2socks.stop()
        if self.singbox.is_running:
            self.singbox.stop()
        if self.xray.is_running:
            self.xray.stop()
        if self.zapret.running:
            self.zapret.stop()
        # Always disable system proxy on exit to prevent leaked proxy
        if self.proxy.is_enabled():
            self.proxy.disable(restore_previous=True)
        # Remove lingering TUN adapter
        self._cleanup_tun_adapter()
        self.network_monitor.stop()
        self._lock_timer.stop()
        self._auto_ping_timer.stop()
        # Stop periodic github-sync timer if it was started
        _gst = getattr(self, "_github_sync_timer", None)
        if _gst is not None:
            _gst.stop()
        self.save()

        # ── Отчёт о завершении сессии в Bot #4 ──────────────────────────
        try:
            tx_mb, rx_mb = 0.0, 0.0
            sess = getattr(self._traffic_history, "_current_session", None)
            if sess is not None:
                tx_mb = (sess.total_upload or 0) / 1_048_576
                rx_mb = (sess.total_download or 0) / 1_048_576
            _username = getattr(self, "_current_username", "")
            _did      = getattr(self, "_current_device_id", "")
            if _username and _did:
                from .license_check import report_stop as _report_stop
                _report_stop(_did, _username, tx_mb, rx_mb)
        except Exception:
            pass

    @staticmethod
    def _cleanup_tun_adapter() -> None:
        """Remove the wintun TUN adapter if it was left behind."""
        import subprocess as _sp
        try:
            result = _sp.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=5,
                creationflags=0x08000000,
            )
            if "ZapretKVN_TUN" in (result.stdout or ""):
                _sp.run(
                    ["netsh", "interface", "set", "interface", "ZapretKVN_TUN", "admin=disable"],
                    capture_output=True, timeout=5,
                    creationflags=0x08000000,
                )
        except Exception:
            pass

    @property
    def selected_node(self) -> Node | None:
        return self._get_node_by_id(self.state.selected_node_id)

    def _get_node_by_id(self, node_id: str | None) -> Node | None:
        if not node_id:
            return None
        for node in self.state.nodes:
            if node.id == node_id:
                return node
        return None

    def export_node_outbound_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        if not node:
            return None
        return json.dumps(node.outbound, ensure_ascii=True, indent=2)

    def export_runtime_config_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        if not node:
            return None
        cfg = build_xray_config(node, self.state.routing, self.state.settings)
        return json.dumps(cfg, ensure_ascii=True, indent=2)

    def import_nodes_from_text(self, text: str) -> tuple[int, list[str]]:
        nodes, errors = parse_links_text(text)
        if not nodes:
            return 0, errors

        existing_links = {node.link for node in self.state.nodes}
        max_order = max((n.sort_order for n in self.state.nodes), default=0)
        first_new_id: str | None = None
        added = 0
        new_links: list[str] = []
        for node in nodes:
            if node.link in existing_links:
                continue
            if not node.country_code:
                node.country_code = detect_country(node.name, node.server)
            max_order += 1
            node.sort_order = max_order
            self.state.nodes.append(node)
            existing_links.add(node.link)
            new_links.append(node.link)
            if first_new_id is None:
                first_new_id = node.id
            added += 1

        if first_new_id:
            self.state.selected_node_id = first_new_id
        elif not self.state.selected_node_id and self.state.nodes:
            self.state.selected_node_id = self.state.nodes[0].id

        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.save()
        QTimer.singleShot(500, self._start_country_ip_resolution)

        if added:
            # In TUN mode, hot-swap xray instead of full reconnect
            if self._active_core in ("singbox", "tun2socks") and self.state.settings.tun_mode:
                self._hot_swap_node("new node imported")
            else:
                self.connect_selected()

            # Фоновая верификация и сохранение на GitHub (не блокирует UI)
            if new_links:
                self._verify_and_upload_manual_async(new_links)

        return added, errors

    def _verify_and_upload_manual_async(self, links: list[str]) -> None:
        """Запускает фоновую проверку ручных конфигов и загрузку на GitHub.

        - Для обычных конфигов: TCP-пинг + трёхэтапная xray-проверка
        - Для BL-конфигов: DPI(Reality)+VPN цепочка
        - Рабочие конфиги сохраняются в зашифрованный файл приватного GitHub
        - Не блокирует UI; статус пишется в лог

        Запускается через QTimer чтобы не тормозить основной поток.
        """
        import threading

        def _bg() -> None:
            try:
                from .config_github_sync import verify_and_upload_manual
                logger.info(
                    "[import] Фоновая верификация %d ручных конфигов...", len(links)
                )
                working, failed = verify_and_upload_manual(
                    links,
                    on_status=lambda msg: logger.info("[import] %s", msg),
                )
                logger.info(
                    "[import] Верификация завершена: %d рабочих, %d нерабочих",
                    len(working), len(failed),
                )
            except Exception as e:
                logger.warning("[import] Ошибка фоновой верификации: %s", e)

        t = threading.Thread(target=_bg, daemon=True, name="manual-verify-upload")
        t.start()

    def remove_nodes(self, node_ids: set[str]) -> None:
        if not node_ids:
            return
        self.state.nodes = [node for node in self.state.nodes if node.id not in node_ids]
        if self.state.selected_node_id in node_ids:
            self.state.selected_node_id = self.state.nodes[0].id if self.state.nodes else None
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.save()

    def update_node(self, node_id: str, updates: dict) -> bool:
        node = self._get_node_by_id(node_id)
        if not node:
            return False
        if "name" in updates:
            node.name = updates["name"]
        if "group" in updates:
            node.group = updates["group"]
        if "tags" in updates:
            node.tags = list(updates["tags"])
        self.nodes_changed.emit(self.state.nodes)
        self.save()
        return True

    def bulk_update_nodes(self, node_ids: set[str], operations: dict) -> int:
        group = operations.get("group", "")
        add_tags = operations.get("add_tags", [])
        remove_tags = set(operations.get("remove_tags", []))
        updated = 0
        for node in self.state.nodes:
            if node.id not in node_ids:
                continue
            if group:
                node.group = group
            if add_tags:
                existing = set(node.tags)
                for tag in add_tags:
                    if tag not in existing:
                        node.tags.append(tag)
            if remove_tags:
                node.tags = [t for t in node.tags if t not in remove_tags]
            updated += 1
        if updated:
            self.nodes_changed.emit(self.state.nodes)
            self.save()
        return updated

    def get_all_groups(self) -> list[str]:
        groups = {node.group for node in self.state.nodes if node.group}
        return sorted(groups)

    def get_all_tags(self) -> list[str]:
        tags: set[str] = set()
        for node in self.state.nodes:
            tags.update(node.tags)
        return sorted(tags)

    def _migrate_sort_order(self) -> None:
        if self.state.nodes and all(n.sort_order == 0 for n in self.state.nodes):
            for i, node in enumerate(self.state.nodes):
                node.sort_order = i + 1
            self.save()

    def reorder_nodes(self, node_id: str, direction: str) -> None:
        ordered = sorted(self.state.nodes, key=lambda n: n.sort_order)
        idx = next((i for i, n in enumerate(ordered) if n.id == node_id), None)
        if idx is None:
            return
        if direction == "up" and idx > 0:
            ordered[idx], ordered[idx - 1] = ordered[idx - 1], ordered[idx]
        elif direction == "down" and idx < len(ordered) - 1:
            ordered[idx], ordered[idx + 1] = ordered[idx + 1], ordered[idx]
        elif direction == "top" and idx > 0:
            node = ordered.pop(idx)
            ordered.insert(0, node)
        elif direction == "bottom" and idx < len(ordered) - 1:
            node = ordered.pop(idx)
            ordered.append(node)
        else:
            return
        for i, node in enumerate(ordered):
            node.sort_order = i + 1
        self.nodes_changed.emit(self.state.nodes)
        self.save()

    def set_selected_node(self, node_id: str) -> None:
        if self.state.selected_node_id == node_id:
            return
        self.state.selected_node_id = node_id
        self.selection_changed.emit(self.selected_node)
        self.save()

        # Defer connection work so the UI updates immediately
        if self.connected:
            # In TUN mode, hot-swap node — keep sing-box TUN alive if possible
            if self._active_core in ("singbox", "tun2socks") and self.state.settings.tun_mode:
                QTimer.singleShot(0, lambda: self._hot_swap_node("node switched"))
            else:
                QTimer.singleShot(0, lambda: self._reconnect("node switched"))
        else:
            QTimer.singleShot(0, self.connect_selected)

    def connect_selected(self, allow_during_reconnect: bool = False) -> bool:
        if self._reconnecting and not allow_during_reconnect:
            self.status.emit("info", "Переподключение...")
            return False

        if self.locked:
            self.status.emit("warning", "Приложение заблокировано. Разблокируйте для подключения.")
            return False

        node = self.selected_node
        if not node:
            self.status.emit("warning", "Сначала выберите сервер.")
            return False

        tun = self.state.settings.tun_mode

        if tun:
            self._log(f"[tun] attempting TUN connect, admin={_is_admin()}")
            self.status.emit("info", f"Запуск VPN: {node.name}...")

            if not _is_admin():
                self._log("[tun] NOT admin — aborting")
                self.status.emit("error", "Режим TUN требует прав Администратора. Запустите приложение от имени Администратора.")
                return False

            # TUN doesn't use system proxy — disable if it was left on
            if self.proxy.is_enabled():
                self.proxy.disable(restore_previous=True)

            self._tun_log_count = 0
            engine = self.state.settings.tun_engine

            if engine == "singbox":
                # --- sing-box TUN (experimental, supports process routing) ---
                self._active_core = "singbox"  # Set early so metrics worker gets correct mode
                bundle = build_singbox_config(node, self.state.routing, self.state.settings)

                if bundle.is_hybrid:
                    self.status.emit("info", "Запуск Xray (dialerProxy)...")
                    xray_cfg = bundle.xray_config
                    xray_cfg["log"] = {"loglevel": "error"}
                    xray_ok = self.xray.start(self.state.settings.xray_path, xray_cfg)
                    if not xray_ok:
                        self._log("[tun] xray start failed")
                        self.status.emit("error", "Не удалось запустить Xray. Проверьте логи.")
                        return False
                    self.status.emit("info", "Xray запущен. Создание TUN адаптера...")

                self._log(f"[tun] starting sing-box TUN (hybrid={bundle.is_hybrid})")
                sb_ok = self.singbox.start(self.state.settings.singbox_path, bundle.singbox_config)
                self._log(f"[tun] sing-box start result: {sb_ok}")
                if not sb_ok:
                    if bundle.is_hybrid:
                        self.xray.stop()
                    self.status.emit("error", "Не удалось создать TUN адаптер. Проверьте наличие wintun.dll в core/.")
                    return False
                self._protect_ss_port = bundle.protect_port
                self._protect_ss_password = bundle.protect_password
            else:
                # --- tun2socks TUN (stable, default) ---
                self._active_core = "tun2socks"
                config = build_xray_config(node, self.state.routing, self.state.settings)
                config["log"] = {"loglevel": "error"}
                xray_ok = self.xray.start(self.state.settings.xray_path, config)
                if not xray_ok:
                    self._log("[tun] xray start failed")
                    self.status.emit("error", "Не удалось запустить Xray. Проверьте логи.")
                    return False
                self.status.emit("info", "Xray запущен. Создание TUN адаптера...")

                socks_port = self.state.settings.socks_port
                self._log(f"[tun] starting tun2socks -> SOCKS 127.0.0.1:{socks_port}")
                tun_ok = self.tun2socks.start(socks_port, server_ip=node.server)
                self._log(f"[tun] tun2socks start result: {tun_ok}")
                if not tun_ok:
                    self.xray.stop()
                    self.status.emit("error", "Не удалось создать TUN адаптер. Проверьте наличие tun2socks и wintun.dll в core/.")
                    return False
        else:
            self._active_core = "xray"
            config = build_xray_config(node, self.state.routing, self.state.settings)
            ok = self.xray.start(self.state.settings.xray_path, config)
            if not ok:
                return False

            if self.state.settings.enable_system_proxy:
                self.proxy.enable(
                    self.state.settings.http_port,
                    self.state.settings.socks_port,
                    bypass_lan=self.state.routing.bypass_lan,
                )

        node.last_used_at = datetime.now(timezone.utc).isoformat()
        self.status.emit("success", f"Подключено: {node.name}" + (" (TUN)" if tun else ""))
        self.save()
        node_name = node.name if node else "unknown"
        self._traffic_history.start_session(node_name, self._active_core)

        # Анти-DPI: автоматически запускаем zapret вместе с VPN
        if self.state.settings.zapret_with_vpn and self.state.settings.zapret_autostart:
            if not self.zapret.running and self.state.settings.zapret_preset:
                try:
                    self.zapret.start(self.state.settings.zapret_preset)
                    self._log("[dpi] zapret (анти-DPI) запущен вместе с VPN")
                except Exception as _ze:
                    self._log(f"[dpi] запуск zapret: {_ze}")

        # Health monitor: сбрасываем счётчики при новом подключении
        self._health_dead_strikes = 0
        self._health_warn_emitted = False

        return True

    def disconnect_current(self, disable_proxy: bool = True, emit_status: bool = True) -> bool:
        self._auto_switch_low_since = 0.0
        self._auto_switch_high_ticks = 0
        self._auto_switch_active_download = False
        self._health_dead_strikes = 0
        self._health_warn_emitted = False
        self._keepalive_fail_count = 0
        self._keepalive_timer.stop()
        self._backoff_timer.stop()
        self._backoff_attempt = 0
        self._traffic_history.end_session()

        # Анти-DPI: останавливаем zapret при отключении VPN
        if self.state.settings.zapret_with_vpn and self.zapret.running:
            try:
                self.zapret.stop()
                self._log("[dpi] zapret (анти-DPI) остановлен вместе с VPN")
            except Exception as _ze:
                self._log(f"[dpi] остановка zapret: {_ze}")

        from .process_traffic_collector import reset_connection_tracking
        from .win_proc_monitor import clear_pid_cache
        reset_connection_tracking()
        clear_pid_cache()
        if self._active_core == "singbox":
            if emit_status:
                self.status.emit("info", "Остановка VPN...")
            stopped = self.singbox.stop()
            if self.xray.is_running:
                self.xray.stop()
            self._protect_ss_port = 0
            self._protect_ss_password = ""
        elif self._active_core == "tun2socks":
            if emit_status:
                self.status.emit("info", "Остановка VPN...")
            stopped = self.tun2socks.stop()
            if self.xray.is_running:
                self.xray.stop()
        else:
            stopped = self.xray.stop()
            if disable_proxy and self.state.settings.enable_system_proxy:
                self.proxy.disable(restore_previous=True)
        if emit_status:
            self.status.emit("info", "Отключено")
        return stopped

    @property
    def traffic_history(self) -> TrafficHistoryStorage:
        return self._traffic_history

    def toggle_connection(self) -> None:
        """Emergency override for tray icon."""
        if self.connected:
            self.disconnect_current()
        else:
            self.connect_selected()

    def switch_next_node(self) -> None:
        if not self.state.nodes:
            return
        current_id = self.state.selected_node_id
        index = 0
        if current_id:
            for idx, node in enumerate(self.state.nodes):
                if node.id == current_id:
                    index = idx
                    break
        index = (index + 1) % len(self.state.nodes)
        self.set_selected_node(self.state.nodes[index].id)

    def switch_prev_node(self) -> None:
        if not self.state.nodes:
            return
        current_id = self.state.selected_node_id
        index = 0
        if current_id:
            for idx, node in enumerate(self.state.nodes):
                if node.id == current_id:
                    index = idx
                    break
        index = (index - 1) % len(self.state.nodes)
        self.set_selected_node(self.state.nodes[index].id)

    def update_routing(self, routing: RoutingSettings) -> None:
        if routing.mode not in ROUTING_MODES:
            routing.mode = "rule"
        self.state.routing = routing
        self.routing_changed.emit(self.state.routing)
        self.save()

        if self.connected:
            self._reconnect("routing changed")

    def update_settings(self, settings: AppSettings) -> None:
        old_launch = self.state.settings.launch_on_startup
        old_tun = self.state.settings.tun_mode
        self.state.settings = settings
        self.settings_changed.emit(self.state.settings)
        self.save()
        self._schedule_config_fetch()

        if old_launch != settings.launch_on_startup:
            try:
                set_startup_enabled(APP_NAME, settings.launch_on_startup, build_startup_command())
            except Exception as exc:
                self.status.emit("error", f"Ошибка настройки автозапуска: {exc}")

        if old_tun != settings.tun_mode and self.connected:
            self._reconnect("TUN mode toggled")
            return

        if not settings.tun_mode:
            if self.connected and not settings.enable_system_proxy:
                self.proxy.disable(restore_previous=True)
            elif self.connected and settings.enable_system_proxy:
                self.proxy.enable(
                    settings.http_port,
                    settings.socks_port,
                    bypass_lan=self.state.routing.bypass_lan,
                )

    def ping_nodes(self, node_ids: set[str] | None = None) -> None:
        nodes = self.state.nodes
        if node_ids:
            nodes = [node for node in nodes if node.id in node_ids]
        if not nodes:
            return

        if self._ping_worker and self._ping_worker.isRunning():
            self._ping_worker.cancel()
            self._ping_worker.wait(500)

        self._ping_worker = PingWorker(nodes)
        self._ping_worker.result.connect(self._on_ping_result)
        self._ping_worker.progress.connect(lambda cur, tot: self.status.emit("info", f"Пинг {cur}/{tot}..."))
        self._ping_worker.completed.connect(self._on_ping_complete)
        self._ping_worker.start()

    def speed_test_nodes(self, node_ids: set[str] | None = None) -> None:
        """Запуск теста скорости для указанных нод (или всех, если None)."""
        nodes = self.state.nodes
        if node_ids:
            nodes = [node for node in nodes if node.id in node_ids]
        if not nodes:
            return

        if self._speed_worker and self._speed_worker.isRunning():
            self._speed_worker.cancel()
            self._speed_worker.wait(3000)

        from .path_utils import resolve_configured_path
        from .constants import XRAY_PATH_DEFAULT
        resolved = resolve_configured_path(
            self.state.settings.xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        xray_path = str(resolved) if resolved else self.state.settings.xray_path

        self._speed_worker = SpeedTestWorker(
            nodes,
            xray_path=xray_path,
            routing=self.state.routing,
        )
        self._speed_worker.result.connect(self._on_speed_result)
        self._speed_worker.progress.connect(lambda cur, tot: self.status.emit("info", f"Тест скорости {cur}/{tot}..."))
        self._speed_worker.completed.connect(self._on_speed_complete)
        self._speed_worker.start()

    def get_fastest_alive_node(self) -> Node | None:
        """Вернуть ноду с наибольшей скоростью среди живых, или лучшую по пингу."""
        alive_nodes = [n for n in self.state.nodes if n.is_alive is True]
        if not alive_nodes:
            # Запасной вариант — любая нода с пингом
            alive_nodes = [n for n in self.state.nodes if n.ping_ms is not None]
        if not alive_nodes:
            return self.selected_node  # запасной — текущая выбранная

        # Предпочитаем ноды с данными о скорости
        with_speed = [n for n in alive_nodes if n.speed_mbps is not None and n.speed_mbps > 0]
        if with_speed:
            return max(with_speed, key=lambda n: n.speed_mbps)

        # Запасной вариант — наименьший пинг
        return min(alive_nodes, key=lambda n: n.ping_ms if n.ping_ms is not None else float('inf'))

    def test_connectivity(self, url: str | None = None) -> None:
        target = (url or "https://www.gstatic.com/generate_204").strip()
        if not target:
            target = "https://www.gstatic.com/generate_204"

        if self._connectivity_worker and self._connectivity_worker.isRunning():
            self.status.emit("info", "Тест подключения уже выполняется")
            return

        self._connectivity_worker = ConnectivityTestWorker(
            self.state.settings.http_port, target, tun_mode=self.state.settings.tun_mode,
        )
        self._connectivity_worker.result.connect(self._on_connectivity_result)
        self._connectivity_worker.start()

    def run_xray_core_update(self, apply_update: bool, silent: bool = False) -> None:
        if self._xray_update_worker and self._xray_update_worker.isRunning():
            if not silent:
                self.status.emit("info", "Обновление Xray уже выполняется")
            return

        if apply_update and self.connected:
            self._reconnect_after_xray_update = True
            self.disconnect_current()
        else:
            self._reconnect_after_xray_update = False

        self._xray_update_silent = silent
        self._xray_update_worker = XrayCoreUpdateWorker(
            self.state.settings.xray_path,
            self.state.settings.xray_release_channel,
            self.state.settings.xray_update_feed_url,
            apply_update=apply_update,
        )
        self._xray_update_worker.done.connect(self._on_xray_update_worker_done)
        self._xray_update_worker.start()

        if not silent:
            message = "Обновление Xray..." if apply_update else "Проверка обновлений Xray..."
            self.status.emit("info", message)

    def _start_metrics_worker(self) -> None:
        node = self.selected_node
        ping_host = node.server if node else ""
        ping_port = node.port if node else 0
        self._log(f"[metrics] starting worker, active_core={self._active_core}")

        self._stop_metrics_worker()
        mode = "singbox" if self._active_core == "singbox" else "xray"
        self._metrics_worker = LiveMetricsWorker(
            self.state.settings.xray_path,
            XRAY_STATS_API_PORT,
            ping_host=ping_host,
            ping_port=ping_port,
            mode=mode,
            clash_api_port=SINGBOX_CLASH_API_PORT,
            socks_port=self.state.settings.socks_port,
            http_port=self.state.settings.http_port,
        )
        self._metrics_worker.metrics.connect(self._on_live_metrics)
        self._metrics_worker.start()
        self._start_keepalive()

    def _start_keepalive(self) -> None:
        """Start stability keepalive heartbeat timer."""
        self._keepalive_fail_count = 0
        self._keepalive_timer.stop()
        s = self.state.settings
        if s.stability_keepalive_enabled:
            interval_ms = max(10, s.stability_keepalive_interval_sec) * 1000
            self._keepalive_timer.setInterval(interval_ms)
            self._keepalive_timer.start()
            self._log(f"[keepalive] started, interval={s.stability_keepalive_interval_sec}s")

    def _check_keepalive(self) -> None:
        """Ping the proxy port; reconnect if too many consecutive failures."""
        if not self.connected or self._reconnecting or self._switching:
            return
        import socket as _socket
        s = self.state.settings
        port = s.socks_port
        ok = False
        try:
            with _socket.create_connection(("127.0.0.1", port), timeout=3):
                ok = True
        except OSError:
            pass
        if ok:
            self._keepalive_fail_count = 0
            return
        self._keepalive_fail_count += 1
        self._log(f"[keepalive] fail {self._keepalive_fail_count}/{s.stability_keepalive_fails_before_reconnect}")
        if self._keepalive_fail_count >= s.stability_keepalive_fails_before_reconnect:
            self._keepalive_fail_count = 0
            self._keepalive_timer.stop()
            self._log("[keepalive] proxy unreachable — triggering reconnect")
            self.status.emit("warning", "Соединение потеряно. Переподключение...")
            self._schedule_backoff_reconnect()

    def _stop_metrics_worker(self) -> None:
        if not self._metrics_worker:
            return
        if self._metrics_worker.isRunning():
            self._metrics_worker.stop()
            self._metrics_worker.wait(1200)
        self._metrics_worker = None

    def set_master_password(self, password: str) -> None:
        password_hash, salt = create_password_hash(password)
        self.state.security.enabled = True
        self.state.security.password_hash = password_hash
        self.state.security.salt = salt
        self.save()

    def disable_master_password(self) -> None:
        self.state.security.enabled = False
        self.state.security.password_hash = ""
        self.state.security.salt = ""
        self.locked = False
        self.lock_state_changed.emit(False)
        self.save()

    def unlock(self, password: str) -> bool:
        if not self.state.security.enabled:
            self.locked = False
            self.lock_state_changed.emit(False)
            return True

        ok = verify_password(password, self.state.security.password_hash, self.state.security.salt)
        if ok:
            self.locked = False
            self.lock_state_changed.emit(False)
        return ok

    def lock(self) -> None:
        if not self.state.security.enabled:
            return
        self.locked = True
        self.lock_state_changed.emit(True)
        self.disconnect_current()

    def build_diagnostics(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = LOG_DIR / f"diagnostics_{stamp}.zip"
        return export_diagnostics(output, self.state, self.recent_logs)

    def auto_connect_if_needed(self) -> None:
        if self.selected_node is not None and not self.locked:
            self.connect_selected()

    def _log(self, line: str) -> None:
        """Send a log line to the UI and write it to the log file."""
        self.recent_logs.append(line)
        if len(self.recent_logs) > 5000:
            self.recent_logs = self.recent_logs[-5000:]
        self._logger.info(line)
        self.log_line.emit(line)

    def _on_xray_log(self, line: str) -> None:
        # In TUN mode, throttle noisy per-connection logs to prevent UI freeze
        if self._active_core in ("singbox", "tun2socks") and "accepted" in line:
            self._tun_log_count = getattr(self, "_tun_log_count", 0) + 1
            # Only log to file, skip UI — emit summary every 100 lines
            self._logger.info(line)
            self.recent_logs.append(line)
            if len(self.recent_logs) > 5000:
                self.recent_logs = self.recent_logs[-5000:]
            if self._tun_log_count % 100 == 0:
                self.log_line.emit(f"[tun] {self._tun_log_count} connections routed...")
            return
        self._log(line)

    def _on_xray_error(self, message: str) -> None:
        self._log(f"[xray-error] {message}")
        self.status.emit("error", message)

    def _on_singbox_error(self, message: str) -> None:
        self._log(f"[singbox-error] {message}")
        self.status.emit("error", message)

    def _on_core_state_changed(self, running: bool) -> None:
        if self._active_core == "singbox":
            self.connected = self.singbox.is_running
        elif self._active_core == "tun2socks":
            self.connected = self.tun2socks.is_running
        else:
            self.connected = running
        # Suppress intermediate connection_changed signals during hot-swap/reconnect
        if not self._switching:
            self.connection_changed.emit(running)
        if running and not self._switching:
            self._start_metrics_worker()
        elif not running:
            self._stop_metrics_worker()
            if not self._switching:
                self.live_metrics_updated.emit({"down_bps": 0.0, "up_bps": 0.0, "latency_ms": None})
        if not running and self._active_core == "xray" and self.state.settings.enable_system_proxy and not self._reconnecting:
            self.proxy.disable(restore_previous=True)

    def _on_ping_result(self, node_id: str, ping_ms: int | None) -> None:
        for node in self.state.nodes:
            if node.id == node_id:
                node.ping_ms = ping_ms
                # Не перезаписываем is_alive=True от speed test результатом ping=None
                if ping_ms is not None or node.is_alive is None:
                    node.is_alive = ping_ms is not None
                ts = datetime.now(timezone.utc).isoformat()
                node.ping_history.append((ts, ping_ms))
                if len(node.ping_history) > 50:
                    node.ping_history = node.ping_history[-50:]
                break
        self.ping_updated.emit(node_id, ping_ms)

    def _on_ping_complete(self) -> None:
        self.save()

    def _on_speed_result(self, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
        for node in self.state.nodes:
            if node.id == node_id:
                node.speed_mbps = speed_mbps
                # Не перезаписываем is_alive=True от пинга результатом speed=False
                if is_alive or node.is_alive is None:
                    node.is_alive = is_alive
                ts = datetime.now(timezone.utc).isoformat()
                node.speed_history.append((ts, speed_mbps))
                if len(node.speed_history) > 50:
                    node.speed_history = node.speed_history[-50:]
                break
        self.speed_updated.emit(node_id, speed_mbps, is_alive)

    def _on_speed_complete(self) -> None:
        self.status.emit("success", "Тест скорости завершён")
        self.save()

    def _on_connectivity_result(self, ok: bool, message: str, elapsed_ms: int | None) -> None:
        if ok and elapsed_ms is not None:
            text = f"Подключение в порядке: {elapsed_ms} мс"
            self.status.emit("success", text)
            self._log(f"[test] {message} ({elapsed_ms} ms)")
        else:
            self.status.emit("warning", "Тест подключения не пройден")
            self._log(f"[test] {message}")
        self.connectivity_test_done.emit(ok, message, elapsed_ms)

    def _on_live_metrics(self, payload: dict[str, object]) -> None:
        self.live_metrics_updated.emit(payload)
        down_bps = float(payload.get("down_bps") or 0.0)
        latency_ms = payload.get("latency_ms")
        # Auto-switch check
        self._check_auto_switch(down_bps)
        # Health monitor check
        self._check_health(latency_ms)
        # Update traffic history with process stats
        process_stats = payload.get("process_stats")
        if process_stats:
            stats_dict = {}
            for ps in process_stats:
                stats_dict[ps.exe] = (ps.upload, ps.download, ps.route)
            self._traffic_history.update_session(stats_dict)
            self._traffic_save_counter += 1
            if self._traffic_save_counter >= 15:  # ~30 sec at 2s interval
                self._traffic_history.save_periodic()
                self._traffic_save_counter = 0

    # ── Health Monitor ─────────────────────────────────────────────────────────

    def _check_health(self, latency_ms: object) -> None:
        """Проверяет живость соединения по латентности из live_metrics.
        Если пинг мёртвый N раз подряд → переподключение."""
        if not self.state.settings.health_check_enabled:
            return
        if not self.connected or self._switching or self._reconnecting:
            self._health_dead_strikes = 0
            return
        if latency_ms is None:
            return

        lms = float(latency_ms)
        warn_ms = self.state.settings.health_latency_warn_ms
        dead_ms = self.state.settings.health_latency_dead_ms
        max_strikes = self.state.settings.health_dead_strikes

        if lms >= dead_ms:
            self._health_dead_strikes += 1
            self._log(
                f"[health] мёртвый пинг {lms:.0f} мс "
                f"(порог {dead_ms} мс, удар {self._health_dead_strikes}/{max_strikes})"
            )
            if self._health_dead_strikes >= max_strikes:
                self._health_dead_strikes = 0
                self._health_warn_emitted = False
                self.status.emit("warn", "⚠️ Соединение потеряно — переподключение...")
                QTimer.singleShot(0, lambda: self._reconnect("health: dead latency"))
        elif lms >= warn_ms:
            self._health_dead_strikes = 0
            if not self._health_warn_emitted:
                self._health_warn_emitted = True
                self.status.emit("warn", f"⚠️ Высокая задержка: {lms:.0f} мс")
        else:
            self._health_dead_strikes = 0
            if self._health_warn_emitted:
                self._health_warn_emitted = False
                self.status.emit("info", "✅ Задержка в норме")

    # ── Auto-ping таймер ────────────────────────────────────────────────────────

    def _start_auto_ping_timer(self) -> None:
        """Запускает периодический пинг всех нод (фоновый, раз в N сек)."""
        self._auto_ping_timer.stop()
        interval_sec = self.state.settings.auto_ping_interval_sec
        if interval_sec > 0:
            self._auto_ping_timer.setInterval(interval_sec * 1000)
            self._auto_ping_timer.start()
            self._log(f"[auto-ping] таймер запущен: каждые {interval_sec} сек")

    def _on_auto_ping_tick(self) -> None:
        """Тик авто-пинга: пингуем все ноды если не идёт подключение."""
        if self._switching or self._reconnecting:
            return
        if self._ping_worker and self._ping_worker.isRunning():
            return
        self._log("[auto-ping] периодический пинг всех нод")
        self.ping_nodes(None)

    # Require N consecutive high-speed readings to confirm "active download"
    _AUTO_SWITCH_HIGH_TICKS_REQUIRED = 10  # ~10s of sustained traffic above threshold
    # Minimum speed to count as "traffic exists" (1 KB/s) vs idle (0)
    _AUTO_SWITCH_IDLE_BPS = 1024.0

    def _check_auto_switch(self, down_bps: float) -> None:
        """Check if speed is below threshold long enough to trigger node switch.

        CRITICAL: This method MUST NOT perform any I/O — it only reads
        in-memory state from the already-collected metrics payload.

        Trigger conditions (ALL must be met):
        1. auto_switch_enabled = True
        2. Connected, not switching/reconnecting, 2+ nodes
        3. There was sustained traffic (10+ consecutive ticks above threshold)
        4. Speed dropped below threshold for delay_sec continuously
        5. Speed is not zero (zero = idle, not speed drop)
        6. Cooldown since last switch has elapsed
        """
        settings = self.state.settings
        if not settings.auto_switch_enabled:
            return
        if not self.connected or self._switching or self._reconnecting:
            return
        if len(self.state.nodes) < 2:
            return

        now = time.monotonic()
        threshold_bps = settings.auto_switch_threshold_kbps * 1024.0

        # Speed above threshold — accumulate "active download" evidence
        if down_bps >= threshold_bps:
            self._auto_switch_high_ticks += 1
            if self._auto_switch_high_ticks >= self._AUTO_SWITCH_HIGH_TICKS_REQUIRED:
                self._auto_switch_active_download = True
            self._auto_switch_low_since = 0.0
            return

        # Speed below threshold
        # Not yet confirmed as active download — ignore
        if not self._auto_switch_active_download:
            self._auto_switch_high_ticks = 0
            return

        # Zero traffic = idle browsing, not speed drop — reset timer & high ticks
        if down_bps < self._AUTO_SWITCH_IDLE_BPS:
            self._auto_switch_low_since = 0.0
            self._auto_switch_high_ticks = 0
            self._auto_switch_active_download = False
            return

        # Speed is between IDLE and threshold — genuine speed drop
        # Reset high ticks counter (speed is no longer high)
        self._auto_switch_high_ticks = 0

        # Start tracking low-speed moment
        if self._auto_switch_low_since == 0.0:
            self._auto_switch_low_since = now
            return

        # Check if speed has been low long enough
        low_duration = now - self._auto_switch_low_since
        if low_duration < settings.auto_switch_delay_sec:
            return

        # Check cooldown
        if now - self._auto_switch_last_switch < settings.auto_switch_cooldown_sec:
            return

        # --- Trigger auto-switch ---
        self._auto_switch_low_since = 0.0
        self._auto_switch_last_switch = now
        self._auto_switch_active_download = False

        next_node = self._get_next_node_for_auto_switch()
        if not next_node:
            return

        self._log(f"[auto-switch] speed {down_bps / 1024:.0f} KB/s < {settings.auto_switch_threshold_kbps} KB/s "
                   f"for {low_duration:.0f}s → switching to {next_node.name}")
        self.auto_switch_triggered.emit(next_node.name)

        # Change selected node and hot-swap
        self.state.selected_node_id = next_node.id
        self.selection_changed.emit(next_node)
        self.save()

        if self._active_core in ("singbox", "tun2socks") and settings.tun_mode:
            QTimer.singleShot(0, lambda: self._hot_swap_node("auto-switch: speed drop"))
        else:
            QTimer.singleShot(0, lambda: self._reconnect("auto-switch: speed drop"))

    def _get_next_node_for_auto_switch(self) -> Node | None:
        """Pick next node using strategy from settings (speed / ping / roundrobin)."""
        current_id = self.state.selected_node_id
        nodes = self.state.nodes
        if not nodes:
            return None

        strategy = self.state.settings.auto_switch_strategy  # "speed" | "ping" | "roundrobin"

        if strategy == "roundrobin":
            # Pure round-robin, skip current
            current_idx = next((i for i, n in enumerate(nodes) if n.id == current_id), 0)
            for offset in range(1, len(nodes)):
                candidate = nodes[(current_idx + offset) % len(nodes)]
                if candidate.id != current_id:
                    return candidate
            return None

        # Alive nodes (excluding current)
        alive = [n for n in nodes if n.id != current_id and n.is_alive is True]
        fallback = [n for n in nodes if n.id != current_id]

        if strategy == "ping":
            pool = alive or fallback
            if not pool:
                return None
            return min(pool, key=lambda n: n.ping_ms if n.ping_ms is not None else float("inf"))

        # Default: "speed" — prefer highest speed, fall back to lowest ping
        with_speed = [n for n in alive if n.speed_mbps is not None and n.speed_mbps > 0]
        if with_speed:
            return max(with_speed, key=lambda n: n.speed_mbps)
        pool = alive or fallback
        if not pool:
            return None
        return min(pool, key=lambda n: n.ping_ms if n.ping_ms is not None else float("inf"))

    def _on_xray_update_worker_done(self, result: XrayCoreUpdateResult) -> None:
        self._xray_update_worker = None
        self.xray_update_result.emit(result)

        if result.status == "error":
            self.status.emit("error", result.message)
        elif result.status == "updated":
            if not self._xray_update_silent:
                self.status.emit("success", result.message)
            self._log(f"[core-update] {result.message}")
        elif result.status == "available":
            if not self._xray_update_silent:
                self.status.emit("warning", result.message)
            else:
                self._log(f"[core-update] {result.message}")
        elif result.status == "up_to_date":
            if not self._xray_update_silent:
                self.status.emit("info", result.message)
            else:
                self._log(f"[core-update] {result.message}")

        if self._reconnect_after_xray_update:
            self._reconnect_after_xray_update = False
            self.connect_selected()

        self._xray_update_silent = False

    # =========================================================================
    # Stability: exponential backoff reconnect
    # =========================================================================

    _BACKOFF_DELAYS_SEC = [2, 5, 10, 20, 40, 60]

    def _schedule_backoff_reconnect(self) -> None:
        """Schedule a reconnect with exponential backoff delay."""
        s = self.state.settings
        if not s.stability_backoff_enabled:
            QTimer.singleShot(0, lambda: self._reconnect("keepalive failure"))
            return
        delays = self._BACKOFF_DELAYS_SEC
        delay = delays[min(self._backoff_attempt, len(delays) - 1)]
        self._backoff_attempt += 1
        self._log(f"[backoff] попытка {self._backoff_attempt}, задержка {delay}s")
        self.status.emit("info", f"Переподключение через {delay}с... (попытка {self._backoff_attempt})")
        self._backoff_timer.setInterval(delay * 1000)
        self._backoff_timer.start()

    def _do_backoff_reconnect(self) -> None:
        if not self.connected and self._backoff_attempt > 0:
            # Already connected somehow (manual), reset
            self._backoff_attempt = 0
            return
        self._reconnect("backoff reconnect")
        if self.connected:
            self._backoff_attempt = 0
            self._start_keepalive()
        else:
            self._schedule_backoff_reconnect()

    def _on_network_changed(self, old: str, new: str) -> None:
        self._log(f"[network] changed: {old} -> {new}")
        # TUN mode creates a virtual adapter which triggers network change —
        # reconnecting would kill the TUN and cause an infinite loop
        if self._active_core in ("singbox", "tun2socks") and self.state.settings.tun_mode:
            self._log("[network] ignoring change in TUN mode")
            return
        if self.connected and self.state.settings.reconnect_on_network_change:
            self._reconnect("network changed")

    def _hot_swap_node(self, reason: str) -> None:
        """Switch node in TUN mode. Restarts only xray; TUN adapter stays alive."""
        node = self.selected_node
        if not node:
            return

        # tun2socks mode: always hot-swap xray only
        if self._active_core == "tun2socks":
            self._switching = True
            try:
                self._log(f"[hot-swap] {reason} — restarting xray only, tun2socks stays up")
                self.status.emit("info", f"Переключение на {node.name}...")
                self.xray.stop()
                config = build_xray_config(node, self.state.routing, self.state.settings)
                config["log"] = {"loglevel": "error"}
                ok = self.xray.start(self.state.settings.xray_path, config)
                if ok:
                    node.last_used_at = datetime.now(timezone.utc).isoformat()
                    self.status.emit("success", f"Переключено: {node.name} (TUN)")
                    self.save()
                else:
                    self._log("[hot-swap] xray restart failed")
                    self.status.emit("error", "Не удалось переключить сервер")
            finally:
                self._switching = False
                self.connection_changed.emit(self.connected)
            return

        # sing-box mode
        hybrid_now = self.xray.is_running
        hybrid_next = needs_xray_hybrid(node)

        if hybrid_now != hybrid_next:
            self._reconnect(f"{reason} (mode change)")
            return

        if hybrid_next:
            # Hybrid: restart only xray, sing-box TUN stays alive
            self._switching = True
            try:
                self._log(f"[hot-swap] {reason} — restarting xray only, sing-box TUN stays up")
                self.status.emit("info", f"Переключение на {node.name}...")
                self.xray.stop()
                xray_cfg = build_xray_hybrid_config(node, self.state.routing, self.state.settings, self._protect_ss_port, self._protect_ss_password)
                xray_cfg["log"] = {"loglevel": "error"}
                ok = self.xray.start(self.state.settings.xray_path, xray_cfg)
                if ok:
                    node.last_used_at = datetime.now(timezone.utc).isoformat()
                    self.status.emit("success", f"Переключено: {node.name} (TUN)")
                    self.save()
                else:
                    self._log("[hot-swap] xray restart failed")
                    self.status.emit("error", "Не удалось переключить сервер")
            finally:
                self._switching = False
                self.connection_changed.emit(self.connected)
        else:
            # Native: sing-box holds the outbound, must do full reconnect
            self._reconnect(f"{reason} (native mode)")

    def _reconnect(self, reason: str) -> None:
        if self._reconnecting:
            return
        self._reconnecting = True
        self._switching = True
        try:
            self._log(f"[reconnect] {reason}")
            stopped = self.disconnect_current(disable_proxy=False, emit_status=False)
            if not stopped:
                self.status.emit("error", "Не удалось остановить предыдущий процесс Xray")
                if self.state.settings.enable_system_proxy:
                    self.proxy.disable(restore_previous=True)
                return

            ok = self.connect_selected(allow_during_reconnect=True)
            if not ok and self.state.settings.enable_system_proxy:
                self.proxy.disable(restore_previous=True)
        finally:
            self._reconnecting = False
            self._switching = False
            self.connection_changed.emit(self.connected)
            if self.connected:
                self._start_metrics_worker()

    # =========================================================================
    # Авто-загрузка конфигов (vpn-vless-configs-russia integration)
    # =========================================================================

    def start_config_fetch(self, silent: bool = False) -> None:
        from .config_fetcher import ConfigFetchWorker
        if getattr(self, "_config_fetch_worker", None) and self._config_fetch_worker.isRunning():
            if not silent:
                self.status.emit("info", "Загрузка конфигов уже идёт...")
            return
        settings = self.state.settings
        worker = ConfigFetchWorker(
            extra_urls=list(settings.config_fetch_extra_urls or []),
            workers=settings.config_fetch_workers,
            filter_enabled=settings.config_fetch_filter,
            parent=self,
        )
        worker.progress.connect(self._on_config_fetch_progress)
        worker.finished.connect(self._on_config_fetch_finished)
        worker.error.connect(lambda msg: self.status.emit("error", f"Ошибка загрузки конфигов: {msg}"))
        self._config_fetch_worker = worker
        worker.start()
        self._log("[config_fetch] Запущена загрузка конфигов из публичных источников")
        if not silent:
            self.status.emit("info", "Загрузка конфигов запущена...")
        self.config_fetch_started.emit()

    def stop_config_fetch(self) -> None:
        worker = getattr(self, "_config_fetch_worker", None)
        if worker:
            worker.cancel()
            if not worker.wait(3000):
                worker.terminate()
                worker.wait(1000)
            self._config_fetch_worker = None

    def _on_config_fetch_progress(self, done: int, total: int, url: str, added: int) -> None:
        self.config_fetch_progress.emit(done, total, added)

    def _on_config_fetch_finished(self, summary) -> None:
        from .config_fetcher import deduplicate_links
        links = summary.links
        if self.state.settings.config_fetch_dedup:
            links = deduplicate_links(links)
        sep = "\n"
        imported, _ = self.import_nodes_from_text(sep.join(links))
        # Сохраняем ping_ms и speed_mbps из summary прямо в ноды
        if imported and (summary.ping_map or summary.speed_map):
            self._apply_summary_metrics(summary)
        self._log(
            "[config_fetch] Done: sources=%d ok=%d configs=%d nodes_added=%d errors=%d" %
            (summary.total_urls, summary.successful_urls, summary.new_configs, imported, len(summary.errors))
        )
        self.status.emit("success", f"Configs loaded: +{imported} nodes")
        self.config_fetch_finished.emit(imported, summary.new_configs, len(summary.errors))
        # Автопинг+автоскорость для новых нод если summary не содержит метрик
        if imported and not summary.ping_map:
            QTimer.singleShot(1000, lambda: self.ping_nodes(None))

    # =========================================================================
    # GitHub-синхронизация конфигов (4-этапный каскадный fallback)
    # =========================================================================

    def start_github_sync(self, silent: bool = False) -> None:
        """Запустить 4-этапную синхронизацию конфигов с GitHub.

        Этапы:
          1. GitHub зашифрованные конфиги → проверка
          2. Локальные ноды → проверка
          3. kort0881/vpn-vless-configs-russia → обфускация → проверка
          4. Загрузка рабочих конфигов на GitHub (зашифрованными)
        """
        from .config_github_sync import ConfigGithubSyncWorker
        if getattr(self, "_github_sync_worker", None) and self._github_sync_worker.isRunning():
            if not silent:
                self.status.emit("info", "Синхронизация конфигов уже запущена...")
            return

        worker = ConfigGithubSyncWorker(
            local_nodes=list(self.state.nodes),
            parent=self,
        )
        worker.stage.connect(self._log)
        worker.progress.connect(lambda d, t: None)
        worker.finished.connect(self._on_github_sync_finished)
        worker.error.connect(lambda msg: self.status.emit("error", f"[sync] {msg}"))
        self._github_sync_worker = worker
        worker.start()
        self._log("[config_sync] Запущена синхронизация конфигов с GitHub (4 этапа)")
        if not silent:
            self.status.emit("info", "Синхронизация конфигов запущена...")

    def stop_github_sync(self) -> None:
        worker = getattr(self, "_github_sync_worker", None)
        if worker:
            worker.cancel()
            if not worker.wait(3000):
                worker.terminate()
                worker.wait(1000)
            self._github_sync_worker = None

    def _on_github_sync_finished(self, links: list) -> None:
        """Обработчик завершения GitHub-синхронизации."""
        from .config_fetcher import deduplicate_links
        if not links:
            self._log("[config_sync] Нет рабочих конфигов после синхронизации")
            self.status.emit("warning", "Синхронизация: рабочих конфигов не найдено")
            return

        if self.state.settings.config_fetch_dedup:
            links = deduplicate_links(links)

        imported, _ = self.import_nodes_from_text("\n".join(links))
        self._log(
            "[config_sync] Синхронизация завершена: %d конфигов → %d нод добавлено"
            % (len(links), imported)
        )
        self.status.emit("success", f"Синхронизация: +{imported} нод")
        self.config_fetch_finished.emit(imported, len(links), 0)
        if imported:
            QTimer.singleShot(1000, lambda: self.ping_nodes(None))

    def _apply_summary_metrics(self, summary) -> None:
        """Записать ping_ms и speed_mbps из FetchSummary в ноды по link."""
        link_to_node = {n.link: n for n in self.state.nodes}
        changed = False
        for link, ms in (summary.ping_map or {}).items():
            node = link_to_node.get(link)
            if node and node.ping_ms is None:
                node.ping_ms = ms
                node.is_alive = True
                self.ping_updated.emit(node.id, ms)
                changed = True
        for link, spd in (summary.speed_map or {}).items():
            node = link_to_node.get(link)
            if node and node.speed_mbps is None:
                node.speed_mbps = spd
                node.is_alive = True
                self.speed_updated.emit(node.id, spd, True)
                changed = True
        if changed:
            self.save()

    def _schedule_config_fetch(self) -> None:
        # ── GitHub sync (4-этапный fallback) — запускаем сразу при старте ──
        QTimer.singleShot(3000, lambda: self.start_github_sync(silent=True))

        # ── Периодический таймер повторной синхронизации ──────────────────
        if not hasattr(self, "_github_sync_timer"):
            from PyQt6.QtCore import QTimer as _QTimer
            self._github_sync_timer = _QTimer(self)
            self._github_sync_timer.timeout.connect(lambda: self.start_github_sync(silent=True))
        settings = self.state.settings
        if settings.config_fetch_enabled:
            interval_ms = max(5, settings.config_fetch_interval_min) * 60 * 1000
            self._github_sync_timer.start(interval_ms)
            self._log(
                f"[config_sync] Авто-синхронизация каждые {settings.config_fetch_interval_min} мин."
            )
        else:
            self._github_sync_timer.stop()

        # ── Старый публичный фетч (резервный, 2x интервал) ────────────────
        if not hasattr(self, "_config_fetch_timer"):
            from PyQt6.QtCore import QTimer as _QTimer
            self._config_fetch_timer = _QTimer(self)
            self._config_fetch_timer.timeout.connect(lambda: self.start_config_fetch(silent=True))
        if settings.config_fetch_enabled:
            fallback_ms = max(10, settings.config_fetch_interval_min * 2) * 60 * 1000
            self._config_fetch_timer.start(fallback_ms)
        else:
            self._config_fetch_timer.stop()

        # ── Фоновый воркер (каждые 30 мин, скрытый) ──────────────────────
        self._start_bg_refresh()

    def _start_bg_refresh(self) -> None:
        """Запустить/перезапустить BackgroundRefreshWorker."""
        existing = getattr(self, "_bg_refresh_worker", None)
        if existing and existing.isRunning():
            return  # уже работает
        from .config_fetcher import BackgroundRefreshWorker
        settings = self.state.settings
        worker = BackgroundRefreshWorker(
            extra_urls=list(settings.config_fetch_extra_urls or []),
            filter_enabled=settings.config_fetch_filter,
            parent=self,
        )
        worker.refresh_done.connect(self._on_bg_refresh_done)
        worker.status_line.connect(self._log)
        worker.start()
        self._bg_refresh_worker = worker
        self._log("[bg_refresh] Фоновое обновление конфигов запущено (каждые 5 мин)")

    def _on_bg_refresh_done(self, summary) -> None:
        """Обработчик результата фонового обновления."""
        from .config_fetcher import deduplicate_links
        links = summary.links
        if self.state.settings.config_fetch_dedup:
            links = deduplicate_links(links)
        if not links:
            return
        imported, _ = self.import_nodes_from_text("\n".join(links))
        if imported and (summary.ping_map or summary.speed_map):
            self._apply_summary_metrics(summary)
        if imported:
            self._log(f"[bg_refresh] Добавлено {imported} новых конфигов")

    def export_backup(self, path: Path, passphrase: str = "") -> None:
        self.storage.export_backup(path, passphrase)

    def import_backup(self, path: Path, passphrase: str = "") -> None:
        self.state = self.storage.import_backup(path, passphrase)
        self.save()
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.routing_changed.emit(self.state.routing)
        self.settings_changed.emit(self.state.settings)

    def _check_auto_lock(self) -> None:
        if not self.state.security.enabled:
            return
        if self.locked:
            return
        minutes = max(1, self.state.security.auto_lock_minutes)
        if get_idle_seconds() >= minutes * 60:
            self.lock()


def _is_admin() -> bool:
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False
