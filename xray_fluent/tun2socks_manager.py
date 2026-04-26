from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from .constants import BASE_DIR
from .core_unpacker import get_core_dir

def _tun2socks_default_path() -> Path:
    try:
        return get_core_dir() / "tun2socks.exe"
    except Exception:
        return BASE_DIR / "core" / "tun2socks.exe"

TUN2SOCKS_PATH_DEFAULT = _tun2socks_default_path()
TUN_DEVICE_NAME = "AegisNET_TUN"
TUN_GW = "172.19.0.1"
TUN_ADDR = "172.19.0.2"
TUN_MASK = "255.255.255.252"
TUN_GW6 = "fd00::1"
TUN_CIDR = "172.19.0.1/30"


class Tun2SocksManager(QObject):
    started = pyqtSignal()
    stopped = pyqtSignal(int)
    log_received = pyqtSignal(str)
    error = pyqtSignal(str)
    state_changed = pyqtSignal(bool)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_ready_read)
        self._process.started.connect(self._on_started)
        self._process.errorOccurred.connect(self._on_error)
        self._process.finished.connect(self._on_finished)
        self._running = False
        self._stop_requested = False
        self._server_ip: str = ""

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, socks_port: int, server_ip: str = "") -> bool:
        exe = TUN2SOCKS_PATH_DEFAULT
        if not exe.is_file():
            self.error.emit(f"tun2socks.exe not found: {exe}")
            return False

        self._server_ip = server_ip

        if self._process.state() != QProcess.ProcessState.NotRunning:
            if not self.stop(expected=True):
                self.error.emit("failed to stop previous tun2socks process")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        # Kill orphaned tun2socks
        self._kill_orphaned()

        self._process.setProgram(str(exe))
        self._process.setArguments([
            "-device", f"tun://{TUN_DEVICE_NAME}",
            "-proxy", f"socks5://127.0.0.1:{socks_port}",
            "-loglevel", "error",
        ])
        self._process.start()

        if not self._process.waitForStarted(5000):
            self.error.emit(f"failed to start tun2socks: {self._process.errorString()}")
            return False

        # Wait for TUN adapter to be created
        self._process.waitForReadyRead(3000)
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self.error.emit("tun2socks exited right after start")
            return False

        # Wait until TUN interface appears (up to 10 seconds)
        from PyQt6.QtWidgets import QApplication
        for _ in range(20):
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                capture_output=True, text=True, timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            if TUN_DEVICE_NAME in (result.stdout or ""):
                break
            # Process Qt events so UI doesn't freeze
            app = QApplication.instance()
            if app:
                app.processEvents()
            time.sleep(0.5)

        # Configure routes
        self._setup_routes()
        return True

    def stop(self, expected: bool = True) -> bool:
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._stop_requested = False
            if self._running:
                self._running = False
                self.state_changed.emit(False)
            return True

        self._stop_requested = expected
        self._process.terminate()
        if self._process.waitForFinished(2000):
            self._cleanup_routes()
            return True

        self._process.kill()
        if self._process.waitForFinished(1000):
            self._cleanup_routes()
            return True

        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._cleanup_routes()
            return True

        self._stop_requested = False
        self.error.emit("failed to stop tun2socks in time")
        return False

    def _setup_routes(self) -> None:
        """Set up routes so all traffic goes through the TUN adapter."""
        if os.name != "nt":
            return
        try:
            # Find TUN interface index by name
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                capture_output=True, text=True, timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            tun_idx = ""
            for line in (result.stdout or "").splitlines():
                if TUN_DEVICE_NAME in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        tun_idx = parts[0]
                        break

            # Get current default gateway
            result = subprocess.run(
                ["cmd", "/c", "route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            orig_gw = ""
            for line in (result.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    orig_gw = parts[2]
                    break
            if not orig_gw:
                orig_gw = "192.168.1.1"
            self._orig_gateway = orig_gw
            self._tun_idx = tun_idx

            # Set TUN interface metric very low so it wins
            if tun_idx:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface", tun_idx, "metric=1"],
                    capture_output=True, timeout=5, creationflags=_CREATE_NO_WINDOW,
                )

            cmds = [
                # Route proxy server IP through original gateway (prevent loop)
                ["route", "add", self._server_ip, "mask", "255.255.255.255", orig_gw, "metric", "1"],
                # Keep gateway/LAN reachable for DHCP, ARP, local network
                ["route", "add", orig_gw, "mask", "255.255.255.255", orig_gw, "metric", "1"],
                ["route", "add", "192.168.0.0", "mask", "255.255.0.0", orig_gw, "metric", "1"],
                ["route", "add", "10.0.0.0", "mask", "255.0.0.0", orig_gw, "metric", "1"],
                ["route", "add", "172.16.0.0", "mask", "255.240.0.0", orig_gw, "metric", "1"],
                ["route", "add", "169.254.0.0", "mask", "255.255.0.0", orig_gw, "metric", "1"],
            ]
            # Use netsh to add TUN routes — this correctly sets interface metric
            if tun_idx:
                cmds += [
                    # IPv4 default via TUN
                    ["netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", f"interface={tun_idx}", f"nexthop={TUN_GW}", "metric=0"],
                    ["netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", f"interface={tun_idx}", f"nexthop={TUN_GW}", "metric=0"],
                    # Block IPv6 globally while TUN is active — tun2socks only handles IPv4
                    # This forces all apps to use IPv4 which goes through TUN
                    ["netsh", "interface", "ipv6", "add", "route", "::/0", f"interface=1", "metric=1"],
                ]
            else:
                cmds += [
                    ["route", "add", "0.0.0.0", "mask", "128.0.0.0", TUN_GW, "metric", "1"],
                    ["route", "add", "128.0.0.0", "mask", "128.0.0.0", TUN_GW, "metric", "1"],
                ]
            for cmd in cmds:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=5, creationflags=_CREATE_NO_WINDOW)
                self.log_received.emit(f"[tun2socks] {' '.join(cmd)} -> rc={r.returncode}")
        except Exception as exc:
            self.log_received.emit(f"[tun2socks] route setup error: {exc}")

    def _cleanup_routes(self) -> None:
        """Remove routes added by _setup_routes."""
        if os.name != "nt":
            return
        try:
            cmds = [
                ["route", "delete", "0.0.0.0", "mask", "128.0.0.0", TUN_GW],
                ["route", "delete", "128.0.0.0", "mask", "128.0.0.0", TUN_GW],
                # Restore IPv6
                ["netsh", "interface", "ipv6", "delete", "route", "::/0", "interface=1"],
            ]
            if hasattr(self, '_tun_idx') and self._tun_idx:
                cmds += [
                    ["netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", f"interface={self._tun_idx}"],
                    ["netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", f"interface={self._tun_idx}"],
                ]
            if self._server_ip:
                cmds.append(["route", "delete", self._server_ip])
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=5, creationflags=_CREATE_NO_WINDOW)
        except Exception:
            pass

    @staticmethod
    def _kill_orphaned() -> None:
        if os.name != "nt":
            return
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", "tun2socks.exe"],
                capture_output=True, timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                time.sleep(1)
        except Exception:
            pass

    def _on_ready_read(self) -> None:
        chunk = self._process.readAllStandardOutput()
        raw = getattr(chunk, "data")()
        if isinstance(raw, (bytes, bytearray)):
            text = bytes(raw).decode("utf-8", errors="replace")
        else:
            text = str(raw)
        for line in text.splitlines():
            clean = line.rstrip()
            if clean:
                self.log_received.emit(clean)

    def _on_started(self) -> None:
        self._stop_requested = False
        self._running = True
        self.started.emit()
        self.state_changed.emit(True)

    def _on_error(self, process_error: QProcess.ProcessError) -> None:
        if self._stop_requested and process_error == QProcess.ProcessError.Crashed:
            return
        self.error.emit(f"tun2socks error: {process_error.name} ({self._process.errorString()})")

    def _on_finished(self, exit_code: int, _exit_status: int = 0) -> None:
        self._stop_requested = False
        self._running = False
        self._cleanup_routes()
        self.stopped.emit(exit_code)
        self.state_changed.emit(False)
