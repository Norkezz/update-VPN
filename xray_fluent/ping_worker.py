from __future__ import annotations

import socket
import time

from PyQt6.QtCore import QThread, pyqtSignal

from .models import Node


def tcp_ping(host: str, port: int, timeout: float = 2.0) -> int | None:
    if not host or not port:
        return None
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000.0
            return int(elapsed)
    except OSError:
        return None


class PingWorker(QThread):
    result = pyqtSignal(str, object)
    progress = pyqtSignal(int, int)  # current, total
    completed = pyqtSignal()

    def __init__(self, nodes: list[Node], timeout: float = 2.0):
        super().__init__()
        self._nodes = nodes
        self._timeout = timeout
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        total = len(self._nodes)
        for i, node in enumerate(self._nodes):
            if self._cancelled:
                break
            self.progress.emit(i + 1, total)
            ms = tcp_ping(node.server, node.port, timeout=self._timeout)
            self.result.emit(node.id, ms)
        self.completed.emit()
