"""
watchdog.py — Дочерний процесс-сторож для гарантированной очистки temp-папок
при hard kill (TerminateProcess, диспетчер задач, SIGKILL).

Схема работы:
  1. Основной процесс (AegisNET.exe) при старте вызывает launch_watchdog().
  2. Watchdog запускается как дочерний процесс с флагом --_aegis_watchdog
     через тот же AegisNET.exe (frozen) или python.exe (dev).
  3. Watchdog открывает OpenProcess(SYNCHRONIZE) на родителя и вызывает
     WaitForSingleObject(INFINITE) — блокирует до смерти родителя.
  4. Как только родитель умирает (по любой причине) — watchdog удаляет
     все зарегистрированные temp-папки и завершается.
  5. Watchdog НЕ зависит от Qt, atexit, excepthook — чистый ctypes + stdlib.

Флаг запуска: --_aegis_watchdog <parent_pid> <path1> [<path2> ...]
  Это внутренний флаг; пользователь его не видит.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

# ── Single-launch guard ───────────────────────────────────────────────────────
# Ensures only ONE watchdog process is ever spawned per AegisNET instance,
# even if launch_watchdog() is called from both main.py and core_unpacker.py.
_watchdog_launched: bool = False
# ─────────────────────────────────────────────────────────────────────────────

# ── Флаг subprocess ───────────────────────────────────────────────────────────
_WATCHDOG_FLAG = "--_aegis_watchdog"

# ── Windows API ───────────────────────────────────────────────────────────────
_SYNCHRONIZE           = 0x00100000
_PROCESS_SYNCHRONIZE   = 0x00100000
_WAIT_OBJECT_0         = 0x00000000
_INFINITE              = 0xFFFFFFFF
_CREATE_NO_WINDOW      = 0x08000000


def _watchdog_main() -> None:
    """
    Точка входа дочернего процесса-сторожа.
    Вызывается когда sys.argv содержит --_aegis_watchdog.

    Синтаксис argv:
        ... --_aegis_watchdog <ppid> <path1> [<path2> ...]
    """
    argv = sys.argv
    try:
        idx = argv.index(_WATCHDOG_FLAG)
    except ValueError:
        return

    args_after = argv[idx + 1:]
    if len(args_after) < 2:
        sys.exit(1)

    try:
        parent_pid = int(args_after[0])
    except ValueError:
        sys.exit(1)

    guard_paths = [Path(p) for p in args_after[1:]]

    # Открываем хэндл родителя с правом SYNCHRONIZE
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    h_parent = kernel32.OpenProcess(_PROCESS_SYNCHRONIZE, False, parent_pid)
    if not h_parent:
        # Родитель уже мёртв — сразу чистим
        _cleanup(guard_paths)
        sys.exit(0)

    # Блокируем до смерти родителя (по любой причине)
    kernel32.WaitForSingleObject(h_parent, _INFINITE)
    kernel32.CloseHandle(h_parent)

    # Родитель умер — удаляем temp-папки
    _cleanup(guard_paths)
    sys.exit(0)


def _cleanup(paths: list[Path]) -> None:
    """Удаляет все переданные папки."""
    for p in paths:
        if not p.exists():
            continue
        try:
            shutil.rmtree(p, ignore_errors=True)
        except Exception:
            pass


def launch_watchdog(guard_paths: list[Path]) -> None:
    """
    Запускает дочерний процесс-сторож.

    Вызывается из main.py после того как TempGuard зарегистрировал
    все temp-директории.

    guard_paths — список Path-объектов для защиты (core_tmp, _internal_tmp).
    """
    global _watchdog_launched

    if sys.platform != "win32":
        return
    if not guard_paths:
        return

    # Prevent double-launch: only one watchdog per AegisNET.exe process
    if _watchdog_launched:
        log.debug("[watchdog] Already launched — skipping duplicate launch_watchdog() call")
        return
    _watchdog_launched = True

    # Фильтруем только реально существующие папки
    existing = [p for p in guard_paths if p.exists()]
    if not existing:
        return

    ppid = str(os.getpid())
    path_args = [str(p) for p in existing]

    # В frozen-режиме запускаем тот же .exe со скрытым флагом.
    # В dev-режиме — python.exe с этим же модулем как __main__.
    if getattr(sys, "frozen", False):
        exe = sys.executable
        cmd = [exe, _WATCHDOG_FLAG, ppid] + path_args
    else:
        cmd = [sys.executable, "-m", "xray_fluent.watchdog",
               _WATCHDOG_FLAG, ppid] + path_args

    try:
        subprocess.Popen(
            cmd,
            # Дочерний процесс НЕ наследует наш консольный хэндл
            # и НЕ показывает окно консоли
            creationflags=_CREATE_NO_WINDOW,
            # Не ждём завершения — watchdog живёт параллельно
            close_fds=True,
            # Полностью отвязываем от нашего stdout/stderr
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info(
            "[watchdog] Запущен сторожевой процесс для %d путей: %s",
            len(existing), ", ".join(str(p) for p in existing),
        )
    except Exception as e:
        log.warning("[watchdog] Не удалось запустить watchdog: %s", e)


# ── Поддержка запуска как модуль (dev-режим) ─────────────────────────────────

if __name__ == "__main__":
    # Запуск: python -m xray_fluent.watchdog --_aegis_watchdog <ppid> <paths...>
    _watchdog_main()
