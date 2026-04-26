"""
temp_guard.py — Охрана временных директорий с распакованными бинарниками.

Задачи:
  1. Регистрация temp-папок (core, _internal) для защиты.
  2. Мониторинг файловых операций через ReadDirectoryChangesW —
     если файл открывает сторонний процесс, приложение немедленно завершается.
  3. При штатном выходе — синхронная очистка через shutil.rmtree.
  4. При вылете (crash, kill) — отложенное удаление через
     MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT) как страховка.
  5. Интеграция с sys.excepthook и atexit.

Использование:
    from xray_fluent.temp_guard import TempGuard
    guard = TempGuard.instance()
    guard.register(path)          # зарегистрировать папку
    guard.start_monitoring()      # запустить мониторинг (после register)
    guard.install_hooks()         # подключить к atexit + excepthook
    guard.cleanup()               # явная очистка (вызывается при shutdown)
"""
from __future__ import annotations

import atexit
import ctypes
import ctypes.wintypes
import logging
import os
import shutil
import sys
import threading
from pathlib import Path

log = logging.getLogger(__name__)

# ── Windows API ───────────────────────────────────────────────────────────────

if sys.platform == "win32":
    _kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    _ntdll    = ctypes.windll.ntdll     # type: ignore[attr-defined]
else:
    _kernel32 = None  # type: ignore[assignment]
    _ntdll    = None  # type: ignore[assignment]

# CreateFile flags
_GENERIC_READ               = 0x80000000
_FILE_SHARE_READ            = 0x00000001
_FILE_SHARE_WRITE           = 0x00000002
_FILE_SHARE_DELETE          = 0x00000004
_OPEN_EXISTING              = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

# ReadDirectoryChangesW flags
_FILE_NOTIFY_CHANGE_FILE_NAME  = 0x00000001
_FILE_NOTIFY_CHANGE_DIR_NAME   = 0x00000002
_FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010

_NOTIFY_FILTER = (
    _FILE_NOTIFY_CHANGE_FILE_NAME
    | _FILE_NOTIFY_CHANGE_DIR_NAME
    | _FILE_NOTIFY_CHANGE_LAST_WRITE
)

# FILE_NOTIFY_INFORMATION actions
_FILE_ACTION_ADDED            = 1
_FILE_ACTION_REMOVED          = 2
_FILE_ACTION_MODIFIED         = 3
_FILE_ACTION_RENAMED_OLD_NAME = 4
_FILE_ACTION_RENAMED_NEW_NAME = 5

# MoveFileEx
_MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004

# Process access
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value

# ── NtQueryInformationFile для получения открывающего PID ─────────────────────

class _IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status",      ctypes.c_ulong),
        ("Information", ctypes.POINTER(ctypes.c_ulong)),
    ]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _our_pids() -> frozenset[int]:
    """Возвращает PID текущего процесса."""
    return frozenset([os.getpid()])


def _pid_exe_name(pid: int) -> str:
    """Имя exe процесса по PID (best-effort)."""
    if not _kernel32:
        return ""
    try:
        h = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(512)
            size = ctypes.wintypes.DWORD(512)
            if _kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return os.path.basename(buf.value)
        finally:
            _kernel32.CloseHandle(h)
    except Exception:
        pass
    return ""


def _open_dir_handle(path: str):
    """Открыть хэндл директории для ReadDirectoryChangesW."""
    h = _kernel32.CreateFileW(
        path,
        _GENERIC_READ,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    return h


def _schedule_reboot_delete(path: str) -> None:
    """Зарегистрировать папку/файл для удаления при следующей перезагрузке."""
    if not _kernel32:
        return
    try:
        _kernel32.MoveFileExW(path, None, _MOVEFILE_DELAY_UNTIL_REBOOT)
        log.info("[guard] Отложенное удаление при перезагрузке: %s", path)
    except Exception as e:
        log.warning("[guard] MoveFileExW failed for %s: %s", path, e)


def _schedule_reboot_delete_tree(root: Path) -> None:
    """Рекурсивно зарегистрировать все файлы и папки для удаления при ребуте.
    Регистрируем сначала файлы, потом папки от глубины к корню."""
    if not root.exists():
        return
    # Файлы
    for f in sorted(root.rglob("*")):
        if f.is_file():
            _schedule_reboot_delete(str(f))
    # Папки от глубины к корню
    for d in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if d.is_dir():
            _schedule_reboot_delete(str(d))
    # Сама папка
    _schedule_reboot_delete(str(root))


# ── Парсинг FILE_NOTIFY_INFORMATION ──────────────────────────────────────────

def _parse_notify_buffer(buf: bytes) -> list[tuple[int, str]]:
    """Разбирает буфер ReadDirectoryChangesW. Возвращает [(action, filename), ...]."""
    results = []
    offset = 0
    while offset < len(buf):
        if offset + 12 > len(buf):
            break
        next_offset = int.from_bytes(buf[offset:offset+4], "little")
        action      = int.from_bytes(buf[offset+4:offset+8], "little")
        name_len    = int.from_bytes(buf[offset+8:offset+12], "little")
        name_start  = offset + 12
        name_end    = name_start + name_len
        if name_end > len(buf):
            break
        filename = buf[name_start:name_end].decode("utf-16-le", errors="replace")
        results.append((action, filename))
        if next_offset == 0:
            break
        offset += next_offset
    return results


# ── TempGuard ─────────────────────────────────────────────────────────────────

class TempGuard:
    """Singleton-охранник временных директорий."""

    _instance: "TempGuard | None" = None
    _lock = threading.Lock()

    @classmethod
    def instance(cls) -> "TempGuard":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._dirs: list[Path] = []
        self._monitor_threads: list[threading.Thread] = []
        self._stop_events: list[threading.Event] = []
        self._dir_handles: list[int] = []
        self._hooks_installed = False
        self._cleaned = False

    # ── Регистрация ───────────────────────────────────────────────────────────

    def register(self, path: Path | str) -> None:
        """Зарегистрировать временную директорию для защиты и очистки."""
        p = Path(path).resolve()
        if p not in self._dirs:
            self._dirs.append(p)
            log.info("[guard] Зарегистрирована защищённая директория: %s", p)
            # Немедленно ставим страховку на случай hard kill
            if sys.platform == "win32":
                _schedule_reboot_delete_tree(p)

    # ── Мониторинг ────────────────────────────────────────────────────────────

    def start_monitoring(self) -> None:
        """Запустить поток мониторинга для каждой зарегистрированной директории."""
        if sys.platform != "win32":
            return
        for path in self._dirs:
            if not path.exists():
                continue
            stop_event = threading.Event()
            self._stop_events.append(stop_event)
            t = threading.Thread(
                target=self._monitor_dir,
                args=(path, stop_event),
                daemon=True,
                name=f"TempGuard-{path.name}",
            )
            self._monitor_threads.append(t)
            t.start()
            log.info("[guard] Мониторинг запущен: %s", path)

    def _monitor_dir(self, path: Path, stop_event: threading.Event) -> None:
        """Поток мониторинга одной директории через ReadDirectoryChangesW."""
        h = _open_dir_handle(str(path))
        if h == INVALID_HANDLE_VALUE or h == 0:
            log.warning("[guard] Не удалось открыть хэндл для %s", path)
            return

        self._dir_handles.append(h)
        buf_size = 65536
        buf = ctypes.create_string_buffer(buf_size)
        bytes_returned = ctypes.wintypes.DWORD(0)
        our_pids = _our_pids()

        try:
            while not stop_event.is_set():
                ok = _kernel32.ReadDirectoryChangesW(
                    h,
                    buf,
                    buf_size,
                    True,   # watchSubtree
                    _NOTIFY_FILTER,
                    ctypes.byref(bytes_returned),
                    None,
                    None,
                )
                if not ok:
                    # Хэндл закрыт (при shutdown) — выходим нормально
                    break
                if stop_event.is_set():
                    break

                n = bytes_returned.value
                if n == 0:
                    continue

                events = _parse_notify_buffer(buf.raw[:n])
                for action, filename in events:
                    # Нас интересуют любые обращения к файлам
                    if action in (
                        _FILE_ACTION_ADDED,
                        _FILE_ACTION_MODIFIED,
                        _FILE_ACTION_RENAMED_NEW_NAME,
                    ):
                        self._on_file_event(path, filename, our_pids)
        except Exception as e:
            log.error("[guard] Ошибка мониторинга %s: %s", path, e)
        finally:
            try:
                _kernel32.CloseHandle(h)
            except Exception:
                pass

    def _on_file_event(self, guarded_dir: Path, filename: str, our_pids: frozenset[int]) -> None:
        """Вызывается при файловом событии в охраняемой директории.

        Проверяет — кто открыл файл. Если не наш процесс — завершаем приложение.
        """
        full_path = guarded_dir / filename

        # Пытаемся определить, кто открыл файл, через попытку открыть его
        # с флагом FILE_SHARE_NONE — если не можем, значит файл занят чужим процессом.
        # Дополнительно проверяем через NtQuerySystemInformation (handle enumeration).
        foreign_pid = self._find_foreign_opener(full_path, our_pids)
        if foreign_pid is None:
            # Файл открыт только нашим процессом или никем — всё нормально
            return

        exe = _pid_exe_name(foreign_pid)
        log.critical(
            "[guard] НАРУШЕНИЕ: файл %s открыт сторонним процессом PID=%d (%s). "
            "Экстренное завершение.",
            full_path, foreign_pid, exe,
        )
        # Немедленная очистка и завершение
        self._emergency_shutdown()

    def _find_foreign_opener(self, path: Path, our_pids: frozenset[int]) -> int | None:
        """Попытка обнаружить чужой процесс, открывший файл.

        Метод 1: пробуем открыть файл без FILE_SHARE_READ.
        Если файл недоступен — значит кто-то держит его открытым.
        Затем проверяем через GetProcessId всех потенциальных нарушителей.

        Возвращает PID нарушителя или None если всё чисто.
        """
        if not path.exists():
            return None

        # Пробуем открыть файл эксклюзивно (без шаринга)
        # Если не можем — файл занят чужим (или нашим) процессом
        h = _kernel32.CreateFileW(
            str(path),
            _GENERIC_READ,
            0,  # никакого FILE_SHARE — эксклюзивный доступ
            None,
            _OPEN_EXISTING,
            0,
            None,
        )

        if h != INVALID_HANDLE_VALUE and h != 0:
            # Смогли открыть эксклюзивно — файл никем не занят, всё чисто
            _kernel32.CloseHandle(h)
            return None

        # Файл занят. Проверяем — не мы ли сами его держим.
        # Используем NtQuerySystemInformation для перечисления хэндлов.
        foreign = self._enumerate_foreign_handles(path, our_pids)
        return foreign

    def _enumerate_foreign_handles(self, path: Path, our_pids: frozenset[int]) -> int | None:
        """Перечисляет системные хэндлы через NtQuerySystemInformation
        чтобы найти чужой процесс, удерживающий файл открытым.

        Возвращает первый найденный чужой PID или None.
        """
        # SystemHandleInformation = 16
        _SystemHandleInformation = 16

        class _SYSTEM_HANDLE_ENTRY(ctypes.Structure):
            _fields_ = [
                ("OwnerPid",      ctypes.c_ulong),
                ("ObjectType",    ctypes.c_ubyte),
                ("HandleFlags",   ctypes.c_ubyte),
                ("HandleValue",   ctypes.c_ushort),
                ("ObjectPointer", ctypes.c_void_p),
                ("AccessMask",    ctypes.c_ulong),
            ]

        class _SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Count",   ctypes.c_ulong),
                ("Handles", _SYSTEM_HANDLE_ENTRY * 1),
            ]

        # Получаем нужный размер буфера
        size = ctypes.c_ulong(0x10000)
        while True:
            buf = ctypes.create_string_buffer(size.value)
            status = _ntdll.NtQuerySystemInformation(
                _SystemHandleInformation,
                buf,
                size,
                ctypes.byref(size),
            )
            # STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
            if status == ctypes.c_long(0xC0000004).value:
                size.value *= 2
                continue
            if status != 0:
                return None
            break

        info = ctypes.cast(buf, ctypes.POINTER(_SYSTEM_HANDLE_INFORMATION)).contents
        count = info.Count
        entries = ctypes.cast(
            ctypes.byref(info.Handles),
            ctypes.POINTER(_SYSTEM_HANDLE_ENTRY * count),
        ).contents

        # Получаем имя нашего файла для сравнения
        target_name = str(path).lower()

        for i in range(count):
            entry = entries[i]
            pid = entry.OwnerPid
            if pid in our_pids:
                continue
            if pid == 0 or pid == 4:  # System/Idle
                continue

            # Дублируем хэндл в наш процесс чтобы получить имя объекта
            h_proc = _kernel32.OpenProcess(
                _PROCESS_QUERY_LIMITED_INFORMATION | 0x0040,  # PROCESS_DUP_HANDLE
                False,
                pid,
            )
            if not h_proc:
                continue

            try:
                h_dup = ctypes.wintypes.HANDLE(0)
                dup_ok = _kernel32.DuplicateHandle(
                    h_proc,
                    ctypes.wintypes.HANDLE(entry.HandleValue),
                    _kernel32.GetCurrentProcess(),
                    ctypes.byref(h_dup),
                    0,
                    False,
                    0x00000002,  # DUPLICATE_SAME_ACCESS
                )
                if not dup_ok or not h_dup.value:
                    continue

                try:
                    # Получаем имя файла из хэндла
                    name = self._get_handle_name(h_dup.value)
                    if name and target_name in name.lower():
                        return pid
                finally:
                    _kernel32.CloseHandle(h_dup)
            except Exception:
                pass
            finally:
                _kernel32.CloseHandle(h_proc)

        return None

    def _get_handle_name(self, handle: int) -> str | None:
        """Получить путь файла из хэндла через GetFinalPathNameByHandleW."""
        buf = ctypes.create_unicode_buffer(512)
        # VOLUME_NAME_DOS = 0
        n = _kernel32.GetFinalPathNameByHandleW(handle, buf, 512, 0)
        if n > 0:
            name = buf.value
            # Убираем префикс \\?\
            if name.startswith("\\\\?\\"):
                name = name[4:]
            return name
        return None

    # ── Аварийное завершение ──────────────────────────────────────────────────

    def _emergency_shutdown(self) -> None:
        """Немедленно очищает temp-директории и завершает процесс."""
        log.critical("[guard] Аварийное завершение — очищаем temp-директории")
        self._stop_monitoring()
        self._do_cleanup(emergency=True)
        # Завершаем процесс немедленно, минуя Qt event loop
        os._exit(1)

    # ── Штатная очистка ───────────────────────────────────────────────────────

    def cleanup(self) -> None:
        """Штатная очистка при завершении приложения."""
        if self._cleaned:
            return
        self._cleaned = True
        log.info("[guard] Штатная очистка temp-директорий")
        self._stop_monitoring()
        self._do_cleanup(emergency=False)

    def _stop_monitoring(self) -> None:
        """Останавливаем потоки мониторинга."""
        for ev in self._stop_events:
            ev.set()
        # Закрываем хэндлы директорий — это разблокирует ReadDirectoryChangesW
        for h in self._dir_handles:
            try:
                _kernel32.CloseHandle(h)
            except Exception:
                pass
        self._dir_handles.clear()
        for t in self._monitor_threads:
            t.join(timeout=2.0)
        self._monitor_threads.clear()

    def _do_cleanup(self, emergency: bool) -> None:
        """Удаляем все зарегистрированные директории.
        Перед удалением убиваем все xray/sing-box процессы, которые могут
        держать файлы из temp-директорий открытыми — иначе rmtree зависает.
        """
        # Убиваем дочерние xray/sing-box процессы перед удалением
        self._kill_core_processes()

        for p in self._dirs:
            if not p.exists():
                continue
            # Несколько попыток с паузой — на случай если процессы ещё не упали
            for attempt in range(4):
                try:
                    shutil.rmtree(p, ignore_errors=False)
                    log.info("[guard] Удалена директория: %s", p)
                    break
                except Exception as e:
                    if attempt < 3:
                        import time as _t
                        _t.sleep(0.3)
                        # Повторная попытка убить процессы
                        if attempt == 1:
                            self._kill_core_processes()
                    else:
                        # Последняя попытка с ignore_errors
                        try:
                            shutil.rmtree(p, ignore_errors=True)
                        except Exception:
                            pass
                        log.warning(
                            "[guard] Не удалось полностью удалить %s: %s — страховка ребута активна",
                            p, e,
                        )
        if not emergency:
            self._dirs.clear()

    @staticmethod
    def _kill_core_processes() -> None:
        """Принудительно завершает xray.exe и sing-box.exe которые могут держать
        файлы в temp-директориях открытыми, вызывая зависание при cleanup.
        """
        if sys.platform != "win32":
            return
        targets = ("xray.exe", "sing-box.exe", "tun2socks.exe")
        try:
            import subprocess as _sp
            _flags = 0x08000000  # CREATE_NO_WINDOW
            for proc_name in targets:
                try:
                    _sp.run(
                        ["taskkill", "/F", "/IM", proc_name],
                        capture_output=True,
                        timeout=3,
                        creationflags=_flags,
                    )
                except Exception:
                    pass
        except Exception as e:
            log.debug("[guard] _kill_core_processes: %s", e)

    # ── Интеграция с приложением ──────────────────────────────────────────────

    def install_hooks(self) -> None:
        """Подключает очистку к atexit и sys.excepthook."""
        if self._hooks_installed:
            return
        self._hooks_installed = True

        # atexit — штатный выход и большинство вылетов через Python
        atexit.register(self.cleanup)

        # Оборачиваем sys.excepthook — необработанные исключения главного потока
        _prev_excepthook = sys.excepthook

        def _guarded_excepthook(exc_type, exc_value, exc_tb):
            try:
                self.cleanup()
            except Exception:
                pass
            _prev_excepthook(exc_type, exc_value, exc_tb)

        sys.excepthook = _guarded_excepthook

        log.info("[guard] Хуки установлены (atexit + excepthook)")
