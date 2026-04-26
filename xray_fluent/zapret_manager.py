"""Minimal winws2 (zapret2) process manager — preset-based, no orchestrator."""

from __future__ import annotations

import atexit
import io
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal

from .constants import BASE_DIR

log = logging.getLogger(__name__)

# ── Zapret XOR-ключ (должен совпадать с build.py:_ZAPRET_XOR_KEY) ─────────────
_ZAPRET_XOR_KEY = bytes([
    0x4A, 0xE3, 0x17, 0xCB, 0x92, 0x5F, 0xD0, 0x38,
    0xA1, 0x7B, 0x2E, 0xF4, 0x66, 0x0D, 0xB9, 0x53,
    0x81, 0xC4, 0x3A, 0x7F, 0xE2, 0x19, 0x5C, 0xD6,
    0x0B, 0x44, 0xA8, 0x31, 0xF7, 0x6E, 0x29, 0x90,
])
_ZAPRET_DAT_NAME = "_zr.dat"

# ── Глобальный tmp-dir для распакованного zapret (очищается при выходе) ────────
_zapret_tmp_dir: str | None = None


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _unpack_zapret_dat() -> Path | None:
    """Распаковывает _zr.dat во временную директорию при запуске из exe.
    Возвращает Path к распакованной папке, либо None при ошибке.
    Повторные вызовы возвращают уже распакованный путь (singleton)."""
    global _zapret_tmp_dir
    if _zapret_tmp_dir is not None:
        p = Path(_zapret_tmp_dir)
        if p.exists():
            return p

    dat_path = BASE_DIR / _ZAPRET_DAT_NAME
    if not dat_path.exists():
        log.error("[zapret] _zr.dat не найден: %s", dat_path)
        return None

    try:
        encrypted = dat_path.read_bytes()
        raw_zip = _xor_bytes(encrypted, _ZAPRET_XOR_KEY)
        tmp = tempfile.mkdtemp(prefix="aegis_zr_")
        with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
            zf.extractall(tmp)
        _zapret_tmp_dir = tmp
        atexit.register(_cleanup_zapret_tmp)
        log.info("[zapret] Распакован в %s", tmp)
        return Path(tmp)
    except Exception as e:
        log.error("[zapret] Ошибка распаковки _zr.dat: %s", e)
        return None


def _cleanup_zapret_tmp() -> None:
    global _zapret_tmp_dir
    if _zapret_tmp_dir and Path(_zapret_tmp_dir).exists():
        try:
            shutil.rmtree(_zapret_tmp_dir, ignore_errors=True)
            log.info("[zapret] Временная директория удалена: %s", _zapret_tmp_dir)
        except Exception:
            pass
        _zapret_tmp_dir = None


def _get_zapret_dir() -> Path:
    """Возвращает путь к zapret. В exe — распаковывает из _zr.dat.
    В dev-режиме — возвращает BASE_DIR/zapret напрямую."""
    if getattr(sys, "frozen", False):
        unpacked = _unpack_zapret_dat()
        if unpacked:
            return unpacked
        # fallback: если распаковка не удалась — попробуем рядом с exe
        return BASE_DIR / "zapret"
    return BASE_DIR / "zapret"


# Ленивая инициализация путей — вычисляются при первом обращении
def _zapret_dir() -> Path:
    return _get_zapret_dir()

def _winws2_exe() -> Path:
    return _get_zapret_dir() / "exe" / "winws2.exe"

def _presets_dir() -> Path:
    return _get_zapret_dir() / "presets"


# Для обратной совместимости с кодом который импортирует ZAPRET_DIR напрямую
ZAPRET_DIR   = BASE_DIR / "zapret"   # dev-путь (используется только в dev)
WINWS2_EXE   = ZAPRET_DIR / "exe" / "winws2.exe"
PRESETS_DIR  = ZAPRET_DIR / "presets"

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


@dataclass
class PresetInfo:
    name: str
    description: str
    created: str
    modified: str
    arg_count: int
    file_path: Path


class ZapretManager(QObject):
    """Start / stop winws2.exe with a preset file."""

    started  = pyqtSignal()
    stopped  = pyqtSignal()
    error    = pyqtSignal(str)
    log_line = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._process: QProcess | None = None
        self._current_preset: str = ""
        self._start_args: list[str] = []
        self._health_timer = QTimer(self)
        self._health_timer.setInterval(3000)
        self._health_timer.timeout.connect(self._check_health)

    # ── public API ──────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.state() == QProcess.ProcessState.Running

    @staticmethod
    def list_presets() -> list[str]:
        """Return sorted list of available preset names (without .txt)."""
        if not _presets_dir().is_dir():
            return []
        return sorted(
            p.stem for p in _presets_dir().iterdir()
            if p.suffix == ".txt" and not p.name.startswith("_")
        )

    @staticmethod
    def preset_path(name: str) -> Path:
        return _presets_dir() / f"{name}.txt"

    @staticmethod
    def _parse_preset_args(preset: Path) -> list[str]:
        """Read preset file and return list of arguments (skip comments/blanks)."""
        args: list[str] = []
        text = preset.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                args.append(stripped)
        return args

    @staticmethod
    def _parse_metadata(text: str) -> dict[str, str]:
        """Extract metadata from comment headers."""
        meta: dict[str, str] = {}
        for line in text.splitlines()[:15]:
            stripped = line.strip()
            if not stripped.startswith("#"):
                if stripped:
                    break
                continue
            for key in ("Preset", "Description", "Created", "Modified", "BuiltinVersion"):
                prefix = f"# {key}:"
                if stripped.startswith(prefix):
                    meta[key] = stripped[len(prefix):].strip()
                    break
        return meta

    @staticmethod
    def list_preset_infos() -> list[PresetInfo]:
        """Return list of PresetInfo for all presets, sorted by name."""
        if not _presets_dir().is_dir():
            return []
        result = []
        for p in sorted(_presets_dir().iterdir()):
            if p.suffix != ".txt" or p.name.startswith("_"):
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            meta = ZapretManager._parse_metadata(text)
            arg_count = sum(1 for line in text.splitlines()
                           if line.strip() and not line.strip().startswith("#"))
            result.append(PresetInfo(
                name=p.stem,
                description=meta.get("Description", ""),
                created=meta.get("Created", ""),
                modified=meta.get("Modified", ""),
                arg_count=arg_count,
                file_path=p,
            ))
        return result

    @staticmethod
    def read_preset(name: str) -> str:
        """Return full text content of a preset file."""
        path = _presets_dir() / f"{name}.txt"
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def save_preset(name: str, content: str, description: str = "") -> PresetInfo:
        """Write preset file with updated metadata headers."""
        path = _presets_dir() / f"{name}.txt"
        _presets_dir().mkdir(parents=True, exist_ok=True)

        created = ""
        if path.is_file():
            old_text = path.read_text(encoding="utf-8", errors="replace")
            old_meta = ZapretManager._parse_metadata(old_text)
            created = old_meta.get("Created", "")

        now = datetime.now().isoformat(timespec="seconds")
        if not created:
            created = now

        lines = content.splitlines()
        body_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("# Preset:") or stripped.startswith("# Description:") \
               or stripped.startswith("# Created:") or stripped.startswith("# Modified:"):
                continue
            body_lines.append(line)

        while body_lines and not body_lines[0].strip():
            body_lines.pop(0)

        header = f"# Preset: {name}\n# Description: {description}\n# Created: {created}\n# Modified: {now}\n\n"
        full_text = header + "\n".join(body_lines) + "\n"
        path.write_text(full_text, encoding="utf-8")

        arg_count = sum(1 for l in body_lines if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=name, description=description, created=created,
                         modified=now, arg_count=arg_count, file_path=path)

    @staticmethod
    def rename_preset(old_name: str, new_name: str) -> PresetInfo | None:
        """Rename preset file. Returns new PresetInfo or None on failure."""
        old_path = _presets_dir() / f"{old_name}.txt"
        new_path = _presets_dir() / f"{new_name}.txt"
        if not old_path.is_file() or new_path.exists():
            return None

        text = old_path.read_text(encoding="utf-8", errors="replace")
        text = text.replace(f"# Preset: {old_name}", f"# Preset: {new_name}", 1)
        new_path.write_text(text, encoding="utf-8")
        old_path.unlink()

        meta = ZapretManager._parse_metadata(text)
        arg_count = sum(1 for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=new_name, description=meta.get("Description", ""),
                         created=meta.get("Created", ""), modified=meta.get("Modified", ""),
                         arg_count=arg_count, file_path=new_path)

    @staticmethod
    def delete_preset(name: str) -> bool:
        """Delete preset file. Returns True if deleted."""
        path = _presets_dir() / f"{name}.txt"
        if path.is_file():
            path.unlink()
            return True
        return False

    @staticmethod
    def import_preset(source_path: Path) -> PresetInfo | None:
        """Import a preset file from external path. Handles name conflicts."""
        if not source_path.is_file():
            return None
        _presets_dir().mkdir(parents=True, exist_ok=True)

        base_name = source_path.stem
        target = _presets_dir() / f"{base_name}.txt"
        counter = 1
        while target.exists():
            target = _presets_dir() / f"{base_name} ({counter}).txt"
            counter += 1

        shutil.copy2(source_path, target)

        text = target.read_text(encoding="utf-8", errors="replace")
        meta = ZapretManager._parse_metadata(text)
        arg_count = sum(1 for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=target.stem, description=meta.get("Description", ""),
                         created=meta.get("Created", ""), modified=meta.get("Modified", ""),
                         arg_count=arg_count, file_path=target)

    # ── запуск / остановка ──────────────────────────────────────

    def start(self, preset_name: str) -> None:
        if self.running:
            self.stop()

        killed = self._kill_orphaned()
        for name in killed:
            self.log_line.emit(f"[zapret] Завершён сторонний процесс: {name}")

        exe = _winws2_exe()
        if not exe.exists():
            self.error.emit(f"winws2.exe не найден: {exe}")
            return

        preset = self.preset_path(preset_name)
        if not preset.exists():
            self.error.emit(f"Пресет не найден: {preset}")
            return

        args = self._parse_preset_args(preset)
        if not args:
            self.error.emit(f"Пресет пустой: {preset_name}")
            return

        # ── Проверка файлов ipset/lua, указанных в аргументах (задача 2) ──
        missing = self._check_required_files(args)
        if missing:
            for m in missing:
                self.log_line.emit(f"[zapret] ⚠️  Файл не найден: {m}")
            first = missing[0]
            hint = self._missing_file_hint(first)
            msg = f"Файл не найден: {first}"
            if hint:
                msg += f"\n{hint}"
            self.error.emit(msg)
            return

        self._current_preset = preset_name
        self._start_args = args

        self._process = QProcess(self)
        self._process.setProgram(str(exe))
        self._process.setArguments(args)
        self._process.setWorkingDirectory(str(_zapret_dir()))
        self._process.readyReadStandardOutput.connect(self._on_stdout)
        self._process.readyReadStandardError.connect(self._on_stderr)
        self._process.finished.connect(self._on_finished)

        log.info("zapret start: %s [%s] (%d args)", exe.name, preset_name, len(args))
        self.log_line.emit(f"[zapret] Запуск: {preset_name} ({len(args)} аргументов)")
        self._process.start()

        if not self._process.waitForStarted(5000):
            self.error.emit("Не удалось запустить winws2.exe")
            self._process = None
            return

        self._health_timer.start()
        self.started.emit()

    def stop(self) -> None:
        self._health_timer.stop()
        if self._process is None:
            return

        if self._process.state() == QProcess.ProcessState.Running:
            log.info("zapret stop")
            self._process.kill()
            self._process.waitForFinished(5000)

        self._process = None
        self.stopped.emit()

    # ── Проверка файлов, упомянутых в аргументах ───────────────

    @staticmethod
    def _check_required_files(args: list[str]) -> list[str]:
        """
        Парсим аргументы winws2 и ищем пути к файлам (ipset, lua, листы).
        Возвращаем список относительных путей (относительно _zapret_dir()),
        которые физически отсутствуют.

        Поддерживаемые форматы аргументов:
          --ipset=lists/ipset-base.txt
          --ipset-include=lists/ipset-base.txt
          --lua-init=@lua/zapret-lib.lua
          --lua-init=lua/zapret-lib.lua
          --hostlist=lists/hostlist.txt
          --hostlist-exclude=lists/exclude.txt
        """
        file_patterns = [
            # --key=value или --key=@value
            re.compile(
                r"--(?:ipset|ipset-include|ipset-exclude|hostlist|hostlist-exclude"
                r"|lua-init|lua-script|blocklist|allowlist)"
                r"=@?(.+)",
                re.IGNORECASE,
            ),
        ]

        missing: list[str] = []
        seen: set[str] = set()

        for arg in args:
            for pat in file_patterns:
                m = pat.match(arg.strip())
                if not m:
                    continue
                rel = m.group(1).strip()
                if rel in seen:
                    continue
                seen.add(rel)

                # Путь может быть абсолютным или относительным к _zapret_dir()
                p = Path(rel)
                if p.is_absolute():
                    if not p.exists():
                        missing.append(rel)
                else:
                    if not (_zapret_dir() / p).exists():
                        missing.append(rel)

        return missing

    @staticmethod
    def _missing_file_hint(rel_path: str) -> str:
        """Человекочитаемая подсказка для отсутствующего файла."""
        name = Path(rel_path).name.lower()
        if "ipset" in name or "hostlist" in name or "blocklist" in name or "allowlist" in name:
            return (
                "Скачайте актуальные списки: https://github.com/zapret-info/z-i\n"
                f"и поместите файл в папку zapret/{Path(rel_path).parent}"
            )
        if name.endswith(".lua"):
            return (
                f"Lua-скрипт отсутствует в папке zapret/{Path(rel_path).parent}\n"
                "Переустановите zapret или скопируйте скрипты вручную."
            )
        return f"Поместите файл в папку zapret/{Path(rel_path).parent}"

    # ── internals ───────────────────────────────────────────────

    @staticmethod
    def _kill_orphaned() -> list[str]:
        """Kill any orphaned winws.exe / winws2.exe processes."""
        killed: list[str] = []
        if os.name != "nt":
            return killed
        for exe_name in ("winws2.exe", "winws.exe"):
            try:
                result = subprocess.run(
                    ["taskkill", "/F", "/IM", exe_name],
                    capture_output=True, timeout=5,
                    creationflags=_CREATE_NO_WINDOW,
                )
                if result.returncode == 0:
                    killed.append(exe_name)
            except Exception:
                pass
        if killed:
            time.sleep(1)
        return killed

    @staticmethod
    def _exit_code_hint(code: int) -> str:
        hints = {
            1: "общая ошибка (другой экземпляр / не удалось открыть WinDivert)",
            2: "ошибка аргументов командной строки",
            3: "не удалось загрузить WinDivert драйвер (нужны права администратора)",
        }
        return hints.get(code, "")

    def _drain_output(self) -> list[str]:
        lines: list[str] = []
        if self._process is None:
            return lines
        for reader in (self._process.readAllStandardOutput,
                       self._process.readAllStandardError):
            data = reader().data()
            if data:
                for line in data.decode("utf-8", errors="replace").splitlines():
                    stripped = line.strip()
                    if stripped:
                        lines.append(stripped)
        return lines

    def _on_stdout(self) -> None:
        if self._process is None:
            return
        data = self._process.readAllStandardOutput().data()
        for line in data.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                self.log_line.emit(f"[zapret] {line.strip()}")

    def _on_stderr(self) -> None:
        if self._process is None:
            return
        data = self._process.readAllStandardError().data()
        for line in data.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                self.log_line.emit(f"[zapret] {line.strip()}")

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self._health_timer.stop()

        remaining = self._drain_output()
        for line in remaining:
            self.log_line.emit(f"[zapret] {line}")

        preset = self._current_preset or "?"
        log.info("zapret finished: code=%d status=%s preset=%s", exit_code, exit_status.name, preset)

        if exit_code != 0 or exit_status == QProcess.ExitStatus.CrashExit:
            hint = self._exit_code_hint(exit_code)
            if hint:
                self.log_line.emit(f"[zapret] Код {exit_code}: {hint}")
            self.log_line.emit(f"[zapret] Пресет: {preset}")
            if self._start_args:
                preview = " ".join(self._start_args[:6])
                if len(self._start_args) > 6:
                    preview += f" ... (+{len(self._start_args) - 6} аргументов)"
                self.log_line.emit(f"[zapret] Команда: winws2.exe {preview}")
            if not remaining:
                self.log_line.emit("[zapret] Процесс не вывел ничего в stdout/stderr")

            short = f"winws2 завершился с кодом {exit_code}"
            if hint:
                short += f" — {hint}"
            self.error.emit(short)

        self._process = None
        self._current_preset = ""
        self._start_args = []
        self.stopped.emit()

    def _check_health(self) -> None:
        if not self.running:
            self._health_timer.stop()
            self.stopped.emit()
