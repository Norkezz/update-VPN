"""
core_unpacker.py — Распаковка _cr.dat (core/) при запуске из exe.

Формат _cr.dat: ZIP(содержимое core/) → XOR(_CORE_XOR_KEY) → _cr.dat
Аналогично _zr.dat для zapret.

Используется в constants.py для определения реального пути к core/:
    from .core_unpacker import get_core_dir
    XRAY_PATH_DEFAULT = get_core_dir() / "xray.exe"
"""
from __future__ import annotations

import io
import logging
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

log = logging.getLogger(__name__)

# ── Core XOR-ключ (должен совпадать с build.py:_CORE_XOR_KEY) ─────────────────
_CORE_XOR_KEY = bytes([
    0x3D, 0xF1, 0x82, 0xA4, 0xC7, 0x56, 0x0E, 0x9B,
    0x74, 0xE8, 0x2A, 0xD3, 0x5F, 0x1C, 0x47, 0xB0,
    0x93, 0x6B, 0xD5, 0x28, 0xE4, 0x71, 0x0A, 0xCF,
    0x38, 0x52, 0x9E, 0x1D, 0xA7, 0x64, 0xFB, 0x8C,
])
_CORE_DAT_NAME = "_cr.dat"

# ── Глобальный tmp-dir для распакованного core (очищается при выходе) ──────────
_core_tmp_dir: str | None = None


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def _unpack_core_dat() -> Path | None:
    """Распаковывает _cr.dat во временную директорию при запуске из exe.
    Возвращает Path к распакованной папке, либо None при ошибке.
    Повторные вызовы возвращают уже распакованный путь (singleton)."""
    global _core_tmp_dir
    if _core_tmp_dir is not None:
        p = Path(_core_tmp_dir)
        if p.exists():
            return p

    base_dir = _get_base_dir()
    dat_path = base_dir / _CORE_DAT_NAME
    if not dat_path.exists():
        log.error("[core] _cr.dat не найден: %s", dat_path)
        return None

    try:
        encrypted = dat_path.read_bytes()
        raw_zip = _xor_bytes(encrypted, _CORE_XOR_KEY)
        tmp = tempfile.mkdtemp(prefix="aegis_cr_")
        with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
            zf.extractall(tmp)
        _core_tmp_dir = tmp
        log.info("[core] Распакован в %s", tmp)

        # Регистрируем в TempGuard — мониторинг + гарантированная очистка
        try:
            from .temp_guard import TempGuard
            TempGuard.instance().register(Path(tmp))
        except Exception as _tg_err:
            log.warning("[core] TempGuard недоступен: %s", _tg_err)

        # Watchdog: если он ещё не запущен (список был пуст при старте main.py),
        # запускаем сейчас когда core-папка зарегистрирована.
        # Если watchdog уже живёт — новая папка будет удалена через MoveFileExW(reboot).
        if getattr(sys, "frozen", False):
            try:
                from .watchdog import launch_watchdog
                from .temp_guard import TempGuard as _TG
                launch_watchdog(list(_TG.instance()._dirs))
            except Exception as _wd_err:
                log.debug("[core] watchdog deferred launch failed: %s", _wd_err)

        return Path(tmp)
    except Exception as e:
        log.error("[core] Ошибка распаковки _cr.dat: %s", e)
        return None



def get_core_dir() -> Path:
    """Возвращает путь к core/.
    В exe — распаковывает из _cr.dat во временную директорию.
    В dev-режиме — возвращает BASE_DIR/core напрямую."""
    if getattr(sys, "frozen", False):
        unpacked = _unpack_core_dat()
        if unpacked:
            return unpacked
        # fallback: если _cr.dat не найден — папка core/ рядом с exe
        return _get_base_dir() / "core"
    return _get_base_dir() / "core"
