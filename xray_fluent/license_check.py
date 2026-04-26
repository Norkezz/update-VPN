"""xray_fluent/license_check.py — AegisNET License Check via Private GitHub Repo.

Архитектура:
  1. cfg_ptr.bin вшит в exe при сборке (build_obfuscated.py).
     Содержит: GitHub Token + Owner/Repo + filename + nonce — зашифровано
     многослойно (XOR + AES-256-CBC + unshuffle + base85 + мусорные байты).

  2. Клиент расшифровывает cfg_ptr.bin → получает параметры доступа к GitHub.

  3. Читает файл лицензий из приватного репо через GitHub Contents API (HTTPS).

  4. Каждая строка файла = один пользователь:
       compute_license_hash(login, password, device_id, nonce)
     Цепочка: MD5 → SHA256 → CRC32 → AES-ECB → SHA256 → MD5

  5. Клиент вычисляет тот же хэш → ищет строку → пускает/отклоняет.

Nonce и параметры GitHub задаются при сборке через build_obfuscated.py.
cfg_ptr.bin хранится в data/ рядом с exe с обфусцированным именем.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import struct
import sys
import urllib.request
import urllib.error
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("xray_fluent.license")


# ── Paths ──────────────────────────────────────────────────────────────────────

def _data_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data"
    return Path(__file__).resolve().parents[1] / "data"

def _cfg_ptr_path() -> Path:
    # В exe-сборке cfg_ptr встроен в _MEIPASS/.ir/ (скрытая папка, не в data/).
    # В dev-режиме — ищем в data/ как обычно.
    cfg_name = "cfg\u200b_ptr\u200c.bin"
    if getattr(sys, "frozen", False):
        # sys._MEIPASS — временная директория PyInstaller с embedded ресурсами
        meipass = Path(getattr(sys, "_MEIPASS", ""))
        hidden = meipass / ".ir" / cfg_name
        if hidden.exists():
            return hidden
        # fallback для обратной совместимости
        return _data_dir() / cfg_name
    return _data_dir() / cfg_name


# ── Многослойное дешифрование cfg_ptr.bin ─────────────────────────────────────

_CFG_MAGIC   = b"\xAE\x61\x19\x5F"
_CFG_VERSION = 2


def _cfg_master_key() -> bytes:
    """Мастер-ключ, вшитый в несколько мест кода для усложнения RE."""
    a = b"AegisNET"
    b_ = b"\x4c\x69\x63\x65\x6e\x73\x65"   # "License"
    c  = b"\x76\x32\x2e\x30"                # "v2.0"
    d  = b"\xDE\xAD\xC0\xDE\x13\x37\xBE\xEF"
    return hashlib.sha256(a + b_ + c + d).digest()


def _xor_layer(data: bytes, key: bytes) -> bytes:
    kb = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(b ^ k for b, k in zip(data, kb))


def _unshuffle(data: bytes, seed: int) -> bytes:
    import random
    n = len(data)
    indices = list(range(n))
    random.Random(seed).shuffle(indices)
    result = bytearray(n)
    for new_idx, orig_idx in enumerate(indices):
        result[orig_idx] = data[new_idx]
    return bytes(result)


def _aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _decode_cfg_ptr(raw_bytes: bytes) -> dict:
    """Расшифровывает cfg_ptr.bin → dict(token, owner, repo, filename, nonce)."""
    if len(raw_bytes) < 20:
        raise ValueError("cfg_ptr too short")

    # 1. Убираем мусорные байты: первые 7, последние 5
    raw_bytes = raw_bytes[7:-5]

    # 2. base85 decode
    decoded = base64.b85decode(raw_bytes)

    # 3. Проверка magic + version
    if decoded[:4] != _CFG_MAGIC:
        raise ValueError("Bad cfg_ptr magic")
    if decoded[4] != _CFG_VERSION:
        raise ValueError(f"Unsupported cfg_ptr version: {decoded[4]}")
    payload = decoded[5:]

    # 4. IV — первые 16 байт payload
    iv      = payload[:16]
    payload = payload[16:]

    # 5. AES-256-CBC decrypt
    key       = _cfg_master_key()
    decrypted = _aes_cbc_decrypt(payload, key, iv)

    # 6. Unshuffle (seed = CRC32 первых 4 байт ключа)
    seed      = zlib.crc32(key[:4]) & 0xFFFFFFFF
    unshuffled = _unshuffle(decrypted, seed)

    # 7. XOR
    xor_key   = hashlib.md5(key).digest()
    plaintext = _xor_layer(unshuffled, xor_key)

    # 8. TLV: Type(1) + Len(2 LE) + Value
    fields: dict[int, bytes] = {}
    pos = 0
    while pos + 3 <= len(plaintext):
        t = plaintext[pos]
        l = struct.unpack_from("<H", plaintext, pos + 1)[0]
        pos += 3
        if pos + l > len(plaintext):
            break
        fields[t] = plaintext[pos:pos + l]
        pos += l

    def f(tag: int) -> str:
        return fields[tag].decode("utf-8") if tag in fields else ""

    return {
        "token":    f(0x01),
        "owner":    f(0x02),
        "repo":     f(0x03),
        "filename": f(0x04),
        "nonce":    f(0x05),
    }


_cfg_cache: Optional[dict] = None


def _load_cfg() -> Optional[dict]:
    global _cfg_cache
    if _cfg_cache is not None:
        return _cfg_cache

    # Переопределение через env (для dev/test)
    env_vars = {
        "token":    os.environ.get("AEGIS_GH_TOKEN", ""),
        "owner":    os.environ.get("AEGIS_GH_OWNER", ""),
        "repo":     os.environ.get("AEGIS_GH_REPO", ""),
        "filename": os.environ.get("AEGIS_GH_FILE", ""),
        "nonce":    os.environ.get("AEGIS_NONCE", ""),
    }
    if all(env_vars.values()):
        _cfg_cache = env_vars
        return _cfg_cache

    ptr = _cfg_ptr_path()
    if not ptr.exists():
        logger.error("[license] cfg_ptr.bin не найден: %s", ptr)
        return None
    try:
        _cfg_cache = _decode_cfg_ptr(ptr.read_bytes())
        return _cfg_cache
    except Exception as e:
        logger.error("[license] Расшифровка cfg_ptr: %s", e)
        return None


# ── Цепочка хэширования ───────────────────────────────────────────────────────

def _aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc    = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def compute_license_hash(login: str, password: str, device_id: str, nonce: str) -> str:
    """
    MD5 → SHA256 → CRC32(hex) → AES-ECB → SHA256 → MD5
    Возвращает hex-строку нижнего регистра — это и есть запись в файле лицензий.
    """
    combined = f"{login}\x00{password}\x00{device_id}\x00{nonce}".encode("utf-8")

    s1 = hashlib.md5(combined).hexdigest().encode()
    s2 = hashlib.sha256(s1).hexdigest().encode()
    s3 = format(zlib.crc32(s2) & 0xFFFFFFFF, "08x").encode()

    aes_key = hashlib.sha256(nonce.encode()).digest()
    s4 = _aes_ecb_encrypt(s3, aes_key)

    s5 = hashlib.sha256(s4).hexdigest().encode()
    s6 = hashlib.md5(s5).hexdigest()
    return s6


# ── Получение файла лицензий из GitHub ────────────────────────────────────────

def _fetch_license_lines(token: str, owner: str, repo: str, filename: str) -> Optional[list[str]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization":        f"token {token}",
            "Accept":               "application/vnd.github.v3.raw",
            "User-Agent":           "AegisNET/2.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    import ssl as _ssl

    # Попытка 1 — стандартный SSL-контекст (доверенные системные CA).
    # Попытка 2 — без проверки сертификата (fallback для сломанных ОС / корп. MITM).
    contexts = [
        _ssl.create_default_context(),
        _ssl._create_unverified_context(),  # noqa: SLF001
    ]

    for attempt, ctx in enumerate(contexts, start=1):
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read().decode("utf-8")
            return [ln.strip() for ln in raw.splitlines() if ln.strip()]
        except urllib.error.HTTPError as e:
            logger.warning("[license] GitHub HTTP %s %s", e.code, e.reason)
            return None  # HTTP-ошибка — повтор бессмысленен
        except OSError as e:
            logger.debug("[license] GitHub fetch (attempt %d): %s", attempt, e)
    logger.warning("[license] GitHub fetch: все попытки подключения исчерпаны")
    return None


_license_lines_cache: Optional[list[str]] = None
_license_lines_ts:    float = 0.0
_LICENSE_CACHE_TTL:   float = 300.0   # 5 минут


def _get_license_lines(cfg: dict) -> Optional[list[str]]:
    global _license_lines_cache, _license_lines_ts
    import time
    now = time.time()
    if _license_lines_cache is not None and (now - _license_lines_ts) < _LICENSE_CACHE_TTL:
        return _license_lines_cache
    lines = _fetch_license_lines(cfg["token"], cfg["owner"], cfg["repo"], cfg["filename"])
    if lines is not None:
        _license_lines_cache = lines
        _license_lines_ts    = now
    return lines


# ── LicenseResult + check_license ─────────────────────────────────────────────

@dataclass
class LicenseResult:
    ok:       bool
    message:  str
    username: str  = ""
    kill:     bool = False


def check_license(device_id: str, username: str, password: str, version: str = "") -> LicenseResult:
    """Основная точка входа — вызывается из LoginScreen."""
    cfg = _load_cfg()
    if cfg is None:
        return LicenseResult(
            ok=False,
            message="Ошибка конфигурации лицензионного сервера.\nОбратитесь к администратору.",
        )

    nonce = cfg.get("nonce", "")
    if not nonce:
        return LicenseResult(ok=False, message="Отсутствует nonce конфигурации.")

    expected = compute_license_hash(username, password, device_id, nonce)
    logger.debug("[license] hash=%s user=%s", expected, username)

    lines = _get_license_lines(cfg)
    if lines is None:
        return LicenseResult(
            ok=False,
            message="Не удалось подключиться к серверу лицензий.\nПроверьте интернет-соединение.",
        )

    if expected in lines:
        logger.info("[license] OK user='%s'", username)
        return LicenseResult(ok=True, message="OK", username=username)

    logger.warning("[license] DENIED user='%s'", username)
    return LicenseResult(
        ok=False,
        message="Лицензия не найдена.\nПроверьте логин, пароль и Device ID.",
        username=username,
    )


# Заглушки для совместимости с app_controller

def report_start(device_id: str, username: str, version: str = "") -> None:
    pass

def report_stop(device_id: str, username: str, tx_mb: float = 0, rx_mb: float = 0) -> None:
    pass

def poll_kill_command(device_id: str, username: str) -> bool:
    return False


POLL_INTERVAL_SEC = 300
