"""config_github_sync.py — Синхронизация VPN-конфигов с GitHub.

Логика (4 этапа, каскадный fallback):

  1. GitHub-конфиги    — читаем зашифрованный файл из приватного репо
                         (тот же cfg_ptr.bin → token+repo, но отдельный файл configs).
                         Расшифровываем, прогоняем каждый конфиг через ВСЕ 3 этапа
                         проверки (ya.ru / google.com / 100kb.txt) через xray.
                         Если рабочих ≥ MIN_WORKING_CONFIGS → используем, переходим к шагу 4.
                         Только если наши конфиги НЕ прошли все 3 этапа (working < MIN) —
                         переходим к следующим шагам.

  2. Локальные конфиги — берём ноды, уже сохранённые в хранилище приложения.
                         Проверяем каждую. Если рабочих ≥ MIN_WORKING_CONFIGS → используем.

  3. Сбор с kort0881   — скачиваем https://github.com/kort0881/vpn-vless-configs-russia,
                         парсим VLESS-ссылки, добавляем обфускацию (REALITY/WS/gRPC),
                         проверяем. Если пусто — ошибка.

  4. Upload на GitHub  — рабочие конфиги шифруем (Fernet + passphrase из cfg_ptr)
                         и загружаем в тот же приватный репо в отдельный файл
                         (имя берётся из cfg_ptr поле 0x06 = configs_filename).

Шифрование: encrypt_with_passphrase(data, passphrase) из security.py
             passphrase = SHA256(nonce + token)[:32]

QThread-воркер: ConfigGithubSyncWorker
  Сигналы: stage(str), progress(int, int), finished(list[str]), error(str)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger("xray_fluent.config_sync")

# ── Константы ─────────────────────────────────────────────────────────────────

MIN_WORKING_CONFIGS = 3          # минимум рабочих конфигов чтобы остановить fallback
CHECK_TIMEOUT       = 8.0        # таймаут проверки одного конфига (сек)
CHECK_WORKERS       = 12         # параллельных воркеров проверки
PING_TIMEOUT        = 1.5
MAX_UPLOAD_CONFIGS  = 30         # не более N конфигов в одном загружаемом файле

# ── Скрипты агрегации (запускаем сами, не зависим от готовых файлов) ──────────
#
# kort0881/vpn-vless-configs-russia
#   Скрипт: update.py — собирает VLESS-конфиги из Telegram-каналов и GitHub
#   Нас интересует только его OUTPUT, поэтому запускаем в изолированном tmpdir
#   и читаем vless.txt / configs.txt из рабочей директории после выполнения.
KORT0881_REPO       = "https://github.com/kort0881/vpn-vless-configs-russia.git"
KORT0881_SCRIPT     = "update.py"          # точка входа в репо kort0881
KORT0881_OUTPUTS    = ["vless.txt", "configs.txt", "output/vless.txt"]

# mahdibland/V2RayAggregator
#   Скрипт: main.py — собирает конфиги из 100+ подписок, валидирует, дедупликует
#   После запуска кладёт результаты в sub/splitted/*.txt
V2RAY_AGG_REPO      = "https://github.com/mahdibland/V2RayAggregator.git"
V2RAY_AGG_SCRIPT    = "main.py"
V2RAY_AGG_OUTPUTS   = [
    "sub/splitted/vless.txt",
    "sub/splitted/vmess.txt",
    "sub/splitted/trojan.txt",
    "sub/splitted/mix.txt",
]

# Таймаут на весь запуск скрипта (секунды). Скрипты агрегаторов могут работать долго.
AGGREGATOR_RUN_TIMEOUT = 180   # 3 минуты на скрипт

# TLV-тег для configs_filename в cfg_ptr.bin
_TAG_CONFIGS_FILE   = 0x06

# ── Шифрование ────────────────────────────────────────────────────────────────

def _make_passphrase(token: str, nonce: str) -> str:
    """Деривируем фразу-пароль из токена и nonce — не хранится нигде явно."""
    raw = f"aegis-configs:{token}:{nonce}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def encrypt_configs(links: list[str], passphrase: str) -> str:
    """Шифруем список конфигов → строка для загрузки на GitHub."""
    from .security import encrypt_with_passphrase
    payload = "\n".join(links).encode("utf-8")
    return encrypt_with_passphrase(payload, passphrase)


def decrypt_configs(encrypted: str, passphrase: str) -> list[str]:
    """Расшифровываем список конфигов с GitHub."""
    from .security import decrypt_with_passphrase, is_passphrase_encrypted
    if not is_passphrase_encrypted(encrypted):
        # Файл ещё не зашифрован (первая инициализация) — читаем как plain text
        lines = [ln.strip() for ln in encrypted.splitlines() if ln.strip()]
        return [ln for ln in lines if "://" in ln]
    raw = decrypt_with_passphrase(encrypted, passphrase)
    lines = raw.decode("utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and "://" in ln]


# ── cfg_ptr — чтение параметров GitHub ───────────────────────────────────────

def _load_github_cfg() -> Optional[dict]:
    """Читает cfg_ptr.bin и возвращает dict с полями token, owner, repo,
    filename (лицензий), configs_filename (конфигов), nonce.
    Поле configs_filename берётся из TLV тега 0x06; если отсутствует —
    используется fallback-имя."""
    try:
        from .license_check import _load_cfg as _load_license_cfg
        cfg = _load_license_cfg()
        if not cfg:
            return None
        # configs_filename — отдельный TLV тег 0x06 в cfg_ptr.bin
        # Пробуем прочитать расширенные поля напрямую
        cfg["configs_filename"] = _read_configs_filename_from_ptr() or "c0nf1gs.bin"
        return cfg
    except Exception as e:
        logger.warning("[config_sync] Не удалось загрузить cfg_ptr: %s", e)
        return None


def _read_configs_filename_from_ptr() -> Optional[str]:
    """Пытается прочитать тег 0x06 (configs_filename) из cfg_ptr.bin напрямую.
    Повторяет логику _decode_cfg_ptr из license_check.py."""
    try:
        from .license_check import (
            _cfg_ptr_path, _CFG_MAGIC, _CFG_VERSION,
            _cfg_master_key, _aes_cbc_decrypt, _unshuffle, _xor_layer,
        )
        raw = _cfg_ptr_path().read_bytes()
        if len(raw) < 20:
            return None
        raw = raw[7:-5]
        decoded = base64.b85decode(raw)
        if decoded[:4] != _CFG_MAGIC or decoded[4] != _CFG_VERSION:
            return None
        payload = decoded[5:]
        iv, payload = payload[:16], payload[16:]
        key = _cfg_master_key()
        decrypted = _aes_cbc_decrypt(payload, key, iv)
        seed = zlib.crc32(key[:4]) & 0xFFFFFFFF
        unshuffled = _unshuffle(decrypted, seed)
        xor_key = hashlib.md5(key).digest()
        plaintext = _xor_layer(unshuffled, xor_key)
        pos = 0
        while pos + 3 <= len(plaintext):
            t = plaintext[pos]
            l = struct.unpack_from("<H", plaintext, pos + 1)[0]
            pos += 3
            if pos + l > len(plaintext):
                break
            if t == _TAG_CONFIGS_FILE:
                return plaintext[pos:pos + l].decode("utf-8")
            pos += l
    except Exception:
        pass
    return None


# ── GitHub API helpers ────────────────────────────────────────────────────────

def _gh_auth_scheme(token: str) -> str:
    """GitHub fine-grained PAT требует Bearer, classic PAT (ghp_) работает с token."""
    return "Bearer" if token.startswith("github_pat_") else "token"


def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"{_gh_auth_scheme(token)} {token}",
        "Accept":        "application/vnd.github.v3.raw",
        "User-Agent":    "AegisNET/2.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _github_get_file(token: str, owner: str, repo: str, filename: str) -> Optional[str]:
    """Скачать содержимое файла из GitHub репо. Возвращает текст или None."""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
    req = urllib.request.Request(url, headers=_gh_headers(token))
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            logger.info("[config_sync] Файл %s не найден в репо (404)", filename)
        else:
            logger.warning("[config_sync] GitHub GET %s: HTTP %s", filename, e.code)
    except Exception as e:
        logger.warning("[config_sync] GitHub GET %s: %s", filename, e)
    return None


def _github_put_file(
    token: str, owner: str, repo: str, filename: str,
    content: str, commit_msg: str = "sync: update configs"
) -> bool:
    """Создать/обновить файл на GitHub через Contents API. Возвращает True при успехе."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"

    # Получаем SHA существующего файла (нужно для обновления)
    sha: Optional[str] = None
    try:
        info_req = urllib.request.Request(
            api_url,
            headers={
                "Authorization": f"{_gh_auth_scheme(token)} {token}",
                "Accept":        "application/vnd.github.v3+json",
                "User-Agent":    "AegisNET/2.0",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        with urllib.request.urlopen(info_req, timeout=10) as r:
            info = json.loads(r.read().decode("utf-8"))
            sha = info.get("sha")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            logger.warning("[config_sync] GitHub SHA fetch: HTTP %s", e.code)
    except Exception as e:
        logger.warning("[config_sync] GitHub SHA fetch: %s", e)

    body: dict = {
        "message": commit_msg,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
    }
    if sha:
        body["sha"] = sha

    data = json.dumps(body).encode("utf-8")
    put_req = urllib.request.Request(
        api_url,
        data=data,
        method="PUT",
        headers={
            "Authorization": f"{_gh_auth_scheme(token)} {token}",
            "Accept":        "application/vnd.github.v3+json",
            "Content-Type":  "application/json",
            "User-Agent":    "AegisNET/2.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(put_req, timeout=20) as r:
            status = r.status
            logger.info("[config_sync] GitHub PUT %s → HTTP %s", filename, status)
            return status in (200, 201)
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass
        logger.error("[config_sync] GitHub PUT %s: HTTP %s — %s", filename, e.code, body_text)
    except Exception as e:
        logger.error("[config_sync] GitHub PUT %s: %s", filename, e)
    return False


# ── Проверка конфигов (ping + HTTP) ──────────────────────────────────────────

def _tcp_ping(host: str, port: int, timeout: float = PING_TIMEOUT) -> bool:
    import socket
    try:
        host.encode("ascii")
    except (UnicodeEncodeError, AttributeError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _extract_host_port(link: str) -> Optional[tuple[str, int]]:
    try:
        p = urllib.parse.urlparse(link)
        host = p.hostname or ""
        port = p.port or 443
        if host and len(host) <= 253:
            return host, port
    except Exception:
        pass
    return None


def check_config(link: str) -> bool:
    """Быстрая двухэтапная проверка: TCP-ping + (опционально) HTTP через xray.
    Возвращает True если конфиг пингуется.
    """
    hp = _extract_host_port(link)
    if not hp:
        return False
    return _tcp_ping(hp[0], hp[1])


def check_configs_parallel(
    links: list[str],
    cancelled: threading.Event,
    progress_cb=None,
    workers: int = CHECK_WORKERS,
) -> list[str]:
    """Параллельная проверка. Возвращает список рабочих конфигов."""
    working: list[str] = []
    lock = threading.Lock()
    done = [0]

    def _task(link: str) -> tuple[str, bool]:
        if cancelled.is_set():
            return link, False
        return link, check_config(link)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_task, lnk): lnk for lnk in links}
        for future in as_completed(futures):
            if cancelled.is_set():
                ex.shutdown(wait=False, cancel_futures=True)
                break
            lnk, ok = future.result()
            with lock:
                done[0] += 1
                if ok:
                    working.append(lnk)
            if progress_cb:
                progress_cb(done[0], len(links))

    return working


# ── Обфускация конфигов kort0881 ──────────────────────────────────────────────

def _add_obfuscation(link: str) -> str:
    """Добавляем обфускационные параметры к VLESS/VMESS/Trojan ссылкам kort0881.

    Правила:
    - Если уже есть параметры обфускации (type=ws/grpc/h2, security=reality/tls) — не трогаем
    - Если голый TCP без TLS — добавляем REALITY-style параметры (fp=chrome, sni из host)
    - Если есть TLS без fp — добавляем fp=chrome
    """
    if "://" not in link:
        return link

    try:
        parsed = urllib.parse.urlparse(link)
        qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

        changed = False

        # Fingerprint для TLS/REALITY
        if qs.get("security") in ("tls", "reality") and not qs.get("fp"):
            qs["fp"] = "chrome"
            changed = True

        # Если нет обфускации транспорта — оставляем как есть, только добавляем fp если tls
        transport = qs.get("type", "tcp")

        # SNI: если нет — берём hostname
        if qs.get("security") in ("tls", "reality") and not qs.get("sni"):
            host = parsed.hostname or ""
            if host and not _is_ip(host):
                qs["sni"] = host
                changed = True

        # allowInsecure по умолчанию 0
        if qs.get("security") == "tls" and "allowInsecure" not in qs:
            qs["allowInsecure"] = "0"
            changed = True

        if not changed:
            return link

        new_query = urllib.parse.urlencode(qs)
        rebuilt = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        return rebuilt
    except Exception:
        return link


def _is_ip(s: str) -> bool:
    import re
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s) or re.match(r"^[0-9a-fA-F:]+$", s))


def _parse_links_from_text(text: str) -> list[str]:
    """Извлекаем VPN-ссылки из произвольного текста (plain + base64)."""
    protocols = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")
    lines: list[str] = []

    # Пробуем base64 decode если нет схемы
    chunks = [text]
    if "://" not in text:
        try:
            decoded = base64.b64decode(text + "==").decode("utf-8", errors="ignore")
            chunks.append(decoded)
        except Exception:
            pass

    for chunk in chunks:
        for line in chunk.splitlines():
            line = line.strip()
            if any(line.startswith(p) for p in protocols):
                lines.append(line)

    return list(dict.fromkeys(lines))  # дедупликация


def _find_python_exe() -> str | None:
    """Ищет python.exe для запуска внешних скриптов.

    ВАЖНО: никогда не используем sys.executable в frozen-режиме (AegisNET.exe) —
    это привело бы к запуску копий приложения вместо Python-интерпретатора.
    """
    import shutil

    # В frozen-режиме sys.executable — это AegisNET.exe, не Python.
    # Ищем системный Python в PATH.
    if getattr(sys, "frozen", False):
        for name in ("python3", "python"):
            found = shutil.which(name)
            if found:
                return found
        return None  # Python не найден — скрипты запустить нельзя

    # Dev-режим: sys.executable — настоящий Python
    import sys as _sys
    return _sys.executable


def _run_aggregator_script(
    repo_url: str,
    script_name: str,
    output_files: list[str],
    timeout: int = AGGREGATOR_RUN_TIMEOUT,
) -> list[str]:
    """Клонирует репо, запускает скрипт сборки, читает output-файлы.

    Принцип: мы запускаем САМИ скрипты агрегаторов в изолированной tmpdir,
    вместо того чтобы зависеть от уже собранных ими файлов. Это значит,
    что даже если чужое репо удалят или забросят — при наличии скрипта и
    исходников Telegram/GitHub-каналов мы пересоберём конфиги сами.

    Требует: git и python3 в PATH. Если недоступны — возвращает пустой список.
    """
    import subprocess
    import shutil
    import tempfile

    python_exe = _find_python_exe()
    if not python_exe:
        logger.warning(
            "[config_sync] Python не найден в PATH — пропускаем запуск %s", script_name
        )
        return []

    all_links: list[str] = []
    tmpdir = tempfile.mkdtemp(prefix="aegis_agg_")
    try:
        # 1. git clone --depth=1 (только последний коммит, быстро)
        clone_result = subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", repo_url, tmpdir],
            capture_output=True, timeout=60,
        )
        if clone_result.returncode != 0:
            logger.warning(
                "[config_sync] git clone %s failed: %s",
                repo_url, clone_result.stderr.decode(errors="replace")[:200],
            )
            return []

        script_path = os.path.join(tmpdir, script_name)
        if not os.path.exists(script_path):
            logger.warning("[config_sync] Скрипт %s не найден в %s", script_name, repo_url)
            return []

        # 2. pip install requirements (если есть), тихо
        req_txt = os.path.join(tmpdir, "requirements.txt")
        if os.path.exists(req_txt):
            subprocess.run(
                [python_exe, "-m", "pip", "install", "-q", "-r", req_txt],
                capture_output=True, timeout=90, cwd=tmpdir,
            )

        # 3. Запускаем скрипт сборки
        run_result = subprocess.run(
            [python_exe, script_path],
            capture_output=True, timeout=timeout, cwd=tmpdir,
        )
        if run_result.returncode != 0:
            logger.warning(
                "[config_sync] %s exit=%d stderr=%s",
                script_name, run_result.returncode,
                run_result.stderr.decode(errors="replace")[:300],
            )
            # Не прерываемся: скрипт мог упасть с кодом != 0 но всё равно записать файлы

        # 4. Читаем output-файлы, которые скрипт должен был создать
        for rel_path in output_files:
            abs_path = os.path.join(tmpdir, rel_path)
            if not os.path.exists(abs_path):
                continue
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                links = _parse_links_from_text(text)
                logger.info(
                    "[config_sync] %s / %s → %d конфигов",
                    repo_url.split("/")[-1], rel_path, len(links)
                )
                all_links.extend(links)
            except Exception as e:
                logger.warning("[config_sync] Чтение %s: %s", abs_path, e)

    except subprocess.TimeoutExpired:
        logger.warning("[config_sync] Таймаут запуска %s (%ds)", script_name, timeout)
    except FileNotFoundError:
        logger.warning("[config_sync] git не найден в PATH — пропускаем запуск скриптов агрегаторов")
    except Exception as e:
        logger.warning("[config_sync] _run_aggregator_script %s: %s", repo_url, e)
    finally:
        try:
            import shutil as _sh
            _sh.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

    return all_links


def _fetch_aggregated_configs() -> list[str]:
    """Запускаем скрипты kort0881 и V2RayAggregator, собираем конфиги сами.

    Порядок:
      1. kort0881/vpn-vless-configs-russia  — Россия-ориентированный VLESS
      2. mahdibland/V2RayAggregator         — широкий агрегатор 100+ источников

    Если git недоступен или скрипт упал — тихо пропускаем этот источник.
    """
    all_links: list[str] = []

    logger.info("[config_sync] Запуск скрипта kort0881 (клонирование + update.py)...")
    kort_links = _run_aggregator_script(KORT0881_REPO, KORT0881_SCRIPT, KORT0881_OUTPUTS)
    logger.info("[config_sync] kort0881 скрипт: %d конфигов", len(kort_links))
    all_links.extend(kort_links)

    logger.info("[config_sync] Запуск скрипта V2RayAggregator (клонирование + main.py)...")
    agg_links = _run_aggregator_script(V2RAY_AGG_REPO, V2RAY_AGG_SCRIPT, V2RAY_AGG_OUTPUTS)
    logger.info("[config_sync] V2RayAggregator скрипт: %d конфигов", len(agg_links))
    all_links.extend(agg_links)

    # Дедупликация + обфускация
    seen: set[str] = set()
    result: list[str] = []
    for lnk in all_links:
        key = lnk.split("#")[0]  # без имени
        if key not in seen:
            seen.add(key)
            result.append(_add_obfuscation(lnk))

    logger.info("[config_sync] Итого после дедуп+обфускации: %d конфигов", len(result))
    return result


# ── Основной воркер ───────────────────────────────────────────────────────────

class ConfigGithubSyncWorker(QThread):
    """4-этапный воркер синхронизации конфигов.

    Этапы:
      1. Читаем зашифрованные конфиги с GitHub → проверяем
      2. Локальные ноды из хранилища → проверяем
      3. Собираем с kort0881 → добавляем обфускацию → проверяем
      4. Загружаем рабочие конфиги обратно на GitHub (зашифрованными)

    Сигналы:
      stage(str)            — текстовое описание текущего этапа
      progress(int, int)    — (done, total) проверенных конфигов
      finished(list[str])   — список рабочих конфигов (ссылки)
      error(str)            — критическая ошибка
    """

    stage    = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(object)   # list[str]
    error    = pyqtSignal(str)

    def __init__(self, local_nodes: list | None = None, parent=None):
        super().__init__(parent)
        self._local_nodes  = local_nodes or []
        self._cancelled    = False
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        self._cancelled = True
        self._cancel_event.set()

    def run(self) -> None:
        try:
            result = self._run_sync()
            if not self._cancelled:
                self.finished.emit(result)
        except Exception as exc:
            logger.exception("[config_sync] Воркер упал: %s", exc)
            self.error.emit(str(exc))

    # ── Основной pipeline ────────────────────────────────────────────────────
    # Логика строго по схеме:
    #
    #  [0] Есть конфиги на GitHub?
    #      ДА  → [1] Проверка 3 этапа
    #              ДА  → Используем GitHub-конфиги, перезаписываем GitHub, СТОП
    #              НЕТ → [2] Локальные файлы
    #      НЕТ → [2] Локальные файлы
    #
    #  [2] Проверка локальных в 3 этапа
    #      ДА  → Используем локальные, перезаписываем GitHub, СТОП
    #      НЕТ → [3] Обновляем локальные с kort0881
    #
    #  [3] Обновляем локальные с kort0881, проверка 3 этапа
    #      ДА  → Используем, перезаписываем GitHub, СТОП
    #      НЕТ → Сообщение пользователю: обратиться в поддержку

    def _run_sync(self) -> list[str]:
        cfg = _load_github_cfg()
        passphrase = _make_passphrase(
            cfg.get("token", "") if cfg else "",
            cfg.get("nonce",  "") if cfg else "",
        )

        # ═══════════════════════════════════════════════════════
        # [0] Есть ли конфиги на GitHub?
        # ═══════════════════════════════════════════════════════
        self.stage.emit("🔐  [0] Проверяем наличие конфигов на GitHub...")
        github_links: list[str] = []
        if cfg:
            github_links = self._fetch_github_configs(cfg, passphrase)

        if self._cancelled:
            return []

        # ═══════════════════════════════════════════════════════
        # [1] GitHub-конфиги ЕСТЬ → проверяем в 3 этапа
        # ═══════════════════════════════════════════════════════
        if github_links:
            self.stage.emit(
                f"📡  [1] GitHub: найдено {len(github_links)} конфигов, проверяем (3 этапа)..."
            )
            working = self._check_three_stages(github_links, source="GitHub")
            if self._cancelled:
                return []

            if len(working) >= MIN_WORKING_CONFIGS:
                # ✅ GitHub прошёл → используем только их, не трогаем локальные
                self.stage.emit(
                    f"✅  [1] GitHub: {len(working)} рабочих — используем."
                )
                return working
            else:
                self.stage.emit(
                    f"⚠️  [1] GitHub: только {len(working)}/{MIN_WORKING_CONFIGS} рабочих — "
                    f"переходим к локальным файлам [2]"
                )
        else:
            self.stage.emit("⚠️  [0] Конфигов на GitHub нет — переходим к локальным файлам [2]")

        if self._cancelled:
            return []

        # ═══════════════════════════════════════════════════════
        # [2] Локальные файлы → проверяем в 3 этапа
        # ═══════════════════════════════════════════════════════
        self.stage.emit("📋  [2] Загружаем и проверяем локальные конфиги (3 этапа)...")
        local_links = [n.link for n in self._local_nodes if getattr(n, "link", "")]
        local_working: list[str] = []
        if local_links:
            local_working = self._check_three_stages(local_links, source="Local")

        if self._cancelled:
            return []

        if len(local_working) >= MIN_WORKING_CONFIGS:
            # ✅ Локальные прошли → используем их
            self.stage.emit(
                f"✅  [2] Локальные: {len(local_working)} рабочих — используем."
            )
            return local_working
        else:
            self.stage.emit(
                f"⚠️  [2] Локальные: только {len(local_working)}/{MIN_WORKING_CONFIGS} рабочих — "
                f"обновляем локальные с kort0881 [3]"
            )

        # ═══════════════════════════════════════════════════════
        # [3] Запускаем скрипты агрегаторов (kort0881 + V2RayAggregator)
        #     Клонируем репо, запускаем update.py / main.py локально —
        #     не зависим от готовых файлов в чужих репо.
        # ═══════════════════════════════════════════════════════
        self.stage.emit(
            "🛠️  [3] Запуск скриптов агрегаторов (kort0881 + V2RayAggregator)..."
        )
        agg_links = _fetch_aggregated_configs()

        if self._cancelled:
            return []

        if not agg_links:
            self.stage.emit("❌  [3] Агрегаторы: не удалось получить конфиги (git недоступен?)")
            logger.error("[config_sync] [3] Агрегаторы: нет конфигов")
            self._emit_support_needed()
            return []

        self.stage.emit(
            f"📡  [3] Агрегаторы: получено {len(agg_links)} конфигов, проверяем (3 этапа)..."
        )
        agg_working = self._check_three_stages(agg_links, source="Aggregators")

        if self._cancelled:
            return []

        if len(agg_working) >= MIN_WORKING_CONFIGS:
            # ✅ Агрегаторы прошли → используем
            self.stage.emit(
                f"✅  [3] Агрегаторы: {len(agg_working)} рабочих — используем."
            )
            return agg_working
        else:
            # ❌ Ничего не работает → сообщение в поддержку
            self.stage.emit(
                f"❌  [3] Агрегаторы: только {len(agg_working)}/{MIN_WORKING_CONFIGS} рабочих"
            )
            logger.error(
                "[config_sync] [3] Нет рабочих конфигов ни из одного источника (%d)",
                len(agg_working),
            )
            self._emit_support_needed()
            return agg_working  # возвращаем что есть (может 0–2 шт)

    # ── Вспомогательные ─────────────────────────────────────────────────────

    # ── Единый 3-этапный проверяльщик ──────────────────────────────────────

    def _check_three_stages(self, links: list[str], source: str = "") -> list[str]:
        """Полная трёхэтапная проверка через xray (ya.ru / google / 100kb).
        Если xray не найден — fallback на TCP-пинг.
        Возвращает список прошедших конфигов.
        """
        label = f"[{source}] " if source else ""
        try:
            from .config_fetcher import (
                _find_xray_exe,
                _check_stage1, _check_stage2, _check_stage3,
                LIVE_SOCKS_PORT_BASE, CHECK_WORKERS as CF_WORKERS,
            )
        except ImportError as e:
            logger.warning("%sНе удалось импортировать config_fetcher (%s), TCP-пинг fallback", label, e)
            return self._check(links)

        xray_exe = _find_xray_exe()
        if not xray_exe:
            logger.warning("%sxray не найден — TCP-пинг fallback", label)
            return self._check(links)

        total = len(links)
        done_count = [0]
        lock = threading.Lock()
        working: list[str] = []
        early_stop = [False]

        port_counter = [LIVE_SOCKS_PORT_BASE + 900]
        port_lock = threading.Lock()

        def _get_base_port() -> int:
            with port_lock:
                p = port_counter[0]
                port_counter[0] += 3
                return p

        def _task(lnk: str) -> tuple[str, bool]:
            if self._cancel_event.is_set() or early_stop[0]:
                return lnk, False
            base = _get_base_port()
            if not _check_stage1(lnk, xray_exe, base):
                return lnk, False
            if self._cancel_event.is_set():
                return lnk, False
            if not _check_stage2(lnk, xray_exe, base + 1):
                return lnk, False
            if self._cancel_event.is_set():
                return lnk, False
            if not _check_stage3(lnk, xray_exe, base + 2):
                return lnk, False
            return lnk, True

        self.stage.emit(f"🔬  {label}3-этапная проверка: {total} конфигов...")

        with ThreadPoolExecutor(max_workers=CF_WORKERS) as ex:
            futures = {ex.submit(_task, lnk): lnk for lnk in links}
            for future in as_completed(futures):
                if self._cancel_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                lnk, ok = future.result()
                with lock:
                    done_count[0] += 1
                    if ok:
                        working.append(lnk)
                    # Ранний выход: нашли достаточно, не гоняем все остальные
                    if len(working) >= MIN_WORKING_CONFIGS * 3:
                        early_stop[0] = True
                        ex.shutdown(wait=False, cancel_futures=True)
                self.progress.emit(done_count[0], total)
                if done_count[0] % 5 == 0 or done_count[0] == total or early_stop[0]:
                    self.stage.emit(
                        f"🔬  {label}{done_count[0]}/{total}  рабочих: {len(working)}"
                        + (" ✓" if early_stop[0] else "")
                    )
                if early_stop[0]:
                    break

        logger.info("[config_sync] %s3-этап: %d/%d прошли", label, len(working), total)
        return working

    def _emit_support_needed(self) -> None:
        """Сигнализируем пользователю обратиться в поддержку."""
        msg = (
            "❌  Ни один конфиг не работает. "
            "Пожалуйста, обратитесь в поддержку."
        )
        self.stage.emit(msg)
        self.error.emit(
            "Не удалось найти рабочие VPN-конфиги ни из одного источника.\n"
            "Пожалуйста, обратитесь в поддержку."
        )
        logger.error("[config_sync] Нет рабочих конфигов — пользователь направлен в поддержку")

    def _fetch_github_configs(self, cfg: dict, passphrase: str) -> list[str]:
        """Читает и расшифровывает файл конфигов из GitHub."""
        filename = cfg.get("configs_filename", "c0nf1gs.bin")
        raw = _github_get_file(cfg["token"], cfg["owner"], cfg["repo"], filename)
        if not raw:
            return []
        try:
            return decrypt_configs(raw.strip(), passphrase)
        except Exception as e:
            logger.warning("[config_sync] Расшифровка конфигов с GitHub: %s", e)
            return []

    def _check(self, links: list[str]) -> list[str]:
        """Параллельная проверка конфигов с прогрессом (TCP-пинг)."""
        def _progress(done, total):
            self.progress.emit(done, total)

        return check_configs_parallel(
            links,
            self._cancel_event,
            progress_cb=_progress,
            workers=CHECK_WORKERS,
        )

    def _upload(self, working: list[str], cfg: Optional[dict], passphrase: str) -> None:
        """Upload на GitHub отключён по политике безопасности.
        Пользователь не может изменять файл конфигов на GitHub — только читать."""
        logger.debug("[config_sync] Upload на GitHub отключён (запись недоступна)")



# ── Локальное хранилище ручных конфигов ─────────────────────────────────────────────────────────

def _manual_configs_path() -> "Path":
    """Путь к файлу ручных конфигов рядом с exe/скриптом."""
    import sys
    from pathlib import Path as _Path
    if getattr(sys, "frozen", False):
        base = _Path(sys.executable).resolve().parent
    else:
        base = _Path(__file__).resolve().parents[1]
    return base / "data" / "manual_configs.txt"


def _save_manual_configs_local(links: list[str]) -> None:
    """Сохраняет ручные конфиги в локальный файл data/manual_configs.txt рядом с exe.
    Новые конфиги добавляются к существующим (дедупликация).
    Пользователь может читать файл, но запись на GitHub отключена.
    """
    from pathlib import Path as _Path
    path = _manual_configs_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        existing: list[str] = []
        if path.exists():
            existing = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        existing_set = set(existing)
        merged = existing[:]
        for lnk in links:
            if lnk not in existing_set:
                merged.append(lnk)
                existing_set.add(lnk)
        merged = merged[:MAX_UPLOAD_CONFIGS]
        path.write_text("\n".join(merged) + "\n", encoding="utf-8")
        logger.info("[manual_local] Сохранено %d конфигов в %s", len(merged), path)
    except Exception as e:
        logger.error("[manual_local] Ошибка записи локального файла: %s", e)


def load_manual_configs_local() -> list[str]:
    """Загружает ручные конфиги из локального файла."""
    path = _manual_configs_path()
    try:
        if path.exists():
            return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except Exception as e:
        logger.warning("[manual_local] Ошибка чтения локального файла: %s", e)
    return []


# ── Публичные утилиты (для app_controller) ────────────────────────────────────

def start_github_sync(
    local_nodes: list,
    on_stage,
    on_progress,
    on_finished,
    on_error,
    parent=None,
) -> "ConfigGithubSyncWorker":
    """Запустить синхронизацию. Возвращает запущенный воркер.

    Пример:
        worker = start_github_sync(
            local_nodes=self.state.nodes,
            on_stage=lambda s: self._log(s),
            on_progress=lambda d, t: ...,
            on_finished=self._on_sync_finished,
            on_error=lambda e: self.status.emit("error", e),
            parent=self,
        )
    """
    worker = ConfigGithubSyncWorker(local_nodes=local_nodes, parent=parent)
    worker.stage.connect(on_stage)
    worker.progress.connect(on_progress)
    worker.finished.connect(on_finished)
    worker.error.connect(on_error)
    worker.start()
    return worker

# ── Загрузка ручных конфигов на GitHub ───────────────────────────────────────

def _merge_and_upload_configs(
    new_links: list[str],
    cfg: Optional[dict],
    passphrase: str,
    commit_msg: str = "manual: add verified config",
) -> bool:
    """Добавляет новые конфиги к существующим на GitHub и загружает обратно.

    Читает текущий файл конфигов, мержит с новыми (дедупликация),
    шифрует и загружает. Возвращает True при успехе.
    """
    if not cfg or not cfg.get("token") or not cfg.get("owner") or not cfg.get("repo"):
        logger.warning("[manual_upload] Неполные данные GitHub в cfg_ptr")
        return False

    filename = cfg.get("configs_filename", "c0nf1gs.bin")
    token = cfg["token"]
    owner = cfg["owner"]
    repo  = cfg["repo"]

    # Читаем существующие конфиги
    existing: list[str] = []
    try:
        raw = _github_get_file(token, owner, repo, filename)
        if raw:
            existing = decrypt_configs(raw.strip(), passphrase)
    except Exception as e:
        logger.warning("[manual_upload] Не удалось прочитать существующие конфиги: %s", e)

    # Мерж с дедупликацией; новые конфиги идут ПЕРВЫМИ (приоритет)
    merged_set: set[str] = set(existing)
    merged: list[str] = list(new_links)  # новые вперёд
    for lnk in existing:
        if lnk not in set(new_links):
            merged.append(lnk)

    # Ограничение по размеру
    merged = merged[:MAX_UPLOAD_CONFIGS]

    try:
        encrypted = encrypt_configs(merged, passphrase)
    except Exception as e:
        logger.error("[manual_upload] Ошибка шифрования: %s", e)
        return False

    ok = _github_put_file(token, owner, repo, filename, encrypted, commit_msg)
    if ok:
        logger.info(
            "[manual_upload] GitHub обновлён: %d конфигов (было %d, добавлено %d) → %s",
            len(merged), len(existing), len(new_links), filename,
        )
    else:
        logger.error("[manual_upload] Ошибка загрузки на GitHub")
    return ok


def verify_and_upload_manual(
    links: list[str],
    on_status: "Optional[callable]" = None,
) -> tuple[list[str], list[str]]:
    """Проверяет ручные конфиги и загружает рабочие на приватный GitHub.

    Используется при ручном добавлении конфига пользователем.
    - Для обычных конфигов: TCP-пинг + трёхэтапная xray-проверка
    - Для BL-конфигов: DPI(Reality)+VPN цепочка через check_bl_config_full()

    Аргументы:
        links      — список VPN-ссылок для проверки
        on_status  — callback(str) для статусных сообщений (опционально)

    Возвращает:
        (working, failed) — списки рабочих и нерабочих ссылок
    """
    def _status(msg: str) -> None:
        logger.info("[manual_upload] %s", msg)
        if on_status:
            try:
                on_status(msg)
            except Exception:
                pass

    _status(f"Проверка {len(links)} конфигов...")

    # Загружаем cfg_ptr для GitHub-доступа
    cfg = _load_github_cfg()
    passphrase = ""
    if cfg:
        passphrase = _make_passphrase(cfg.get("token", ""), cfg.get("nonce", ""))

    # Находим xray для live-проверки
    xray_exe: Optional[str] = None
    try:
        from .config_fetcher import _find_xray_exe, check_bl_config_full, _is_bl_config
        xray_exe = _find_xray_exe()
    except Exception:
        pass

    working: list[str] = []
    failed: list[str]  = []

    PORT_BASE = 19700  # базовый порт для проверки ручных конфигов

    for i, link in enumerate(links):
        _status(f"  [{i+1}/{len(links)}] Проверяем: {link[:60]}...")

        # TCP-пинг
        hp = _extract_host_port(link)
        if not hp or not _tcp_ping(hp[0], hp[1]):
            _status(f"    ✗ TCP-пинг не прошёл")
            failed.append(link)
            continue

        # xray live-проверка
        if xray_exe:
            port = PORT_BASE + i * 10
            try:
                from .config_fetcher import _is_bl_config, check_bl_config_full
                if _is_bl_config(link):
                    _status(f"    ⚡ BL-конфиг → DPI(Reality)+VPN цепочка")
                    ok = check_bl_config_full(link, xray_exe, port)
                else:
                    # Обычная проверка для CIDR/Reality-конфигов
                    from .config_fetcher import (
                        _check_stage1, _check_stage2, _check_stage3,
                    )
                    ok = (
                        _check_stage1(link, xray_exe, port) and
                        _check_stage2(link, xray_exe, port + 1) and
                        _check_stage3(link, xray_exe, port + 2)
                    )
            except Exception as e:
                logger.warning("[manual_upload] xray-проверка упала: %s", e)
                ok = True  # при ошибке xray — считаем рабочим (пинг прошёл)
        else:
            ok = True  # xray недоступен — доверяем пингу

        if ok:
            _status(f"    ✓ Рабочий")
            working.append(link)
        else:
            _status(f"    ✗ Не прошёл live-проверку")
            failed.append(link)

    # Рабочие конфиги сохраняются только локально (запись на GitHub отключена)
    if working:
        _save_manual_configs_local(working)
        _status(f"✅  Рабочих конфигов: {len(working)} — сохранены локально.")

    _status(f"Итого: рабочих={len(working)}, нерабочих={len(failed)}")
    return working, failed
