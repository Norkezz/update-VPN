"""config_fetcher.py — загрузка и фоновое обновление VPN-конфигураций.

Этапы Splash-загрузки (ConfigFetchWorker):
  1. GitHub   — читаем зашифрованные конфиги из приватного репо (ЕДИНСТВЕННЫЙ источник).
                Если рабочих ≥ 3 → сразу возвращаем, публичные источники НЕ трогаем.
  2. Ping     — TCP-пинг (≤ MAX_PING_MS), 200 потоков
  3. Check    — трёхэтапная проверка (ya.ru / google.com / 100kb.txt) через xray:
                • CIDR/Reality-конфиги — стандартная проверка (прямой xray)
                • BL-конфиги (blacklist/split-tunnel) — DPI(Reality)+VPN цепочка:
                  запускаем BL-конфиг в глобальном режиме → весь трафик через туннель
                  → проверяем ya.ru/google.com через реальный VPN, а не напрямую
  4. Filter   — страновой лимит + итоговый cap

Фоновое обновление (BackgroundRefreshWorker):
  - Запускается каждые 30 минут автоматически
  - Только приватный GitHub — никаких публичных источников
  - TCP-пинг для отсева протухших конфигов
  - Результат передаётся через сигнал refresh_done(FetchSummary)

DPI(Reality)+VPN для BL-конфигов:
  - _is_bl_config(link) — детектирует BL-конфиг по маркерам в имени
  - _check_bl_config_via_chain() — запускает BL-xray в глобальном режиме,
    проверяет через него (без split-tunnel) → корректная задержка
  - check_bl_config_full() — полная трёхэтапная проверка для ручного импорта
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests
from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal

logger = logging.getLogger("xray_fluent")

# ---------------------------------------------------------------------------
# Константы фильтрации
# ---------------------------------------------------------------------------
MAX_PING_MS: int     = 150   # порог пинга (мс, было 200)
MAX_CONFIGS: int     = 25
MAX_PER_COUNTRY: int = 10
PING_WORKERS: int    = 200   # много потоков — быстро
PING_TIMEOUT: float  = 1.0

CHECK_WORKERS: int   = 32    # параллельных check-потоков (было 16)

# Этап 1: ya.ru — загрузка должна занять ≥ 100 мс (иначе нерабочий)
CHECK1_URL: str      = "https://ya.ru"
CHECK1_TIMEOUT: float = 5.0
CHECK1_MIN_MS: int   = 100   # мс — меньше = нерабочий

# Этап 2: google.com — загрузка должна занять ≥ 100 мс (иначе нерабочий)
CHECK2_URL: str      = "https://google.com"
CHECK2_TIMEOUT: float = 5.0
CHECK2_MIN_MS: int   = 100   # мс — меньше = нерабочий

# Этап 3: скачать 100 KB с github — должно занять ≥ 250 мс (иначе нерабочий)
CHECK3_URL: str      = "https://gist.githubusercontent.com/aal89/0e8d16a81a72d420aae9806ee87e3399/raw/100kb.txt"
CHECK3_BYTES: int    = 100_000  # 100 KB
CHECK3_TIMEOUT: float = 10.0
CHECK3_MIN_MS: int   = 250   # мс — меньше = нерабочий

LIVE_SOCKS_PORT_BASE = 19300

# Legacy aliases (используются в фоновом воркере и SpeedTestWorker)
SPEED_WORKERS: int   = CHECK_WORKERS
SPEED_TIMEOUT: float = CHECK3_TIMEOUT
SPEED_MIN_MBPS: float = 0.0   # фильтрация теперь по времени, не скорости
SPEED_CHECK_BYTES    = CHECK3_BYTES
LIVE_WORKERS: int    = CHECK_WORKERS
LIVE_TIMEOUT: float  = CHECK1_TIMEOUT
LIVE_CHECK_URL: str  = CHECK1_URL
SPEED_CHECK_URL: str = CHECK3_URL

BG_INTERVAL_SEC: int = 1800  # 30 минут между фоновыми обновлениями (было 5 мин)
BG_SOCKS_PORT_BASE   = 19500 # порты для фоновых xray-инстансов

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

PROTOCOLS = ["vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2", "tuic"]

GOOD_DOMAINS = [
    "ru", "by", "kz", "su", "rf",
    "de", "nl", "fi", "gb", "uk", "fr", "se", "pl", "cz", "at",
    "ch", "it", "es", "no", "dk", "be", "ie", "lu", "ee", "lv", "lt",
]

GOOD_TAGS = [
    "🇷🇺", "🇧🇾", "🇰🇿", "RUSSIA", "MOSCOW", "SPB", "PETERSBURG", "KAZAKHSTAN",
    "BELARUS", "RU_", "RUS", "РФ", "МОСКВА", "СПБ",
    "🇩🇪", "🇳🇱", "🇫🇮", "🇬🇧", "🇫🇷", "🇸🇪", "🇵🇱", "🇨🇿", "🇦🇹", "🇨🇭",
    "🇮🇹", "🇪🇸", "🇳🇴", "🇩🇰", "🇧🇪", "🇮🇪", "🇱🇺", "🇪🇪", "🇱🇻", "🇱🇹", "🇪🇺",
    "GERMANY", "DEUTSCHLAND", "NETHERLANDS", "HOLLAND", "FINLAND",
    "UK", "UNITED KINGDOM", "BRITAIN", "FRANCE", "SWEDEN", "POLAND",
    "CZECH", "AUSTRIA", "SWISS", "SWITZERLAND", "ITALY", "SPAIN",
    "NORWAY", "DENMARK", "BELGIUM", "IRELAND", "ESTONIA", "LATVIA", "LITHUANIA",
    "EUROPE", "AMSTERDAM", "FRANKFURT", "LONDON", "PARIS", "FALKENSTEIN",
    "LIMBURG", "HELSINKI", "STOCKHOLM", "WARSAW", "PRAGUE", "VIENNA",
    "ZURICH", "OSLO", "COPENHAGEN", "BRUSSELS", "DUBLIN", "TALLINN", "RIGA", "VILNIUS",
]

URLS_BASE: list[str] = [
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Pawdro/Collection/main/sub",
    "https://raw.githubusercontent.com/free-v2ray-config/vmess/main/vmess.txt",
    "https://raw.githubusercontent.com/free-v2ray-config/vless/main/vless.txt",
    "https://raw.githubusercontent.com/free-v2ray-config/trojan/main/trojan.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub7.txt",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/sarina-ad/v2ray/main/v2ray",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/raw/refs/heads/main/sublinks/mix.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/actives.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/subscribe",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Vless.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt",
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS",
    "https://raw.githubusercontent.com/Mosifec/-FREE2CONFIG/refs/heads/main/Reality",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
    "https://raw.githubusercontent.com/mehran1404/Sub_Link/refs/heads/main/V2RAY-Sub.txt",
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/main/speed.txt",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Airuop/cross/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/yebekhe/V2Hub/main/merged",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/refs/heads/main/AzadNet.txt",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/dimzon/scaling-sniffle/7f5f4f1c31d96015218da9ead3d07405f3471e46/by-country/EE.txt",
    # ── mahdibland/V2RayAggregator — pre-validated aggregated subscriptions ──
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/ss.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/mix.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    # ── kort0881/vpn-vless-configs-russia — daily-updated Russia-focused VLESS ─
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/configs.txt",
]

_FLAG_TO_CC: dict[str, str] = {
    "🇷🇺": "RU", "🇩🇪": "DE", "🇳🇱": "NL", "🇫🇮": "FI", "🇬🇧": "GB",
    "🇫🇷": "FR", "🇸🇪": "SE", "🇵🇱": "PL", "🇨🇿": "CZ", "🇦🇹": "AT",
    "🇨🇭": "CH", "🇮🇹": "IT", "🇪🇸": "ES", "🇳🇴": "NO", "🇩🇰": "DK",
    "🇧🇪": "BE", "🇮🇪": "IE", "🇱🇺": "LU", "🇪🇪": "EE", "🇱🇻": "LV",
    "🇱🇹": "LT", "🇧🇾": "BY", "🇰🇿": "KZ", "🇺🇦": "UA", "🇺🇸": "US",
    "🇸🇬": "SG", "🇯🇵": "JP", "🇰🇷": "KR", "🇹🇷": "TR", "🇮🇳": "IN",
    "🇨🇦": "CA", "🇦🇺": "AU",
}

_KEYWORD_TO_CC: dict[str, str] = {
    "RUSSIA": "RU", "MOSCOW": "RU", "SPB": "RU", "PETERSBURG": "RU",
    "RUS": "RU", "МОСКВА": "RU", "СПБ": "RU",
    "GERMANY": "DE", "DEUTSCHLAND": "DE", "FRANKFURT": "DE",
    "NETHERLANDS": "NL", "HOLLAND": "NL", "AMSTERDAM": "NL",
    "FINLAND": "FI", "HELSINKI": "FI",
    "UK": "GB", "BRITAIN": "GB", "LONDON": "GB",
    "FRANCE": "FR", "PARIS": "FR",
    "SWEDEN": "SE", "STOCKHOLM": "SE",
    "POLAND": "PL", "WARSAW": "PL",
    "CZECH": "CZ", "PRAGUE": "CZ",
    "AUSTRIA": "AT", "VIENNA": "AT",
    "SWISS": "CH", "SWITZERLAND": "CH", "ZURICH": "CH",
    "ITALY": "IT", "SPAIN": "ES",
    "NORWAY": "NO", "OSLO": "NO",
    "DENMARK": "DK", "COPENHAGEN": "DK",
    "BELGIUM": "BE", "BRUSSELS": "BE",
    "IRELAND": "IE", "DUBLIN": "IE",
    "ESTONIA": "EE", "TALLINN": "EE",
    "LATVIA": "LV", "RIGA": "LV",
    "LITHUANIA": "LT", "VILNIUS": "LT",
    "BELARUS": "BY", "KAZAKHSTAN": "KZ",
    "FALKENSTEIN": "DE", "LIMBURG": "NL",
    "NUREMBERG": "DE", "BERLIN": "DE", "DUSSELDORF": "DE",
}


def get_user_country() -> str:
    """Определяем страну пользователя через ipapi.co (fallback: ip-api.com).
    Возвращает 2-буквенный ISO-код в верхнем регистре, например 'RU', 'GB'.
    При ошибке возвращает пустую строку.
    """
    try:
        import urllib.request as _ur
        req = _ur.Request(
            "https://ipapi.co/country/",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with _ur.urlopen(req, timeout=6) as r:
            cc = r.read().decode().strip().upper()
            if len(cc) == 2 and cc.isalpha():
                return cc
    except Exception:
        pass
    try:
        import urllib.request as _ur
        req = _ur.Request(
            "http://ip-api.com/line/?fields=countryCode",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with _ur.urlopen(req, timeout=6) as r:
            cc = r.read().decode().strip().upper()
            if len(cc) == 2 and cc.isalpha():
                return cc
    except Exception:
        pass
    return ""


# Кэш страны пользователя — определяем один раз за сессию
_USER_COUNTRY_CACHE: list[str] = []


def _get_cached_user_country() -> str:
    if not _USER_COUNTRY_CACHE:
        cc = get_user_country()
        _USER_COUNTRY_CACHE.append(cc)
        if cc:
            logger.info("[geo] Страна пользователя определена: %s", cc)
        else:
            logger.warning("[geo] Не удалось определить страну пользователя")
    return _USER_COUNTRY_CACHE[0]


def _guess_country(link: str) -> str:
    name = ""
    if "#" in link:
        name = urllib.parse.unquote(link.split("#", 1)[-1]).upper()
    for flag, cc in _FLAG_TO_CC.items():
        if flag in name or flag in link:
            return cc
    for kw, cc in _KEYWORD_TO_CC.items():
        if kw in name:
            return cc
    try:
        host = urllib.parse.urlparse(link).hostname or ""
        if host and not re.match(r"^\d", host):
            tld = host.rsplit(".", 1)[-1].upper()
            if len(tld) == 2:
                return tld
    except Exception:
        pass
    return "XX"


def protocol_of(line: str) -> str | None:
    for p in PROTOCOLS:
        if line.startswith(p + "://"):
            return p
    return None


def _is_ip_address(s: str) -> bool:
    if not s:
        return False
    return bool(
        re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s)
        or re.match(r"^[0-9a-fA-F:]+$", s)
    )


def _extract_host_port(link: str) -> tuple[str, int] | None:
    try:
        parsed = urllib.parse.urlparse(link)
        host = parsed.hostname or ""
        port = parsed.port or 443
        if host and len(host) <= 253:
            return host, port
    except Exception:
        pass
    return None


def is_good_key(line: str) -> bool:
    line_upper = line.upper()
    name = ""
    if "#" in line:
        name = urllib.parse.unquote(line.split("#")[-1]).upper()
    for tag in GOOD_TAGS:
        if tag in name or tag in line_upper:
            return True
    try:
        host = urllib.parse.urlparse(line).hostname or ""
        if host and not _is_ip_address(host):
            host_lower = host.lower()
            for dom in GOOD_DOMAINS:
                if host_lower.endswith("." + dom) or host_lower == dom:
                    return True
    except Exception:
        pass
    return False


def _tcp_ping(host: str, port: int, timeout: float = PING_TIMEOUT) -> int | None:
    if not host or len(host) > 253:
        return None
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        return None
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            return int((time.perf_counter() - start) * 1000)
    except (OSError, UnicodeError):
        return None


# ---------------------------------------------------------------------------
# Утилиты xray
# ---------------------------------------------------------------------------

def _find_xray_exe() -> str | None:
    # Сначала ищем через core_unpacker (актуальный путь при запуске из exe)
    try:
        from .core_unpacker import get_core_dir
        core_dir = get_core_dir()
        for name in ("xray.exe", "xray"):
            p = core_dir / name
            if p.exists():
                return str(p)
    except Exception:
        pass
    # Fallback: стандартный путь BASE_DIR/core/
    try:
        from .constants import BASE_DIR
        for c in [BASE_DIR / "core" / "xray.exe", BASE_DIR / "core" / "xray"]:
            if c.exists():
                return str(c)
    except Exception:
        pass
    return None


def _build_minimal_xray_config(link: str, socks_port: int) -> dict | None:
    try:
        from .link_parser import parse_links_text
        nodes, _ = parse_links_text(link)
        if not nodes:
            return None
        outbound = dict(nodes[0].outbound)
        outbound["tag"] = "proxy"

        # Санитизация: невалидное значение security (напр. "false") ломает xray
        VALID_SECURITY = {"none", "tls", "reality", "xtls", ""}
        stream = outbound.get("streamSettings")
        if isinstance(stream, dict):
            sec = stream.get("security", "none")
            if sec not in VALID_SECURITY:
                stream["security"] = "none"
            outbound["streamSettings"] = stream

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }],
            "outbounds": [
                outbound,
                {"tag": "direct", "protocol": "freedom", "settings": {}},
            ],
            "routing": {
                "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}]
            },
        }
    except Exception:
        return None


def _start_xray(link: str, xray_exe: str, socks_port: int) -> tuple[subprocess.Popen | None, str | None]:
    """Запустить xray для link на socks_port. Вернуть (proc, tmp_path)."""
    cfg = _build_minimal_xray_config(link, socks_port)
    if cfg is None:
        return None, None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cfg, f)
            tmp_path = f.name
        flags = 0x08000000 if os.name == "nt" else 0
        proc = subprocess.Popen(
            [xray_exe, "run", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
        return proc, tmp_path
    except Exception:
        return None, None


def _wait_port(port: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _kill_xray(proc: subprocess.Popen | None, tmp_path: str | None) -> None:
    if proc is not None:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
    if tmp_path:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Три этапа проверки: ya.ru / google.com / 100kb.txt
# Логика одна: измеряем время ответа, если < порога — нерабочий (слишком быстро
# означает, что трафик не идёт через прокси / ответ фейковый).
# ---------------------------------------------------------------------------

def _http_check_ms(proxies: dict, url: str, timeout: float,
                   stream: bool = False, max_bytes: int = 0) -> int | None:
    """
    Выполняет GET-запрос через proxies, возвращает время в мс или None при ошибке.
    Если stream=True — читает до max_bytes байт перед остановкой.
    """
    try:
        start = time.perf_counter()
        resp = requests.get(
            url,
            proxies=proxies,
            stream=stream,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if stream and max_bytes > 0:
            received = 0
            for chunk in resp.iter_content(chunk_size=8192):
                received += len(chunk)
                if received >= max_bytes:
                    break
            if received < 1024:
                return None
        else:
            _ = resp.content  # читаем тело полностью
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return elapsed_ms
    except Exception:
        return None


def _check_stage1(link: str, xray_exe: str, socks_port: int) -> bool:
    """Этап 1: ya.ru — время загрузки должно быть ≥ CHECK1_MIN_MS мс.

    Если конфиг определён как BL-тип (split-tunnel/blacklist) —
    автоматически использует DPI(Reality)+VPN цепочку, чтобы ya.ru
    шёл через реальный туннель, а не напрямую.
    """
    if _is_bl_config(link):
        return _check_bl_config_via_chain(link, xray_exe, socks_port, stage=1)
    proc, tmp = _start_xray(link, xray_exe, socks_port)
    if proc is None:
        return False
    try:
        if not _wait_port(socks_port, timeout=3.0):
            return False
        proxies = {
            "http":  f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        ms = _http_check_ms(proxies, CHECK1_URL, CHECK1_TIMEOUT)
        return ms is not None and ms >= CHECK1_MIN_MS
    except Exception:
        return False
    finally:
        _kill_xray(proc, tmp)


def _check_stage2(link: str, xray_exe: str, socks_port: int) -> bool:
    """Этап 2: google.com — время загрузки должно быть ≥ CHECK2_MIN_MS мс.

    BL-конфиги проверяются через DPI(Reality)+VPN цепочку.
    """
    if _is_bl_config(link):
        return _check_bl_config_via_chain(link, xray_exe, socks_port, stage=2)
    proc, tmp = _start_xray(link, xray_exe, socks_port)
    if proc is None:
        return False
    try:
        if not _wait_port(socks_port, timeout=3.0):
            return False
        proxies = {
            "http":  f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        ms = _http_check_ms(proxies, CHECK2_URL, CHECK2_TIMEOUT)
        return ms is not None and ms >= CHECK2_MIN_MS
    except Exception:
        return False
    finally:
        _kill_xray(proc, tmp)


def _check_stage3(link: str, xray_exe: str, socks_port: int) -> bool:
    """Этап 3: 100kb.txt — время скачивания должно быть ≥ CHECK3_MIN_MS мс.

    BL-конфиги проверяются через DPI(Reality)+VPN цепочку.
    """
    if _is_bl_config(link):
        return _check_bl_config_via_chain(link, xray_exe, socks_port, stage=3)
    proc, tmp = _start_xray(link, xray_exe, socks_port)
    if proc is None:
        return False
    try:
        if not _wait_port(socks_port, timeout=3.0):
            return False
        proxies = {
            "http":  f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        ms = _http_check_ms(proxies, CHECK3_URL, CHECK3_TIMEOUT,
                            stream=True, max_bytes=CHECK3_BYTES)
        return ms is not None and ms >= CHECK3_MIN_MS
    except Exception:
        return False
    finally:
        _kill_xray(proc, tmp)


# Legacy wrapper — используется в фоновом pipeline
def _speed_check_one(link: str, xray_exe: str, socks_port: int) -> float | None:
    """Обёртка для совместимости с фоновым воркером: возвращает 1.0 если прошёл все 3 этапа."""
    p1 = socks_port
    p2 = socks_port + 1
    p3 = socks_port + 2
    if not _check_stage1(link, xray_exe, p1):
        return None
    if not _check_stage2(link, xray_exe, p2):
        return None
    if not _check_stage3(link, xray_exe, p3):
        return None
    return 1.0  # прошёл все этапы


def _live_check_one(link: str, xray_exe: str, socks_port: int) -> bool:
    """Алиас _speed_check_one → bool. Используется в _bg_live фонового воркера."""
    return _speed_check_one(link, xray_exe, socks_port) is not None


# ---------------------------------------------------------------------------
# DPI(Reality)+VPN — проверка BL-конфигов через цепочку прокси
#
# BL-конфиг (blacklist/split-tunnel) маршрутизирует заблокированные домены
# через VPN, а остальное — напрямую. Из-за этого ya.ru и google.com при
# стандартной проверке идут МИМО прокси (слишком быстро → конфиг отклоняется).
#
# Решение: строим цепочку из двух xray-процессов:
#   [внешний SOCKS :порт] → [BL-конфиг] → [Интернет]
# Внешний xray отправляет ВЕСЬ трафик в BL-конфиг (без split),
# BL-конфиг дальше сам решает куда слать.
# Таким образом проверочные запросы ya.ru/google.com проходят через реальный
# VPN-туннель, и задержка соответствует действительной работе конфига.
# ---------------------------------------------------------------------------

# Порты для цепочечной проверки BL-конфигов
BL_CHAIN_PORT_BASE = 19800   # промежуточный SOCKS для BL-процесса
BL_OUTER_PORT_BASE = 19900   # внешний SOCKS для цепочечной проверки


def _is_bl_config(link: str) -> bool:
    """Определяет, является ли конфиг BL-типом (blacklist/split-tunnel).

    Признаки BL-конфига:
    - В имени (фрагменте #...) есть маркеры: BL, BLACKLIST, SPLIT, BYPASS, WL, WHITELIST
    - security=reality + тип транспорта tcp (это НЕ CIDR — это Reality-конфиг с маршрутизацией)
    - Явная пометка в имени: "bl", "bypass", "split"

    CIDR-конфиги НЕ считаются BL — они работают через глобальный прокси.
    """
    link_upper = link.upper()
    fragment = ""
    if "#" in link:
        fragment = urllib.parse.unquote(link.split("#", 1)[-1]).upper()

    bl_markers = ("BL", "BLACKLIST", "SPLIT", "BYPASS", "WHITELIST", " WL", "_WL", "-WL",
                  "РОССИЙ", "RU-ONLY", "RUONLY", "БЛОКИРОВК")
    if any(m in fragment for m in bl_markers):
        return True

    return False


def _build_bl_inner_config(link: str, inner_socks_port: int) -> dict | None:
    """Строит xray-конфиг для BL-процесса (всё через proxy, без split-tunnel).

    Запускаем BL-конфиг в режиме «глобальный прокси» — весь трафик идёт
    через outbound, routing по blacklist не применяется. Это нужно ТОЛЬКО
    для проверки — в реальной работе конфиг используется с родным routing.
    """
    try:
        from .link_parser import parse_links_text
        nodes, _ = parse_links_text(link)
        if not nodes:
            return None
        outbound = dict(nodes[0].outbound)
        outbound["tag"] = "proxy"

        VALID_SECURITY = {"none", "tls", "reality", "xtls", ""}
        stream = outbound.get("streamSettings")
        if isinstance(stream, dict):
            sec = stream.get("security", "none")
            if sec not in VALID_SECURITY:
                stream["security"] = "none"
            outbound["streamSettings"] = stream

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "tag": "bl-socks-in",
                "listen": "127.0.0.1",
                "port": inner_socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }],
            "outbounds": [
                outbound,
                {"tag": "direct", "protocol": "freedom", "settings": {}},
            ],
            # Глобальный режим — весь трафик через proxy (без blacklist-routing)
            "routing": {
                "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}]
            },
        }
    except Exception:
        return None


def _start_xray_raw(cfg: dict, xray_exe: str) -> tuple[subprocess.Popen | None, str | None]:
    """Запускает xray с готовым dict-конфигом. Возвращает (proc, tmp_path)."""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(cfg, f)
            tmp_path = f.name
        flags = 0x08000000 if os.name == "nt" else 0
        proc = subprocess.Popen(
            [xray_exe, "run", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
        return proc, tmp_path
    except Exception:
        return None, None


def _check_bl_config_via_chain(
    link: str,
    xray_exe: str,
    outer_socks_port: int,
    stage: int = 1,
) -> bool:
    """Проверяет BL-конфиг через цепочку DPI(Reality)+VPN.

    Архитектура:
        Тест-запрос → SOCKS :outer_socks_port → BL-xray :inner_port → VPN-сервер → Интернет

    BL-xray запускается в глобальном режиме (весь трафик через proxy),
    поэтому проверочные запросы ya.ru/google.com реально идут через туннель.

    stage: 1=ya.ru, 2=google.com, 3=100kb.txt
    """
    inner_port = outer_socks_port + 50  # смещение чтобы не конфликтовать

    # Шаг 1: стартуем BL-конфиг в глобальном режиме
    inner_cfg = _build_bl_inner_config(link, inner_port)
    if inner_cfg is None:
        return False

    proc_inner, tmp_inner = _start_xray_raw(inner_cfg, xray_exe)
    if proc_inner is None:
        return False

    try:
        if not _wait_port(inner_port, timeout=4.0):
            return False

        # Шаг 2: проверяем через inner SOCKS (BL-конфиг в глобальном режиме)
        proxies = {
            "http":  f"socks5h://127.0.0.1:{inner_port}",
            "https": f"socks5h://127.0.0.1:{inner_port}",
        }

        if stage == 1:
            ms = _http_check_ms(proxies, CHECK1_URL, CHECK1_TIMEOUT)
            return ms is not None and ms >= CHECK1_MIN_MS
        elif stage == 2:
            ms = _http_check_ms(proxies, CHECK2_URL, CHECK2_TIMEOUT)
            return ms is not None and ms >= CHECK2_MIN_MS
        else:  # stage == 3
            ms = _http_check_ms(proxies, CHECK3_URL, CHECK3_TIMEOUT,
                                stream=True, max_bytes=CHECK3_BYTES)
            return ms is not None and ms >= CHECK3_MIN_MS

    except Exception:
        return False
    finally:
        _kill_xray(proc_inner, tmp_inner)


def check_bl_config_full(link: str, xray_exe: str, port_base: int) -> bool:
    """Полная трёхэтапная проверка BL-конфига через DPI(Reality)+VPN цепочку.

    Используется при ручном добавлении конфига и в splash-проверке.
    Возвращает True если конфиг прошёл все три этапа.
    """
    if not _check_bl_config_via_chain(link, xray_exe, port_base, stage=1):
        return False
    if not _check_bl_config_via_chain(link, xray_exe, port_base + 1, stage=2):
        return False
    if not _check_bl_config_via_chain(link, xray_exe, port_base + 2, stage=3):
        return False
    return True


# ---------------------------------------------------------------------------
# Структуры данных
# ---------------------------------------------------------------------------

@dataclass
class FetchResult:
    url: str
    added: int = 0
    trash: int = 0
    error: str | None = None


@dataclass
class FetchSummary:
    total_urls: int = 0
    successful_urls: int = 0
    new_configs: int = 0
    duplicate_configs: int = 0
    filtered_configs: int = 0
    ping_filtered: int = 0
    speed_filtered: int = 0
    live_filtered: int = 0
    country_filtered: int = 0
    links: list[str] = field(default_factory=list)
    # ping_ms и speed_mbps для каждой итоговой ссылки
    ping_map: dict[str, int] = field(default_factory=dict)
    speed_map: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Async fetch — ускорение через asyncio + aiohttp-like через ThreadPool
# ---------------------------------------------------------------------------

def _fetch_all_async(
    urls: list[str],
    filter_enabled: bool,
    progress_cb,      # callable(done, total, url, added)
    cancelled: threading.Event,
    workers: int = 50,
) -> tuple[set[str], int, list[str]]:
    """
    Параллельно скачиваем все URLs через asyncio + ThreadPoolExecutor.
    Возвращает (seen_links, trash_count, errors).
    """
    seen: set[str] = set()
    lock = threading.Lock()
    trash_total = 0
    errors: list[str] = []
    done_count = 0
    total = len(urls)

    loop = asyncio.new_event_loop()

    def _fetch_sync(url: str) -> FetchResult:
        r = FetchResult(url=url)
        try:
            resp = requests.get(url, timeout=12, headers=HEADERS)
            if resp.status_code != 200:
                r.error = f"HTTP {resp.status_code}"
                return r
            content = resp.text.strip()
            if not content:
                r.error = "пустой ответ"
                return r
            if "://" not in content:
                try:
                    content = base64.b64decode(content + "==").decode("utf-8", errors="ignore")
                except Exception:
                    pass
            lines = []
            for line in content.splitlines():
                line = line.strip()
                if not protocol_of(line):
                    continue
                if not filter_enabled or is_good_key(line):
                    lines.append(line)
                    r.added += 1
                else:
                    r.trash += 1
            with lock:
                seen.update(lines)
        except requests.exceptions.Timeout:
            r.error = "таймаут"
        except Exception as e:
            r.error = str(e)
        return r

    async def _run_fetch(url: str) -> FetchResult:
        return await loop.run_in_executor(None, _fetch_sync, url)

    semaphore = asyncio.Semaphore(workers)

    async def _bounded(url: str) -> FetchResult:
        async with semaphore:
            return await _run_fetch(url)

    async def _main():
        nonlocal done_count, trash_total
        tasks = [asyncio.ensure_future(_bounded(u)) for u in urls]
        for coro in asyncio.as_completed(tasks):
            if cancelled.is_set():
                for t in tasks:
                    t.cancel()
                break
            result = await coro
            done_count += 1
            trash_total += result.trash
            if result.error:
                errors.append(f"{result.url}: {result.error}")
            progress_cb(done_count, total, result.url, result.added)

    try:
        loop.run_until_complete(_main())
    finally:
        loop.close()

    return seen, trash_total, errors


# ---------------------------------------------------------------------------
# Основной воркер
# ---------------------------------------------------------------------------

class ConfigFetchWorker(QThread):
    """
    Fetch → Ping → Speed → Live → Filter.
    Все этапы параллельны. Splash подключает этот воркер напрямую.
    """

    progress      = pyqtSignal(int, int, str, int)
    ping_progress = pyqtSignal(int, int)
    speed_progress = pyqtSignal(int, int)
    live_progress = pyqtSignal(int, int)
    stage         = pyqtSignal(str)
    finished      = pyqtSignal(object)
    error         = pyqtSignal(str)

    def __init__(
        self,
        extra_urls: list[str] | None = None,
        workers: int = 50,
        filter_enabled: bool = True,
        max_ping_ms: int = MAX_PING_MS,
        max_configs: int = MAX_CONFIGS,
        max_per_country: int = MAX_PER_COUNTRY,
        skip_live_check: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._extra_urls      = extra_urls or []
        self._workers         = workers
        self._filter_enabled  = filter_enabled
        self._max_ping_ms     = max_ping_ms
        self._max_configs     = max_configs
        self._max_per_country = max_per_country
        self._skip_live_check = skip_live_check
        self._cancelled       = False
        self._cancel_event    = threading.Event()

    def cancel(self) -> None:
        self._cancelled = True
        self._cancel_event.set()

    def run(self) -> None:
        try:
            summary = self._run_all()
            if not self._cancelled:
                self.finished.emit(summary)
        except Exception as exc:
            logger.exception("ConfigFetchWorker crashed: %s", exc)
            self.error.emit(str(exc))

    def _run_all(self) -> FetchSummary:
        summary = FetchSummary(total_urls=1)

        # ── Единственный источник: Приватный GitHub ────────────────────────
        # В VPN-клиенте у пользователя проверка ТОЛЬКО по приватному GitHub.
        # Публичные источники не используются — конфиги туда попадают только
        # через admin-скрипт после полной верификации.
        self.stage.emit("🔐  Загружаем конфиги из приватного GitHub...")
        github_links = self._load_from_private_github()

        if not github_links:
            self.stage.emit("⚠️  Приватный GitHub недоступен или пуст")
            summary.links = []
            return summary

        self.stage.emit(
            f"📡  GitHub: {len(github_links)} конфигов, проверяем пинг..."
        )
        summary.new_configs = len(github_links)

        # ── Быстрый TCP-пинг ──────────────────────────────────────────────
        pinged = self._run_ping_filter(github_links, summary)
        if self._cancelled or not pinged:
            summary.links = pinged
            return summary

        # ── Трёхэтапная xray-проверка (включая DPI(Reality)+VPN для BL) ──
        # BL-конфиги автоматически проходят через chain-режим (_check_stage1/2/3).
        xray_exe = _find_xray_exe()
        all_links = pinged

        if xray_exe and all_links:
            self.stage.emit("🔍  Проверка ya.ru через xray (CIDR/Reality + BL-цепочка)...")
            all_links = self._run_check_stage(
                all_links, summary, xray_exe,
                stage_num=1,
                check_fn=_check_stage1,
                label="ya.ru",
                port_base=LIVE_SOCKS_PORT_BASE,
                early_exit_count=self._max_configs * 3,
            )
        else:
            self.stage.emit("⚠️  Проверка пропущена: xray.exe не найден")

        if self._cancelled:
            summary.links = all_links
            return summary

        if xray_exe and all_links:
            self.stage.emit("🔍  Проверка google.com...")
            all_links = self._run_check_stage(
                all_links, summary, xray_exe,
                stage_num=2,
                check_fn=_check_stage2,
                label="google.com",
                port_base=LIVE_SOCKS_PORT_BASE + 300,
                early_exit_count=self._max_configs * 2,
            )

        if self._cancelled:
            summary.links = all_links
            return summary

        if not self._skip_live_check and xray_exe and all_links:
            self.stage.emit("🔍  Проверка скорости 100kb.txt...")
            all_links = self._run_check_stage(
                all_links, summary, xray_exe,
                stage_num=3,
                check_fn=_check_stage3,
                label="100kb.txt",
                port_base=LIVE_SOCKS_PORT_BASE + 600,
                early_exit_count=self._max_configs,
            )

        if self._cancelled:
            summary.links = all_links
            return summary

        # ── Страновой лимит ───────────────────────────────────────────────
        self.stage.emit(
            f"🌍  Отбор: макс. {self._max_per_country} на страну, итого {self._max_configs}..."
        )
        final_links, country_filtered = self._apply_country_limit(all_links)
        summary.country_filtered = country_filtered
        summary.links = final_links

        self.stage.emit(
            f"✅  Готово! Конфигов: {len(final_links)}  •  "
            f"Пинг: -{summary.ping_filtered}  •  "
            f"ya.ru: -{summary.speed_filtered}  •  "
            f"google: -{summary.live_filtered}"
        )
        return summary

    def _load_from_private_github(self) -> list[str]:
        """Читает и расшифровывает проверенные конфиги из приватного GitHub-репо.

        Использует тот же cfg_ptr.bin + config_github_sync.py что и
        ConfigGithubSyncWorker — единый источник правды.
        Возвращает список ссылок или [] если репо недоступен / файл не найден.
        """
        try:
            from .config_github_sync import (
                _load_github_cfg, _make_passphrase,
                _github_get_file, decrypt_configs,
            )
            cfg = _load_github_cfg()
            if not cfg:
                return []
            passphrase = _make_passphrase(
                cfg.get("token", ""), cfg.get("nonce", "")
            )
            filename = cfg.get("configs_filename", "c0nf1gs.bin")
            raw = _github_get_file(cfg["token"], cfg["owner"], cfg["repo"], filename)
            if not raw:
                return []
            links = decrypt_configs(raw.strip(), passphrase)
            logger.info("[config_fetch] Приватный GitHub: %d конфигов загружено", len(links))
            return links
        except Exception as e:
            logger.warning("[config_fetch] Приватный GitHub недоступен: %s", e)
            return []

    def _run_ping_filter(self, links: list[str], summary: FetchSummary) -> list[str]:
        total = len(links)
        self.stage.emit(f"📡  TCP-пинг {total} конфигов ({PING_WORKERS} потоков, порог {self._max_ping_ms} мс)...")

        results: list[tuple[int, str]] = []
        lock = threading.Lock()
        done_count = 0

        def _ping_task(link: str) -> tuple[str, int | None]:
            hp = _extract_host_port(link)
            if not hp:
                return link, None
            return link, _tcp_ping(hp[0], hp[1])

        with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
            futures = {ex.submit(_ping_task, lnk): lnk for lnk in links}
            for future in as_completed(futures):
                if self._cancelled:
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                link, ms = future.result()
                with lock:
                    done_count += 1
                    if ms is not None and ms <= self._max_ping_ms:
                        results.append((ms, link))
                        summary.ping_map[link] = ms
                    else:
                        summary.ping_filtered += 1
                self.ping_progress.emit(done_count, total)
                if done_count % 100 == 0 or done_count == total:
                    self.stage.emit(
                        f"📡  Пинг {done_count}/{total}  •  "
                        f"прошли: {len(results)}  •  отброшено: {summary.ping_filtered}"
                    )

        results.sort(key=lambda t: t[0])
        return [lnk for _, lnk in results]

    def _run_check_stage(
        self,
        links: list[str],
        summary: FetchSummary,
        xray_exe: str,
        stage_num: int,
        check_fn,
        label: str,
        port_base: int,
        early_exit_count: int = 0,
    ) -> list[str]:
        """Универсальный этап проверки: запускает check_fn параллельно.
        early_exit_count > 0: останавливаемся как только найдено достаточно рабочих.
        """
        total = len(links)
        self.stage.emit(
            f"{'⚡' if stage_num == 3 else '🌐'}  Этап {stage_num}/3: {label} — "
            f"{total} конфигов ({CHECK_WORKERS} потоков)..."
        )

        results: list[str] = []
        filtered_count = [0]
        lock = threading.Lock()
        done_count = [0]
        early_stop = [False]

        port_counter = [port_base]
        port_lock = threading.Lock()

        def _get_port() -> int:
            with port_lock:
                p = port_counter[0]
                port_counter[0] += 1
                return p

        def _task(link: str) -> tuple[str, bool]:
            if early_stop[0]:
                return link, False
            port = _get_port()
            return link, check_fn(link, xray_exe, port)

        with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as ex:
            futures = {ex.submit(_task, lnk): lnk for lnk in links}
            for future in as_completed(futures):
                if self._cancelled:
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                link, ok = future.result()
                with lock:
                    done_count[0] += 1
                    if ok:
                        results.append(link)
                    else:
                        filtered_count[0] += 1
                        if stage_num == 1:
                            summary.speed_filtered += 1
                        elif stage_num == 2:
                            summary.live_filtered += 1
                    # Ранний выход — нашли достаточно рабочих конфигов
                    if early_exit_count > 0 and len(results) >= early_exit_count:
                        early_stop[0] = True
                        ex.shutdown(wait=False, cancel_futures=True)
                if stage_num in (1, 2):
                    signal = self.speed_progress if stage_num == 1 else self.live_progress
                    signal.emit(done_count[0], total)
                if done_count[0] % 5 == 0 or done_count[0] == total or early_stop[0]:
                    self.stage.emit(
                        f"{'⚡' if stage_num == 3 else '🌐'}  Этап {stage_num}/3 {label}  "
                        f"{done_count[0]}/{total}  •  "
                        f"рабочих: {len(results)}  •  отброшено: {filtered_count[0]}"
                        + (" ✓ EARLY EXIT" if early_stop[0] else "")
                    )
                if early_stop[0]:
                    break

        logger.info("Check stage %d (%s): %d passed / %d total", stage_num, label, len(results), total)
        return results

    def _apply_country_limit(self, links: list[str]) -> tuple[list[str], int]:
        # Исключаем конфиги из страны самого пользователя — через них нет смысла.
        user_cc = _get_cached_user_country()
        per_country: dict[str, int] = defaultdict(int)
        result: list[str] = []
        filtered = 0
        for link in links:
            if len(result) >= self._max_configs:
                filtered += len(links) - links.index(link)
                break
            cc = _guess_country(link)
            # Фильтруем конфиги из страны пользователя (если удалось определить)
            if user_cc and cc == user_cc:
                filtered += 1
                logger.debug("[geo] Отброшен конфиг из страны пользователя (%s): %.60s", cc, link)
                continue
            if per_country[cc] >= self._max_per_country:
                filtered += 1
                continue
            per_country[cc] += 1
            result.append(link)
        return result, filtered

    def _fetch_one(self, url: str, seen: set[str], lock: threading.Lock) -> FetchResult:
        result = FetchResult(url=url)
        try:
            resp = requests.get(url, timeout=12, headers=HEADERS)
            if resp.status_code != 200:
                result.error = f"HTTP {resp.status_code}"
                return result
            content = resp.text.strip()
            if not content:
                result.error = "пустой ответ"
                return result
            if "://" not in content:
                try:
                    content = base64.b64decode(content + "==").decode("utf-8", errors="ignore")
                except Exception:
                    pass
            new_lines: list[str] = []
            for line in content.splitlines():
                line = line.strip()
                if not protocol_of(line):
                    continue
                if not self._filter_enabled or is_good_key(line):
                    new_lines.append(line)
                    result.added += 1
                else:
                    result.trash += 1
            with lock:
                seen.update(new_lines)
        except requests.exceptions.Timeout:
            result.error = "таймаут"
        except requests.exceptions.ConnectionError as e:
            result.error = f"нет соединения: {e}"
        except Exception as e:
            result.error = str(e)
        return result


# ---------------------------------------------------------------------------
# Фоновое обновление каждые 5 минут
# ---------------------------------------------------------------------------

class BackgroundRefreshWorker(QThread):
    """
    Фоновый воркер: каждые BG_INTERVAL_SEC секунд обновляет конфиги.

    Источник: ТОЛЬКО приватный GitHub (публичные источники не используются).

    Pipeline:
      1. GitHub   — читаем зашифрованный файл конфигов из приватного репо
      2. TCP-пинг — 30 потоков, отсеиваем протухшие хосты (≤ MAX_PING_MS)
      3. xray-проверка — ya.ru этап через xray:
           • CIDR/Reality-конфиги — стандартная проверка (_check_stage1)
           • BL-конфиги           — DPI(Reality)+VPN цепочка (_check_bl_config_via_chain)
         Этапы 2 (google.com) и 3 (100kb.txt) пропускаются в фоне для скорости.

    Принципы:
    - Не влияет на основной поток и активное подключение
    - Поднимает собственные xray-инстансы на портах BG_SOCKS_PORT_BASE+
    - Не использует системный прокси
    - При обнаружении рабочих конфигов испускает refresh_done(FetchSummary)

    Использование:
        worker = BackgroundRefreshWorker()
        worker.refresh_done.connect(controller._on_bg_refresh_done)
        worker.start()
        worker.stop()  # при остановке
    """

    refresh_done = pyqtSignal(object)   # FetchSummary
    status_line  = pyqtSignal(str)      # краткий статус для лога

    def __init__(
        self,
        extra_urls: list[str] | None = None,
        filter_enabled: bool = True,
        parent=None,
    ):
        super().__init__(parent)
        self._extra_urls     = extra_urls or []
        self._filter_enabled = filter_enabled
        self._stop_event     = threading.Event()
        self._cancel_event   = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()
        self._cancel_event.set()
        self.quit()

    def run(self) -> None:
        logger.info("[bg_refresh] Старт (interval=%ds, источник: только приватный GitHub)", BG_INTERVAL_SEC)
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=BG_INTERVAL_SEC)
            if self._stop_event.is_set():
                break

            self._cancel_event.clear()
            self.status_line.emit("[bg_refresh] Фоновое обновление...")
            try:
                summary = self._run_pipeline()
                if not self._stop_event.is_set() and summary.links:
                    self.status_line.emit(
                        f"[bg_refresh] Готово: {len(summary.links)} конфигов "
                        f"(ping:-{summary.ping_filtered} live:-{summary.live_filtered})"
                    )
                    self.refresh_done.emit(summary)
                elif not summary.links:
                    self.status_line.emit("[bg_refresh] Нет рабочих конфигов")
            except Exception as e:
                logger.exception("[bg_refresh] Ошибка: %s", e)
                self.status_line.emit(f"[bg_refresh] Ошибка: {e}")

    def _run_pipeline(self) -> FetchSummary:
        """Фоновый pipeline: только приватный GitHub + TCP-пинг + xray ya.ru.

        BL-конфиги проходят через DPI(Reality)+VPN цепочку (_check_bl_config_via_chain),
        CIDR/Reality-конфиги — через стандартный _check_stage1.
        Этапы google.com и 100kb.txt пропускаются для скорости фонового цикла.
        """
        summary = FetchSummary(total_urls=1)

        # ── Этап 1: Приватный GitHub ───────────────────────────────────────
        links = self._load_from_private_github()
        summary.new_configs = len(links)
        if self._stop_event.is_set() or not links:
            summary.links = []
            return summary

        logger.info("[bg_refresh] GitHub: %d конфигов получено", len(links))

        # ── Этап 2: TCP-пинг (30 потоков) ─────────────────────────────────
        pinged = self._bg_ping(links, summary)
        if self._stop_event.is_set() or not pinged:
            summary.links = pinged
            return summary

        logger.info("[bg_refresh] После пинга: %d конфигов (отсеяно: %d)",
                    len(pinged), summary.ping_filtered)

        # ── Этап 3: xray ya.ru (CIDR/Reality + BL chain) ──────────────────
        xray_exe = _find_xray_exe()
        if not xray_exe:
            logger.info("[bg_refresh] xray не найден — пропускаем live-проверку")
            summary.links = pinged
            return summary

        verified = self._bg_live_check(pinged, summary, xray_exe)
        if self._stop_event.is_set():
            summary.links = verified
            return summary

        logger.info("[bg_refresh] После ya.ru-проверки: %d конфигов (отсеяно: %d)",
                    len(verified), summary.live_filtered)

        summary.links = verified
        return summary

    def _bg_live_check(
        self,
        links: list[str],
        summary: FetchSummary,
        xray_exe: str,
    ) -> list[str]:
        """Фоновая xray-проверка (ya.ru / этап 1).

        CIDR/Reality-конфиги: стандартный _check_stage1.
        BL-конфиги: _check_bl_config_via_chain (DPI(Reality)+VPN цепочка).

        Параллельность: до 8 потоков одновременно.
        Порты: BG_SOCKS_PORT_BASE + смещение × 10.
        """
        _BG_LIVE_WORKERS = 8
        results: list[str] = []
        lock = threading.Lock()
        port_counter = [0]

        def _task(link: str) -> tuple[str, bool]:
            if self._stop_event.is_set():
                return link, False
            with lock:
                slot = port_counter[0]
                port_counter[0] += 1
            port = BG_SOCKS_PORT_BASE + slot * 10

            try:
                if _is_bl_config(link):
                    # BL-конфиг: запускаем в глобальном режиме (без split-tunnel)
                    ok = _check_bl_config_via_chain(link, xray_exe, port, stage=1)
                else:
                    # CIDR/Reality: стандартная проверка ya.ru
                    ok = _check_stage1(link, xray_exe, port)
            except Exception as e:
                logger.debug("[bg_refresh] live-check error %s: %s", link[:40], e)
                ok = False
            return link, ok

        with ThreadPoolExecutor(max_workers=_BG_LIVE_WORKERS) as ex:
            futures = {ex.submit(_task, lnk): lnk for lnk in links}
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                link, ok = future.result()
                with lock:
                    if ok:
                        results.append(link)
                    else:
                        summary.live_filtered += 1

        return results

    def _load_from_private_github(self) -> list[str]:
        """Читает и расшифровывает конфиги из приватного GitHub-репо."""
        try:
            from .config_github_sync import (
                _load_github_cfg, _make_passphrase,
                _github_get_file, decrypt_configs,
            )
            cfg = _load_github_cfg()
            if not cfg:
                return []
            passphrase = _make_passphrase(
                cfg.get("token", ""), cfg.get("nonce", "")
            )
            filename = cfg.get("configs_filename", "c0nf1gs.bin")
            raw = _github_get_file(cfg["token"], cfg["owner"], cfg["repo"], filename)
            if not raw:
                return []
            links = decrypt_configs(raw.strip(), passphrase)
            logger.info("[bg_refresh] Приватный GitHub: %d конфигов", len(links))
            return links
        except Exception as e:
            logger.warning("[bg_refresh] GitHub недоступен: %s", e)
            return []

    _BG_PING_WORKERS = 30

    def _bg_ping(self, links: list[str], summary: FetchSummary) -> list[str]:
        results: list[tuple[int, str]] = []
        lock = threading.Lock()

        def _task(link: str) -> tuple[str, int | None]:
            if self._stop_event.is_set():
                return link, None
            hp = _extract_host_port(link)
            if not hp:
                return link, None
            return link, _tcp_ping(hp[0], hp[1])

        with ThreadPoolExecutor(max_workers=self._BG_PING_WORKERS) as ex:
            futures = {ex.submit(_task, lnk): lnk for lnk in links}
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                link, ms = future.result()
                with lock:
                    if ms is not None and ms <= MAX_PING_MS:
                        results.append((ms, link))
                        summary.ping_map[link] = ms
                    else:
                        summary.ping_filtered += 1

        results.sort(key=lambda t: t[0])
        return [lnk for _, lnk in results]


# ---------------------------------------------------------------------------
# Дедупликация
# ---------------------------------------------------------------------------

def deduplicate_links(links: list[str]) -> list[str]:
    seen: set[tuple] = set()
    result: list[str] = []
    for line in links:
        try:
            u = urllib.parse.urlparse(line)
            key = (u.hostname, u.port or 443, u.scheme)
            if key not in seen:
                seen.add(key)
                result.append(line)
        except Exception:
            pass
    return result
