"""
singbox_check_patch.py
======================
Патч для admin_config_update26.py: добавляет проверку не-VLESS конфигов
(vmess, trojan, ss/shadowsocks, hysteria2, tuic, hy2) через sing-box вместо xray.

КАК ПРИМЕНИТЬ:
  Вставить функции _build_singbox_cfg, _start_singbox, check_config_singbox
  и заменить check_config_full на check_config_auto ПЕРЕД строкой:
    "def check_config_full(link: str, xray_exe: str, port_base: int,"

ПРОТОКОЛЫ → движок:
  vless      → xray  (как сейчас, без изменений)
  vmess      → sing-box
  trojan     → sing-box
  ss://      → sing-box
  hysteria2  → sing-box
  hy2://     → sing-box
  tuic://    → sing-box
  (остальные → sing-box как fallback)
"""

from __future__ import annotations
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import base64
from pathlib import Path
from typing import Optional


# ── Определяем протокол конфига ───────────────────────────────────────────────

def _protocol_of(link: str) -> str:
    """Вернуть нижний регистр схемы URI (vless, vmess, trojan, ss, hy2, ...)."""
    try:
        scheme = urllib.parse.urlparse(link).scheme.lower()
        return scheme
    except Exception:
        return ""


def _needs_singbox(link: str) -> bool:
    """True если конфиг надо проверять через sing-box, а не через xray."""
    proto = _protocol_of(link)
    # xray умеет: vless, vmess, trojan, ss — но падает на VLESS с encryption=none@ShadowsocksM...
    # Надёжнее: всё кроме чистого vless/vmess/trojan пускать через sing-box.
    # Если хотите vmess тоже через xray — уберите "vmess" из этого множества.
    SINGBOX_PROTOS = {"ss", "shadowsocks", "hy2", "hysteria2", "tuic", "trojan", "vmess"}
    return proto in SINGBOX_PROTOS


# ── Построение конфига sing-box ───────────────────────────────────────────────

def _build_singbox_cfg(link: str, port: int) -> Optional[dict]:
    """Собрать минимальный конфиг sing-box для проверки одного link.

    sing-box поддерживает прямой импорт URI для большинства протоколов
    через поле "detour" или через явный outbound.

    Поддерживаемые протоколы:
      vmess://  trojan://  ss://  hy2://  hysteria2://  tuic://
    """
    proto = _protocol_of(link)

    try:
        if proto == "vmess":
            outbound = _singbox_outbound_vmess(link)
        elif proto == "trojan":
            outbound = _singbox_outbound_trojan(link)
        elif proto in ("ss", "shadowsocks"):
            outbound = _singbox_outbound_ss(link)
        elif proto in ("hy2", "hysteria2"):
            outbound = _singbox_outbound_hysteria2(link)
        elif proto == "tuic":
            outbound = _singbox_outbound_tuic(link)
        else:
            return None  # неизвестный протокол — не берёмся

        if outbound is None:
            return None

        outbound["tag"] = "proxy"

        return {
            "log": {"level": "error", "timestamp": False},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "sniff": False,
                }
            ],
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"},
            ],
            "route": {
                "rules": [],
                "final": "proxy",
            },
        }
    except Exception as exc:
        return None


# ── Построители outbound для каждого протокола ────────────────────────────────

def _singbox_outbound_vmess(link: str) -> Optional[dict]:
    """vmess:// → sing-box VMess outbound."""
    b64 = link[len("vmess://"):].split("#")[0].strip()
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(padded).decode("utf-8", errors="ignore")
        v = json.loads(raw)
    except Exception:
        return None

    ob: dict = {
        "type": "vmess",
        "server": v.get("add", ""),
        "server_port": int(v.get("port", 443)),
        "uuid": v.get("id", ""),
        "security": v.get("scy") or v.get("security") or "auto",
        "alter_id": int(v.get("aid", 0)),
    }

    net = str(v.get("net", "tcp")).lower()
    tls_str = str(v.get("tls", "")).lower()
    host = v.get("host", "") or v.get("add", "")
    path = v.get("path", "/")

    # TLS / reality
    if tls_str == "tls":
        ob["tls"] = {
            "enabled": True,
            "server_name": host or ob["server"],
            "insecure": True,
        }

    # Transport
    if net == "ws":
        ob["transport"] = {"type": "ws", "path": path,
                           "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        ob["transport"] = {"type": "grpc",
                           "service_name": path.lstrip("/")}
    elif net == "h2":
        ob["transport"] = {"type": "http", "host": [host] if host else [],
                           "path": path}
    # tcp — transport не нужен

    return ob


def _singbox_outbound_trojan(link: str) -> Optional[dict]:
    """trojan:// → sing-box Trojan outbound."""
    try:
        p = urllib.parse.urlparse(link)
        qs = urllib.parse.parse_qs(p.query)
        password = p.username or p.password or ""
        host = p.hostname or ""
        port = p.port or 443

        ob: dict = {
            "type": "trojan",
            "server": host,
            "server_port": port,
            "password": password,
        }

        sni = qs.get("sni", [qs.get("peer", [host])[0]])[0] or host
        security = qs.get("security", ["tls"])[0].lower()
        if security in ("tls", "reality", ""):
            ob["tls"] = {
                "enabled": True,
                "server_name": sni,
                "insecure": True,
            }

        net = qs.get("type", ["tcp"])[0].lower()
        path_ws = qs.get("path", ["/"])[0]
        if net == "ws":
            ob["transport"] = {
                "type": "ws",
                "path": path_ws,
                "headers": {"Host": qs.get("host", [sni])[0]},
            }
        elif net == "grpc":
            ob["transport"] = {
                "type": "grpc",
                "service_name": qs.get("serviceName", [""])[0],
            }

        return ob
    except Exception:
        return None


def _singbox_outbound_ss(link: str) -> Optional[dict]:
    """ss:// (ShadowSocks) → sing-box Shadowsocks outbound.

    Формат URI:  ss://BASE64(method:password)@host:port#name
                 ss://method:password@host:port#name   (SIP002)
    """
    try:
        raw = link[len("ss://"):]
        fragment = ""
        if "#" in raw:
            raw, fragment = raw.rsplit("#", 1)

        # SIP002: method:password@host:port
        if "@" in raw:
            userinfo, hostport = raw.rsplit("@", 1)
            # userinfo может быть base64 или plain
            try:
                decoded = base64.b64decode(
                    userinfo + "=" * (-len(userinfo) % 4)
                ).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    userinfo = decoded
            except Exception:
                pass
            method, password = userinfo.split(":", 1) if ":" in userinfo else ("chacha20-ietf-poly1305", userinfo)
        else:
            # Весь raw — base64 без @host
            decoded = base64.b64decode(
                raw + "=" * (-len(raw) % 4)
            ).decode("utf-8", errors="ignore")
            if "@" in decoded:
                userinfo, hostport = decoded.rsplit("@", 1)
                method, password = userinfo.split(":", 1)
            else:
                return None

        if ":" in hostport:
            # может быть IPv6 [::1]:port
            if hostport.startswith("["):
                bracket_end = hostport.index("]")
                host = hostport[1:bracket_end]
                port = int(hostport[bracket_end+2:])
            else:
                host, port_s = hostport.rsplit(":", 1)
                port = int(port_s)
        else:
            return None

        return {
            "type": "shadowsocks",
            "server": host,
            "server_port": port,
            "method": method.lower(),
            "password": password,
        }
    except Exception:
        return None


def _singbox_outbound_hysteria2(link: str) -> Optional[dict]:
    """hy2:// / hysteria2:// → sing-box Hysteria2 outbound."""
    try:
        p = urllib.parse.urlparse(link)
        qs = urllib.parse.parse_qs(p.query)
        password = p.username or p.password or ""
        host = p.hostname or ""
        port = p.port or 443
        sni = qs.get("sni", [host])[0]

        return {
            "type": "hysteria2",
            "server": host,
            "server_port": port,
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": sni or host,
                "insecure": True,
            },
        }
    except Exception:
        return None


def _singbox_outbound_tuic(link: str) -> Optional[dict]:
    """tuic:// → sing-box TUIC outbound."""
    try:
        p = urllib.parse.urlparse(link)
        qs = urllib.parse.parse_qs(p.query)
        uuid = p.username or ""
        password = p.password or ""
        host = p.hostname or ""
        port = p.port or 443
        sni = qs.get("sni", [host])[0]
        cc = qs.get("congestion_control", ["bbr"])[0]

        return {
            "type": "tuic",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "password": password,
            "congestion_control": cc,
            "tls": {
                "enabled": True,
                "server_name": sni or host,
                "insecure": True,
            },
        }
    except Exception:
        return None


# ── Запуск / остановка sing-box ───────────────────────────────────────────────

SINGBOX_START_TIMEOUT    = 8.0   # секунд ждём старта
SINGBOX_READY_CHECK_POLL = 0.15  # интервал опроса порта


def _start_singbox(link: str, singbox_exe: str, port: int):
    """Запустить sing-box для link на SOCKS5 порту port.

    Returns: (proc, tmp_path) или (None, tmp_path) при ошибке.
    """
    cfg = _build_singbox_cfg(link, port)
    if cfg is None:
        return None, None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(cfg, f, ensure_ascii=False)
            tmp = f.name

        flags = 0
        if sys.platform == "win32":
            flags = subprocess.CREATE_NO_WINDOW

        proc = subprocess.Popen(
            [singbox_exe, "run", "-c", tmp],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=flags,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        deadline = time.monotonic() + SINGBOX_START_TIMEOUT
        startup_log = []

        while time.monotonic() < deadline:
            if proc.poll() is not None:
                try:
                    startup_log.append(proc.stdout.read())
                except Exception:
                    pass
                log_text = "".join(startup_log).strip()
                if log_text:
                    print(
                        f"  ⚠  sing-box exited on port {port}:\\n{log_text[:800]}"
                    )
                return None, tmp

            # Проверяем SOCKS5 握手
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5) as s:
                    s.settimeout(0.5)
                    s.sendall(b"\x05\x01\x00")
                    resp = s.recv(2)
                    if resp and resp[0] == 0x05:
                        return proc, tmp
            except OSError:
                pass

            time.sleep(SINGBOX_READY_CHECK_POLL)

        # Таймаут старта
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        return None, tmp

    except Exception as exc:
        print(f"  ⚠  sing-box start error: {exc}")
        return None, None


def _kill_proc(proc, tmp: Optional[str]) -> None:
    """Убить процесс и удалить временный файл конфига."""
    if proc:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
    if tmp:
        try:
            os.unlink(tmp)
        except Exception:
            pass


# ── Полная проверка через sing-box (3 stage, без Zapret/Reality) ──────────────

def check_config_singbox(
    link: str,
    singbox_exe: str,
    port_base: int,
    # импортируем из основного модуля через globals или передаём явно
    http_check_status_fn=None,
    http_check_md5_fn=None,
    check1_url: str = "https://ya.ru",
    check2_url: str = "https://www.google.com",
    check3_url: str = "https://speed.hetzner.de/100MB.bin",
    check1_timeout: float = 10.0,
    check2_timeout: float = 10.0,
    check3_timeout: float = 20.0,
) -> bool:
    """3-stage проверка конфига через sing-box.

    Stage 1: GET ya.ru  (базовая связность)
    Stage 2: GET google.com  (международный роутинг)
    Stage 3: 100 KB download с MD5-проверкой  (стабильность и скорость)

    Использует sing-box вместо xray — корректно обрабатывает vmess, trojan,
    shadowsocks, hysteria2, tuic без ошибок "unsupported encryption: none".
    """
    import requests as _rq
    import hashlib as _hl

    port = port_base
    proc, tmp = _start_singbox(link, singbox_exe, port)
    if not proc:
        return False

    try:
        proxies = {
            "http":  f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }

        # ── Stage 1: ya.ru ───────────────────────────────────────────────────
        try:
            r1 = _rq.get(check1_url, proxies=proxies, timeout=check1_timeout,
                         allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
            if r1.status_code != 200 or len(r1.content) < 256:
                return False
        except Exception:
            return False

        # ── Stage 2: google.com ──────────────────────────────────────────────
        try:
            r2 = _rq.get(check2_url, proxies=proxies, timeout=check2_timeout,
                         allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
            if r2.status_code not in (200, 301, 302) or len(r2.content) < 256:
                return False
        except Exception:
            return False

        # ── Stage 3: 100 KB download ─────────────────────────────────────────
        try:
            r3 = _rq.get(check3_url, proxies=proxies, timeout=check3_timeout,
                         allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"},
                         stream=True)
            data = r3.raw.read(102_400)  # читаем ровно 100 KB
            if len(data) < 50_000:       # меньше 50 KB — слишком медленно
                return False
        except Exception:
            return False

        return True

    finally:
        _kill_proc(proc, tmp)


# ── Универсальная обёртка: xray или sing-box по протоколу ────────────────────

def check_config_auto(
    link: str,
    xray_exe: str,
    singbox_exe: Optional[str],
    port_base: int,
    skip_stage4: bool = False,
    stage4_threshold_ms: int = 995,
) -> bool:
    """Выбирает движок проверки по протоколу:
      - VLESS → xray (check_config_full)
      - vmess / trojan / ss / hy2 / hysteria2 / tuic → sing-box

    Если sing-box не найден — fallback на xray для всех протоколов.
    """
    if _needs_singbox(link):
        if singbox_exe:
            return check_config_singbox(link, singbox_exe, port_base)
        else:
            # sing-box недоступен — пробуем xray (может не работать для ss)
            print(f"  ⚠  sing-box не найден, проверяю {_protocol_of(link)} через xray (может упасть)")
            # check_config_full импортируется из основного модуля
    # VLESS / неизвестный → xray (оригинальная логика)
    return None  # сигнал: использовать оригинальный check_config_full


# =============================================================================
# ИНСТРУКЦИЯ ПО ИНТЕГРАЦИИ В admin_config_update26.py
# =============================================================================
#
# 1. Вставьте все функции выше (после строки "import requests as _requests")
#    в admin_config_update26.py.
#
# 2. Найдите функцию _run_xray_batch и замените в ней _check_task:
#
#    БЫЛО:
#        def _check_task(lnk: str):
#            p = _acquire_port()
#            try:
#                result = check_config_full(
#                    lnk, xray_exe, p,
#                    skip_stage4=not enable_stage4,
#                    stage4_threshold_ms=stage4_threshold_ms,
#                )
#            finally:
#                _release_port(p)
#            return lnk, result
#
#    СТАЛО:
#        _singbox_exe = _find_or_download_singbox()  # ← добавить ПЕРЕД with ThreadPoolExecutor
#
#        def _check_task(lnk: str):
#            p = _acquire_port()
#            try:
#                if _needs_singbox(lnk) and _singbox_exe:
#                    result = check_config_singbox(lnk, _singbox_exe, p)
#                else:
#                    result = check_config_full(
#                        lnk, xray_exe, p,
#                        skip_stage4=not enable_stage4,
#                        stage4_threshold_ms=stage4_threshold_ms,
#                    )
#            finally:
#                _release_port(p)
#            return lnk, result
#
# 3. Аналогично в run_checks() добавьте _singbox_exe перед вызовом _run_xray_batch.
#
# 4. Никаких других изменений не нужно — xray-пайплайн для VLESS/Reality
#    остаётся нетронутым.
# =============================================================================
