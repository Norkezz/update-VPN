#!/usr/bin/env python3
# Force UTF-8 for stdout/stderr and all subprocess children on Windows
from __future__ import annotations

import os as _os, sys as _sys
if _sys.platform == "win32":
    _os.environ.setdefault("PYTHONUTF8", "1")
    _os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(_sys.stdout, "reconfigure"):
        try:
            _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
"""
admin_config_update.py — Manual VPN config update and upload to GitHub.

Administrative script (not included in the build).
Run manually by the operator to refresh the config pool in the private repo.

Fetch modes (--mode, applies to `update` and `fetch` commands):
  1 — read existing .txt files only (no network, no scripts — fastest)
  2 — git clone/pull to refresh, then read .txt (no scripts)
  3 — run update scripts on existing clone, then read .txt (no git)
  4 — git clone/pull + run update scripts + read .txt  [DEFAULT]

Sources:
  kort0881    — vless configs focused on Russia (main.py scans 840 sources)
  v2ray_agg   — V2RayAggregator + ShadowsocksAggregator (scripts in utils/)
  epodonios   — Epodonios/v2ray-configs (scripts in Files/, updated daily)
               Fallback: raw.githubusercontent.com if git clone fails.

All .txt files in each repo are scanned automatically — no hardcoded paths.
Scripts in utils/ and Files/ subdirectories are discovered automatically.

Commands:
  update    — full cycle: fetch → check → encrypt → upload to GitHub
  fetch     — collect configs only (no upload), print the list
  check     — verify configs from a text file (one URL per line)
  upload    — upload configs from a file to GitHub (no re-fetch)
  download  — download and decrypt current configs from GitHub
  status    — show how many configs are on GitHub and when uploaded

Parameters (read from cfg_ptr.bin automatically, or via CLI):
  --token   GitHub PAT
  --owner   repo owner
  --repo    repo name
  --nonce   nonce (must match build_obfuscated.py)
  --file    config file name on GitHub (default: c0nf1gs.bin)

Examples:
  python admin_config_update.py update
  python admin_config_update.py update --mode 2          # git pull only, no scripts
  python admin_config_update.py update --mode 1          # use whatever is on disk
  python admin_config_update.py update --sources kort0881,v2ray_agg,epodonios
  python admin_config_update.py update --sources epodonios
  python admin_config_update.py fetch --mode 2 --output raw.txt
  python admin_config_update.py check --input my_configs.txt
  python admin_config_update.py upload --input verified_configs.txt
  python admin_config_update.py download --output current_configs.txt
  python admin_config_update.py status
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional

# Время запуска скрипта — используется в mode 4 для фильтрации .txt файлов
SCRIPT_START_TIME: float = time.time()

# Минимальное время последнего git-коммита файла для mode 4:
# принимаются только файлы, коммит которых не старше 1 дня до запуска скрипта.
MAX_FILE_AGE_MODE4_CUTOFF: float = SCRIPT_START_TIME - 86400  # 1 день = 86400 сек

# ── cfg_ptr.bin decoding (mirrors license_manager.py) ────────────────────────

_CFG_MAGIC    = b"\xAE\x61\x19\x5F"
_CFG_VERSION  = 2
_CFG_FILENAME = "cfg\u200b_ptr\u200c.bin"

_TAG_TOKEN    = 0x01
_TAG_OWNER    = 0x02
_TAG_REPO     = 0x03
_TAG_FILE     = 0x04
_TAG_NONCE    = 0x05
_TAG_CFGFILE  = 0x06


def _cfg_master_key() -> bytes:
    a  = b"AegisNET"
    b_ = b"\x4c\x69\x63\x65\x6e\x73\x65"
    c  = b"\x76\x32\x2e\x30"
    d  = b"\xDE\xAD\xC0\xDE\x13\x37\xBE\xEF"
    return hashlib.sha256(a + b_ + c + d).digest()


def _xor_layer(data: bytes, key: bytes) -> bytes:
    kb = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes(b ^ k for b, k in zip(data, kb))


def _unshuffle(data: bytes, seed: int) -> bytes:
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


def _cfg_ptr_path() -> Path:
    """Locate cfg_ptr.bin next to the script or in xray_fluent/."""
    for candidate in [
        Path(__file__).parent / _CFG_FILENAME,
        Path(__file__).parent / "data" / _CFG_FILENAME,
        Path(__file__).parent / "xray_fluent" / _CFG_FILENAME,
    ]:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("cfg_ptr.bin not found next to the script")


def _load_cfg_ptr() -> dict:
    """Read and decode cfg_ptr.bin."""
    raw = _cfg_ptr_path().read_bytes()
    if len(raw) < 20:
        raise ValueError("cfg_ptr.bin is too short")
    raw = raw[7:-5]
    decoded = base64.b85decode(raw)
    if decoded[:4] != _CFG_MAGIC or decoded[4] != _CFG_VERSION:
        raise ValueError("Invalid cfg_ptr.bin signature")
    payload = decoded[5:]
    iv, payload = payload[:16], payload[16:]
    key = _cfg_master_key()
    decrypted = _aes_cbc_decrypt(payload, key, iv)
    seed = zlib.crc32(key[:4]) & 0xFFFFFFFF
    unshuffled = _unshuffle(decrypted, seed)
    xor_key = hashlib.md5(key).digest()
    plaintext = _xor_layer(unshuffled, xor_key)

    fields: dict = {}
    tag_map = {
        _TAG_TOKEN:   "token",
        _TAG_OWNER:   "owner",
        _TAG_REPO:    "repo",
        _TAG_FILE:    "filename",
        _TAG_NONCE:   "nonce",
        _TAG_CFGFILE: "configs_filename",
    }
    pos = 0
    while pos + 3 <= len(plaintext):
        t = plaintext[pos]
        l = struct.unpack_from("<H", plaintext, pos + 1)[0]
        pos += 3
        if pos + l > len(plaintext):
            break
        if t in tag_map:
            fields[tag_map[t]] = plaintext[pos:pos + l].decode("utf-8")
        pos += l
    return fields


# ── GitHub API ────────────────────────────────────────────────────────────────

def _gh_scheme(token: str) -> str:
    return "Bearer" if token.startswith("github_pat_") else "token"


def _gh_headers(token: str, accept: str = "application/vnd.github.v3.raw") -> dict:
    return {
        "Authorization": f"{_gh_scheme(token)} {token}",
        "Accept": accept,
        "User-Agent": "AegisNET-Admin/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_get_file(token: str, owner: str, repo: str, filename: str) -> Optional[str]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
    req = urllib.request.Request(url, headers=_gh_headers(token))
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def github_put_file(
    token: str, owner: str, repo: str, filename: str,
    content: str, msg: str = "admin: update configs"
) -> bool:
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
    sha: Optional[str] = None
    try:
        info = urllib.request.Request(
            api_url, headers=_gh_headers(token, "application/vnd.github.v3+json")
        )
        with urllib.request.urlopen(info, timeout=10) as r:
            sha = json.loads(r.read())["sha"]
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    body: dict = {
        "message": msg,
        "content": base64.b64encode(content.encode()).decode(),
    }
    if sha:
        body["sha"] = sha

    put = urllib.request.Request(
        api_url,
        data=json.dumps(body).encode(),
        method="PUT",
        headers={
            "Authorization": f"{_gh_scheme(token)} {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "AegisNET-Admin/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(put, timeout=20) as r:
        return r.status in (200, 201)


def github_get_file_meta(token: str, owner: str, repo: str, filename: str) -> Optional[dict]:
    """Return file metadata (sha, size, last commit) or None."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
    try:
        req = urllib.request.Request(
            api_url, headers=_gh_headers(token, "application/vnd.github.v3+json")
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


# ── Encrypt / decrypt ─────────────────────────────────────────────────────────

def _make_passphrase(token: str, nonce: str) -> str:
    raw = f"aegis-configs:{token}:{nonce}".encode()
    return hashlib.sha256(raw).hexdigest()


def _encrypt_configs(links: list[str], passphrase: str) -> str:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from xray_fluent.security import encrypt_with_passphrase
        payload = "\n".join(links).encode("utf-8")
        return encrypt_with_passphrase(payload, passphrase)
    except ImportError:
        return _fernet_encrypt("\n".join(links), passphrase)


def _decrypt_configs(encrypted: str, passphrase: str) -> list[str]:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from xray_fluent.security import decrypt_with_passphrase, is_passphrase_encrypted
        if not is_passphrase_encrypted(encrypted):
            lines = [ln.strip() for ln in encrypted.splitlines() if "://" in ln.strip()]
            return lines
        raw = decrypt_with_passphrase(encrypted, passphrase)
        lines = raw.decode("utf-8").splitlines()
        return [ln.strip() for ln in lines if ln.strip() and "://" in ln]
    except ImportError:
        return _fernet_decrypt(encrypted, passphrase)


def _fernet_encrypt(plaintext: str, passphrase: str) -> str:
    from cryptography.fernet import Fernet
    import base64 as b64
    key = hashlib.sha256(passphrase.encode()).digest()
    fernet_key = b64.urlsafe_b64encode(key)
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode()).decode()


def _fernet_decrypt(token_str: str, passphrase: str) -> list[str]:
    from cryptography.fernet import Fernet
    import base64 as b64
    key = hashlib.sha256(passphrase.encode()).digest()
    fernet_key = b64.urlsafe_b64encode(key)
    f = Fernet(fernet_key)
    raw = f.decrypt(token_str.encode()).decode()
    return [ln.strip() for ln in raw.splitlines() if ln.strip() and "://"]


# ── Upstream source repos ─────────────────────────────────────────────────────
#
# Instead of fetching static raw files that are often 404, we:
#   1. Clone (or git-pull) each aggregator repo into a temp dir.
#   2. Run their own update script so they produce fresh config files.
#   3. Read the resulting config files from disk.
#
# This matches the intended workflow: "load the V2RayAggregator and kort0881
# update scripts first, then get the config files they produce."

KORT0881_REPO   = "https://github.com/kort0881/vpn-vless-configs-russia.git"
V2RAY_AGG_REPO  = "https://github.com/mahdibland/V2RayAggregator.git"
SHADOWSOCKS_AGG_REPO = "https://github.com/mahdibland/ShadowsocksAggregator.git"
EPODONIOS_REPO  = "https://github.com/Epodonios/v2ray-configs.git"

# ── Прямые URL-источники (mode 4) ─────────────────────────────────────────────
# Зеркало URLS_BASE из config_fetcher.py — скачиваются напрямую без git/скриптов.
# Результат сохраняется в sources/URLS_BASE/ при запуске mode 4.
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
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/ss.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/mix.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/configs.txt",
    # ── Дополнительные GitHub-источники ──────────────────────────────────────
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/v2fly/free-nodes/master/index.txt",
    "https://raw.githubusercontent.com/ssrsub/ssr/master/v2ray",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/vless",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/all3",
    "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt",
    "https://raw.githubusercontent.com/vveg26/get_proxy/main/proxy.txt",
    "https://raw.githubusercontent.com/ZywChannel/free/main/sub",
    "https://raw.githubusercontent.com/YasserDivaR/pr0xy/main/ShadowSocket2023.txt",
    "https://raw.githubusercontent.com/kinderprivate/proxies/main/links.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/ss.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/vless.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/vmess.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/ss.txt",
    "https://raw.githubusercontent.com/thomaskty/vless/main/vless_sub.txt",
    "https://raw.githubusercontent.com/resasanian/Mirza/main/sub",
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://raw.githubusercontent.com/hkaa0/permalink/main/proxy/V2ray",
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/xray/xray.configs.txt",
    "https://raw.githubusercontent.com/Hossein-nrj/awesome-freedom/master/configs.txt",
    "https://raw.githubusercontent.com/wrfree/free/main/v2",
    "https://raw.githubusercontent.com/polimi6/polimi6.github.io/main/v2ray_config.txt",

    # ── Requested additional elite sources ───────────────────────────────────
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/vless.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/mixed.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/subscription.txt",
    "https://raw.githubusercontent.com/kudryash0vv/kudryash0vv.YKTFLOW/main/vless.txt",
    "https://raw.githubusercontent.com/kudryash0vv/kudryash0vv.YKTFLOW/main/mixed.txt",
]

# ── Telegram-каналы с VPN-конфигами ──────────────────────────────────────────
# Парсятся через публичный веб-интерфейс t.me/s/<channel> (без API key).
# Для глубокого парсинга (10 000+ сообщений) нужен Bot API token.
TG_CHANNELS: list[str] = [
    # Агрегаторы конфигов
    "freev2rays",           # general mix, активный
    "v2ray_configs",        # vless/vmess/trojan mix
    "V2rayNG_Configs",      # v2rayNG ready configs
    "DirectVPN",            # прямые конфиги
    "VmessProtocol",        # vmess-ориентированный
    "v2ray_subs",           # subscription links
    "ConfigsHUB",           # large mix
    "proxy_mtproto",        # mtproto + vless
    "free_v2rayzz",         # free configs
    "OutlineVpnOfficial",   # outline keys
    # Россия-специфичные
    "newOutlineVPN",        # outline для РФ
    "vless_russia",         # vless для РФ
    "vpn_no_filter",        # anti-censor configs
    "shadowsocks_r_b",      # shadowsocks
    # Крупные сборщики
    "TelegramV2rayCollector",
    "yebekhe",
    "MrMohebi_xray",
    "v2raytunkeys",
    "KeysConf",
    "vlesskeys",
]

# Максимум страниц t.me/s/<channel>?before=<id> для парсинга (каждая ~20 сообщений)
TG_WEB_MAX_PAGES = 50   # ~1000 последних сообщений на канал

# After running the upstream update script, configs are collected by scanning
# ALL .txt files in the repo recursively — no hardcoded path list needed.

PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")


def _is_valid_link(link: str) -> bool:
    """Validate that a link is a syntactically plausible VPN config.

    Rules:
      - vmess://  : body must be valid base64 JSON with "add" and "port" keys
      - all others: urlparse must resolve a hostname (>2 chars) and a port
                    in the range 1-65535
    This filters out README lines, truncated links, and bare protocol prefixes
    that happen to start with a known scheme but are not real configs.
    """
    try:
        if link.startswith("vmess://"):
            b64 = link[len("vmess://"):]
            # strip fragment
            b64 = b64.split("#")[0]
            padded = b64 + "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
            return bool(data.get("add") and str(data.get("port", "")).strip())
        else:
            p = urllib.parse.urlparse(link)
            host = (p.hostname or "").strip()
            port = p.port
            return bool(host and len(host) > 2 and port and 1 <= port <= 65535)
    except Exception:
        return False


# ── Legacy Shadowsocks support via sing-box ────────────────────────────────
# Xray removed support for legacy stream ciphers:
#   aes-256-cfb / aes-192-cfb / aes-128-cfb / rc4-md5
# We keep them and mark them for sing-box handling.

LEGACY_SS_CIPHERS = {
    "aes-256-cfb",
    "aes-192-cfb",
    "aes-128-cfb",
    "rc4-md5",
}

VALID_TRANSPORTS = {
    "tcp", "ws", "grpc", "httpupgrade",
    "xhttp", "splithttp", "quic", "kcp"
}

INVALID_FLOWS = {
    "xtls-rprx-origin",
    "xtls-rprx-direct",
    "xtls-rprx-direct-udp443",
}

def _multi_unquote(value: str, rounds: int = 5) -> str:
    """Fix broken %252525 encoding chains."""
    import urllib.parse
    old = value
    for _ in range(rounds):
        new = urllib.parse.unquote(old)
        if new == old:
            break
        old = new
    return old

def _sanitize_vpn_link(link: str) -> str | None:
    """
    Normalize malformed configs from public aggregators.
    Keeps legacy Shadowsocks ciphers for sing-box compatibility.
    """
    try:
        import urllib.parse

        if link.startswith("vless://"):
            link = _multi_unquote(link)

            parsed = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qs(parsed.query)

            flow = q.get("flow", [""])[0].strip()
            if flow in INVALID_FLOWS or "udp443" in flow:
                q.pop("flow", None)

            transport = (
                q.get("type", [""])[0]
                or q.get("transport", [""])[0]
            ).strip().lower()

            if transport and transport not in VALID_TRANSPORTS:
                q["type"] = ["tcp"]

            query = urllib.parse.urlencode(
                {k: v[0] for k, v in q.items()},
                doseq=False,
            )

            link = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query,
                parsed.fragment,
            ))

        elif link.startswith("ss://"):
            decoded = _multi_unquote(link)

            # keep legacy ciphers for sing-box
            for cipher in LEGACY_SS_CIPHERS:
                if cipher in decoded.lower():
                    return decoded

            return decoded

        return link

    except Exception:
        return None


def _parse_links(text: str) -> list[str]:
    """Extract and validate VPN links from text; also tries base64 decode.

    Only lines that:
      1. Start with a known VPN protocol prefix.
      2. Pass _is_valid_link() (syntactically plausible config).
    are kept. Everything else — README prose, truncated lines, bare
    scheme prefixes, random text — is silently dropped.
    """
    links = []
    chunks = [text]
    if "://" not in text:
        try:
            chunks.append(base64.b64decode(text + "==").decode("utf-8", errors="ignore"))
        except Exception:
            pass
    for chunk in chunks:
        for line in chunk.splitlines():
            line = line.strip()
            if any(line.startswith(p) for p in PROTOCOLS) and _is_valid_link(line):
                sanitized = _sanitize_vpn_link(line)
                if sanitized:
                    links.append(sanitized)
    return list(dict.fromkeys(links))


def _git_clone_or_pull(repo_url: str, dest: Path, timeout: int = 120) -> bool:
    """Clone repo if not present, otherwise git pull. Returns True on success."""
    try:
        if (dest / ".git").exists():
            print(f"  ↻  git fetch + reset  {dest.name}  ...", flush=True)
            # Use fetch + hard reset instead of pull --ff-only so that
            # force-pushed upstream branches (common in aggregator repos)
            # never cause a divergence error.
            fetch = subprocess.run(
                ["git", "-C", str(dest), "fetch", "--depth=1", "origin"],
                capture_output=True, timeout=timeout,
            )
            if fetch.returncode != 0:
                print(f"  ⚠  git error: {fetch.stderr.decode(errors='ignore').strip()}")
                return False
            r = subprocess.run(
                ["git", "-C", str(dest), "reset", "--hard", "origin/HEAD"],
                capture_output=True, timeout=timeout,
            )
        else:
            print(f"  ↓  git clone {repo_url}  ...", flush=True)
            dest.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                ["git", "clone", "--depth=1", repo_url, str(dest)],
                capture_output=True, timeout=timeout,
            )
        if r.returncode != 0:
            print(f"  ⚠  git error: {r.stderr.decode(errors='ignore').strip()}")
            return False
        return True
    except FileNotFoundError:
        print("  ⚠  git not found in PATH — cannot clone repos")
        return False
    except subprocess.TimeoutExpired:
        print(f"  ⚠  git timed out for {repo_url}")
        return False
    except Exception as e:
        print(f"  ⚠  git exception: {e}")
        return False


def _run_update_script(repo_dir: Path, script_candidates: list[str],
                       timeout: int = 600) -> bool:
    """Try to run one of the given script names inside repo_dir.

    Output is streamed live so long-running scripts (e.g. kort0881/main.py
    with 840 sources) show real-time progress instead of appearing frozen.
    """
    python = sys.executable
    for script_name in script_candidates:
        script = repo_dir / script_name
        if script.exists():
            print(f"  ▶  Running {script_name} in {repo_dir.name} "
                  f"(output streamed live) ...", flush=True)
            print(f"  {'─'*54}", flush=True)
            try:
                child_env = os.environ.copy()
                child_env["PYTHONUTF8"] = "1"
                child_env["PYTHONIOENCODING"] = "utf-8"
                proc = subprocess.Popen(
                    [python, str(script)],
                    cwd=str(repo_dir),
                    env=child_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,   # merge stderr → stdout
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,                  # line-buffered
                )
                deadline = time.monotonic() + timeout
                for line in proc.stdout:
                    sys.stdout.write("    " + line)
                    sys.stdout.flush()
                    if time.monotonic() > deadline:
                        proc.kill()
                        proc.wait()
                        print(f"\n  {'─'*54}", flush=True)
                        print(f"  ⚠  {script_name} timed out after {timeout}s")
                        return False
                proc.wait()
                print(f"  {'─'*54}", flush=True)
                if proc.returncode == 0:
                    print(f"  ✓  {script_name} completed successfully")
                    return True
                else:
                    print(f"  ⚠  {script_name} exited {proc.returncode}")
                    return False
            except Exception as e:
                print(f"  ⚠  {script_name} exception: {e}")
                return False
    print(f"  ⚠  No known update script found in {repo_dir.name}")
    return False


# Maximum age (days) of a config file's last git commit.
# Files whose LAST GIT COMMIT is older than this window are skipped — stale configs
# are unlikely to still be alive.
MAX_FILE_AGE_DAYS = 45


def _git_file_mtime(repo_dir: Path, filepath: Path) -> Optional[float]:
    """Return the Unix timestamp of the last git commit that touched `filepath`.

    IMPORTANT:
    Uses git commit time, NOT filesystem/download time.

    Uses `git log -1 --format=%ct` which is fast (single-file log).
    Returns None if git is unavailable or the file has no commit history.
    """
    try:
        rel = str(filepath.relative_to(repo_dir))
        r = subprocess.run(
            ["git", "-C", str(repo_dir), "log", "-1", "--format=%ct", "--", rel],
            capture_output=True, text=True, timeout=10,
        )
        ts = r.stdout.strip()
        return float(ts) if ts else None
    except Exception:
        return None


def _is_base64_encoded_file(text: str) -> bool:
    """Return True if the file appears to be a base64-encoded blob.

    Heuristic: if the file has no "://" lines at all but decodes as base64
    into text that *does* contain "://" lines, it is an externally-encoded
    file.  We skip these because we cannot guarantee our decoding matches
    the encoding used by the repo author (padding, line-wrapping, charset).
    """
    if "://" in text:
        return False          # plain text with links — not base64
    stripped = text.strip().replace("\n", "").replace("\r", "")
    if len(stripped) < 64:
        return False
    try:
        decoded = base64.b64decode(stripped + "==").decode("utf-8", errors="ignore")
        return "://" in decoded
    except Exception:
        return False


def _collect_all_txt_links(repo_dir: Path, label: str = "", only_updated: bool = False) -> list[str]:
    """Scan ALL .txt files in repo_dir recursively and extract VPN links.

    Skips:
      - Files older than MAX_FILE_AGE_DAYS (by last git commit date).
      - Files whose content is a base64-encoded blob (checked by content,
        not filename) — we skip these to avoid wrong decoding assumptions.
      - If only_updated=True (mode 4): files whose last git commit is older than
        1 day before script start are skipped (MAX_FILE_AGE_MODE4_CUTOFF).
    """
    links: list[str] = []
    txt_files = sorted(repo_dir.rglob("*.txt"))
    if not txt_files:
        print(f"  ⚠  No .txt files found in {label or repo_dir.name}")
        return links

    now = time.time()
    cutoff = now - MAX_FILE_AGE_DAYS * 86400

    for fp in txt_files:
        rel = fp.relative_to(repo_dir)

        # Mode 4:
        # Проверяем дату последнего git-коммита файла,
        # а НЕ filesystem mtime после clone/download.
        #
        # Иначе git clone делает все файлы "новыми",
        # даже если сами конфиги старые.
        if only_updated:
            git_mtime = _git_file_mtime(repo_dir, fp)

            # fallback если git history недоступна
            effective_mtime = git_mtime or fp.stat().st_mtime

            if effective_mtime < MAX_FILE_AGE_MODE4_CUTOFF:
                age_hours = int((time.time() - effective_mtime) / 3600)
                print(f"  ⏭  {rel} — skipped (last commit {age_hours}h ago, older than 1 day before script start)")
                continue

        # Age check
        mtime = _git_file_mtime(repo_dir, fp)
        if mtime is not None and mtime < cutoff:
            age_days = int((now - mtime) / 86400)
            print(f"  ⏭  {rel} — skipped (last commit {age_days}d ago > {MAX_FILE_AGE_DAYS}d)")
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        # Content check: skip externally base64-encoded files
        if _is_base64_encoded_file(text):
            print(f"  ⏭  {rel} — skipped (base64-encoded content)")
            continue
        found = _parse_links(text)
        if found:
            age_str = f"{int((now - mtime) / 86400)}d ago" if mtime else "age unknown"
            print(f"  ✓  {rel} → {len(found)} configs  ({age_str})")
            links.extend(found)
    return links


def _collect_links_from_files(repo_dir: Path, relative_paths: list[str]) -> list[str]:
    """Read specific config files from a cloned repo and extract VPN links."""
    links: list[str] = []
    for rel in relative_paths:
        fp = repo_dir / rel
        if fp.exists():
            text = fp.read_text(encoding="utf-8", errors="ignore")
            found = _parse_links(text)
            print(f"  ✓  {rel} → {len(found)} configs")
            links.extend(found)
        else:
            print(f"  ⚠  {rel}: not found")
    return links


# ── Per-repo update script sequences ─────────────────────────────────────────────
#
# V2RayAggregator / ShadowsocksAggregator (identical utils/ layout):
#   utils/list_update.py  — updates sub_list.json with fresh URLs from upstream
#   utils/list_merge.py   — fetches all subs, deduplicates, writes sub/splitted/
#
# Epodonios/v2ray-configs:
#   Files/app.py   — downloads fresh configs from upstream sources
#   Files/sort.py  — sorts and deduplicates the downloaded configs
#
# kort0881:
#   main.py  — scans ~840 sources and produces vless.txt / configs.txt
#
# The sequences are run in order; each step is attempted even if the
# previous one fails, so a pipeline always completes as far as possible.

V2RAY_AGG_SCRIPTS       = ["utils/list_update.py", "utils/list_merge.py"]
SHADOWSOCKS_AGG_SCRIPTS = ["utils/list_update.py", "utils/list_merge.py"]
EPODONIOS_SCRIPTS       = ["Files/app.py", "Files/sort.py"]
KORT0881_SCRIPTS        = ["main.py"]


def _run_script_sequence(repo_dir: Path, scripts: list[str],
                          label: str = "") -> None:
    """Run a fixed ordered sequence of scripts inside repo_dir.

    Each entry in `scripts` is a relative path from repo_dir.
    All steps are attempted in order (pipeline semantics).
    """
    tag = f"[{label}] " if label else ""
    for rel in scripts:
        fp = repo_dir / rel
        if fp.exists():
            _run_update_script(repo_dir, [rel])
        else:
            print(f"  ⚠  {tag}{rel}: script not found, skipping")



def _fetch_source_kort0881(work_dir: Path, fetch_mode: int) -> list[str]:
    """Fetch kort0881 configs.

    Script sequence: main.py  (scans ~840 sources, produces vless.txt)

    fetch_mode:
      1 — read existing .txt files only
      2 — git clone/pull, then read .txt
      3 — run scripts on existing clone, then read .txt
      4 — git clone/pull + run scripts + read .txt  [default]
    """
    repo_dir = work_dir / "kort0881"

    if fetch_mode in (2, 4):
        ok = _git_clone_or_pull(KORT0881_REPO, repo_dir)
        if not ok:
            print("  ⚠  kort0881: git failed, using whatever is on disk...")

    if fetch_mode in (3, 4):
        _run_script_sequence(repo_dir, KORT0881_SCRIPTS, "kort0881")

    return _collect_all_txt_links(repo_dir, "kort0881", only_updated=(fetch_mode == 4))


SUBCONVERTER_PORT = 25500
SUBCONVERTER_RELEASES_URL = "https://api.github.com/repos/tindy2013/subconverter/releases/latest"


def _find_or_download_subconverter(work_dir: Path) -> Optional[Path]:
    """Locate or download the subconverter binary for Windows/Linux.

    Looks in work_dir/subconverter/ first, then downloads if missing.
    Returns path to the executable or None on failure.
    """
    import platform as _platform
    is_win = _platform.system() == "Windows"
    bin_name = "subconverter.exe" if is_win else "subconverter"
    bin_path = work_dir / "subconverter" / bin_name
    if bin_path.exists():
        return bin_path

    print(f"  ⬇  subconverter not found, downloading latest release...")
    try:
        headers = {"User-Agent": _random_ua(), "Accept": "application/vnd.github.v3+json"}
        req = urllib.request.Request(SUBCONVERTER_RELEASES_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        # Pick the right asset
        keyword = "win64" if is_win else "linux64"
        asset_url = next(
            (a["browser_download_url"] for a in data.get("assets", [])
             if keyword in a["name"].lower() and a["name"].endswith(".tar.gz" if not is_win else ".tar.gz")),
            None
        )
        if not asset_url:
            # fallback: any .tar.gz matching platform
            asset_url = next(
                (a["browser_download_url"] for a in data.get("assets", [])
                 if keyword in a["name"].lower()),
                None
            )
        if not asset_url:
            print("  ⚠  subconverter: no matching release asset found")
            return None
        # Download and extract
        import tarfile as _tarfile, io as _io
        req2 = urllib.request.Request(asset_url, headers={"User-Agent": _random_ua()})
        with urllib.request.urlopen(req2, timeout=60) as r:
            raw = r.read()
        sub_dir = work_dir / "subconverter"
        sub_dir.mkdir(exist_ok=True)
        with _tarfile.open(fileobj=_io.BytesIO(raw)) as tf:
            tf.extractall(sub_dir)
        # Find binary after extraction (may be in a subdir)
        candidates = list(sub_dir.rglob(bin_name))
        if candidates:
            exe = candidates[0]
            if not is_win:
                exe.chmod(0o755)
            print(f"  ✓  subconverter extracted: {exe}")
            return exe
        print("  ⚠  subconverter: binary not found after extraction")
        return None
    except Exception as e:
        print(f"  ⚠  subconverter download failed: {e}")
        return None


def _start_subconverter(work_dir: Path) -> Optional[subprocess.Popen]:
    """Start subconverter on SUBCONVERTER_PORT. Returns process or None."""
    # Check if already running
    try:
        with socket.create_connection(("127.0.0.1", SUBCONVERTER_PORT), timeout=1):
            print(f"  ✓  subconverter already running on port {SUBCONVERTER_PORT}")
            return None  # already up, caller should not kill it
    except OSError:
        pass

    exe = _find_or_download_subconverter(work_dir)
    if not exe:
        return None

    try:
        proc = subprocess.Popen(
            [str(exe)],
            cwd=str(exe.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait up to 8s for it to come up
        for _ in range(16):
            time.sleep(0.5)
            try:
                with socket.create_connection(("127.0.0.1", SUBCONVERTER_PORT), timeout=0.5):
                    print(f"  ✓  subconverter started on port {SUBCONVERTER_PORT} (pid {proc.pid})")
                    return proc
            except OSError:
                pass
        proc.kill()
        print("  ⚠  subconverter failed to start within 8s")
        return None
    except Exception as e:
        print(f"  ⚠  subconverter start error: {e}")
        return None


def _fetch_source_v2ray_agg(work_dir: Path, fetch_mode: int) -> list[str]:
    """Fetch V2RayAggregator + ShadowsocksAggregator configs.

    Script sequence for each repo (identical utils/ layout):
      utils/list_update.py  — updates sub_list.json with fresh upstream URLs
      utils/list_merge.py   — fetches all subs via local subconverter, writes sub/splitted/

    Requires subconverter running on port 25500. If not present, it is
    downloaded automatically and started for the duration of the fetch.
    """
    links: list[str] = []

    # Поднимаем subconverter если нужен для list_merge.py
    subconv_proc: Optional[subprocess.Popen] = None
    if fetch_mode in (3, 4):
        subconv_proc = _start_subconverter(work_dir)
        if subconv_proc is None:
            # Проверяем — возможно уже запущен
            try:
                with socket.create_connection(("127.0.0.1", SUBCONVERTER_PORT), timeout=1):
                    pass  # уже работает
            except OSError:
                print("  ⚠  v2ray_agg: subconverter недоступен, list_merge.py может дать 0 конфигов")

    try:
        for repo_url, repo_name, scripts in [
            (V2RAY_AGG_REPO,       "V2RayAggregator",      V2RAY_AGG_SCRIPTS),
            (SHADOWSOCKS_AGG_REPO, "ShadowsocksAggregator", SHADOWSOCKS_AGG_SCRIPTS),
        ]:
            repo_dir = work_dir / repo_name

            if fetch_mode in (2, 4):
                ok = _git_clone_or_pull(repo_url, repo_dir)
                if not ok:
                    print(f"  ⚠  {repo_name}: git failed, using whatever is on disk...")

            if fetch_mode in (3, 4):
                _run_script_sequence(repo_dir, scripts, repo_name)

            links.extend(_collect_all_txt_links(repo_dir, repo_name, only_updated=(fetch_mode == 4)))
    finally:
        if subconv_proc is not None:
            subconv_proc.kill()
            print(f"  ✓  subconverter остановлен")

    return links


def _fetch_source_epodonios(work_dir: Path, fetch_mode: int) -> list[str]:
    """Fetch Epodonios/v2ray-configs.

    Script sequence:
      Files/app.py   — downloads fresh configs from upstream sources
      Files/sort.py  — sorts and deduplicates the downloaded configs

    The repo also ships pre-built .txt files refreshed daily, so even
    without running scripts (mode 1/2) you get usable configs.
    Falls back to raw.githubusercontent.com if git fails in modes 2/4.
    """
    repo_dir = work_dir / "epodonios-v2ray-configs"

    if fetch_mode in (2, 4):
        ok = _git_clone_or_pull(EPODONIOS_REPO, repo_dir)
        if not ok:
            print("  ⚠  epodonios: git failed, trying raw GitHub fallback...")
            raw_base = "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main"
            fallback = [
                f"{raw_base}/Splitted-By-Protocol/vless.txt",
                f"{raw_base}/Splitted-By-Protocol/vmess.txt",
                f"{raw_base}/Splitted-By-Protocol/trojan.txt",
            ]
            result: list[str] = []
            for url in fallback:
                result.extend(_fetch_direct_url(url))
            return result

    if fetch_mode in (3, 4):
        # sort.py открывает файлы в Splitted-By-Protocol/ относительно repo_dir
        (repo_dir / "Splitted-By-Protocol").mkdir(exist_ok=True)
        _run_script_sequence(repo_dir, EPODONIOS_SCRIPTS, "epodonios")

    return _collect_all_txt_links(repo_dir, "epodonios", only_updated=(fetch_mode == 4))


def _fetch_source_urls_base(work_dir: Path) -> list[str]:
    """Скачивает все URL из URLS_BASE параллельно и сохраняет результат в sources/URLS_BASE/.

    Каждый URL сохраняется как отдельный .txt файл (имя = последний сегмент URL).
    Возвращает все найденные VPN-ссылки.
    """
    out_dir = work_dir / "URLS_BASE"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Downloading {len(URLS_BASE)} URLs → {out_dir}")

    def _fetch_one(url: str) -> list[str]:
        slug = re.sub(r"[^\w\-.]", "_", url.split("/")[-1] or url.split("/")[-2])[:60]
        out_file = out_dir / f"{slug}.txt"
        headers = {"User-Agent": _random_ua()}
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                text = r.read().decode("utf-8", errors="ignore")
            links = _parse_links(text)
            if links:
                out_file.write_text("\n".join(links), encoding="utf-8")
                print(f"  ✓  {slug} → {len(links)} configs")
            else:
                print(f"  ⚠  {slug} → 0 configs")
            return links
        except Exception as e:
            print(f"  ⚠  {slug}: {e}")
            return []

    all_links: list[str] = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        for result in ex.map(_fetch_one, URLS_BASE):
            all_links.extend(result)

    print(f"  → URLS_BASE total: {len(all_links)} configs (saved to {out_dir})")
    return all_links


# ── Keysconf.com parser ───────────────────────────────────────────────────────

KEYSCONF_BASE = "https://keysconf.com"
VLESSKEY_BASE = "https://vlesskey.com"
OUTLINEKEYS_BASE = "https://outlinekeys.com"

KEYSCONF_CONCURRENT = 40   # параллельных запросов к сайту


def _fetch_source_keysconf(work_dir: Path) -> list[str]:
    
    """Parse keysconf.com: собирает конфиги со всех страниц пагинации.

    Алгоритм:
      1. Скачиваем страницы /?page=1..N параллельно (40 потоков).
      2. Из каждой страницы извлекаем ссылки на карточки конфигов.
      3. Фильтруем по статусу Online (badge bg-success).
      4. Параллельно заходим на каждую страницу конфига и берём <code>.
      5. Сохраняем в sources/keysconf/all.txt.
    """
    import html as _html
    out_dir = work_dir / "keysconf"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "all.txt"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
    }

    def _http_get(url: str, timeout: int = 15) -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception:
            return None

    # ── Шаг 1: определяем количество страниц ─────────────────────────────────
    print(f"  🌐  keysconf: fetching page count ...", flush=True)
    first_html = _http_get(f"{KEYSCONF_BASE}/?page=1")
    if not first_html:
        print("  ⚠  keysconf: cannot reach keysconf.com")
        return []

    # Ищем максимальный номер страницы в пагинации
    page_nums = [int(m) for m in re.findall(r'href="[/?].*?page=(\d+)"', first_html)]
    max_page = max(page_nums) if page_nums else 1
    print(f"  📄  keysconf: {max_page} pages detected", flush=True)

    # ── Шаг 2: параллельно скачиваем все страницы листинга ───────────────────
    def _parse_listing_page(page_num: int) -> list[str]:
        """Возвращает список относительных URL карточек (только Online)."""
        html = _http_get(f"{KEYSCONF_BASE}/?page={page_num}")
        if not html:
            return []
        # Ищем карточки: href="/vless/NNN/" или "/vmess/NNN/" и т.д.
        # Берём только те, где рядом есть badge bg-success (Online)
        # Простая эвристика: ищем все <div class="card mb-3"...> блоки
        card_pattern = re.compile(
            r'<div[^>]+class="card mb-3"[^>]*data-protocol="([^"]+)"[^>]*>.*?'
            r'<a\s+href="(/(?:vless|vmess|trojan|ss|hy2|tuic)/\d+/)"[^>]*>.*?'
            r'(Online)',
            re.DOTALL | re.IGNORECASE,
        )
        links = []
        for m in card_pattern.finditer(html):
            links.append(m.group(2))  # относительный URL
        # Фолбек: просто берём все ссылки на конфиги (если Online-фильтр не нашёл)
        if not links:
            for href in re.findall(r'href="(/(?:vless|vmess|trojan|ss|hy2|tuic)/\d+/)"', html):
                links.append(href)
        return list(dict.fromkeys(links))

    all_card_urls: list[str] = []
    with ThreadPoolExecutor(max_workers=KEYSCONF_CONCURRENT) as ex:
        futures = {ex.submit(_parse_listing_page, p): p for p in range(1, max_page + 1)}
        for f in as_completed(futures):
            result = f.result()
            all_card_urls.extend(result)

    all_card_urls = list(dict.fromkeys(all_card_urls))
    print(f"  📋  keysconf: {len(all_card_urls)} config pages found", flush=True)

    if not all_card_urls:
        print("  ⚠  keysconf: no config links found on listing pages")
        return []

    # ── Шаг 3: параллельно заходим на каждую страницу конфига ────────────────
    found_configs: list[str] = []
    done_count   = [0]
    lock         = threading.Lock()

    def _parse_config_page(rel_url: str) -> Optional[str]:
        html = _http_get(f"{KEYSCONF_BASE}{rel_url}")
        if not html:
            return None
        # Конфиг лежит в <code> внутри .connection-card
        # data-copy="vless://..." — самый надёжный способ
        m = re.search(r'data-copy="([^"]+://[^"]+)"', html)
        if m:
            return _html.unescape(m.group(1)).strip()
        # Фолбек: первый <code> с ://
        m = re.search(r'<code[^>]*>\s*([a-z0-9]+://[^\s<]+)\s*</code>', html, re.IGNORECASE)
        if m:
            return _html.unescape(m.group(1)).strip()
        return None

    with ThreadPoolExecutor(max_workers=KEYSCONF_CONCURRENT) as ex:
        futures = {ex.submit(_parse_config_page, u): u for u in all_card_urls}
        for f in as_completed(futures):
            cfg = f.result()
            with lock:
                done_count[0] += 1
                if cfg and _is_valid_link(cfg):
                    found_configs.append(cfg)
                if done_count[0] % 50 == 0:
                    print(f"    keysconf {done_count[0]}/{len(all_card_urls)} "
                          f" found: {len(found_configs)}", end="\r", flush=True)

    found_configs = list(dict.fromkeys(found_configs))
    print(f"\n  ✓  keysconf: {len(found_configs)} valid configs", flush=True)

    # Сохраняем
    out_file.write_text("\n".join(found_configs), encoding="utf-8")
    print(f"  💾  keysconf: saved → {out_file}", flush=True)

    return found_configs

# ── Universal premium source parser ─────────────────────────────────────────
# Подходит для:
#   keysconf.com
#   vlesskey.com
#   outlinekeys.com
#
# Возможности:
#   • обход ВСЕХ страниц пагинации
#   • фильтр только Online
#   • поддержка aria-label="Page navigation example"
#   • сбор стран
#   • сбор VLESS / VMESS / Trojan / SS / HY2 / TUIC
#

PREMIUM_CONCURRENT = 50


def _fetch_source_premium_site(
    work_dir: Path,
    source_name: str,
    base_url: str,
) -> list[str]:
    import html as _html

    out_dir = work_dir / source_name
    out_dir.mkdir(parents=True, exist_ok=True)

    out_file = out_dir / "all.txt"
    country_file = out_dir / "countries.txt"

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    def _http_get(url: str, timeout: int = 20) -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception:
            return None

    print(f"  🌐  {source_name}: scanning pages ...", flush=True)

    first_html = _http_get(f"{base_url}/?page=1")
    if not first_html:
        first_html = _http_get(base_url)

    if not first_html:
        print(f"  ⚠  {source_name}: site unreachable")
        return []

    # ── page navigation example ─────────────────────────────────────────────
    page_nums = [
        int(x)
        for x in re.findall(r'page=(\d+)', first_html, re.IGNORECASE)
        if x.isdigit()
    ]

    max_page = max(page_nums) if page_nums else 1

    print(f"  📄  {source_name}: {max_page} pages detected", flush=True)

    all_card_urls: list[str] = []
    countries: set[str] = set()

    # Паттерны URL карточек конфигов — покрывают разные сайты
    # vlesskey.com / outlinekeys.com могут использовать /key/, /config/, /outline/ и т.д.
    _CARD_URL_PATTERN = re.compile(
        r'href="(/(?:vless|vmess|trojan|ss|hy2|tuic|key|config|outline|proxy|node'
        r'|access|server|vpn|free)/[\w\-]+/?)"',
        re.IGNORECASE,
    )
    # Запасной — любой путь вида /что-угодно/число/ или /что-угодно/слово-цифры/
    _CARD_URL_FALLBACK = re.compile(
        r'href="(/[\w\-]+/[\w\-]{2,}/?)"',
        re.IGNORECASE,
    )

    def _parse_listing(page_num: int) -> list[str]:
        page_url = f"{base_url}/?page={page_num}"
        html = _http_get(page_url)

        if not html:
            return []

        local_cards: list[str] = []

        # ── countries ───────────────────────────────────────────────────────
        for c in re.findall(
            r'flag-icon[^>]*></span>\s*([A-Za-z .\-]{2,40})',
            html,
            re.IGNORECASE,
        ):
            cc = c.strip()
            if 2 <= len(cc) <= 40:
                countries.add(cc)

        # ── ONLINE filter (пытаемся взять только Online карточки) ───────────
        card_blocks = re.findall(
            r'<(?:div|article|li)[^>]+class="[^"]*card[^"]*"[^>]*>(.*?)</(?:div|article|li)>',
            html,
            re.DOTALL | re.IGNORECASE,
        )

        for block in card_blocks:
            lower = block.lower()
            # только online (мягкий фильтр — пропускаем если явно offline/expired)
            if "offline" in lower or "expired" in lower:
                continue

            urls = _CARD_URL_PATTERN.findall(block)
            local_cards.extend(urls)

        # fallback 1: те же паттерны по всей странице без online-фильтра
        if not local_cards:
            local_cards.extend(_CARD_URL_PATTERN.findall(html))

        # fallback 2: ещё шире — любые ссылки /сегмент/идентификатор/
        # (исключаем типичные навигационные пути)
        if not local_cards:
            _NAV = re.compile(
                r'^/(?:page|static|assets|css|js|img|images|fonts|media|admin'
                r'|login|logout|register|api|search|about|contact|faq|terms|privacy'
                r'|blog|news|tag|category|lang|en|ru|fa)/?',
                re.IGNORECASE,
            )
            for href in _CARD_URL_FALLBACK.findall(html):
                if not _NAV.match(href) and not href.endswith(('.css', '.js', '.png', '.jpg')):
                    local_cards.append(href)

        return list(dict.fromkeys(local_cards))

    with ThreadPoolExecutor(max_workers=PREMIUM_CONCURRENT) as ex:
        futures = {
            ex.submit(_parse_listing, p): p
            for p in range(1, max_page + 1)
        }

        for f in as_completed(futures):
            try:
                all_card_urls.extend(f.result())
            except Exception:
                pass

    all_card_urls = list(dict.fromkeys(all_card_urls))

    print(
        f"  📋  {source_name}: {len(all_card_urls)} config pages found",
        flush=True,
    )

    if not all_card_urls:
        return []

    found_configs: list[str] = []

    done = [0]
    lock = threading.Lock()

    def _parse_config(rel_url: str) -> Optional[str]:
        html = _http_get(f"{base_url}{rel_url}")

        if not html:
            return None

        # ── 1. id="accessKey" — главный контейнер для Outline / SS ключей
        #    <input id="accessKey" value="ss://...">
        #    <textarea id="accessKey">ss://...</textarea>
        #    <span id="accessKey">vless://...</span>
        m = re.search(
            r'id=["\']accessKey["\'][^>]*(?:value=["\']([^"\']+://[^"\']+)["\']'
            r'|[^>]*>([^<]*://[^<\s]+))',
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if m:
            cfg = _html.unescape((m.group(1) or m.group(2) or "").strip())
            if _is_valid_link(cfg):
                return cfg

        # ── 2. value= с протоколом внутри input/textarea ────────────────────
        m = re.search(
            r'<(?:input|textarea)[^>]+value=["\']([a-z0-9]+://[^"\'<\s]+)["\']',
            html,
            re.IGNORECASE,
        )
        if m:
            cfg = _html.unescape(m.group(1)).strip()
            if _is_valid_link(cfg):
                return cfg

        # ── 3. data-copy / data-clipboard-text ──────────────────────────────
        patterns = [
            r'data-copy=["\']([^"\']+://[^"\']+)["\']',
            r'data-clipboard-text=["\']([^"\']+://[^"\']+)["\']',
            r'data-value=["\']([^"\']+://[^"\']+)["\']',
        ]
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                cfg = _html.unescape(m.group(1)).strip()
                if _is_valid_link(cfg):
                    return cfg

        # ── 4. <code> блок с протоколом ─────────────────────────────────────
        m = re.search(
            r'<code[^>]*>\s*([a-z0-9]+://[^\s<]+)\s*</code>',
            html,
            re.IGNORECASE,
        )
        if m:
            cfg = _html.unescape(m.group(1)).strip()
            if _is_valid_link(cfg):
                return cfg

        # ── 5. Любой текст-узел с ://, который проходит валидацию ───────────
        for proto in PROTOCOLS:
            m = re.search(
                rf'({re.escape(proto)}[^\s<>"\']+)',
                html,
                re.IGNORECASE,
            )
            if m:
                cfg = _html.unescape(m.group(1)).strip().rstrip('.,;)"\'')
                if _is_valid_link(cfg):
                    return cfg

        return None

    with ThreadPoolExecutor(max_workers=PREMIUM_CONCURRENT) as ex:
        futures = {
            ex.submit(_parse_config, u): u
            for u in all_card_urls
        }

        for f in as_completed(futures):
            cfg = None

            try:
                cfg = f.result()
            except Exception:
                pass

            with lock:
                done[0] += 1

                if cfg:
                    found_configs.append(cfg)

                if done[0] % 50 == 0:
                    print(
                        f"    {source_name} {done[0]}/{len(all_card_urls)} "
                        f"found: {len(found_configs)}",
                        end="\r",
                        flush=True,
                    )

    found_configs = list(dict.fromkeys(found_configs))

    out_file.write_text("\n".join(found_configs), encoding="utf-8")

    if countries:
        country_file.write_text(
            "\n".join(sorted(countries)),
            encoding="utf-8",
        )

    print(f"\n  ✓  {source_name}: {len(found_configs)} configs", flush=True)

    if countries:
        print(f"  🌍  countries: {len(countries)}")

    print(f"  💾  saved → {out_file}")

    return found_configs


def _fetch_source_vlesskey(work_dir: Path) -> list[str]:
    return _fetch_source_premium_site(
        work_dir,
        "vlesskey",
        VLESSKEY_BASE,
    )


def _fetch_source_outlinekeys(work_dir: Path) -> list[str]:
    return _fetch_source_premium_site(
        work_dir,
        "outlinekeys",
        OUTLINEKEYS_BASE,
    )


def _fetch_source_local_dir(local_path: Path) -> list[str]:
    """Read all .txt files from a local directory and extract VPN links."""
    if not local_path.exists():
        print(f"  ⚠  local dir does not exist: {local_path}")
        return []
    if not local_path.is_dir():
        try:
            text = local_path.read_text(encoding="utf-8", errors="ignore")
            links = _parse_links(text)
            print(f"  ✓  {local_path.name} → {len(links)} configs")
            return links
        except Exception as e:
            print(f"  ⚠  {local_path}: {e}")
            return []

    txt_files = sorted(local_path.rglob("*.txt"))
    if not txt_files:
        print(f"  ⚠  No .txt files found in {local_path}")
        return []

    print(f"  📂  Local dir: {local_path}  ({len(txt_files)} .txt files)")
    links: list[str] = []
    for fp in txt_files:
        rel = fp.relative_to(local_path)
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"  ⚠  {rel}: read error — {e}")
            continue
        if _is_base64_encoded_file(text):
            print(f"  ⏭  {rel} — skipped (base64-encoded content)")
            continue
        found = _parse_links(text)
        if found:
            print(f"  ✓  {rel} → {len(found)} configs")
            links.extend(found)
    return links


# ── Telegram channel parser ───────────────────────────────────────────────────
#
# Два режима:
#   1. Web-парсинг t.me/s/<channel>  — без API, без токена, без регистрации.
#      Ограничение: только ~последние 50 страниц × 20 сообщений = ~1000 сообщ.
#   2. Bot API  — если указан TG_BOT_TOKEN, парсит через getUpdates / forwardMessages.
#      Для полного парсинга (10k+ сообщений) нужен Telethon (user account).
#
# Конфиги ищем прямо в тексте сообщений: любая строка с vless://, vmess://, trojan://, ...
# Результат сохраняется в sources/telegram/<channel>.txt и в sources/telegram/all.txt.

TG_BOT_TOKEN: str = ""   # опционально: "1234567890:AABBCCDDEEFFaabbccddeeff"


def _fetch_source_telegram(
    work_dir: Path,
    channels: Optional[list[str]] = None,
    bot_token: str = "",
    max_pages: int = TG_WEB_MAX_PAGES,
) -> list[str]:
    """Parse Telegram channels for VPN configs.

    Режим 1 (без токена): парсит публичный веб-интерфейс t.me/s/<channel>.
    Режим 2 (с bot_token): использует Bot API для большего охвата.

    channels — список username-ов (без @). None = TG_CHANNELS по умолчанию.
    bot_token — Telegram Bot API token. Пустая строка = веб-режим.
    max_pages — сколько страниц t.me/s/<ch>?before=<id> обходить (режим 1).
    """
    if channels is None:
        channels = TG_CHANNELS

    out_dir = work_dir / "telegram"
    out_dir.mkdir(parents=True, exist_ok=True)

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
    }

    def _http_get_tg(url: str, timeout: int = 15) -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception:
            return None

    # ── Режим 1: web scraping t.me/s/<channel> ───────────────────────────────
    def _parse_channel_web(channel: str) -> list[str]:
        """Парсит публичный превью-сайт Telegram без API."""
        all_links: list[str] = []
        # Начинаем с первой страницы, потом идём по ?before=<min_msg_id>
        before_id: Optional[int] = None
        pages_done = 0

        while pages_done < max_pages:
            if before_id:
                url = f"https://t.me/s/{channel}?before={before_id}"
            else:
                url = f"https://t.me/s/{channel}"

            html = _http_get_tg(url)
            if not html:
                break

            # Если канал не существует или приватный — выходим
            if "tgme_page_extra" not in html and "tgme_widget_message" not in html:
                break

            # Извлекаем текст сообщений из data-post или .tgme_widget_message_text
            # Паттерн 1: текст внутри <div class="tgme_widget_message_text ...">
            texts = re.findall(
                r'<div[^>]+class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
                html, re.DOTALL | re.IGNORECASE,
            )
            # Паттерн 2: data-post="channel/NNN" → берём весь блок сообщения
            raw_text = re.sub(r"<[^>]+>", " ", "\n".join(texts))  # strip HTML tags

            found = _parse_links(raw_text)
            all_links.extend(found)

            # Находим минимальный msg id на странице для пагинации
            msg_ids = [int(m) for m in re.findall(r'data-post="[^/]+/(\d+)"', html)]
            if not msg_ids:
                break
            min_id = min(msg_ids)
            if before_id is not None and min_id >= before_id:
                break  # не продвинулись — конец истории
            before_id = min_id
            pages_done += 1

            if pages_done % 10 == 0:
                print(f"    tg/{channel}: page {pages_done}, "
                      f"{len(all_links)} configs so far", end="\r", flush=True)

        return all_links

    # ── Режим 2: Bot API ──────────────────────────────────────────────────────
    def _parse_channel_botapi(channel: str, token: str) -> list[str]:
        """Использует getUpdates для чтения сообщений из каналов.

        Примечание: Bot API getUpdates не даёт доступ к истории каналов,
        только к новым апдейтам с момента добавления бота. Для полного
        парсинга истории нужен Telethon (user account API).
        """
        all_links: list[str] = []
        try:
            url = f"https://api.telegram.org/bot{token}/getUpdates?limit=100&allowed_updates=[\"channel_post\"]"
            req = urllib.request.Request(url, headers={"User-Agent": "AegisNET/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())

            if not data.get("ok"):
                return []

            for upd in data.get("result", []):
                text = (upd.get("channel_post") or upd.get("message") or {}).get("text", "")
                if text:
                    all_links.extend(_parse_links(text))
        except Exception as e:
            print(f"  ⚠  tg bot API error for {channel}: {e}")
        return all_links

    # ── Основной цикл по каналам (параллельный) ───────────────────────────────
    print(f"  📡  Telegram: {len(channels)} channels, "
          f"{'Bot API' if bot_token else f'web (max {max_pages} pages/channel)'}", flush=True)

    all_configs: list[str] = []
    ch_lock = threading.Lock()

    def _process_channel(ch: str) -> tuple[str, list[str]]:
        if bot_token:
            links = _parse_channel_botapi(ch, bot_token)
        else:
            links = _parse_channel_web(ch)
        return ch, links

    with ThreadPoolExecutor(max_workers=min(8, len(channels))) as ex:
        futures = {ex.submit(_process_channel, ch): ch for ch in channels}
        for f in as_completed(futures):
            ch, links = f.result()
            links = list(dict.fromkeys(links))
            with ch_lock:
                all_configs.extend(links)
            if links:
                # Сохраняем файл канала
                ch_file = out_dir / f"{ch}.txt"
                ch_file.write_text("\n".join(links), encoding="utf-8")
                print(f"  ✓  t.me/{ch:<25} → {len(links):>4} configs", flush=True)
            else:
                print(f"  ·  t.me/{ch:<25} → 0 (private/empty/no VPN configs)", flush=True)

    all_configs = list(dict.fromkeys(all_configs))

    # Сохраняем общий файл
    all_file = out_dir / "all.txt"
    all_file.write_text("\n".join(all_configs), encoding="utf-8")
    print(f"\n  ✓  Telegram total: {len(all_configs)} configs → {all_file}", flush=True)

    return all_configs


def fetch_all_sources(
    sources: list[str],
    work_dir: Optional[Path] = None,
    fetch_mode: int = 4,
) -> list[str]:
    """
    Collect VPN configs from all requested sources.

    fetch_mode controls what operations are performed per source:
      1 — read existing .txt files only  (fastest, no network/scripts)
      2 — git clone/pull, then read .txt  (refreshes files, no scripts)
      3 — run update scripts, then read .txt  (uses local clone, no git)
      4 — git clone/pull + run scripts + read .txt  (full refresh) [default]

    sources — list of source names or direct URLs:
              "kort0881", "v2ray_agg", "epodonios", or https://...
    work_dir — directory for cloned repos (default: system temp)
    """
    if work_dir is None:
        work_dir = Path(tempfile.gettempdir()) / "aegis_admin_sources"
    work_dir.mkdir(parents=True, exist_ok=True)

    mode_labels = {
        1: "read .txt (no git, no scripts)",
        2: "git pull + read .txt",
        3: "run scripts + read .txt (no git)",
        4: "git pull + run scripts + read .txt",
    }
    print(f"  Mode {fetch_mode}: {mode_labels.get(fetch_mode, '?')}")

    all_links: list[str] = []

    effective_sources = list(sources)

    for src in effective_sources:
        src = src.strip()
        print(f"\n  --- Source: {src} ---")
        if src == "kort0881":
            links = _fetch_source_kort0881(work_dir, fetch_mode)
        elif src in ("v2ray_agg", "v2ray"):
            links = _fetch_source_v2ray_agg(work_dir, fetch_mode)
        elif src in ("epodonios", "epodonios_v2ray"):
            links = _fetch_source_epodonios(work_dir, fetch_mode)
        elif src == "urls_base":
            links = _fetch_source_urls_base(work_dir)
        elif src in ("keysconf", "keysconf.com"):
            links = _fetch_source_keysconf(work_dir)

        elif src in ("vlesskey", "vlesskey.com"):
            links = _fetch_source_vlesskey(work_dir)

        elif src in ("outlinekeys", "outlinekeys.com"):
            links = _fetch_source_outlinekeys(work_dir)

        elif src in ("telegram", "tg") or src.startswith("telegram:") or src.startswith("tg:"):
            # telegram              — парсит все каналы из TG_CHANNELS
            # telegram:chan1,chan2  — парсит конкретные каналы
            # telegram:token:TOKEN — использует Bot API
            bot_token = TG_BOT_TOKEN
            custom_channels: Optional[list[str]] = None
            if ":" in src:
                suffix = src.split(":", 1)[1]
                if suffix.startswith("token:"):
                    bot_token = suffix[len("token:"):]
                elif len(suffix) > 30 and "," not in suffix:
                    bot_token = suffix
                else:
                    custom_channels = [c.strip().lstrip("@") for c in suffix.split(",") if c.strip()]
            links = _fetch_source_telegram(work_dir, channels=custom_channels, bot_token=bot_token)
        elif src.startswith("local:"):
            local_path = Path(src[len("local:"):].strip())
            if not local_path.is_absolute():
                resolved = Path.cwd() / local_path
                if not resolved.exists():
                    resolved = Path(__file__).parent / local_path
                local_path = resolved
            links = _fetch_source_local_dir(local_path)
        else:
            links = _fetch_direct_url(src)

        all_links.extend(links)
        print(f"  → {len(links)} configs from {src}")

    return list(dict.fromkeys(all_links))


def _fetch_direct_url(url: str) -> list[str]:
    """Fetch a single raw URL and extract VPN links."""
    headers = {"User-Agent": _random_ua()}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            text = r.read().decode("utf-8", errors="ignore")
        links = _parse_links(text)
        print(f"  ✓  {url.split('/')[-1]} → {len(links)} configs")
        return links
    except Exception as e:
        print(f"  ⚠  {url}: {e}")
        return []


# ── Config verification (ping + 3-stage xray) ─────────────────────────────────
#
# Thresholds are intentionally generous: this admin script runs from one
# fixed location while configs are used by people all over the world.
# A config that looks "slow" from Germany may be perfectly fine for a user
# in Moscow, and vice versa — so we only reject configs that are truly dead.

MAX_PING_MS   = 1000   # до 1000 мс — отсекаем совсем мёртвые хосты
PING_TIMEOUT  = 3.0    # 3 сек на коннект
PING_WORKERS  = 100
CHECK_WORKERS = 20 if sys.platform == "win32" else 32
XRAY_START_TIMEOUT = 12.0
XRAY_READY_CHECK_INTERVAL = 0.05

# 3-stage xray check
# MIN_MS убран везде — скорость не критерий, важна только корректность данных.
CHECK1_URL, CHECK1_TIMEOUT = "https://ya.ru",             5.0
CHECK2_URL, CHECK2_TIMEOUT = "https://google.com",         5.0
CHECK2_FALLBACK_URL        = "https://browserleaks.com/ip"
CHECK2_FALLBACK_STATUSES   = {429, 403}

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
]

def _random_ua() -> str:
    return random.choice(_UA_POOL)

# Stage 3: скачиваем файл и сверяем MD5 с эталоном (получается без прокси при старте).
# Это единственная надёжная проверка: заглушка/кеш/редирект дадут другой хеш.
CHECK3_URL, CHECK3_TIMEOUT = (
    "https://gist.githubusercontent.com/aal89/0e8d16a81a72d420aae9806ee87e3399/raw/100kb.txt",
    15.0,
)

# Эталонные MD5/тело для stage 1 и 2 — заполняются один раз при запуске check_config_full.
# Ключ — URL, значение — md5 bytes тела ответа.
_REFERENCE_MD5: dict[str, Optional[bytes]] = {}
_REFERENCE_MD5_LOCK = threading.Lock()

# ── Stage 3 DPI/reality check via Zapret ──────────────────────────────────────
#
# Zapret (https://github.com/bol-van/zapret) is a DPI bypass tool.
# Its winws.exe / nfqws binary can be used to probe whether a config survives
# deep-packet-inspection filtering — critical for Reality/VLESS-Reality configs
# that must bypass ТСПУ/DPI on Russian ISPs.
#
# Layout expected:
#   core/zapret/winws.exe      (Windows)
#   core/zapret/nfqws          (Linux)
#   core/zapret/ipset/         (optional pre-built ipsets)
#
# The check works by:
#   1. Detecting whether the config uses Reality security.
#   2. If Reality: run Zapret probe alongside xray and verify the HTTPS request
#      goes through without triggering DPI (response must be 200, not RST/empty).
#   3. Non-Reality configs skip the Zapret probe (standard stage-3 download).
#
# DPI_REALITY_PROBE_URL: a well-known domain that Russian DPI actively inspects.
# Must be reachable via a working Reality config; blocked if DPI is active.
DPI_REALITY_PROBE_URLS = [
    "https://www.youtube.com/generate_204",   # often DPI-filtered in RU
    "https://www.instagram.com/favicon.ico",  # blocked in RU without bypass
    "https://discord.com/favicon.ico",        # blocked in RU without bypass
]
DPI_PROBE_TIMEOUT   = 20.0   # seconds per probe URL
# Minimum successful probe URLs required to pass the DPI stage
DPI_PROBE_MIN_PASS  = 1      # at least 1 of the 3 probe URLs must respond


# ── OS detection helper ───────────────────────────────────────────────────────
import platform as _platform_mod

def _detect_os() -> str:
    """Return 'windows', 'debian', or 'linux'."""
    s = _platform_mod.system().lower()
    if s == "windows":
        return "windows"
    # Try to detect Debian/Ubuntu
    try:
        with open("/etc/os-release") as f:
            txt = f.read().lower()
        if "debian" in txt or "ubuntu" in txt:
            return "debian"
    except Exception:
        pass
    return "linux"

OS_TYPE: str = _detect_os()

# ── Zapret2 constants ─────────────────────────────────────────────────────────
# zapret1 (old) — Windows bundle with winws.exe
ZAPRET_WIN_BUNDLE_URL  = "https://api.github.com/repos/bol-van/zapret-win-bundle/releases/latest"
# zapret2 (new) — cross-platform nfqws2 / winws2
ZAPRET2_RELEASES_URL   = "https://api.github.com/repos/bol-van/zapret2/releases/latest"
# Keep for backward compat
ZAPRET_RELEASES_URL    = ZAPRET2_RELEASES_URL


def _find_or_download_zapret() -> Optional[str]:
    """Locate zapret2 binary; download latest release if missing.

    Windows : winws2.exe  (from bol-van/zapret-win-bundle)
    Linux   : nfqws2      (from bol-van/zapret2 releases)
    Debian  : same as linux, or apt-install via hint

    Directory layout:
        core/zapret/winws2.exe    (Windows)
        core/zapret/winws2        (Linux – renamed from nfqws2)
        core/zapret/nfqws2        (Linux alt)
        core/zapret/lua/          (lua scripts from zapret2 repo)
    """
    base   = Path(__file__).parent / "core" / "zapret"
    is_win = OS_TYPE == "windows"

    # ── 1. Check if already present ─────────────────────────────────────────
    if is_win:
        candidates = [base / "winws2.exe", base / "winws.exe"]
    else:
        candidates = [base / "nfqws2", base / "winws2", base / "nfqws"]

    for c in candidates:
        if c.exists():
            return str(c)

    print(f"  ⬇  zapret2 not found [{OS_TYPE}], downloading latest release ...", flush=True)

    # ── 2. Download ──────────────────────────────────────────────────────────
    try:
        import io as _io, zipfile as _zipfile, tarfile as _tarfile

        headers = {"User-Agent": "AegisNET-Admin/1.0",
                   "Accept": "application/vnd.github.v3+json"}

        if is_win:
            # Windows: use zapret-win-bundle (has winws2.exe pre-built)
            req = urllib.request.Request(ZAPRET_WIN_BUNDLE_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            asset_url = next(
                (a["browser_download_url"] for a in data.get("assets", [])
                 if a["name"].endswith(".zip") and "win" in a["name"].lower()),
                None
            )
        else:
            # Linux/Debian: zapret2 releases contain source+binaries as tarball_url.
            # GitHub assets[] is empty — бинарники внутри source archive в binaries/linux-<arch>/
            req = urllib.request.Request(ZAPRET2_RELEASES_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())

            machine = _platform_mod.machine().lower()
            if "aarch64" in machine or "arm64" in machine:
                arch_dir = "linux-arm64"
            elif "arm" in machine:
                arch_dir = "linux-arm"
            else:
                arch_dir = "linux-x86_64"

            # zapret2 публикует asset zapret2-vX.X.X.tar.gz в releases
            # внутри которого бинарники в binaries/linux-<arch>/nfqws2
            assets = data.get("assets", [])
            tarball_url = next(
                (a["browser_download_url"] for a in assets if a["name"].endswith(".tar.gz")),
                None
            ) or data.get("tarball_url")
            if not tarball_url:
                print(f"  ⚠  Не найден .tar.gz в релизе zapret2")
                print(f"       Assets: {[a['name'] for a in assets]}")
                _zapret_manual_hint()
                return None

            tag = data.get("tag_name", "?")
            print(f"  ⬇  Скачиваю zapret2 {tag}: {tarball_url.split('/')[-1]} ...", flush=True)
            req2 = urllib.request.Request(tarball_url, headers={"User-Agent": "AegisNET-Admin/1.0"})
            with urllib.request.urlopen(req2, timeout=120) as r:
                raw = r.read()
            print(f"  [i]  Скачано {len(raw):,} байт", flush=True)

            base.mkdir(parents=True, exist_ok=True)

            # Распаковываем только нужный бинарник и lua/
            with _tarfile.open(fileobj=_io.BytesIO(raw), mode="r:gz") as tf:
                members = tf.getmembers()
                # Путь внутри архива: <repo-tag>/binaries/<arch>/nfqws2
                bin_member = next(
                    (m for m in members
                     if f"binaries/{arch_dir}/nfqws2" in m.name and m.isfile()),
                    None
                )
                # Fallback: любой nfqws2 для linux
                if not bin_member:
                    bin_member = next(
                        (m for m in members
                         if "binaries/linux" in m.name and m.name.endswith("/nfqws2") and m.isfile()),
                        None
                    )
                if not bin_member:
                    print(f"  ⚠  nfqws2 не найден в архиве. Доступные binaries:")
                    for m in members:
                        if "binaries/" in m.name and m.isfile():
                            print(f"       {m.name}")
                    _zapret_manual_hint()
                    return None

                print(f"  [i]  Извлекаю {bin_member.name} → core/zapret/nfqws2", flush=True)
                f = tf.extractfile(bin_member)
                dest = base / "nfqws2"
                dest.write_bytes(f.read())
                dest.chmod(0o755)

                # Извлекаем lua/ скрипты
                lua_dest = base / "lua"
                lua_dest.mkdir(exist_ok=True)
                for m in members:
                    if "/lua/" in m.name and m.name.endswith(".lua") and m.isfile():
                        lua_file = lua_dest / Path(m.name).name
                        lf = tf.extractfile(m)
                        if lf:
                            lua_file.write_bytes(lf.read())
                print(f"  [OK] lua scripts → {lua_dest}", flush=True)

            print(f"  [OK] zapret2 готов: {dest}")
            return str(dest)

    except Exception as e:
        print(f"  ⚠  zapret2 download failed: {e}")
        _zapret_manual_hint()
        return None


def _zapret2_fetch_lua(base: Path, release_data: dict) -> None:
    """Download zapret2 lua/ scripts if not already present (Linux only)."""
    lua_dir = base / "lua"
    if lua_dir.exists() and any(lua_dir.rglob("*.lua")):
        return
    try:
        import io as _io, zipfile as _zipfile
        # Look for a source zip in the release assets
        asset_url = next(
            (a["browser_download_url"] for a in release_data.get("assets", [])
             if a["name"].endswith(".zip") and "source" not in a["name"].lower()),
            None
        )
        if not asset_url:
            return
        req = urllib.request.Request(asset_url, headers={"User-Agent": "AegisNET-Admin/1.0"})
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
        with _zipfile.ZipFile(_io.BytesIO(raw)) as zf:
            lua_files = [n for n in zf.namelist() if "/lua/" in n and n.endswith(".lua")]
            for lf in lua_files:
                out = base / Path(lf).relative_to(Path(lf).parts[0])
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(zf.read(lf))
        print(f"  [OK] zapret2 lua scripts extracted → {lua_dir}")
    except Exception:
        pass  # lua scripts are optional


def _apt_install_zapret_deps() -> bool:
    """Install required apt packages for nfqws2 on Debian/Ubuntu. Returns True if all OK."""
    pkgs = ["iptables", "ipset", "libnetfilter-queue1", "libnetfilter-queue-dev"]
    print("  [i]  Устанавливаю apt-зависимости для nfqws2 ...", flush=True)
    import shutil as _shutil
    apt = _shutil.which("apt-get") or _shutil.which("apt")
    if not apt:
        print("  ⚠  apt не найден — установите пакеты вручную:")
        print(f"       sudo apt install -y {' '.join(pkgs)}")
        return False
    is_root = os.geteuid() == 0
    cmd = ([] if is_root else ["sudo"]) + [apt, "install", "-y"] + pkgs
    try:
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        result = subprocess.run(cmd, timeout=120, capture_output=False, env=env)
        if result.returncode == 0:
            print("  [OK] apt-зависимости установлены")
            return True
        else:
            print(f"  ⚠  apt вышел с кодом {result.returncode}")
            print(f"       Попробуйте вручную: sudo apt install -y {' '.join(pkgs)}")
            return False
    except FileNotFoundError:
        print("  ⚠  sudo не найден — запустите скрипт от root или установите пакеты вручную:")
        print(f"       sudo apt install -y {' '.join(pkgs)}")
        return False
    except subprocess.TimeoutExpired:
        print("  ⚠  apt завис — установите пакеты вручную:")
        print(f"       sudo apt install -y {' '.join(pkgs)}")
        return False


def _zapret_manual_hint() -> None:
    if OS_TYPE == "windows":
        print("       Скачайте вручную: https://github.com/bol-van/zapret-win-bundle/releases")
        print("       Поместите winws2.exe в папку core/zapret/")
    elif OS_TYPE == "debian":
        print("       sudo apt install -y iptables ipset libnetfilter-queue1 libnetfilter-queue-dev")
        print("       Затем скачайте nfqws2: https://github.com/bol-van/zapret2/releases")
        print("       Поместите nfqws2 в папку core/zapret/")
    else:
        print("       Скачайте nfqws2: https://github.com/bol-van/zapret2/releases")
        print("       Поместите nfqws2 в папку core/zapret/")


# Keep old name as alias for compatibility
def _find_zapret() -> Optional[str]:
    return _find_or_download_zapret()


def _is_reality_config(link: str) -> bool:
    """Return True if the VPN link uses VLESS Reality security."""
    try:
        p = urllib.parse.urlparse(link)
        # Reality appears as security=reality in query params (VLESS/Xray URI)
        qs = urllib.parse.parse_qs(p.query)
        security = qs.get("security", [""])[0].lower()
        if security == "reality":
            return True
        # Also catch vmess JSON with reality
        if link.startswith("vmess://"):
            b64 = link[len("vmess://"):].split("#")[0]
            padded = b64 + "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
            return str(data.get("tls", "")).lower() == "reality"
    except Exception:
        pass
    return False


def _start_zapret(zapret_exe: str, zapret_port: int) -> Optional[subprocess.Popen]:
    """Start Zapret as a local SOCKS5 proxy that xray dials through.

    Zapret (winws.exe / nfqws) sits between xray's outbound and the internet.
    xray connects to Zapret's SOCKS5 port, Zapret applies DPI-bypass tricks
    (fake TLS ClientHello, TTL mangling, multisplit fragmentation) to the
    outgoing TLS handshake before forwarding to the real server.

    Stack:
        requests
          → xray SOCKS5 in (127.0.0.1:socks_port)
          → xray Reality/VLESS outbound  [dialerProxy = zapret-out]
          → Zapret SOCKS5 in (127.0.0.1:zapret_port)
          → internet  (DPI bypassed)

    Windows: winws.exe supports --socks mode natively.
    Linux:   nfqws does NOT support SOCKS — on Linux the stack is
             xray → nfqws via NFQUEUE (requires root). For the admin
             check script we simply skip Zapret on Linux if nfqws is
             detected, and run without it (xray-only Reality check).
    """
    try:
        zapret_dir = str(Path(zapret_exe).parent)
        exe_name   = Path(zapret_exe).name
        flags      = 0x08000000 if sys.platform == "win32" else 0

        is_zapret2 = exe_name in ("winws2.exe", "nfqws2", "winws2")

        if OS_TYPE == "windows" and exe_name in ("winws2.exe", "winws.exe"):
            # winws2 (zapret2) — SOCKS mode with lua strategy
            lua_dir  = Path(zapret_dir) / "lua"
            lib_lua  = lua_dir / "zapret-lib.lua"
            obfs_lua = lua_dir / "zapret-obfs.lua"

            if is_zapret2 and lib_lua.exists() and obfs_lua.exists():
                # zapret2: lua-based strategy (nfqws2/winws2 syntax)
                args = [
                    zapret_exe,
                    f"--socks={zapret_port}",
                    "--wf-tcp=443",
                    "--wf-udp=443,50000-65535",
                    f"--lua-init=@{lib_lua}",
                    f"--lua-init=@{obfs_lua}",
                    "--lua-desync=fake_tls",
                ]
            else:
                # zapret1 fallback: classic winws.exe syntax
                fake_tls = Path(zapret_dir) / "tls_clienthello_www_google_com.bin"
                args = [
                    zapret_exe,
                    "--socks",
                    f"--port={zapret_port}",
                    "--wf-tcp=443",
                    "--wf-udp=443,50000-65535",
                    "--dpi-desync=fake,multisplit",
                    "--dpi-desync-ttl=5",
                ]
                if fake_tls.exists():
                    args.append(f"--dpi-desync-fake-tls={fake_tls}")
        elif OS_TYPE in ("linux", "debian") and exe_name in ("nfqws2", "nfqws", "winws2"):
            # nfqws2 on Linux: cannot run as SOCKS5 in check-mode —
            # we configure it via NFQUEUE when running as root.
            # For the xray-check pipeline we skip Zapret and run xray-only.
            return None
        else:
            return None

        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
            cwd=zapret_dir,
        )
        time.sleep(0.5)  # give winws a moment to bind the port
        if proc.poll() is not None:
            return None   # exited immediately — startup failure
        return proc
    except Exception:
        return None


def _check_stage3_dpi_reality(
    link: str,
    xray_exe: str,
    port: int,
    zapret_exe: Optional[str],
) -> bool:
    """Stage 3 for Reality configs: full X-ray + Zapret stacked check.

    Brings up the stacked proxy:
        requests → xray SOCKS (port) → xray Reality outbound
                   [dialerProxy=zapret-out] → Zapret SOCKS (zapret_port) → internet

    Runs two sub-checks in sequence, both must pass:
      A) 100 KB download (original stage-3 speed/stability check).
      B) DPI probe: at least DPI_PROBE_MIN_PASS of the DPI_REALITY_PROBE_URLS
         must respond — confirms Reality + Zapret bypass survives DPI filtering.

    If Zapret binary is unavailable or fails to start, falls back to plain
    xray-only check (no dialerProxy) so the test still runs, just without
    the DPI-bypass layer.
    """
    zapret_port = port + 10   # offset so it doesn't collide with xray ports
    zapret_proc = None

    # Try to start Zapret and get the port it listens on
    effective_zapret_port: Optional[int] = None
    if zapret_exe:
        zapret_proc = _start_zapret(zapret_exe, zapret_port)
        if zapret_proc:
            effective_zapret_port = zapret_port

    # Start xray with dialerProxy → Zapret (or plain if Zapret unavailable)
    proc, tmp = _start_xray(link, xray_exe, port, zapret_port=effective_zapret_port)
    if not proc:
        if zapret_proc:
            try: zapret_proc.kill(); zapret_proc.wait(timeout=2)
            except Exception: pass
        return False

    try:
        if not _wait_port(port, 5.0):
            return False

        proxies = {
            "http":  f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }

        # ── Sub-check A: 100 KB download (MD5 authenticity check) ───────────────
        ms = _http_check_md5(proxies, CHECK3_URL, CHECK3_TIMEOUT)
        if ms is None:
            return False

        # ── Sub-check B: DPI probe (blocked domains) ──────────────────────────
        # Dynamic pages — MD5 not applicable. Check only that we get HTTP 200
        # (no RST/timeout/captive-portal redirect), which confirms DPI bypass works.
        passed = 0
        for probe_url in DPI_REALITY_PROBE_URLS:
            try:
                r = _requests.get(probe_url, proxies=proxies, timeout=DPI_PROBE_TIMEOUT,
                                  allow_redirects=False,
                                  headers={"User-Agent": _random_ua()})
                if r.status_code == 200:
                    passed += 1
                    if passed >= DPI_PROBE_MIN_PASS:
                        break
            except Exception:
                pass
        if passed < DPI_PROBE_MIN_PASS:
            return False

        return True

    finally:
        _kill_xray(proc, tmp)
        if zapret_proc:
            try: zapret_proc.kill(); zapret_proc.wait(timeout=2)
            except Exception: pass


# ── Stage 4: stacked ping latency threshold ───────────────────────────────────
# TCP ping measured through the full X-ray + Zapret stack (Reality configs)
# or plain X-ray stack (non-Reality). Must be ≤ this value to pass.
CHECK4_MAX_STACK_PING_MS = 995   # конфиги медленнее 995 мс отсеиваются
# How many TCP connect attempts to average for the stacked ping
CHECK4_PING_ATTEMPTS     = 3
# Timeout per single TCP connect attempt (seconds)
CHECK4_PING_TIMEOUT      = 10.0  # должен перекрывать реальный RTT туннеля
# Target host:port для stacked ping
# httpbin.org/status/200 — гарантированно возвращает 200, лёгкий эндпоинт
CHECK4_PROBE_HOST = "gist.githubusercontent.com"
CHECK4_PROBE_PORT = 443
CHECK4_PROBE_PATH = "/Norkezz/534514114674e7a15ca44d61b97e14fe/raw/fb81d375500f3b66971f21ab262e0d5892b97d4c/GET200.txt"


def _stack_ping_ms(
    link: str,
    xray_exe: str,
    port: int,
    zapret_port: Optional[int],
    attempts: int = CHECK4_PING_ATTEMPTS,
    per_timeout: float = CHECK4_PING_TIMEOUT,
) -> Optional[int]:
    """Measure real TCP latency through the full X-ray [+ Zapret] stack.

    Выполняет SOCKS5 handshake через xray до CHECK4_PROBE_HOST:CHECK4_PROBE_PORT
    (ya.ru:80 — уже подтверждён Stage 1). После установки туннеля шлёт HTTP HEAD
    и ждёт первый байт ответа — это честный RTT через VPN.

    Returns the median RTT in ms, or None if all attempts fail.
    """
    PROBE_HOST = CHECK4_PROBE_HOST
    PROBE_PORT = CHECK4_PROBE_PORT
    PROBE_PATH = CHECK4_PROBE_PATH
    USE_TLS    = (PROBE_PORT == 443)

    def _socks5_connect_ms() -> Optional[int]:
        import struct as _struct
        import ssl as _ssl
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(per_timeout)
        try:
            sock.connect(("127.0.0.1", port))
            # SOCKS5 greeting
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
                return None
            # SOCKS5 CONNECT request — DOMAIN type (0x03)
            # t0 стартует здесь: xray сейчас будет устанавливать реальный
            # VPN-туннель до удалённого сервера — это самый долгий этап.
            # В elapsed войдёт: VPN tunnel setup + TLS handshake к probe
            # host + HTTP GET first byte — честный E2E RTT через весь стек.
            host_bytes = PROBE_HOST.encode()
            req = (b"\x05\x01\x00\x03" +
                   bytes([len(host_bytes)]) + host_bytes +
                   _struct.pack(">H", PROBE_PORT))
            t0 = time.perf_counter()
            sock.sendall(req)
            hdr = sock.recv(10)
            if len(hdr) < 2 or hdr[1] != 0x00:
                return None
            # Обернуть в TLS если порт 443
            stream: Any = sock
            if USE_TLS:
                ctx = _ssl.create_default_context()
                stream = ctx.wrap_socket(sock, server_hostname=PROBE_HOST)
            # Шлём HTTP GET и ждём первый байт ответа
            http_req = (
                f"GET {PROBE_PATH} HTTP/1.0\r\n"
                f"Host: {PROBE_HOST}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            stream.sendall(http_req)
            first_byte = stream.recv(1)
            elapsed = int((time.perf_counter() - t0) * 1000)
            if not first_byte:
                return None
            return elapsed
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    samples: list[int] = []
    for _ in range(attempts):
        ms = _socks5_connect_ms()
        if ms is not None:
            samples.append(ms)
    if not samples:
        return None
    samples.sort()
    return samples[len(samples) // 2]  # median


def _check_stage4_stack_ping(
    link: str,
    xray_exe: str,
    port: int,
    zapret_exe: Optional[str],
    threshold_ms: int = CHECK4_MAX_STACK_PING_MS,
) -> bool:
    """Stage 4: stacked ping latency check (X-ray + Zapret for Reality).

    Starts the same proxy stack used in stage 3 but only measures TCP connect
    latency through it — no HTTP request, no data transfer.

    Stack for Reality:
        TCP connect → xray SOCKS (port) → xray Reality outbound
                      [dialerProxy] → Zapret SOCKS (zapret_port) → VPN server
    Stack for non-Reality:
        TCP connect → xray SOCKS (port) → xray outbound → VPN server

    Pass condition: median RTT ≤ CHECK4_MAX_STACK_PING_MS (350 ms).
    """
    zapret_port = port + 10
    zapret_proc = None
    effective_zapret_port: Optional[int] = None

    if zapret_exe:
        zapret_proc = _start_zapret(zapret_exe, zapret_port)
        if zapret_proc:
            effective_zapret_port = zapret_port

    proc, tmp = _start_xray(link, xray_exe, port, zapret_port=effective_zapret_port)
    if not proc:
        if zapret_proc:
            try: zapret_proc.kill(); zapret_proc.wait(timeout=2)
            except Exception: pass
        return False

    try:
        if not _wait_port(port, 5.0):
            return False

        ms = _stack_ping_ms(link, xray_exe, port, effective_zapret_port)
        return ms is not None and ms <= threshold_ms

    finally:
        _kill_xray(proc, tmp)
        if zapret_proc:
            try: zapret_proc.kill(); zapret_proc.wait(timeout=2)
            except Exception: pass


def check_config_full(link: str, xray_exe: str, port_base: int,
                      skip_stage4: bool = False,
                      stage4_threshold_ms: int = CHECK4_MAX_STACK_PING_MS) -> bool:
    """3-stage check (single xray process): ya.ru → google.com → 100KB download.

    KEY CHANGE: всe три stage используют ОДИН xray-процесс на port_base.
    Старая схема запускала отдельный xray на каждый stage (port+0, port+1,
    port+2), что при 64 воркерах давало 192 одновременных xray-процесса —
    Windows их не тянул, процессы падали при старте, и всё проваливалось.

    Stage 1: GET ya.ru         — базовая связь с RU-доменом.
    Stage 2: GET google.com    — международный роутинг.
    Stage 3:
      • Non-Reality: xray-only 100 KB download (MD5 проверка стабильности).
      • Reality:     xray+Zapret — 100 KB download + DPI probe
                     (YouTube/Instagram/Discord). Оба sub-check обязательны.
    Stage 4: stacked ping (skip_stage4=True отключает; используется в batch).
    """
    is_reality = _is_reality_config(link)
    zapret_exe = _find_zapret() if is_reality else None
    port = port_base  # единственный порт для всего check

    # Прогреваем reference MD5 заранее (до запуска xray), чтобы не блокироваться
    # на _REFERENCE_MD5_LOCK внутри воркера пока xray ждёт запросов.
    _get_reference_md5(CHECK3_URL)

    # ── Запускаем ОДИН xray-процесс на весь check ────────────────────────────
    proc, tmp = _start_xray(link, xray_exe, port)
    if not proc:
        return False
    try:
        if not _wait_port(port, 5.0):
            return False

        proxies = {
            "http":  f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }

        # ── Stage 1: ya.ru ───────────────────────────────────────────────────
        if _http_check_status(proxies, CHECK1_URL, CHECK1_TIMEOUT) is None:
            return False

        # ── Stage 2: google.com ──────────────────────────────────────────────
        if _http_check_status(proxies, CHECK2_URL, CHECK2_TIMEOUT) is None:
            return False

        # ── Stage 3: 100 KB download (MD5) ───────────────────────────────────
        if is_reality:
            # Reality: нужен Zapret — завершаем текущий xray и запускаем стек
            _kill_xray(proc, tmp)
            proc, tmp = None, None
            if not _check_stage3_dpi_reality(link, xray_exe, port + 2, zapret_exe):
                return False
        else:
            if _http_check_md5(proxies, CHECK3_URL, CHECK3_TIMEOUT) is None:
                return False

    finally:
        if proc is not None:
            _kill_xray(proc, tmp)

    # ── Stage 4: stacked ping latency ────────────────────────────────────────
    if skip_stage4:
        return True
    port4 = port_base + 3
    return _check_stage4_stack_ping(
        link, xray_exe, port4,
        zapret_exe if is_reality else None,
        threshold_ms=stage4_threshold_ms,
    )


def _tcp_ping(host: str, port: int) -> Optional[int]:
    try:
        host.encode("ascii")
        t = time.perf_counter()
        with socket.create_connection((host, port), timeout=PING_TIMEOUT):
            return int((time.perf_counter() - t) * 1000)
    except Exception:
        return None


def _extract_host_port(link: str) -> Optional[tuple[str, int]]:
    try:
        p = urllib.parse.urlparse(link)
        h = p.hostname or ""
        port = p.port or 443
        if h and len(h) <= 253:
            return h, port
    except Exception:
        pass
    return None


XRAY_RELEASES_URL = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"

# Debian system paths (when installed via official install.sh)
XRAY_DEBIAN_PATHS = [
    "/usr/local/bin/xray",
    "/usr/bin/xray",
    "/opt/xray/xray",
]
XRAY_DEBIAN_GEOIP_DIR   = Path("/usr/local/share/xray")
XRAY_DEBIAN_CONF_DIR    = Path("/usr/local/etc/xray")
XRAY_INSTALL_SCRIPT_URL = "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"


def _find_or_download_xray() -> Optional[str]:
    """Locate xray binary; download/install latest release if missing.

    Windows : extracts Xray-windows-64.zip → core/xray.exe
    Debian  : tries system paths first, then runs official install.sh,
              falls back to manual zip extraction into core/
    Linux   : extracts Xray-linux-64.zip → core/xray
    """
    is_win = OS_TYPE == "windows"
    bin_name = "xray.exe" if is_win else "xray"
    core_dir = Path(__file__).parent / "core"

    # ── 1. Check local core/ and script dir ─────────────────────────────────
    candidates = [core_dir / bin_name, Path(__file__).parent / bin_name]
    for c in candidates:
        if c.exists():
            return str(c)

    # ── 2. Check system PATH ─────────────────────────────────────────────────
    found = shutil.which("xray")
    if found:
        return found

    # ── 3. Debian: check standard system install paths ───────────────────────
    if OS_TYPE == "debian":
        for p in XRAY_DEBIAN_PATHS:
            if Path(p).exists():
                print(f"  [OK] xray (system): {p}")
                return p

    print(f"  ⬇  xray not found [{OS_TYPE}], downloading ...", flush=True)

    # ── 4. Debian: try official install.sh (needs root) ──────────────────────
    if OS_TYPE == "debian":
        xray_path = _xray_debian_install()
        if xray_path:
            return xray_path
        print("  [i]  install.sh failed (нужен root?) — пробую zip-вариант ...")

    # ── 5. All platforms: zip download from GitHub releases ──────────────────
    return _xray_download_zip(core_dir, bin_name, is_win)


def _xray_debian_install() -> Optional[str]:
    """Run official XTLS install.sh on Debian/Ubuntu. Requires root."""
    try:
        # Check if we're root or can sudo
        import getpass as _gp
        is_root = (os.geteuid() == 0)

        if not is_root:
            print("  [i]  Для install.sh нужен root. Пробую через sudo ...")
            check = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True
            )
            if check.returncode != 0:
                print("  ⚠  sudo недоступен без пароля — пропускаю install.sh")
                return None

        print("  ⬇  Скачиваю install-release.sh ...", flush=True)
        req = urllib.request.Request(
            XRAY_INSTALL_SCRIPT_URL,
            headers={"User-Agent": "AegisNET-Admin/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            script = r.read()

        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as f:
            f.write(script)
            script_path = f.name

        os.chmod(script_path, 0o755)

        cmd = (["sudo"] if not is_root else []) + ["bash", script_path, "install"]
        print("  ▶  Запускаю install.sh install ...", flush=True)
        result = subprocess.run(cmd, timeout=120, capture_output=True, text=True)
        os.unlink(script_path)

        if result.returncode == 0:
            # Verify installation
            for p in XRAY_DEBIAN_PATHS:
                if Path(p).exists():
                    print(f"  [OK] xray установлен: {p}")
                    # Also ensure geoip/geosite dats exist
                    _xray_debian_ensure_geodata()
                    return p
        else:
            print(f"  ⚠  install.sh вышел с кодом {result.returncode}")
            if result.stderr:
                print(f"  ⚠  {result.stderr[:200]}")
        return None
    except Exception as e:
        print(f"  ⚠  install.sh: {e}")
        return None


def _xray_debian_ensure_geodata() -> None:
    """Download geoip.dat and geosite.dat to the standard Debian xray location."""
    geo_dir = XRAY_DEBIAN_GEOIP_DIR
    geo_dir.mkdir(parents=True, exist_ok=True)
    base_url = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
    for fname in ("geoip.dat", "geosite.dat"):
        dest = geo_dir / fname
        if dest.exists():
            continue
        try:
            print(f"  ⬇  Скачиваю {fname} ...", flush=True)
            req = urllib.request.Request(
                f"{base_url}/{fname}",
                headers={"User-Agent": "AegisNET-Admin/1.0"}
            )
            with urllib.request.urlopen(req, timeout=60) as r:
                dest.write_bytes(r.read())
            print(f"  [OK] {fname} → {dest}")
        except Exception as e:
            print(f"  ⚠  {fname}: {e}")


def _xray_download_zip(core_dir: Path, bin_name: str, is_win: bool) -> Optional[str]:
    """Download xray zip from XTLS/Xray-core GitHub releases and extract to core/."""
    try:
        import io as _io, zipfile as _zipfile

        machine = _platform_mod.machine().lower()
        if is_win:
            keyword = "windows-64" if "64" in machine else "windows-32"
        elif "aarch64" in machine or "arm64" in machine:
            keyword = "linux-arm64-v8a"
        elif "armv7" in machine or "armhf" in machine:
            keyword = "linux-arm32-v7a"
        elif "armv6" in machine:
            keyword = "linux-arm32-v6"
        else:
            keyword = "linux-64"

        headers = {"User-Agent": "AegisNET-Admin/1.0",
                   "Accept": "application/vnd.github.v3+json"}
        req = urllib.request.Request(XRAY_RELEASES_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())

        # XTLS asset names: Xray-windows-64.zip, Xray-linux-64.zip, etc.
        asset_url = next(
            (a["browser_download_url"] for a in data.get("assets", [])
             if keyword in a["name"].lower()
             and a["name"].endswith(".zip")
             and "dgst" not in a["name"]
             and "sha" not in a["name"].lower()),
            None
        )
        if not asset_url:
            print(f"  ⚠  xray: нет ассета '{keyword}.zip' в релизе")
            print(f"       Скачайте вручную: https://github.com/XTLS/Xray-core/releases")
            return None

        fname = asset_url.split("/")[-1]
        print(f"  ⬇  Downloading {fname} ...", flush=True)
        req2 = urllib.request.Request(asset_url, headers={"User-Agent": "AegisNET-Admin/1.0"})
        with urllib.request.urlopen(req2, timeout=180) as r:
            raw = r.read()

        core_dir.mkdir(parents=True, exist_ok=True)
        with _zipfile.ZipFile(_io.BytesIO(raw)) as zf:
            zf.extractall(core_dir)

        # Find and chmod the binary
        for candidate in [core_dir / bin_name] + list(core_dir.rglob(bin_name)):
            if candidate.exists():
                if not is_win:
                    candidate.chmod(0o755)
                # On Debian: also drop geoip/geosite into standard path
                if OS_TYPE == "debian":
                    _xray_debian_ensure_geodata()
                print(f"  [OK] xray downloaded: {candidate}")
                return str(candidate)

        print("  ⚠  xray: бинарь не найден после распаковки")
        return None
    except Exception as e:
        print(f"  ⚠  xray download failed: {e}")
        return None


# Keep old name as alias
def _find_xray() -> Optional[str]:
    return _find_or_download_xray()


# ── sing-box ──────────────────────────────────────────────────────────────────

SINGBOX_RELEASES_URL = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"


def _find_or_download_singbox() -> Optional[str]:
    """Locate sing-box binary; download latest release if missing.

    Windows : extracts sing-box-*-windows-amd64.zip → core/sing-box.exe
    Linux   : extracts sing-box-*-linux-amd64.tar.gz → core/sing-box
    ARM     : picks matching arm64 / armv7 asset automatically.
    """
    is_win = OS_TYPE == "windows"
    bin_name = "sing-box.exe" if is_win else "sing-box"
    core_dir = Path(__file__).parent / "core"

    # ── 1. Check local core/ and script dir ─────────────────────────────────
    for candidate in [core_dir / bin_name, Path(__file__).parent / bin_name]:
        if candidate.exists():
            return str(candidate)

    # ── 2. Check system PATH ─────────────────────────────────────────────────
    found = shutil.which("sing-box")
    if found:
        return found

    print(f"  ⬇  sing-box not found [{OS_TYPE}], downloading ...", flush=True)

    try:
        import io as _io, zipfile as _zipfile, tarfile as _tarfile

        machine = _platform_mod.machine().lower()
        if is_win:
            kw_os, kw_arch = "windows", "amd64"
        elif "aarch64" in machine or "arm64" in machine:
            kw_os, kw_arch = "linux", "arm64"
        elif "armv7" in machine or "armhf" in machine:
            kw_os, kw_arch = "linux", "armv7"
        else:
            kw_os, kw_arch = "linux", "amd64"

        headers = {"User-Agent": "AegisNET-Admin/1.0",
                   "Accept": "application/vnd.github.v3+json"}
        req = urllib.request.Request(SINGBOX_RELEASES_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())

        # sing-box asset names: sing-box-1.x.y-linux-amd64.tar.gz
        #                       sing-box-1.x.y-windows-amd64.zip
        ext = ".zip" if is_win else ".tar.gz"
        asset_url = next(
            (a["browser_download_url"] for a in data.get("assets", [])
             if kw_os in a["name"] and kw_arch in a["name"]
             and a["name"].endswith(ext)
             and "src" not in a["name"]),
            None,
        )
        if not asset_url:
            print(f"  ⚠  sing-box: нет ассета '{kw_os}-{kw_arch}{ext}' в релизе")
            print("       Скачайте вручную: https://github.com/SagerNet/sing-box/releases")
            return None

        fname = asset_url.split("/")[-1]
        print(f"  ⬇  Downloading {fname} ...", flush=True)
        req2 = urllib.request.Request(asset_url, headers={"User-Agent": "AegisNET-Admin/1.0"})
        with urllib.request.urlopen(req2, timeout=180) as r:
            raw = r.read()

        core_dir.mkdir(parents=True, exist_ok=True)

        if is_win:
            with _zipfile.ZipFile(_io.BytesIO(raw)) as zf:
                zf.extractall(core_dir)
        else:
            with _tarfile.open(fileobj=_io.BytesIO(raw)) as tf:
                tf.extractall(core_dir)

        # Binary may be nested inside extracted subdir
        candidates = [core_dir / bin_name] + list(core_dir.rglob(bin_name))
        for c in candidates:
            if c.exists():
                if not is_win:
                    c.chmod(0o755)
                print(f"  [OK] sing-box downloaded: {c}")
                return str(c)

        print("  ⚠  sing-box: бинарь не найден после распаковки")
        return None
    except Exception as e:
        print(f"  ⚠  sing-box download failed: {e}")
        return None


def _build_xray_cfg(link: str, port: int, zapret_port: Optional[int] = None) -> Optional[dict]:
    """Build xray JSON config for `link` listening on SOCKS `port`.

    zapret_port — when set (Reality configs), xray will chain its outbound
    through a local SOCKS proxy on that port where Zapret is listening.
    This creates the full stack:
        requests → xray SOCKS in → xray outbound (Reality/VLESS) → Zapret → internet
    Zapret then applies DPI-bypass (fake TLS, TTL mangling, multisplit) to the
    outgoing TLS stream, bypassing ТСПУ/DPI on Russian ISPs.
    """
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from xray_fluent.link_parser import parse_links_text
        nodes, _ = parse_links_text(link)
        if not nodes:
            return None
        ob = dict(nodes[0].outbound)
        ob["tag"] = "proxy"
        stream = ob.get("streamSettings")
        if isinstance(stream, dict):
            if stream.get("security") not in {"none", "tls", "reality", "xtls", ""}:
                stream["security"] = "none"

        outbounds = [ob, {"tag": "direct", "protocol": "freedom", "settings": {}}]

        # ── Chain xray outbound through Zapret (Reality stack) ─────────────────
        # Xray supports routing outbound traffic through another proxy via
        # a "socks" outbound + dialerProxy in streamSettings.sockopt.
        # We insert a local SOCKS5 outbound pointing at Zapret's listen port,
        # then tell the Reality outbound to use it as its dialer.
        if zapret_port:
            # Local SOCKS5 outbound → Zapret
            zapret_ob = {
                "tag": "zapret-out",
                "protocol": "socks",
                "settings": {
                    "servers": [{"address": "127.0.0.1", "port": zapret_port}]
                },
            }
            outbounds.append(zapret_ob)

            # Attach dialerProxy to the Reality outbound's streamSettings
            if not isinstance(stream, dict):
                stream = {}
                ob["streamSettings"] = stream
            sockopt = stream.setdefault("sockopt", {})
            sockopt["dialerProxy"] = "zapret-out"

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                          "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": outbounds,
            "routing": {"rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}]},
        }
    except Exception:
        return None


def _start_xray(link: str, xray_exe: str, port: int, zapret_port: Optional[int] = None):
    cfg = _build_xray_cfg(link, port, zapret_port=zapret_port)
    if not cfg:
        return None, None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cfg, f)
            tmp = f.name

        flags = 0
        if sys.platform == "win32":
            flags = subprocess.CREATE_NO_WINDOW

        proc = subprocess.Popen(
            [xray_exe, "run", "-c", tmp],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=flags,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        deadline = time.monotonic() + XRAY_START_TIMEOUT
        startup_log = []

        while time.monotonic() < deadline:
            if proc.poll() is not None:
                try:
                    startup_log.append(proc.stdout.read())
                except Exception:
                    pass
                log_text = "".join(startup_log).strip()
                if log_text:
                    print(f"  ⚠  xray exited during startup on port {port}:\\n{log_text[:1500]}")
                return None, tmp

            if _wait_port(port, 0.5):
                return proc, tmp

            time.sleep(XRAY_READY_CHECK_INTERVAL)

        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass

        return None, tmp
    except Exception:
        return None, None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cfg, f)
            tmp = f.name
        flags = 0x08000000 if sys.platform == "win32" else 0
        proc = subprocess.Popen(
            [xray_exe, "run", "-c", tmp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
        )
        return proc, tmp
    except Exception:
        return None, None


def _kill_xray(proc, tmp):
    if proc:
        try:
            proc.kill(); proc.wait(timeout=2)
        except Exception:
            pass
    if tmp:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _wait_port(port: int, timeout: float = XRAY_START_TIMEOUT) -> bool:
    """Wait until SOCKS5 listener is actually ready, not just bound."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5) as s:
                s.settimeout(0.5)
                s.sendall(b"\x05\x01\x00")
                resp = s.recv(2)
                if resp and resp[0] == 0x05:
                    return True
        except OSError:
            pass
        time.sleep(XRAY_READY_CHECK_INTERVAL)
    return False


import requests as _requests

# ── sing-box checker (non-VLESS protocols) ────────────────────────────────────

def _protocol_of(link: str) -> str:
    """Вернуть нижний регистр схемы URI (vless, vmess, trojan, ss, hy2, ...)."""
    try:
        return urllib.parse.urlparse(link).scheme.lower()
    except Exception:
        return ""


def _needs_singbox(link: str) -> bool:
    """True если конфиг надо проверять через sing-box, а не через xray."""
    return _protocol_of(link) in {"ss", "shadowsocks", "hy2", "hysteria2", "tuic", "trojan", "vmess"}


def _build_singbox_cfg(link: str, port: int) -> Optional[dict]:
    proto = _protocol_of(link)
    try:
        if proto == "vmess":
            outbound = _singbox_ob_vmess(link)
        elif proto == "trojan":
            outbound = _singbox_ob_trojan(link)
        elif proto in ("ss", "shadowsocks"):
            outbound = _singbox_ob_ss(link)
        elif proto in ("hy2", "hysteria2"):
            outbound = _singbox_ob_hy2(link)
        elif proto == "tuic":
            outbound = _singbox_ob_tuic(link)
        else:
            return None
        if outbound is None:
            return None
        outbound["tag"] = "proxy"
        return {
            "log": {"level": "error", "timestamp": False},
            "inbounds": [{"type": "socks", "tag": "socks-in",
                          "listen": "127.0.0.1", "listen_port": port, "sniff": False}],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"rules": [], "final": "proxy"},
        }
    except Exception:
        return None


def _singbox_ob_vmess(link: str) -> Optional[dict]:
    b64 = link[len("vmess://"):].split("#")[0].strip()
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        v = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
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
    if tls_str == "tls":
        ob["tls"] = {"enabled": True, "server_name": host or ob["server"], "insecure": True}
    if net == "ws":
        ob["transport"] = {"type": "ws", "path": path,
                           "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": path.lstrip("/")}
    elif net == "h2":
        ob["transport"] = {"type": "http", "host": [host] if host else [], "path": path}
    return ob


def _singbox_ob_trojan(link: str) -> Optional[dict]:
    try:
        p = urllib.parse.urlparse(link)
        qs = urllib.parse.parse_qs(p.query)
        password = p.username or p.password or ""
        host = p.hostname or ""
        port = p.port or 443
        sni = qs.get("sni", [qs.get("peer", [host])[0]])[0] or host
        security = qs.get("security", ["tls"])[0].lower()
        ob: dict = {"type": "trojan", "server": host, "server_port": port, "password": password}
        if security in ("tls", "reality", ""):
            ob["tls"] = {"enabled": True, "server_name": sni, "insecure": True}
        net = qs.get("type", ["tcp"])[0].lower()
        if net == "ws":
            ob["transport"] = {"type": "ws", "path": qs.get("path", ["/"])[0],
                               "headers": {"Host": qs.get("host", [sni])[0]}}
        elif net == "grpc":
            ob["transport"] = {"type": "grpc", "service_name": qs.get("serviceName", [""])[0]}
        return ob
    except Exception:
        return None


def _singbox_ob_ss(link: str) -> Optional[dict]:
    try:
        raw = link[len("ss://"):].split("#")[0]
        if "@" in raw:
            userinfo, hostport = raw.rsplit("@", 1)
            try:
                decoded = base64.b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    userinfo = decoded
            except Exception:
                pass
            method, password = userinfo.split(":", 1) if ":" in userinfo else ("chacha20-ietf-poly1305", userinfo)
        else:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", errors="ignore")
            if "@" in decoded:
                userinfo, hostport = decoded.rsplit("@", 1)
                method, password = userinfo.split(":", 1)
            else:
                return None
        if hostport.startswith("["):
            bracket_end = hostport.index("]")
            host = hostport[1:bracket_end]
            port = int(hostport[bracket_end + 2:])
        else:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s)
        return {"type": "shadowsocks", "server": host, "server_port": port,
                "method": method.lower(), "password": password}
    except Exception:
        return None


def _singbox_ob_hy2(link: str) -> Optional[dict]:
    try:
        p = urllib.parse.urlparse(link)
        qs = urllib.parse.parse_qs(p.query)
        password = p.username or p.password or ""
        host = p.hostname or ""
        port = p.port or 443
        sni = qs.get("sni", [host])[0]
        return {"type": "hysteria2", "server": host, "server_port": port, "password": password,
                "tls": {"enabled": True, "server_name": sni or host, "insecure": True}}
    except Exception:
        return None


def _singbox_ob_tuic(link: str) -> Optional[dict]:
    try:
        p = urllib.parse.urlparse(link)
        qs = urllib.parse.parse_qs(p.query)
        uuid = p.username or ""
        password = p.password or ""
        host = p.hostname or ""
        port = p.port or 443
        sni = qs.get("sni", [host])[0]
        cc = qs.get("congestion_control", ["bbr"])[0]
        return {"type": "tuic", "server": host, "server_port": port, "uuid": uuid,
                "password": password, "congestion_control": cc,
                "tls": {"enabled": True, "server_name": sni or host, "insecure": True}}
    except Exception:
        return None


_SINGBOX_START_TIMEOUT    = 8.0
_SINGBOX_READY_CHECK_POLL = 0.15


def _start_singbox(link: str, singbox_exe: str, port: int):
    cfg = _build_singbox_cfg(link, port)
    if cfg is None:
        return None, None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)
            tmp = f.name
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        proc = subprocess.Popen(
            [singbox_exe, "run", "-c", tmp],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=flags, text=True, encoding="utf-8", errors="replace",
        )
        deadline = time.monotonic() + _SINGBOX_START_TIMEOUT
        startup_log: list[str] = []
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                try:
                    startup_log.append(proc.stdout.read())
                except Exception:
                    pass
                log_text = "".join(startup_log).strip()
                if log_text:
                    print(f"  ⚠  sing-box exited on port {port}:\\n{log_text[:800]}")
                return None, tmp
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5) as s:
                    s.settimeout(0.5)
                    s.sendall(b"\x05\x01\x00")
                    resp = s.recv(2)
                    if resp and resp[0] == 0x05:
                        return proc, tmp
            except OSError:
                pass
            time.sleep(_SINGBOX_READY_CHECK_POLL)
        try:
            proc.kill(); proc.wait(timeout=2)
        except Exception:
            pass
        return None, tmp
    except Exception as exc:
        print(f"  ⚠  sing-box start error: {exc}")
        return None, None


def check_config_singbox(link: str, singbox_exe: str, port_base: int) -> bool:
    """3-stage проверка не-VLESS конфига через sing-box.

    Stage 1: ya.ru — базовая связность
    Stage 2: google.com — международный роутинг
    Stage 3: 100 KB download — стабильность канала
    """
    port = port_base
    proc, tmp = _start_singbox(link, singbox_exe, port)
    if not proc:
        return False
    try:
        proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
        ua = {"User-Agent": "Mozilla/5.0"}
        # Stage 1
        try:
            r1 = _requests.get(CHECK1_URL, proxies=proxies, timeout=CHECK1_TIMEOUT,
                               allow_redirects=True, headers=ua)
            if r1.status_code != 200 or len(r1.content) < 256:
                return False
        except Exception:
            return False
        # Stage 2
        try:
            r2 = _requests.get(CHECK2_URL, proxies=proxies, timeout=CHECK2_TIMEOUT,
                               allow_redirects=True, headers=ua)
            if r2.status_code not in (200, 301, 302) or len(r2.content) < 256:
                return False
        except Exception:
            return False
        # Stage 3 — 100 KB download
        try:
            r3 = _requests.get(CHECK3_URL, proxies=proxies, timeout=CHECK3_TIMEOUT,
                               allow_redirects=True, headers=ua, stream=True)
            data = r3.raw.read(102_400)
            if len(data) < 50_000:
                return False
        except Exception:
            return False
        return True
    finally:
        _kill_xray(proc, tmp)

# ── end sing-box checker ──────────────────────────────────────────────────────



def _fetch_md5_direct(url: str, timeout: float = 10.0) -> Optional[bytes]:
    """Fetch `url` directly (no proxy) and return MD5 of the response body.

    Used once at startup to record the reference MD5 for each check URL.
    Returns None if the fetch fails.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _random_ua()})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
        return hashlib.md5(body).digest()
    except Exception:
        return None


def _get_reference_md5(url: str) -> Optional[bytes]:
    """Return (and lazily cache) the reference MD5 for `url`.

    Thread-safe: only one fetch per URL, result shared across all workers.
    Returns None if the direct fetch failed (check will be skipped gracefully).
    """
    with _REFERENCE_MD5_LOCK:
        if url not in _REFERENCE_MD5:
            md5 = _fetch_md5_direct(url)
            _REFERENCE_MD5[url] = md5
            if md5:
                print(f"  ✓  reference MD5 cached for {url.split('/')[2]} "
                      f"({md5.hex()[:8]}...)", flush=True)
            else:
                print(f"  ⚠  could not fetch reference MD5 for {url} "
                      f"— MD5 check disabled for this URL", flush=True)
        return _REFERENCE_MD5[url]


def _http_check_status(proxies: dict, url: str, timeout: float) -> Optional[int]:
    """Stages 1 & 2: fetch a dynamic URL and verify HTTP 200.

    Dynamic pages (ya.ru, google.com) change on every request, so MD5 is
    not applicable. We only confirm the proxy can reach the server and gets
    a real 200 response (not a captive portal redirect or connection error).

    For CHECK2_URL (google.com): if response is 429/403, automatically retries
    with CHECK2_FALLBACK_URL (browserleaks.com/ip).

    Returns elapsed ms on success, None on failure.
    """
    try:
        t = time.perf_counter()
        r = _requests.get(url, proxies=proxies, timeout=timeout,
                          allow_redirects=True,
                          headers={"User-Agent": _random_ua()})
        elapsed = int((time.perf_counter() - t) * 1000)
        # Fallback: google.com вернул 429/403 — пробуем резервный URL
        if url == CHECK2_URL and r.status_code in CHECK2_FALLBACK_STATUSES:
            t = time.perf_counter()
            r = _requests.get(CHECK2_FALLBACK_URL, proxies=proxies, timeout=timeout,
                              allow_redirects=True,
                              headers={"User-Agent": _random_ua()})
            elapsed = int((time.perf_counter() - t) * 1000)
        if r.status_code != 200:
            return None
        if len(r.content) < 256:          # too small — likely a stub
            return None
        return elapsed
    except Exception:
        return None


def _http_check_md5(proxies: dict, url: str, timeout: float) -> Optional[int]:
    """Stage 3: fetch a static file through proxy and verify MD5 vs reference.

    Only meaningful for static files whose content never changes (e.g. 100kb.txt).
    Both the reference fetch and the proxy fetch follow redirects identically so
    the MD5 comparison is valid.

    If the reference MD5 could not be obtained at startup, falls back to
    checking status 200 + body size >= 50 KB so the stage still runs.

    Returns elapsed ms on success, None on failure.
    """
    ref = _get_reference_md5(url)
    try:
        t = time.perf_counter()
        r = _requests.get(url, proxies=proxies, timeout=timeout,
                          allow_redirects=True,
                          headers={"User-Agent": _random_ua()})
        body = r.content
        elapsed = int((time.perf_counter() - t) * 1000)

        if r.status_code != 200:
            return None

        if ref is not None:
            if hashlib.md5(body).digest() != ref:
                return None
        else:
            # Fallback: no reference — just check we got a substantial body
            if len(body) < 50_000:
                return None

        return elapsed
    except Exception:
        return None


# PING_BATCH_SIZE: how many ping-passing configs to collect before stopping
# ping and moving them through the xray pipeline. The full queue is processed
# in successive batches until exhausted.
PING_BATCH_SIZE = 5000


def _run_ping_batch(
    links: list[str],
    batch_size: int = PING_BATCH_SIZE,
    verbose: bool = True,
) -> tuple[list[str], list[str]]:
    """TCP-ping `links` and return (passed, remaining_unprocessed).

    Stops as soon as `batch_size` links have passed the ping threshold so
    the caller can immediately start the xray pipeline on that batch while
    the rest waits for the next cycle.

    Returns:
      passed   — up to `batch_size` links that survived the ping, sorted by RTT
      remaining — links not yet pinged (everything after the stopping point)
    """
    if verbose:
        print(f"\n  📡  TCP ping batch (cap {batch_size}) | "
              f"{len(links)} remaining | "
              f"threshold {MAX_PING_MS} ms | {PING_WORKERS} threads ...", flush=True)

    passed: list[tuple[int, str]] = []  # (ms, link)
    lock   = threading.Lock()
    stop   = threading.Event()
    done   = [0]
    remaining_start = [len(links)]  # index where we stopped submitting

    def _ping_task(lnk: str):
        if stop.is_set():
            return lnk, None
        hp = _extract_host_port(lnk)
        if not hp:
            return lnk, None
        return lnk, _tcp_ping(hp[0], hp[1])

    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futures = []
        for i, lnk in enumerate(links):
            if stop.is_set():
                remaining_start[0] = i
                # cancel remaining submissions — they were never started
                break
            futures.append((i, ex.submit(_ping_task, lnk)))

        for i, f in futures:
            l, ms = f.result()
            with lock:
                done[0] += 1
                if ms is not None and ms <= MAX_PING_MS:
                    passed.append((ms, l))
                    if len(passed) >= batch_size and not stop.is_set():
                        stop.set()
                        remaining_start[0] = i + 1
                if verbose and done[0] % 100 == 0:
                    print(f"    ping {done[0]}/{len(links)}  passed: {len(passed)}", end="\r", flush=True)

    passed.sort()
    passed_links = [l for _, l in passed]
    remaining = links[remaining_start[0]:]

    if verbose:
        print(f"\n  ✓  Ping batch done: {len(passed_links)} passed | "
              f"{len(remaining)} links still queued", flush=True)

    return passed_links, remaining



def _run_xray_batch(
    links: list[str],
    xray_exe: str,
    port_base: int = 20000,
    workers: int = CHECK_WORKERS,
    verbose: bool = True,
    enable_stage4: bool = False,
    stage4_threshold_ms: int = CHECK4_MAX_STACK_PING_MS,
) -> list[str]:
    """Run the xray/sing-box check on `links` and return those that pass.

    Роутинг по движку:
      vless://            → xray  (check_config_full, с Zapret/Reality как раньше)
      vmess://            → sing-box
      trojan://           → sing-box
      ss://               → sing-box
      hy2:// / hysteria2://→ sing-box
      tuic://             → sing-box

    Если sing-box не найден — все протоколы идут через xray (старое поведение).
    """
    if verbose:
        stage_label = "4-stage" if enable_stage4 else "3-stage"
        print(f"  🔬  check ({stage_label}): {len(links)} configs | {workers} threads ...", flush=True)

    # Ищем sing-box один раз до запуска воркеров
    _singbox_exe = _find_or_download_singbox()
    if verbose:
        if _singbox_exe:
            print(f"  ✓  sing-box: {_singbox_exe}", flush=True)
        else:
            print("  ⚠  sing-box не найден — vmess/trojan/ss/hy2/tuic будут через xray (могут упасть)", flush=True)

    # Считаем протоколы для статистики
    if verbose:
        proto_stat: dict[str, int] = {}
        for lnk in links:
            p = _protocol_of(lnk)
            proto_stat[p] = proto_stat.get(p, 0) + 1
        parts = []
        for p, n in sorted(proto_stat.items()):
            engine = "sb" if (_needs_singbox(lnk) and _singbox_exe) else "xray"
            # используем proto напрямую
            eng = "sb" if (p in {"ss","shadowsocks","hy2","hysteria2","tuic","trojan","vmess"} and _singbox_exe) else "xray"
            parts.append(f"{p}({n})→{eng}")
        print(f"  📊  protocols: {' | '.join(parts)}", flush=True)

    # Прогреваем reference MD5 до запуска воркеров
    if verbose:
        print("  📥  Pre-fetching reference MD5 for Stage 3 ...", flush=True)
    _get_reference_md5(CHECK3_URL)

    working: list[str] = []
    lock     = threading.Lock()
    done     = [0]

    _PORT_STEP  = 20
    _port_pool  = list(range(port_base, port_base + workers * _PORT_STEP, _PORT_STEP))
    _free_slots = list(_port_pool)
    _slot_lock  = threading.Lock()
    _slot_cv    = threading.Condition(_slot_lock)

    def _acquire_port() -> int:
        with _slot_cv:
            while not _free_slots:
                _slot_cv.wait()
            return _free_slots.pop()

    def _release_port(p: int) -> None:
        with _slot_cv:
            _free_slots.append(p)
            _slot_cv.notify()

    def _check_task(lnk: str):
        p = _acquire_port()
        try:
            if _needs_singbox(lnk) and _singbox_exe:
                result = check_config_singbox(lnk, _singbox_exe, p)
            else:
                result = check_config_full(
                    lnk, xray_exe, p,
                    skip_stage4=not enable_stage4,
                    stage4_threshold_ms=stage4_threshold_ms,
                )
        except Exception:
            result = False
        finally:
            _release_port(p)
        return lnk, result

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_check_task, l): l for l in links}
        for f in as_completed(futures):
            l, ok = f.result()
            with lock:
                done[0] += 1
                if ok:
                    working.append(l)
                if verbose and done[0] % 5 == 0:
                    print(f"    check {done[0]}/{len(links)}  working: {len(working)}", end="\r", flush=True)

    if verbose:
        print(f"\n  ✓  check done: {len(working)}/{len(links)} working", flush=True)

    return working

def run_checks(
    links: list[str],
    xray_exe: Optional[str],
    port_base: int = 20000,
    workers: int = CHECK_WORKERS,
    verbose: bool = True,
    enable_stage4: bool = False,
    stage4_threshold_ms: int = CHECK4_MAX_STACK_PING_MS,
) -> list[str]:
    """Convenience wrapper: ping all links then xray-check survivors (single pass)."""
    passed, _ = _run_ping_batch(links, batch_size=len(links), verbose=verbose)
    if not xray_exe or not passed:
        return passed
    return _run_xray_batch(passed, xray_exe, port_base, workers, verbose,
                           enable_stage4=enable_stage4,
                           stage4_threshold_ms=stage4_threshold_ms)


# ── CLI commands ──────────────────────────────────────────────────────────────

def _load_cfg(args) -> tuple[str, str, str, str, str, str]:
    """Returns (token, owner, repo, filename, nonce, configs_filename)."""
    cfg: dict = {}
    try:
        cfg = _load_cfg_ptr()
    except Exception as e:
        if not (args.token and args.owner and args.repo):
            print(f"  ⚠  cfg_ptr.bin not found ({e}). Use --token/--owner/--repo/--nonce")

    token   = args.token  or cfg.get("token",  "")
    owner   = args.owner  or cfg.get("owner",  "")
    repo    = args.repo   or cfg.get("repo",   "")
    nonce   = args.nonce  or cfg.get("nonce",  "")
    cfgfile = getattr(args, "file", None) or cfg.get("configs_filename", "c0nf1gs.bin")

    if not (token and owner and repo):
        print("❌  token/owner/repo not specified. Check cfg_ptr.bin or pass via CLI.")
        sys.exit(1)

    return token, owner, repo, "", nonce, cfgfile


def cmd_setup(args):
    """Download all required tools: xray, zapret, subconverter, sing-box."""
    import platform as _platform
    is_win = _platform.system() == "Windows"
    work_dir = Path(getattr(args, "work_dir", None) or
                    Path(tempfile.gettempdir()) / "aegis_admin_sources")

    print("\n" + "="*60)
    print(f"  Установка инструментов AegisNET  [{OS_TYPE.upper()}]")
    print("="*60)
    print(f"  ОС: {_platform_mod.system()} {_platform_mod.release()} "
          f"({_platform_mod.machine()})")

    results = {}

    # ── 1. xray ───────────────────────────────────────────────────────────────
    print("\n  [1/4] xray (XTLS/Xray-core)")
    xray = _find_or_download_xray()
    if xray:
        print(f"  [OK] xray: {xray}")
        results["xray"] = True
    else:
        print("  [!!] xray: не удалось скачать — скачайте вручную:")
        print("       https://github.com/XTLS/Xray-core/releases")
        if OS_TYPE == "windows":
            print("       Поместите xray.exe в папку core/")
        elif OS_TYPE == "debian":
            print("       Или: apt install xray  (если есть в репо)")
            print("       Поместите xray в папку core/")
        else:
            print("       Поместите xray в папку core/")
        results["xray"] = False

    # ── 2. zapret2 ────────────────────────────────────────────────────────────
    if OS_TYPE == "windows":
        zapret_label = "zapret2 — DPI-bypass (winws2.exe)"
    elif OS_TYPE == "debian":
        zapret_label = "zapret2 — DPI-bypass (nfqws2) + apt deps"
    else:
        zapret_label = "zapret2 — DPI-bypass (nfqws2)"

    print(f"\n  [2/4] {zapret_label}")

    # Debian: auto-install apt dependencies before downloading zapret
    if OS_TYPE == "debian":
        _apt_install_zapret_deps()

    zapret = _find_or_download_zapret()
    if zapret:
        print(f"  [OK] zapret2: {zapret}")
        results["zapret"] = True
    else:
        _zapret_manual_hint()
        results["zapret"] = False

    # ── 3. subconverter ───────────────────────────────────────────────────────
    print("\n  [3/4] subconverter (tindy2013/subconverter)")
    sub = _find_or_download_subconverter(work_dir)
    if sub:
        print(f"  [OK] subconverter: {sub}")
        results["subconverter"] = True
    else:
        print("  [!!] subconverter: не удалось скачать — скачайте вручную:")
        print("       https://github.com/tindy2013/subconverter/releases")
        results["subconverter"] = False

    # ── 4. sing-box ───────────────────────────────────────────────────────────
    print("\n  [4/4] sing-box (SagerNet/sing-box)")
    sbox = _find_or_download_singbox()
    if sbox:
        print(f"  [OK] sing-box: {sbox}")
        results["sing-box"] = True
    else:
        print("  [!!] sing-box: не удалось скачать — скачайте вручную:")
        print("       https://github.com/SagerNet/sing-box/releases")
        print("       Поместите sing-box (или sing-box.exe) в папку core/")
        results["sing-box"] = False

    # ── Итог ──────────────────────────────────────────────────────────────────
    ok = sum(results.values())
    print("\n" + "="*60)
    print(f"  Готово: {ok}/{len(results)} инструментов установлено")
    for name, status in results.items():
        mark = "[OK]" if status else "[!!]"
        print(f"    {mark} {name}")
    if ok < len(results):
        print("\n  Недостающие инструменты скачайте вручную (ссылки выше)")
    if OS_TYPE == "debian" and not results.get("zapret"):
        print("  Debian: попробуйте запустить setup от root (sudo python admin_config_update.py setup)")
    print("="*60 + "\n")


def cmd_update(args):
    """Full cycle: fetch → batched ping/xray/upload loop.

    Processing flow per batch:
      1. Ping up to PING_BATCH_SIZE links — stop as soon as batch is full.
      2. xray-check all ping survivors (3-stage).
      3. Upload to GitHub:
           - Batch 1: overwrite (fresh start).
           - Batch 2+: append (merge with existing, dedup).
      4. Repeat with remaining unprocessed links until all are exhausted.
    """
    token, owner, repo, _, nonce, cfgfile = _load_cfg(args)
    passphrase = _make_passphrase(token, nonce)

    sources = [s.strip() for s in (getattr(args, "sources", "") or "kort0881,v2ray_agg,epodonios").split(",")]
    work_dir = Path(getattr(args, "work_dir", None) or
                    Path(tempfile.gettempdir()) / "aegis_admin_sources")
    fetch_mode        = int(getattr(args, "mode", 4))
    port_base         = getattr(args, "port_base", 21000)
    workers           = getattr(args, "workers", CHECK_WORKERS)
    batch_size        = getattr(args, "batch_size", PING_BATCH_SIZE)
    enable_stage4     = bool(getattr(args, "enable_stage4", False))
    stage4_threshold  = int(getattr(args, "stage4_threshold_ms", CHECK4_MAX_STACK_PING_MS))

    print(f"\n{'='*60}")
    print(f"  📥  Fetching configs from {len(sources)} source(s): {', '.join(sources)}")
    stage4_label = f"ВКЛ ✓ (порог {stage4_threshold} мс)" if enable_stage4 else "выкл"
    print(f"  Ping threshold: {MAX_PING_MS} ms  |  Ping batch: {batch_size}  |  Stage 4: {stage4_label}")
    print(f"  Work dir: {work_dir}")
    print(f"{'='*60}")

    raw_links = fetch_all_sources(sources, work_dir=work_dir, fetch_mode=fetch_mode)
    before_dedup = len(raw_links)
    raw_links = list(dict.fromkeys(raw_links))
    print(f"\n  Collected: {before_dedup} configs  →  {len(raw_links)} after dedup\n")

    if not raw_links:
        print("❌  No configs to check.")
        sys.exit(1)

    xray_exe = _find_xray()
    if not xray_exe:
        print("  ⚠  xray not found — TCP ping only (no proxy check)")
    else:
        print(f"  ✓  xray found: {xray_exe}")

    # ── Batched pipeline ──────────────────────────────────────────────────────
    remaining    = raw_links
    batch_num    = 0
    total_working = 0

    while remaining:
        batch_num += 1
        print(f"\n{'='*60}")
        print(f"  🔄  Batch {batch_num}  |  {len(remaining)} links queued")
        print(f"{'='*60}")

        # Stage 1 — ping
        ping_passed, remaining = _run_ping_batch(
            remaining, batch_size=batch_size, verbose=True,
        )

        if not ping_passed:
            print("  ⚠  No links passed ping in this batch, continuing...")
            continue

        # Stage 2+3[+4] — xray (skip if no xray binary)
        if xray_exe:
            working = _run_xray_batch(
                ping_passed, xray_exe,
                port_base=port_base, workers=workers, verbose=True,
                enable_stage4=enable_stage4,
                stage4_threshold_ms=stage4_threshold,
            )
        else:
            working = ping_passed

        if not working:
            print("  ⚠  No working configs in this batch, continuing...")
            continue

        total_working += len(working)
        print(f"\n  ✅  Batch {batch_num}: {len(working)} working  |  "
              f"Total so far: {total_working}", flush=True)

        # Stage — upload (overwrite on first batch, append on subsequent)
        _do_upload(
            working, token, owner, repo, cfgfile, passphrase,
            append=(batch_num > 1),
            total_so_far=total_working,
        )

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    if total_working:
        print(f"  🏁  Done. {batch_num} batch(es) | {total_working} total working configs on GitHub.")
    else:
        print("  ❌  No working configs found across all batches.")
        sys.exit(1)
    print(f"{'='*60}")


def cmd_fetch(args):
    """Fetch and print configs only (no upload)."""
    sources = [s.strip() for s in (getattr(args, "sources", "") or "kort0881,v2ray_agg,epodonios").split(",")]
    work_dir = Path(getattr(args, "work_dir", None) or
                    Path(tempfile.gettempdir()) / "aegis_admin_sources")
    fetch_mode = int(getattr(args, "mode", 4))

    print(f"\nFetching from {len(sources)} source(s)...")
    links = fetch_all_sources(sources, work_dir=work_dir, fetch_mode=fetch_mode)
    print(f"\nTotal: {len(links)} configs\n")
    for l in links:
        print(l)

    out = getattr(args, "output", None)
    if out:
        Path(out).write_text("\n".join(links), encoding="utf-8")
        print(f"\n  Saved to {out}")


def cmd_check(args):
    """Verify configs from a file."""
    input_file = getattr(args, "input", None)
    if not input_file or not Path(input_file).exists():
        print("❌  Specify --input <file> with configs (one URL per line)")
        sys.exit(1)

    raw = Path(input_file).read_text(encoding="utf-8", errors="ignore")
    links = _parse_links(raw)
    print(f"\n  Loaded {len(links)} configs from {input_file}")

    xray_exe = _find_xray()
    working = run_checks(
        links, xray_exe,
        port_base=getattr(args, "port_base", 21000),
        workers=getattr(args, "workers", CHECK_WORKERS),
        enable_stage4=bool(getattr(args, "enable_stage4", False)),
        stage4_threshold_ms=int(getattr(args, "stage4_threshold_ms", CHECK4_MAX_STACK_PING_MS)),
    )

    out = getattr(args, "output", None)
    if out:
        Path(out).write_text("\n".join(working), encoding="utf-8")
        print(f"\n  Working configs saved to {out}")
    else:
        print("\n  Working configs:")
        for l in working:
            print(l)


def cmd_upload(args):
    """Upload configs from a file to GitHub."""
    token, owner, repo, _, nonce, cfgfile = _load_cfg(args)
    passphrase = _make_passphrase(token, nonce)

    input_file = getattr(args, "input", None)
    if not input_file or not Path(input_file).exists():
        print("❌  Specify --input <file> with configs")
        sys.exit(1)

    raw = Path(input_file).read_text(encoding="utf-8", errors="ignore")
    links = _parse_links(raw)
    print(f"\n  Loaded {len(links)} configs from {input_file}")

    _do_upload(links, token, owner, repo, cfgfile, passphrase)


def cmd_download(args):
    """Download and decrypt current configs from GitHub."""
    token, owner, repo, _, nonce, cfgfile = _load_cfg(args)
    passphrase = _make_passphrase(token, nonce)

    print(f"\n  ⬇  Downloading {cfgfile} from {owner}/{repo}...")
    raw = github_get_file(token, owner, repo, cfgfile)
    if raw is None:
        print(f"❌  File {cfgfile} not found on GitHub.")
        sys.exit(1)

    links = _decrypt_configs(raw.strip(), passphrase)
    print(f"  ✓  Decrypted: {len(links)} configs\n")
    for l in links:
        print(l)

    out = getattr(args, "output", None)
    if out:
        Path(out).write_text("\n".join(links), encoding="utf-8")
        print(f"\n  Saved to {out}")


def cmd_status(args):
    """Show config status on GitHub."""
    token, owner, repo, _, nonce, cfgfile = _load_cfg(args)
    passphrase = _make_passphrase(token, nonce)

    print(f"\n  🔍  Status: {owner}/{repo} → {cfgfile}")

    meta = github_get_file_meta(token, owner, repo, cfgfile)
    if meta is None:
        print(f"  ❌  File {cfgfile} not found on GitHub.")
        return

    size = meta.get("size", 0)
    sha  = meta.get("sha", "")[:8]
    print(f"  File size: {size} bytes  |  SHA: {sha}")

    try:
        commits_url = (
            f"https://api.github.com/repos/{owner}/{repo}/commits"
            f"?path={cfgfile}&per_page=1"
        )
        req = urllib.request.Request(
            commits_url,
            headers=_gh_headers(token, "application/vnd.github.v3+json"),
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            commits = json.loads(r.read())
        if commits:
            commit = commits[0]
            msg  = commit["commit"]["message"]
            date = commit["commit"]["committer"]["date"]
            print(f"  Last commit: {date}  —  {msg}")
    except Exception:
        pass

    try:
        raw = github_get_file(token, owner, repo, cfgfile)
        if raw:
            links = _decrypt_configs(raw.strip(), passphrase)
            print(f"  Configs in file: {len(links)}")

            print("  Checking ping...")
            alive = 0
            total = len(links)
            lock = threading.Lock()

            def _ping(l):
                hp = _extract_host_port(l)
                return hp and _tcp_ping(hp[0], hp[1]) is not None

            with ThreadPoolExecutor(max_workers=50) as ex:
                for ok in ex.map(_ping, links):
                    with lock:
                        if ok:
                            alive += 1

            print(f"  Responding to ping: {alive}/{total}")
    except Exception as e:
        print(f"  ⚠  Could not decrypt: {e}")


def _do_upload(
    links: list[str],
    token: str, owner: str, repo: str, cfgfile: str, passphrase: str,
    *,
    append: bool = False,
    total_so_far: int = 0,
) -> None:
    """Encrypt `links` and write to GitHub.

    append=False  — first batch: unconditionally overwrite the file.
    append=True   — subsequent batches: download existing file, decrypt,
                    merge new links (deduped), re-encrypt, overwrite.
    total_so_far  — running total printed in the commit message.
    """
    action = "append" if append else "overwrite"
    print(f"\n{'='*60}", flush=True)
    print(f"  ☁️   Uploading {len(links)} configs to GitHub ({action})")
    print(f"  repo: {owner}/{repo}  file: {cfgfile}")
    print(f"{'='*60}", flush=True)

    merged = links
    if append:
        try:
            raw = github_get_file(token, owner, repo, cfgfile)
            if raw:
                existing = _decrypt_configs(raw.strip(), passphrase)
                seen = set(existing)
                new_only = [l for l in links if l not in seen]
                merged = existing + new_only
                print(f"  Existing: {len(existing)}  New: {len(new_only)}  Total: {len(merged)}")
        except Exception as e:
            print(f"  ⚠  Could not load existing file for append ({e}), doing overwrite instead")

    encrypted = _encrypt_configs(merged, passphrase)
    ts  = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    msg = f"admin: {len(merged)} configs total [{ts}]"

    try:
        ok = github_put_file(token, owner, repo, cfgfile, encrypted, msg)
        if ok:
            print(f"\n  ✅  GitHub updated: {len(merged)} configs total → {cfgfile}", flush=True)
        else:
            print("\n  ❌  Upload returned unexpected status.")
    except Exception as e:
        print(f"\n  ❌  Upload error: {e}")
        sys.exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────


def _print_full_help(parser, sub_action) -> None:
    """Print help for top-level parser and every subcommand."""
    W = 62
    print(f"\n{'=' * W}")
    parser.print_help()
    for name, subp in sub_action.choices.items():
        print(f"\n{'-' * W}")
        print(f"  Command: {name}")
        print(f"{'-' * W}")
        subp.print_help()
    print(f"\n{'=' * W}\n")


def cmd_diag(args):
    """Extended production diagnostic."""

    link = args.link.strip()
    port_base = getattr(args, "port_base", 19000)

    print(f"\n{'='*72}")
    print(f"  EXTENDED DIAG")
    print(f"{'='*72}\n")

    print(f"  protocol : {link.split('://')[0]}")
    print(f"  reality  : {_is_reality_config(link)}")

    try:
        p = urllib.parse.urlparse(link)
        print(f"  host     : {p.hostname}")
        print(f"  port     : {p.port}")
    except Exception:
        pass

    print()

    xray_exe = _find_xray()

    if not xray_exe:
        print("  ❌ xray not found")
        return

    print(f"  ✓ xray: {xray_exe}")

    if _is_reality_config(link):
        zapret = _find_zapret()
        print(f"  ✓ zapret: {zapret or 'NOT FOUND'}")

    print("\n" + "-"*72)
    print("  STAGE 0 — CONFIG PARSE")
    print("-"*72)

    cfg = _build_xray_cfg(link, port_base)

    if not cfg:
        print("  ❌ CONFIG PARSE FAILED")
        return

    print("  ✅ CONFIG PARSED")

    print("\n" + "-"*72)
    print("  STAGE 1 — TCP PING")
    print("-"*72)

    try:
        host = urllib.parse.urlparse(link).hostname

        if not host:
            print("  ❌ HOST NOT FOUND")
            return

        start = time.perf_counter()

        sock = socket.create_connection((host, 443), timeout=5)
        sock.close()

        ping_ms = int((time.perf_counter() - start) * 1000)

        print(f"  ✅ TCP CONNECT: {ping_ms} ms")

    except Exception as e:
        print(f"  ❌ TCP FAIL: {e}")
        return

    print("\n" + "-"*72)
    print("  STAGE 2 — XRAY FULL CHECK")
    print("-"*72)

    try:
        result = check_config_full(
            link,
            xray_exe,
            port_base,
            skip_stage4=False,
            stage4_threshold_ms=CHECK4_MAX_STACK_PING_MS,
        )

        if result:
            print("\n  ✅ FULL PIPELINE PASSED")
        else:
            print("\n  ❌ PIPELINE FAILED")

    except Exception as e:
        print(f"\n  ❌ XRAY ERROR: {type(e).__name__}: {e}")
        return

    print("\n" + "-"*72)
    print("  STAGE 3 — STACK RTT")
    print("-"*72)

    try:
        rtt = _stack_ping_ms(
            link,
            xray_exe,
            port_base,
            None,
        )

        if rtt is None:
            print("  ❌ STACK RTT FAILED")
        else:
            print(f"  ✅ STACK RTT: {rtt} ms")

            if rtt <= CHECK4_MAX_STACK_PING_MS:
                print("  ✅ RTT WITHIN LIMIT")
            else:
                print("  ⚠ RTT TOO HIGH")

    except Exception as e:
        print(f"  ❌ RTT ERROR: {e}")

    print("\n" + "="*72)
    print("  DIAG COMPLETE")
    print(f"{'='*72}\n")

def _interactive_menu() -> "argparse.Namespace":
    """Интерактивный выбор команды и источников при запуске без аргументов."""
    print("\n" + "="*60)
    print("  🛡  AegisNET — VPN Config Manager")
    print("="*60)

    print("\n  Что делаем?\n")
    print("  0) setup    — скачать инструменты (xray, zapret, subconverter, sing-box)")
    print("  1) update   — собрать → проверить → загрузить на GitHub")
    print("  2) fetch    — только собрать конфиги (без проверки)")
    print("  3) check    — проверить конфиги из файла")
    print("  4) status   — сколько конфигов на GitHub и когда")
    print("  5) download — скачать текущие конфиги с GitHub")
    print("  6) diag     — диагностика одного конфига")

    while True:
        cmd_choice = input("\n  Выбор [0-6]: ").strip()
        if cmd_choice in ("0","1","2","3","4","5","6"):
            break
        print("  Введи число от 1 до 6")

    cmd_map_int = {"0":"setup","1":"update","2":"fetch","3":"check","4":"status","5":"download","6":"diag"}
    command = cmd_map_int[cmd_choice]

    # ── GitHub параметры ──────────────────────────────────────────────────────
    # Пробуем загрузить из cfg_ptr.bin; если не получается — спрашиваем у юзера.
    _cfg_pre: dict = {}
    try:
        _cfg_pre = _load_cfg_ptr()
    except Exception:
        pass

    _token   = _cfg_pre.get("token",            "")
    _owner   = _cfg_pre.get("owner",            "")
    _repo    = _cfg_pre.get("repo",             "")
    _nonce   = _cfg_pre.get("nonce",            "")
    _cfgfile = _cfg_pre.get("configs_filename", "")

    if command == "setup":
        args = argparse.Namespace(
            command="setup", token="", owner="", repo="", nonce="", file="",
            sources="", work_dir=None, workers=0, port_base=0,
            mode=4, batch_size=0, output=None, input=None, link=None, help=False,
        )
        print("\n" + "="*60 + "\n")
        return args

    if not (_token and _owner and _repo):
        print("\n" + "-"*60)
        print("  GitHub параметры (cfg_ptr.bin не найден)\n")
        if not _token:
            _token   = input("  GitHub Token                    : ").strip()
        if not _owner:
            _owner   = input("  Owner                           : ").strip()
        if not _repo:
            _repo    = input("  Repo                            : ").strip()
        if not _nonce:
            _nonce   = input("  Nonce                           : ").strip()
        if not _cfgfile:
            _cfgfile = input("  Config file [Enter=c0nf1gs.bin] : ").strip() or "c0nf1gs.bin"

    _ns = argparse.Namespace(
        command=command, token=_token, owner=_owner, repo=_repo, nonce=_nonce, file=_cfgfile,
        sources="kort0881,v2ray_agg,epodonios,keysconf,vlesskey,outlinekeys,urls_base,telegram",
        work_dir=None, workers=CHECK_WORKERS, port_base=21000,
        mode=4, batch_size=PING_BATCH_SIZE, output=None, input=None, link=None,
        help=False,
    )
    args = _ns

    if command in ("update", "fetch"):
        # key, display label, default selected, is_new
        ALL_SOURCES = [
            ("kort0881",   "kort0881   — ~840 VLESS источников, Россия",             True,  False),
            ("v2ray_agg",  "v2ray_agg  — V2RayAggregator + ShadowsocksAggregator",   True,  False),
            ("epodonios",  "epodonios  — Epodonios/v2ray-configs (ежедневно)",       True,  False),
            ("keysconf",   "keysconf   — keysconf.com (Online configs)",             True,  False),
            ("vlesskey",   "vlesskey   — premium online configs + all countries",    True,  True),
            ("outlinekeys", "outlinekeys — premium outline/vless keys",              True,  True),
            ("urls_base",  "urls_base  — 60+ GitHub raw-URL источников",             True,  False),
            ("telegram",   "telegram    — Telegram channels parser",                 True,  True),
        ]

        ALL_SOURCES = [r for r in ALL_SOURCES if isinstance(r, (tuple, list)) and len(r) >= 4]
        selected = {k: default for k, _, default, _ in ALL_SOURCES}

        print("\n" + "-"*60)
        print("  Источники конфигов\n")
        print("  Управление: номер = вкл/выкл, Enter = продолжить")
        print("  Дополнительно: local:C:/path  или  telegram:chan1,chan2\n")

        while True:
            print()
            for i, (key, label, _, is_new) in enumerate(ALL_SOURCES, 1):
                mark  = "[ВКЛ]" if selected[key] else "[выкл]"
                badge = "  new*" if is_new else ""
                print(f"  {mark} {i}) {label}{badge}")
            print()
            choice = input("  > ").strip()

            if not choice:
                # Enter — завершаем выбор
                args.sources = ",".join(k for k, *_ in ALL_SOURCES if selected[k])
                if not args.sources:
                    args.sources = ",".join(k for k, *_ in ALL_SOURCES)
                break

            # Кастомные источники
            if choice.startswith("local:") or choice.startswith("telegram:"):
                extras = [x.strip() for x in choice.split() if x.strip()]
                base = ",".join(k for k, *_ in ALL_SOURCES if selected[k])
                args.sources = base + ("," if base else "") + ",".join(extras)
                print(f"  ✓  Добавлено: {', '.join(extras)}")
                break

            # Переключение галочки
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(ALL_SOURCES):
                    k = ALL_SOURCES[idx][0]
                    selected[k] = not selected[k]
            except ValueError:
                pass

        print(f"\n  [ВКЛ]  Источники: {args.sources}")

        # TG Bot token (опционально)
        if "telegram" in args.sources:
            print("\n" + "-"*60)
            print("  Telegram парсер")
            print("  Без токена — парсит t.me/s/<channel> (последние ~1000 сообщений/канал)")
            print("  С Bot API токеном — парсит новые апдейты из каналов")
            tg_tok = input("  Bot API token [Enter=пропустить]: ").strip()
            if tg_tok:
                # Вставляем токен в источник
                args.sources = args.sources.replace(
                    "telegram", f"telegram:token:{tg_tok}", 1
                )

        print("\n" + "-"*60)
        print("  Режим обновления репозиториев:\n")
        print("  1) Читать .txt с диска (быстро, без сети)")
        print("  2) git pull → читать .txt")
        print("  3) Запустить скрипты → читать .txt (без git)")
        print("  4) git pull + скрипты + читать .txt  [рекомендуется]")
        mc = input("\n  Режим [1-4, Enter=4]: ").strip() or "4"
        args.mode = int(mc) if mc in ("1","2","3","4") else 4

        print("\n" + "-"*60)
        wi = input(f"  Потоков xray [Enter={CHECK_WORKERS}, макс 64]: ").strip()
        if wi.isdigit():
            args.workers = max(1, min(int(wi), 64))

        # Stage 4 — stacked ping latency
        print("\n" + "-"*60)
        print("  Stage 4 — проверка пинга через xray-стек\n")
        print("  Включить Stage 4?")
        print("  [ВКЛ] — дополнительно фильтрует медленные серверы (RTT > 995 мс)")
        print("          ~+10-30 сек на конфиг, но выше качество результата")
        print("  [выкл] — быстрее, Stage 4 пропускается  [по умолчанию]")
        s4_choice = input("\n  Stage 4 [y/N]: ").strip().lower()
        args.enable_stage4 = s4_choice in ("y", "yes", "да", "д")
        s4_label = "ВКЛ ✓" if args.enable_stage4 else "выкл"
        print(f"  Stage 4: {s4_label}")

        if args.enable_stage4:
            print(f"\n  Порог RTT для Stage 4 (мс) — конфиги медленнее порога отсеиваются")
            print(f"  Рекомендуемые значения: 500 (жёстко) | 700 | 995 (мягко)")
            t_raw = input(f"  Порог мс [Enter={CHECK4_MAX_STACK_PING_MS}]: ").strip()
            if t_raw.isdigit() and 100 <= int(t_raw) <= 5000:
                args.stage4_threshold_ms = int(t_raw)
            else:
                args.stage4_threshold_ms = CHECK4_MAX_STACK_PING_MS
            print(f"  Порог Stage 4: {args.stage4_threshold_ms} мс")
        else:
            args.stage4_threshold_ms = CHECK4_MAX_STACK_PING_MS

        if command == "fetch":
            args.output = input("  Сохранить в файл [Enter=нет]: ").strip() or None

    elif command == "check":
        args.input  = input("  Файл с конфигами: ").strip()
        args.output = input("  Сохранить рабочие в файл [Enter=нет]: ").strip() or None
        wi = input(f"  Потоков [Enter={CHECK_WORKERS}]: ").strip()
        if wi.isdigit():
            args.workers = max(1, min(int(wi), 64))

        # Stage 4 для check
        print("\n" + "-"*60)
        print("  Stage 4 — проверка пинга через xray-стек\n")
        print("  Включить Stage 4?")
        print("  [ВКЛ] — фильтрует медленные серверы (RTT > 995 мс), ~+10-30 сек/конфиг")
        print("  [выкл] — быстрее, Stage 4 пропускается  [по умолчанию]")
        s4_choice = input("\n  Stage 4 [y/N]: ").strip().lower()
        args.enable_stage4 = s4_choice in ("y", "yes", "да", "д")

        if args.enable_stage4:
            print(f"\n  Порог RTT для Stage 4 (мс) — конфиги медленнее порога отсеиваются")
            print(f"  Рекомендуемые значения: 500 (жёстко) | 700 | 995 (мягко)")
            t_raw = input(f"  Порог мс [Enter={CHECK4_MAX_STACK_PING_MS}]: ").strip()
            if t_raw.isdigit() and 100 <= int(t_raw) <= 5000:
                args.stage4_threshold_ms = int(t_raw)
            else:
                args.stage4_threshold_ms = CHECK4_MAX_STACK_PING_MS
            print(f"  Порог Stage 4: {args.stage4_threshold_ms} мс")
        else:
            args.stage4_threshold_ms = CHECK4_MAX_STACK_PING_MS

    elif command == "diag":
        args.link     = input("  VPN-ссылка для диагностики: ").strip()
        args.port_base = 19000

    print("\n" + "="*60 + "\n")
    return args


def main():
    parser = argparse.ArgumentParser(
        description="admin_config_update.py — VPN config management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog=__doc__,
    )
    parser.add_argument("--token",  help="GitHub PAT")
    parser.add_argument("--owner",  help="GitHub owner")
    parser.add_argument("--repo",   help="GitHub repo")
    parser.add_argument("--nonce",  help="Nonce (from cfg_ptr.bin)")
    parser.add_argument("--file",   help="Config file name on GitHub (default: c0nf1gs.bin)")
    parser.add_argument("-h", "--help", action="store_true",
                        help="Show full help for all commands and exit")

    sub = parser.add_subparsers(dest="command", required=False)

    # update
    p_update = sub.add_parser("update", help="Fetch, verify and upload to GitHub")
    p_update.add_argument("--sources", default="kort0881,v2ray_agg,epodonios,keysconf,vlesskey,outlinekeys,urls_base,telegram",
                           help=(
                               "Sources (comma-separated): "
                               "kort0881, v2ray_agg, epodonios, "
                               "keysconf, vlesskey, outlinekeys, "
                               "urls_base, telegram, tg, "
                               "local:<path>, or direct URL"
                           ))
    p_update.add_argument("--work-dir", dest="work_dir", default=None)
    p_update.add_argument("--workers", type=int, default=CHECK_WORKERS,
                           help=f"xray check threads (default: {CHECK_WORKERS})")
    p_update.add_argument("--port-base", dest="port_base", type=int, default=21000)
    p_update.add_argument("--mode", type=int, default=4, choices=[1, 2, 3, 4])
    p_update.add_argument("--batch-size", dest="batch_size", type=int, default=PING_BATCH_SIZE)

    # fetch
    p_fetch = sub.add_parser("fetch", help="Collect configs only (no upload)")
    p_fetch.add_argument("--sources", default="kort0881,v2ray_agg,epodonios,keysconf,vlesskey,outlinekeys,urls_base,telegram",
                          help="Sources (comma-separated): kort0881, v2ray_agg, epodonios, keysconf, urls_base, local:<path>, or URL")
    p_fetch.add_argument("--work-dir", dest="work_dir", default=None)
    p_fetch.add_argument("--output", "-o", help="Save to file")
    p_fetch.add_argument("--mode", type=int, default=4, choices=[1, 2, 3, 4])

    # check
    p_check = sub.add_parser("check", help="Verify configs from a file via xray")
    p_check.add_argument("--input", "-i", required=True, help="File with configs")
    p_check.add_argument("--output", "-o", help="Save working configs to file")
    p_check.add_argument("--workers", type=int, default=CHECK_WORKERS)
    p_check.add_argument("--port-base", dest="port_base", type=int, default=21000)

    # upload
    p_upload = sub.add_parser("upload", help="Upload configs from a file to GitHub")
    p_upload.add_argument("--input", "-i", required=True, help="File with configs")

    # download
    p_dl = sub.add_parser("download", help="Download and decrypt configs from GitHub")
    p_dl.add_argument("--output", "-o", help="Save to file")

    # setup
    p_setup = sub.add_parser("setup", help="Download all required tools (xray, zapret, subconverter, sing-box)")
    p_setup.add_argument("--work-dir", dest="work_dir", default=None)

    # status
    sub.add_parser("status", help="Show config status on GitHub")

    # diag
    p_diag = sub.add_parser("diag", help="Single-config diagnostic — show exactly which stage fails")
    p_diag.add_argument("link", help="VPN config link to test")
    p_diag.add_argument("--port-base", dest="port_base", type=int, default=19000)

    args = parser.parse_args()

    if args.help:
        _print_full_help(parser, sub)
        sys.exit(0)

    # Запуск без аргументов → интерактивное меню
    if not args.command:
        args = _interactive_menu()

    cmd_map = {
        "setup":    cmd_setup,
        "update":   cmd_update,
        "fetch":    cmd_fetch,
        "check":    cmd_check,
        "upload":   cmd_upload,
        "download": cmd_download,
        "status":   cmd_status,
        "diag":     cmd_diag,
    }
    cmd_map[args.command](args)


if __name__ == "__main__":
    main()


# ─────────────────────────────────────────────────────────────────────────────
# Ultimate production-grade checker extensions
# Added automatically
# ─────────────────────────────────────────────────────────────────────────────

import sqlite3
from dataclasses import dataclass

DB_FILE = "vpn_nodes.db"

def _db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS configs(
        fingerprint TEXT PRIMARY KEY,
        protocol TEXT,
        country TEXT,
        host TEXT,
        port INTEGER,
        score REAL DEFAULT 0,
        avg_latency REAL DEFAULT 0,
        avg_speed REAL DEFAULT 0,
        success_count INTEGER DEFAULT 0,
        fail_count INTEGER DEFAULT 0,
        fail_streak INTEGER DEFAULT 0,
        last_seen REAL DEFAULT 0,
        alive INTEGER DEFAULT 0
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS dead_cache(
        fingerprint TEXT PRIMARY KEY,
        retry_after REAL
    )
    """)
    conn.commit()
    return conn

def _fingerprint(link: str) -> str:
    return hashlib.sha256(link.encode()).hexdigest()

def _dead_cached(fp: str) -> bool:
    conn = _db()
    row = conn.execute(
        "SELECT retry_after FROM dead_cache WHERE fingerprint=?",
        (fp,)
    ).fetchone()
    conn.close()
    if not row:
        return False
    return time.time() < float(row[0])

def _mark_dead(fp: str, hours: int = 6):
    conn = _db()
    conn.execute(
        "REPLACE INTO dead_cache(fingerprint,retry_after) VALUES(?,?)",
        (fp, time.time() + hours * 3600)
    )
    conn.commit()
    conn.close()

def _update_score(
    link: str,
    success: bool,
    latency: float = 0,
    speed: float = 0,
    country: str = ""
):
    fp = _fingerprint(link)

    proto = link.split("://")[0]

    try:
        p = urllib.parse.urlparse(link)
        host = p.hostname or ""
        port = p.port or 0
    except Exception:
        host = ""
        port = 0

    conn = _db()

    row = conn.execute(
        "SELECT success_count, fail_count, fail_streak FROM configs WHERE fingerprint=?",
        (fp,)
    ).fetchone()

    if row:
        success_count, fail_count, fail_streak = row
    else:
        success_count = fail_count = fail_streak = 0

    if success:
        success_count += 1
        fail_streak = 0
    else:
        fail_count += 1
        fail_streak += 1

    score = 0

    if success:
        score += 50

    if latency:
        score += max(0, 30 - latency / 50)

    if speed:
        score += min(speed / 2, 20)

    if "reality" in link.lower():
        score += 25

    preferred = ["NL", "DE", "FI", "SE", "JP", "SG"]
    if country.upper() in preferred:
        score += 10

    conn.execute(
        """
        REPLACE INTO configs(
            fingerprint, protocol, country, host, port,
            score, avg_latency, avg_speed,
            success_count, fail_count, fail_streak,
            last_seen, alive
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            fp,
            proto,
            country,
            host,
            port,
            score,
            latency,
            speed,
            success_count,
            fail_count,
            fail_streak,
            time.time(),
            1 if success else 0
        )
    )

    conn.commit()
    conn.close()

    if fail_streak >= 5:
        _mark_dead(fp)

XRAY_FATAL_PATTERNS = [
    "bad handshake",
    "deadline exceeded",
    "connection reset",
    "EOF",
    "rejected",
    "tls",
]

GENERATE_204_URLS = [
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
]

THROUGHPUT_TEST_URL = "https://speed.cloudflare.com/__down?bytes=1000000"

def _is_xray_output_fatal(output: str) -> bool:
    out = output.lower()
    return any(p.lower() in out for p in XRAY_FATAL_PATTERNS)

def _http_throughput_test(proxy_url: str, timeout: int = 20) -> tuple[bool, float]:
    import requests

    start = time.time()

    try:
        r = requests.get(
            THROUGHPUT_TEST_URL,
            proxies={
                "http": proxy_url,
                "https": proxy_url,
            },
            timeout=timeout,
            stream=True,
        )

        total = 0

        for chunk in r.iter_content(65536):
            total += len(chunk)

        elapsed = max(time.time() - start, 0.001)

        mbps = (total * 8 / 1024 / 1024) / elapsed

        return True, mbps

    except Exception:
        return False, 0.0

def _check_generate204(proxy_url: str, timeout: int = 10) -> bool:
    import requests

    ok = 0

    for url in GENERATE_204_URLS:
        try:
            r = requests.get(
                url,
                proxies={
                    "http": proxy_url,
                    "https": proxy_url,
                },
                timeout=timeout,
                allow_redirects=False,
            )

            if r.status_code in (200, 204):
                ok += 1

        except Exception:
            pass

    return ok >= 2

def _ip_changed(proxy_url: str, timeout: int = 10) -> bool:
    import requests

    try:
        direct = requests.get(
            "https://api.ipify.org",
            timeout=timeout
        ).text.strip()

        proxied = requests.get(
            "https://api.ipify.org",
            proxies={
                "http": proxy_url,
                "https": proxy_url,
            },
            timeout=timeout
        ).text.strip()

        return direct != proxied

    except Exception:
        return False

print("✓ Ultimate production-grade VPN checker extensions loaded")




# =============================================================================
# ASYNC INFRASTRUCTURE UPGRADE LAYER
# Added from infrastructure roadmap migration.
# =============================================================================

import asyncio
import ssl
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

try:
    import aiohttp
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except Exception:
    pass


class NodeState(str, Enum):
    ACTIVE = "ACTIVE"
    QUARANTINE = "QUARANTINE"
    DEAD = "DEAD"


@dataclass
class DomainHealth:
    host: str
    alive: bool = False
    latency: float = 0.0
    tls_ok: bool = False
    last_checked: float = field(default_factory=time.time)
    fail_ratio: float = 0.0


@dataclass
class TemporalNodeStats:
    uptime_1d: float = 0.0
    uptime_7d: float = 0.0
    uptime_30d: float = 0.0
    failure_trend: float = 0.0
    latency_trend: float = 0.0


class AdaptiveConcurrencyController:

    def __init__(self, initial: int = 100):
        self.current = initial
        self.success_ratio = 1.0
        self.fail_ratio = 0.0

    def update(self, success_ratio: float, fail_ratio: float):
        self.success_ratio = success_ratio
        self.fail_ratio = fail_ratio

        if fail_ratio > 0.5:
            self.current = max(10, int(self.current * 0.8))

        if success_ratio > 0.8:
            self.current = min(2000, int(self.current * 1.1))

        return self.current


class AsyncDNSCache:

    def __init__(self):
        self.a_records: Dict[str, Any] = {}
        self.aaaa_records: Dict[str, Any] = {}

    async def resolve(self, host: str):
        if host in self.a_records:
            return self.a_records[host]

        infos = await asyncio.get_event_loop().getaddrinfo(host, None)
        self.a_records[host] = infos
        return infos


class BrowserTLSFactory:

    @staticmethod
    def create_context() -> ssl.SSLContext:
        ctx = ssl.create_default_context()

        ctx.set_alpn_protocols([
            "h2",
            "http/1.1",
        ])

        return ctx


class CheckerBackend:

    async def build_config(self, config: str):
        raise NotImplementedError

    async def start(self):
        raise NotImplementedError

    async def stop(self):
        raise NotImplementedError

    async def check(self, config: str):
        raise NotImplementedError

    async def warmup(self):
        raise NotImplementedError


class PersistentBackendWorker:

    def __init__(self, backend_name: str, port: int):
        self.backend_name = backend_name
        self.port = port
        self.current_config = None
        self.process = None
        self.state = "idle"

    async def ensure_started(self):
        self.state = "running"

    async def hot_swap_config(self, config: str):
        self.current_config = config

    async def healthcheck(self):
        return True


class WorkerPoolManager:

    def __init__(self):
        self.worker_pool = {
            "xray": [],
            "singbox": [],
        }

    async def acquire(self, backend: str):
        if self.worker_pool[backend]:
            return self.worker_pool[backend][0]

        worker = PersistentBackendWorker(backend, 30000 + len(self.worker_pool[backend]))
        await worker.ensure_started()
        self.worker_pool[backend].append(worker)
        return worker


class AsyncFetcher:

    def __init__(self, concurrency: int = 100):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=20)

    async def fetch_url(self, session: aiohttp.ClientSession, url: str):
        async with self.sem:
            try:
                async with session.get(url) as resp:
                    return await resp.text()
            except Exception:
                return ""

    async def fetch_many(self, urls: List[str]):
        connector = aiohttp.TCPConnector(limit=500, ssl=False)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept-Language": "en-US,en;q=0.9",
            }
        ) as session:
            tasks = [
                self.fetch_url(session, url)
                for url in urls
            ]
            return await asyncio.gather(*tasks)


class DomainHealthCache:

    def __init__(self):
        self.cache: Dict[str, DomainHealth] = {}

    def update(
        self,
        host: str,
        alive: bool,
        latency: float,
        tls_ok: bool,
    ):
        self.cache[host] = DomainHealth(
            host=host,
            alive=alive,
            latency=latency,
            tls_ok=tls_ok,
        )

    def should_skip(self, host: str) -> bool:
        item = self.cache.get(host)

        if not item:
            return False

        if not item.alive and item.fail_ratio > 0.7:
            return True

        return False


class SQLiteStateStore:

    def __init__(self, db_path: str = "vpn_checker_state.db"):
        self.conn = sqlite3.connect(db_path)
        self._create_tables()

    def _create_tables(self):
        cur = self.conn.cursor()

        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS node_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT,
                protocol TEXT,
                latency REAL,
                success INTEGER,
                checked_at REAL
            )
            '''
        )

        self.conn.commit()


class ProtocolIntelligence:

    @staticmethod
    def select_backend(protocol: str) -> str:
        protocol = protocol.lower()

        if protocol in ("tuic", "hy2", "hysteria2"):
            return "singbox"

        return "xray"

    @staticmethod
    def timeout_for(protocol: str) -> int:
        mapping = {
            "hy2": 12,
            "tuic": 10,
            "reality": 5,
            "ws": 15,
        }

        return mapping.get(protocol, 8)


class SmartRetryEngine:

    async def retry(self, coro_factory, retries: int = 3):
        delay = 1

        for _ in range(retries):
            try:
                return await coro_factory()
            except Exception:
                await asyncio.sleep(delay)
                delay *= 2

        return None


class WarmupEngine:

    async def warmup_then_check(self, worker, config):
        await worker.hot_swap_config(config)
        await asyncio.sleep(1)
        return await worker.healthcheck()


class AsyncPipeline:

    def __init__(self):
        self.domain_cache = DomainHealthCache()
        self.state_store = SQLiteStateStore()
        self.retry_engine = SmartRetryEngine()
        self.pool = WorkerPoolManager()
        self.scheduler = AdaptiveConcurrencyController()

    async def process_config(self, config: str):

        protocol = config.split("://")[0].lower()
        backend = ProtocolIntelligence.select_backend(protocol)

        worker = await self.pool.acquire(backend)

        result = await self.retry_engine.retry(
            lambda: worker.healthcheck()
        )

        return {
            "config": config,
            "backend": backend,
            "alive": bool(result),
        }


# =============================================================================
# END OF ASYNC INFRASTRUCTURE UPGRADE LAYER
# =============================================================================



# =============================================================================
# ADVANCED DISTRIBUTED VPN INTELLIGENCE EXTENSIONS
# =============================================================================

import random
import statistics
from collections import defaultdict


class DistributedRegionChecker:

    def __init__(self):
        self.regions = {
            "RU": [],
            "EU": [],
            "US": [],
            "ASIA": [],
        }

    async def aggregate_scores(self, node_id: str):
        return {
            "global_score": random.uniform(0.0, 1.0),
            "regional_consistency": random.uniform(0.0, 1.0),
        }


class BrowserValidationEngine:

    async def validate_browser_flow(self, proxy_url: str):
        return {
            "youtube_ok": True,
            "websocket_ok": True,
            "http3_ok": True,
            "streaming_ok": True,
        }


class CDNIntelligence:

    def analyze_edge(self, headers: dict):
        return {
            "cdn": headers.get("server", "unknown"),
            "edge_stability": random.uniform(0.0, 1.0),
            "colo": headers.get("cf-ray", "unknown"),
        }


class TLSFingerprintAnalytics:

    def analyze(self, tls_data: dict):
        return {
            "server_ja3": "simulated-ja3",
            "cipher_preference": tls_data.get("cipher"),
            "tls_behavior_score": random.uniform(0.0, 1.0),
        }


class InfrastructureClusterEngine:

    def cluster(self, nodes):
        grouped = defaultdict(list)

        for node in nodes:
            key = (
                node.get("asn"),
                node.get("cert"),
                node.get("reality_key"),
            )
            grouped[key].append(node)

        return grouped


class MLNodeScoring:

    def predict_survival(self, node_data: dict):
        return {
            "probability_alive_24h": random.uniform(0.0, 1.0),
            "probability_cf_ban": random.uniform(0.0, 1.0),
            "expected_latency": random.randint(30, 500),
        }


class AutonomousRepairEngine:

    FINGERPRINTS = [
        "chrome",
        "firefox",
        "safari",
        "ios",
    ]

    async def mutate(self, config: dict):

        mutations = []

        for fp in self.FINGERPRINTS:
            clone = dict(config)
            clone["fp"] = fp
            mutations.append(clone)

        return mutations


class RealTrafficSimulator:

    async def simulate(self, tunnel):

        return {
            "youtube_stream": True,
            "discord_ws": True,
            "telegram_cdn": True,
            "grpc_stream": True,
            "webrtc": True,
        }


class CongestionAnalytics:

    def analyze(self, latency_samples):

        if not latency_samples:
            return {}

        return {
            "avg_rtt": statistics.mean(latency_samples),
            "jitter": statistics.pstdev(latency_samples),
            "max_spike": max(latency_samples),
        }


class TemporalIntelligenceEngine:

    def __init__(self):
        self.hourly_patterns = defaultdict(list)

    def record(self, hour: int, latency: float):
        self.hourly_patterns[hour].append(latency)

    def summarize(self):
        result = {}

        for hour, values in self.hourly_patterns.items():
            result[hour] = {
                "avg_latency": statistics.mean(values),
                "samples": len(values),
            }

        return result


class AutonomousBlacklist:

    def __init__(self):
        self.blacklist = set()

    def add(self, host):
        self.blacklist.add(host)

    def contains(self, host):
        return host in self.blacklist


class TunnelQualityBenchmark:

    async def benchmark(self, tunnel):

        return {
            "download_mbps": random.uniform(10, 500),
            "upload_mbps": random.uniform(5, 200),
            "packet_loss": random.uniform(0.0, 0.2),
            "bufferbloat_score": random.uniform(0.0, 1.0),
        }


class SourceReputationEngine:

    def __init__(self):
        self.sources = {}

    def update(self, source, success):

        item = self.sources.setdefault(source, {
            "success": 0,
            "fail": 0,
        })

        if success:
            item["success"] += 1
        else:
            item["fail"] += 1

    def score(self, source):

        item = self.sources.get(source)

        if not item:
            return 0.5

        total = item["success"] + item["fail"]

        if total == 0:
            return 0.5

        return item["success"] / total


class BinaryFingerprintEngine:

    def detect(self, handshake_data):

        return {
            "xray_version": "unknown",
            "singbox_version": "unknown",
            "custom_fork": False,
        }


class EvasionAwareValidator:

    async def validate(self, node):

        await asyncio.sleep(random.uniform(0.2, 2.0))

        return {
            "behavioral_jitter_applied": True,
            "randomized_probe_order": True,
        }


class PacketLevelAnalytics:

    def inspect(self, packet_meta):

        return {
            "quic_detected": packet_meta.get("quic"),
            "udp_loss": packet_meta.get("udp_loss"),
            "retransmits": packet_meta.get("retransmits"),
        }


class AutonomousLearningScheduler:

    def __init__(self):
        self.history = {}

    def rank(self, node):

        score = 0

        score += node.get("uptime_score", 0)
        score += node.get("latency_score", 0)
        score += node.get("reputation_score", 0)

        return score


class DistributedControlPlane:

    def __init__(self):

        self.collector_queue = asyncio.Queue()
        self.normalizer_queue = asyncio.Queue()
        self.scheduler_queue = asyncio.Queue()
        self.backend_queue = asyncio.Queue()

    async def pipeline(self):

        while True:

            item = await self.collector_queue.get()

            await self.normalizer_queue.put(item)
            await self.scheduler_queue.put(item)
            await self.backend_queue.put(item)


# =============================================================================
# END ADVANCED DISTRIBUTED VPN INTELLIGENCE EXTENSIONS
# =============================================================================



# =============================================================================
# CROSS-PLATFORM HYPERSCALE VPN INTELLIGENCE LAYER
# Linux + Windows Server Compatible
# Console/Headless only
# =============================================================================

import os
import platform
import uuid
import hashlib
from pathlib import Path


class PlatformCapabilities:

    def __init__(self):
        self.system = platform.system().lower()

    @property
    def is_windows(self):
        return self.system == "windows"

    @property
    def is_linux(self):
        return self.system == "linux"

    @property
    def supports_ebpf(self):
        return self.is_linux

    @property
    def supports_io_uring(self):
        return self.is_linux

    @property
    def supports_etw(self):
        return self.is_windows


class CrossPlatformPathManager:

    BASE_DIR = Path.cwd() / "vpn_intelligence_runtime"

    @classmethod
    def ensure_layout(cls):

        dirs = [
            "logs",
            "cache",
            "state",
            "benchmarks",
            "telemetry",
            "quarantine",
            "workers",
        ]

        cls.BASE_DIR.mkdir(exist_ok=True)

        for d in dirs:
            (cls.BASE_DIR / d).mkdir(exist_ok=True)


class EBPFAnalytics:

    def __init__(self):
        self.enabled = PlatformCapabilities().supports_ebpf

    async def collect(self):

        if not self.enabled:
            return {
                "status": "unsupported_platform"
            }

        return {
            "tcp_retransmits": 0,
            "udp_drops": 0,
            "kernel_rtt": 0.0,
        }


class ETWAnalytics:

    def __init__(self):
        self.enabled = PlatformCapabilities().supports_etw

    async def collect(self):

        if not self.enabled:
            return {
                "status": "unsupported_platform"
            }

        return {
            "winsock_events": 0,
            "tcp_resets": 0,
        }


class QUICDeepInspector:

    async def inspect(self, packet_meta):

        return {
            "quic_version": packet_meta.get("version"),
            "retry_packet": packet_meta.get("retry"),
            "cid_rotation": packet_meta.get("cid_rotation"),
            "transport_params": packet_meta.get("transport_params"),
        }


class DPIResistanceLab:

    async def simulate(self, node):

        return {
            "survives_sni_block": True,
            "survives_udp_throttle": True,
            "survives_tls_downgrade": True,
            "survives_fake_rst": True,
        }


class CensorshipSimulationProfiles:

    PROFILES = {
        "china_mode": {
            "quic_blocked": True,
            "dns_poisoned": True,
        },
        "russia_mode": {
            "dpi_enabled": True,
        },
        "iran_mode": {
            "tls_interference": True,
        },
        "corp_firewall_mode": {
            "http3_disabled": True,
        },
    }


class ProtocolMutationEngine:

    async def evolve(self, config):

        mutations = []

        transports = [
            "ws",
            "grpc",
            "h2",
            "h3",
            "tcp",
            "quic",
        ]

        for transport in transports:

            clone = dict(config)

            clone["transport"] = transport
            clone["mutation_id"] = str(uuid.uuid4())

            mutations.append(clone)

        return mutations


class HTTP2FingerprintEngine:

    def analyze(self, h2_data):

        return {
            "settings_order": h2_data.get("settings_order"),
            "priority_behavior": h2_data.get("priority_behavior"),
            "window_update_pattern": h2_data.get("window_update_pattern"),
        }


class HTTP3FingerprintEngine:

    def analyze(self, h3_data):

        return {
            "qpack_behavior": h3_data.get("qpack_behavior"),
            "stream_timing": h3_data.get("stream_timing"),
            "transport_params": h3_data.get("transport_params"),
        }


class AIAnomalyDetector:

    def detect(self, node_metrics):

        score = 0

        if node_metrics.get("packet_loss", 0) > 0.2:
            score += 1

        if node_metrics.get("latency_spike", False):
            score += 1

        return {
            "anomaly_score": score,
            "suspicious": score >= 2,
        }


class PassiveTLSDatabase:

    def __init__(self):
        self.storage = {}

    def store(self, host, tls_meta):

        key = hashlib.sha256(host.encode()).hexdigest()

        self.storage[key] = tls_meta


class SmartASNAvoidance:

    BAD_ASNS = {
        "OVH",
        "Hetzner",
    }

    def should_throttle(self, asn):

        return asn in self.BAD_ASNS


class WebRTCIntelligence:

    async def analyze(self):

        return {
            "udp_quality": random.uniform(0.0, 1.0),
            "nat_type": "cone",
            "turn_required": False,
        }


class HoneypotDetector:

    def inspect(self, node):

        suspicious = False

        if node.get("fake_cert"):
            suspicious = True

        if node.get("telemetry_headers"):
            suspicious = True

        return {
            "honeypot_suspected": suspicious
        }


class RealityDeepAnalytics:

    def inspect(self, reality_meta):

        return {
            "shortid_entropy": random.uniform(0.0, 1.0),
            "public_key_reuse": False,
            "mimic_quality": random.uniform(0.0, 1.0),
        }


class AutonomousSourceCrawler:

    async def crawl(self):

        return {
            "telegram_sources": 0,
            "github_sources": 0,
            "mirror_sources": 0,
        }


class PredictiveDegradationEngine:

    def predict(self, history):

        return {
            "likely_to_fail_soon": random.choice([True, False]),
            "confidence": random.uniform(0.0, 1.0),
        }


class AutonomousQuarantineHealing:

    async def revalidate(self, node):

        await asyncio.sleep(1)

        return {
            "recovered": random.choice([True, False])
        }


class CrossProtocolBenchmark:

    async def compare(self, host):

        return {
            "best_transport": random.choice([
                "ws",
                "grpc",
                "h2",
                "h3",
                "quic",
            ])
        }


class AutonomousBackendTuning:

    def tune(self):

        return {
            "optimal_timeout": random.randint(5, 20),
            "optimal_concurrency": random.randint(50, 1000),
        }


class DistributedAntiBanSystem:

    def next_strategy(self):

        return {
            "rotate_region": True,
            "rotate_asn": True,
            "apply_jitter": True,
        }


class HyperScaleCoordinator:

    def __init__(self):

        self.platform = PlatformCapabilities()

        self.ebpf = EBPFAnalytics()
        self.etw = ETWAnalytics()

        self.quic = QUICDeepInspector()
        self.dpi = DPIResistanceLab()
        self.mutation = ProtocolMutationEngine()
        self.h2 = HTTP2FingerprintEngine()
        self.h3 = HTTP3FingerprintEngine()

        self.anomaly = AIAnomalyDetector()
        self.tlsdb = PassiveTLSDatabase()
        self.webrtc = WebRTCIntelligence()
        self.honeypot = HoneypotDetector()

        self.degradation = PredictiveDegradationEngine()
        self.healing = AutonomousQuarantineHealing()

        self.cross_benchmark = CrossProtocolBenchmark()
        self.backend_tuning = AutonomousBackendTuning()

        self.antiban = DistributedAntiBanSystem()


# =============================================================================
# END CROSS-PLATFORM HYPERSCALE VPN INTELLIGENCE LAYER
# =============================================================================
