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
                links.append(line)
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
# Files not updated within this window are skipped — stale configs
# are unlikely to still be alive.
MAX_FILE_AGE_DAYS = 45


def _git_file_mtime(repo_dir: Path, filepath: Path) -> Optional[float]:
    """Return the Unix timestamp of the last git commit that touched `filepath`.

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
      - If only_updated=True (mode 4): files not modified since script start
        (compares os.path.getmtime vs SCRIPT_START_TIME).
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

        # Mode 4: пропускаем файлы, не изменённые после запуска скрипта
        if only_updated:
            fs_mtime = fp.stat().st_mtime
            if fs_mtime < SCRIPT_START_TIME:
                print(f"  ⏭  {rel} — skipped (not updated since script start)")
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
CHECK_WORKERS = 24     # 24 воркера = 24 xray-процесса одновременно (стабильно на Windows)

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
            # Linux/Debian: use zapret2 releases — pick nfqws2-linux-x86_64 or arm64
            req = urllib.request.Request(ZAPRET2_RELEASES_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())

            machine = _platform_mod.machine().lower()
            if "aarch64" in machine or "arm64" in machine:
                arch_kw = "arm64"
            elif "arm" in machine:
                arch_kw = "arm"
            else:
                arch_kw = "x86_64"

            # zapret2 releases naming: nfqws2-linux-x86_64, nfqws2-linux-arm64, etc.
            asset_url = next(
                (a["browser_download_url"] for a in data.get("assets", [])
                 if "nfqws2" in a["name"].lower() and "linux" in a["name"].lower()
                 and arch_kw in a["name"].lower()),
                None
            )
            # Fallback: any linux asset
            if not asset_url:
                asset_url = next(
                    (a["browser_download_url"] for a in data.get("assets", [])
                     if "linux" in a["name"].lower() and "nfqws2" in a["name"].lower()),
                    None
                )

        if not asset_url:
            _zapret_manual_hint()
            return None

        fname = asset_url.split("/")[-1]
        print(f"  ⬇  Downloading {fname} ...", flush=True)
        req2 = urllib.request.Request(asset_url, headers={"User-Agent": "AegisNET-Admin/1.0"})
        with urllib.request.urlopen(req2, timeout=120) as r:
            raw = r.read()

        base.mkdir(parents=True, exist_ok=True)

        if fname.endswith(".zip"):
            with _zipfile.ZipFile(_io.BytesIO(raw)) as zf:
                zf.extractall(base)
        else:
            with _tarfile.open(fileobj=_io.BytesIO(raw)) as tf:
                tf.extractall(base)

        # Also try to grab lua/ scripts from zapret2 repo (needed by nfqws2)
        if not is_win:
            _zapret2_fetch_lua(base, data)

        # Re-check
        if is_win:
            to_check = ["winws2.exe", "winws.exe"]
        else:
            to_check = ["nfqws2", "winws2", "nfqws"]

        for name in to_check:
            found_list = list(base.rglob(name))
            if found_list:
                exe = found_list[0]
                if not is_win:
                    exe.chmod(0o755)
                print(f"  [OK] zapret2 extracted: {exe}")
                return str(exe)

        print("  ⚠  zapret2: binary not found after extraction")
        _zapret_manual_hint()
        return None

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


def _zapret_manual_hint() -> None:
    if OS_TYPE == "windows":
        print("       Скачайте вручную: https://github.com/bol-van/zapret-win-bundle/releases")
        print("       Поместите winws2.exe в папку core/zapret/")
    elif OS_TYPE == "debian":
        print("       Debian/Ubuntu: apt install nfqueue-utils iptables")
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
            host_bytes = PROBE_HOST.encode()
            req = (b"\x05\x01\x00\x03" +
                   bytes([len(host_bytes)]) + host_bytes +
                   _struct.pack(">H", PROBE_PORT))
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
            t0 = time.perf_counter()
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
        return ms is not None and ms <= CHECK4_MAX_STACK_PING_MS

    finally:
        _kill_xray(proc, tmp)
        if zapret_proc:
            try: zapret_proc.kill(); zapret_proc.wait(timeout=2)
            except Exception: pass


def check_config_full(link: str, xray_exe: str, port_base: int,
                      skip_stage4: bool = False) -> bool:
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
    return _check_stage4_stack_ping(link, xray_exe, port4, zapret_exe if is_reality else None)


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
    return _find_or_download_xray()'''


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


def _wait_port(port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


import requests as _requests


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
) -> list[str]:
    """Run the 3-stage xray check on `links` and return those that pass."""
    if verbose:
        print(f"  🔬  xray check: {len(links)} configs | {workers} threads ...", flush=True)

    # Прогреваем reference MD5 один раз до запуска воркеров, чтобы не было
    # race condition: без этого все 24 воркера стартуют одновременно и первый
    # же лочит _REFERENCE_MD5_LOCK на 10+ секунд пока скачивает эталон,
    # а остальные 23 ждут — их xray-процессы тем временем таймаутятся.
    if verbose:
        print(f"  📥  Pre-fetching reference MD5 for Stage 3 ...", flush=True)
    _get_reference_md5(CHECK3_URL)

    working: list[str] = []
    lock        = threading.Lock()
    done        = [0]

    # Фиксированный пул портов: workers слотов × 20 портов каждый.
    # Слоты переиспользуются — нет риска выйти за 65535.
    _PORT_STEP   = 20          # портов на один воркер-слот (stages 1-4 + zapret offset)
    _port_pool   = list(range(port_base, port_base + workers * _PORT_STEP, _PORT_STEP))
    _free_slots  = list(_port_pool)   # доступные слоты
    _slot_lock   = threading.Lock()
    _slot_cv     = threading.Condition(_slot_lock)

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
            result = check_config_full(lnk, xray_exe, p, skip_stage4=True)
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
                    print(f"    xray {done[0]}/{len(links)}  working: {len(working)}", end="\r", flush=True)

    if verbose:
        print(f"\n  ✓  xray done: {len(working)}/{len(links)} working", flush=True)

    return working


def run_checks(
    links: list[str],
    xray_exe: Optional[str],
    port_base: int = 20000,
    workers: int = CHECK_WORKERS,
    verbose: bool = True,
) -> list[str]:
    """Convenience wrapper: ping all links then xray-check survivors (single pass).

    Used by `cmd_check` and `cmd_fetch` where batched upload is not needed.
    """
    passed, _ = _run_ping_batch(links, batch_size=len(links), verbose=verbose)
    if not xray_exe or not passed:
        return passed
    return _run_xray_batch(passed, xray_exe, port_base, workers, verbose)


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
    """Download all required tools: xray, zapret, subconverter."""
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
    print("\n  [1/3] xray (XTLS/Xray-core)")
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

    print(f"\n  [2/3] {zapret_label}")

    # Debian: hint about kernel modules needed
    if OS_TYPE == "debian":
        print("  [i]  Для работы nfqws2 нужны пакеты (установить вручную):")
        print("       sudo apt install -y iptables ipset libnetfilter-queue-dev")

    zapret = _find_or_download_zapret()
    if zapret:
        print(f"  [OK] zapret2: {zapret}")
        results["zapret"] = True
    else:
        _zapret_manual_hint()
        results["zapret"] = False

    # ── 3. subconverter ───────────────────────────────────────────────────────
    print("\n  [3/3] subconverter (tindy2013/subconverter)")
    sub = _find_or_download_subconverter(work_dir)
    if sub:
        print(f"  [OK] subconverter: {sub}")
        results["subconverter"] = True
    else:
        print("  [!!] subconverter: не удалось скачать — скачайте вручную:")
        print("       https://github.com/tindy2013/subconverter/releases")
        results["subconverter"] = False

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
        print("  Debian: не забудьте установить apt-пакеты для nfqws2")
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
    fetch_mode  = int(getattr(args, "mode", 4))
    port_base   = getattr(args, "port_base", 21000)
    workers     = getattr(args, "workers", CHECK_WORKERS)
    batch_size  = getattr(args, "batch_size", PING_BATCH_SIZE)

    print(f"\n{'='*60}")
    print(f"  📥  Fetching configs from {len(sources)} source(s): {', '.join(sources)}")
    print(f"  Ping threshold: {MAX_PING_MS} ms  |  Ping batch: {batch_size}  |  Geo filter: DISABLED")
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

        # Stage 2+3 — xray (skip if no xray binary)
        if xray_exe:
            working = _run_xray_batch(
                ping_passed, xray_exe,
                port_base=port_base, workers=workers, verbose=True,
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
    """Single-config diagnostic: run each stage verbosely and show exactly where it fails."""
    link = args.link.strip()
    port_base = getattr(args, "port_base", 19000)

    print(f"\n{'='*62}")
    print(f"  DIAG: {link[:80]}")
    print(f"{'='*62}\n")

    # ── xray binary ───────────────────────────────────────────────────────────
    xray_exe = _find_xray()
    if not xray_exe:
        print("  ❌  xray binary not found — cannot run stages 1-4")
        return
    print(f"  ✓  xray: {xray_exe}")

    # ── Parse config ──────────────────────────────────────────────────────────
    cfg = _build_xray_cfg(link, port_base)
    if not cfg:
        print("  ❌  Could not parse config link (xray_fluent.link_parser failed)")
        return
    print(f"  ✓  Config parsed OK")
    print(f"  is_reality: {_is_reality_config(link)}")

    # ── Reference MD5 ─────────────────────────────────────────────────────────
    print(f"\n  Fetching reference MD5 for stage 3 ({CHECK3_URL[:50]})...")
    ref = _get_reference_md5(CHECK3_URL)
    if ref:
        print(f"  ✓  Reference MD5: {ref.hex()}")
    else:
        print(f"  ⚠  Reference MD5 unavailable — stage 3 will use size fallback")

    # ── Stages 1 & 2 ──────────────────────────────────────────────────────────
    for stage_num, (url, timeout) in enumerate([
        (CHECK1_URL, CHECK1_TIMEOUT),
        (CHECK2_URL, CHECK2_TIMEOUT),
    ], start=1):
        port = port_base + stage_num - 1
        print(f"\n  --- Stage {stage_num}: {url} (port {port}) ---")

        # Start xray with stderr visible
        cfg_s = _build_xray_cfg(link, port)
        tmp_path = None
        try:
            import tempfile as _tf
            with _tf.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(cfg_s, f)
                tmp_path = f.name
            flags = 0x08000000 if sys.platform == "win32" else 0
            proc = subprocess.Popen(
                [xray_exe, "run", "-c", tmp_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=flags, text=True, encoding="utf-8", errors="replace",
            )
        except Exception as e:
            print(f"  ❌  xray start failed: {e}")
            continue

        port_ok = _wait_port(port, 5.0)
        xray_out = ""
        try:
            xray_out = proc.stdout.read(2000) if not port_ok else ""
        except Exception:
            pass

        if not port_ok:
            proc.kill(); proc.wait()
            if tmp_path:
                try: os.unlink(tmp_path)
                except: pass
            print(f"  ❌  xray did not bind port {port} within 5s")
            if xray_out.strip():
                print(f"  xray output:\n{''.join('    ' + l for l in xray_out.splitlines(True))}")
            continue

        print(f"  ✓  xray listening on port {port}")
        proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
        try:
            t0 = time.perf_counter()
            r = _requests.get(url, proxies=proxies, timeout=timeout,
                              allow_redirects=True, headers={"User-Agent": _random_ua()})
            ms = int((time.perf_counter() - t0) * 1000)
            print(f"  ✓  HTTP {r.status_code}  {ms} ms  body={len(r.content)} bytes")
            # Stage 2 fallback: если google.com вернул 429/403 — пробуем резервный URL
            if stage_num == 2 and r.status_code in CHECK2_FALLBACK_STATUSES:
                print(f"  ⚠  Stage 2 — status {r.status_code}, retrying with fallback: {CHECK2_FALLBACK_URL}")
                t0 = time.perf_counter()
                r = _requests.get(CHECK2_FALLBACK_URL, proxies=proxies, timeout=timeout,
                                  allow_redirects=True, headers={"User-Agent": _random_ua()})
                ms = int((time.perf_counter() - t0) * 1000)
                print(f"  ✓  HTTP {r.status_code}  {ms} ms  body={len(r.content)} bytes  [fallback]")
            if r.status_code != 200:
                print(f"  ❌  Stage {stage_num} FAIL — status {r.status_code} != 200")
            elif len(r.content) < 256:
                print(f"  ❌  Stage {stage_num} FAIL — body too small ({len(r.content)} bytes)")
            else:
                print(f"  ✓  Stage {stage_num} PASS")
        except Exception as e:
            print(f"  ❌  Stage {stage_num} FAIL — {type(e).__name__}: {e}")
        finally:
            try: proc.kill(); proc.wait()
            except: pass
            if tmp_path:
                try: os.unlink(tmp_path)
                except: pass

    # ── Stage 3 ───────────────────────────────────────────────────────────────
    port3 = port_base + 2
    print(f"\n  --- Stage 3: {CHECK3_URL[:50]} (port {port3}) ---")
    proc, tmp_path = _start_xray(link, xray_exe, port3)
    if not proc:
        print(f"  ❌  xray start failed")
    else:
        port_ok = _wait_port(port3, 5.0)
        if not port_ok:
            proc.kill(); proc.wait()
            print(f"  ❌  xray did not bind port {port3}")
        else:
            proxies = {"http": f"socks5h://127.0.0.1:{port3}", "https": f"socks5h://127.0.0.1:{port3}"}
            try:
                t0 = time.perf_counter()
                r = _requests.get(CHECK3_URL, proxies=proxies, timeout=CHECK3_TIMEOUT,
                                  allow_redirects=True, headers={"User-Agent": _random_ua()})
                ms = int((time.perf_counter() - t0) * 1000)
                body_md5 = hashlib.md5(r.content).hexdigest()
                print(f"  HTTP {r.status_code}  {ms} ms  body={len(r.content)} bytes  md5={body_md5[:12]}")
                if ref:
                    match = hashlib.md5(r.content).digest() == ref
                    print(f"  MD5 match: {match}")
                    if not match:
                        print(f"  ❌  Stage 3 FAIL — MD5 mismatch")
                    else:
                        print(f"  ✓  Stage 3 PASS")
                else:
                    print(f"  ✓  Stage 3 PASS (no reference, size={len(r.content)})")
            except Exception as e:
                print(f"  ❌  Stage 3 FAIL — {type(e).__name__}: {e}")
            finally:
                _kill_xray(proc, tmp_path)

    # ── Stage 4 ───────────────────────────────────────────────────────────────
    port4 = port_base + 3
    print(f"\n  --- Stage 4: stacked ping latency (port {port4}) ---")
    proc, tmp_path = _start_xray(link, xray_exe, port4)
    if not proc:
        print(f"  ❌  xray start failed")
    else:
        port_ok = _wait_port(port4, 5.0)
        if not port_ok:
            proc.kill(); proc.wait()
            print(f"  ❌  xray did not bind port {port4}")
        else:
            ms = _stack_ping_ms(link, xray_exe, port4, None)
            if ms is None:
                print(f"  ❌  Stage 4 FAIL — no ping response")
            elif ms > CHECK4_MAX_STACK_PING_MS:
                print(f"  ❌  Stage 4 FAIL — {ms} ms > {CHECK4_MAX_STACK_PING_MS} ms threshold")
            else:
                print(f"  ✓  Stage 4 PASS — {ms} ms")
            _kill_xray(proc, tmp_path)

    print(f"\n{'='*62}\n")

def _interactive_menu() -> "argparse.Namespace":
    """Интерактивный выбор команды и источников при запуске без аргументов."""
    print("\n" + "="*60)
    print("  🛡  AegisNET — VPN Config Manager")
    print("="*60)

    print("\n  Что делаем?\n")
    print("  0) setup    — скачать инструменты (xray, zapret, subconverter)")
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
        sources="kort0881,v2ray_agg,epodonios,keysconf",
        work_dir=None, workers=CHECK_WORKERS, port_base=21000,
        mode=4, batch_size=PING_BATCH_SIZE, output=None, input=None, link=None,
        help=False,
    )
    args = _ns

    if command in ("update", "fetch"):
        # key, display label, default selected, is_new
        ALL_SOURCES = [
            ("kort0881",  "kort0881   — ~840 VLESS источников, Россия",             True,  False),
            ("v2ray_agg", "v2ray_agg  — V2RayAggregator + ShadowsocksAggregator",   True,  False),
            ("epodonios", "epodonios  — Epodonios/v2ray-configs (ежедневно)",        True,  False),
            ("keysconf",  "keysconf   — keysconf.com (твой сайт, Online конфиги)",   True,  False),
            ("urls_base", "urls_base  — 60+ GitHub raw-URL источников",              True,  False),
            ("telegram",  "telegram   — 17 TG-каналов с конфигами (без API key)",    False, True),
        ]
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

        if command == "fetch":
            args.output = input("  Сохранить в файл [Enter=нет]: ").strip() or None

    elif command == "check":
        args.input  = input("  Файл с конфигами: ").strip()
        args.output = input("  Сохранить рабочие в файл [Enter=нет]: ").strip() or None
        wi = input(f"  Потоков [Enter={CHECK_WORKERS}]: ").strip()
        if wi.isdigit():
            args.workers = max(1, min(int(wi), 64))

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
    p_update.add_argument("--sources", default="kort0881,v2ray_agg,epodonios,keysconf",
                           help=(
                               "Sources (comma-separated): kort0881, v2ray_agg, epodonios, "
                               "keysconf, urls_base, local:<path>, or direct URL"
                           ))
    p_update.add_argument("--work-dir", dest="work_dir", default=None)
    p_update.add_argument("--workers", type=int, default=CHECK_WORKERS,
                           help=f"xray check threads (default: {CHECK_WORKERS})")
    p_update.add_argument("--port-base", dest="port_base", type=int, default=21000)
    p_update.add_argument("--mode", type=int, default=4, choices=[1, 2, 3, 4])
    p_update.add_argument("--batch-size", dest="batch_size", type=int, default=PING_BATCH_SIZE)

    # fetch
    p_fetch = sub.add_parser("fetch", help="Collect configs only (no upload)")
    p_fetch.add_argument("--sources", default="kort0881,v2ray_agg,epodonios,keysconf",
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
    p_setup = sub.add_parser("setup", help="Download all required tools (xray, zapret, subconverter)")
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
