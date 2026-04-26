from __future__ import annotations

from pathlib import Path
import sys


APP_NAME = "AegisNET"
APP_VERSION = "1.0.5"
STATE_SCHEMA_VERSION = 1

PROXY_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 10808
DEFAULT_HTTP_PORT = 8080
XRAY_STATS_API_PORT = 19085
XRAY_GITHUB_RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases"

ROUTING_GLOBAL = "global"
ROUTING_RULE = "rule"
ROUTING_DIRECT = "direct"
ROUTING_MODES = (ROUTING_GLOBAL, ROUTING_RULE, ROUTING_DIRECT)


def get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


BASE_DIR = get_base_dir()
DATA_DIR = BASE_DIR / "data"
RUNTIME_DIR = DATA_DIR / "runtime"
LOG_DIR = DATA_DIR / "logs"
STATE_FILE = DATA_DIR / "state.enc"
XRAY_CONFIG_FILE = RUNTIME_DIR / "xray_config.json"

SINGBOX_CONFIG_FILE = RUNTIME_DIR / "singbox_config.json"

# Пути к бинарникам core/ — при запуске из exe берутся из get_core_dir()
# (распаковка из _cr.dat), в dev-режиме — BASE_DIR/core напрямую.
def _core_path(binary: str) -> Path:
    """Ленивое вычисление пути к бинарнику core/ с поддержкой _cr.dat."""
    try:
        from .core_unpacker import get_core_dir
        return get_core_dir() / binary
    except Exception:
        return BASE_DIR / "core" / binary

XRAY_PATH_DEFAULT     = _core_path("xray.exe")
SINGBOX_PATH_DEFAULT  = _core_path("sing-box.exe")
SINGBOX_CLASH_API_PORT = 19090

SPEED_TEST_URL = "https://gist.githubusercontent.com/Norkezz/761814b736254b3654b0b39db73e15b6/raw/a9b42a8edd0b00153e11f6fd8a22bb8bcdb29c62/gistfile1.txt"
SPEED_TEST_TIMEOUT = 20  # seconds per single measurement
SPEED_TEST_ROUNDS = 3    # number of measurements per node (best avg of N-1)
SPEED_TEST_TEMP_SOCKS_PORT = 19100
SPEED_TEST_TEMP_HTTP_PORT = 19101

SS_PROTECT_PORT_START = 19200
SS_PROTECT_PORT_END = 19300
