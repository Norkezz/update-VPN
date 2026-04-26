from __future__ import annotations

import ctypes
import sys

if sys.platform == "win32":
    import winreg

from .constants import PROXY_HOST


INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


class ProxyManager:
    def __init__(self) -> None:
        self._backup: dict[str, str | int] | None = None

    @property
    def is_supported(self) -> bool:
        return sys.platform == "win32"

    def _read_settings(self) -> dict[str, str | int]:
        if not self.is_supported:
            return {}
        values: dict[str, str | int] = {}
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
            for name, default in (("ProxyEnable", 0), ("ProxyServer", ""), ("ProxyOverride", "")):
                try:
                    values[name], _ = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    values[name] = default
        return values

    def _write_settings(self, values: dict[str, str | int]) -> None:
        if not self.is_supported:
            return
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if "ProxyEnable" in values:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(values["ProxyEnable"]))
            if "ProxyServer" in values:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(values["ProxyServer"]))
            if "ProxyOverride" in values:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, str(values["ProxyOverride"]))

    def _refresh_system_proxy(self) -> None:
        if not self.is_supported:
            return
        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)

    def enable(self, http_port: int, socks_port: int, bypass_lan: bool = True) -> None:
        if not self.is_supported:
            return
        if self._backup is None:
            self._backup = self._read_settings()

        proxy_server = (
            f"http={PROXY_HOST}:{http_port};"
            f"https={PROXY_HOST}:{http_port};"
            f"socks={PROXY_HOST}:{socks_port}"
        )

        override = "<local>;localhost;127.*"
        if bypass_lan:
            override = (
                "<local>;localhost;127.*;10.*;172.*;192.168.*;"
                "*.local;::1"
            )

        self._write_settings(
            {
                "ProxyEnable": 1,
                "ProxyServer": proxy_server,
                "ProxyOverride": override,
            }
        )
        self._refresh_system_proxy()

    def disable(self, restore_previous: bool = True) -> None:
        if not self.is_supported:
            return
        if restore_previous and self._backup:
            restored = dict(self._backup)
            restored["ProxyEnable"] = 0
            self._write_settings(restored)
        else:
            self._write_settings({"ProxyEnable": 0})
        self._backup = None
        self._refresh_system_proxy()

    def is_enabled(self) -> bool:
        if not self.is_supported:
            return False
        values = self._read_settings()
        return int(values.get("ProxyEnable", 0)) == 1
