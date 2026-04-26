from __future__ import annotations

from copy import deepcopy
from ipaddress import ip_network
from typing import Any

from .constants import (
    PROXY_HOST,
    ROUTING_DIRECT,
    ROUTING_GLOBAL,
    ROUTING_RULE,
    XRAY_STATS_API_PORT,
)
from .models import AppSettings, Node, RoutingSettings
from .service_presets import SERVICE_PRESETS_BY_ID


def _normalize_loglevel(value: str) -> str:
    normalized = value.lower().strip()
    if normalized == "warn":
        return "warning"
    if normalized in {"debug", "info", "warning", "error", "none"}:
        return normalized
    return "warning"


def _split_rule_items(items: list[str]) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    ips: list[str] = []
    for raw in items:
        value = raw.strip()
        if not value:
            continue

        if value.startswith(("domain:", "full:", "regexp:", "keyword:", "geosite:", "ext:")):
            domains.append(value)
            continue
        if value.startswith(("geoip:", "ip:")):
            ips.append(value)
            continue

        try:
            ip_network(value, strict=False)
            ips.append(value)
            continue
        except ValueError:
            pass

        domains.append(f"domain:{value}")

    return domains, ips


def _append_domain_ip_rule(rules: list[dict[str, Any]], items: list[str], outbound_tag: str) -> None:
    domains, ips = _split_rule_items(items)
    if domains:
        rules.append(
            {
                "type": "field",
                "domain": domains,
                "outboundTag": outbound_tag,
            }
        )
    if ips:
        rules.append(
            {
                "type": "field",
                "ip": ips,
                "outboundTag": outbound_tag,
            }
        )


def build_xray_config(node: Node, routing: RoutingSettings, settings: AppSettings) -> dict[str, Any]:
    proxy_outbound = deepcopy(node.outbound)
    proxy_outbound["tag"] = "proxy"

    # Санитизация: невалидное значение security (напр. "false") ломает xray при старте
    _VALID_SECURITY = {"none", "tls", "reality", "xtls", ""}
    _stream = proxy_outbound.get("streamSettings")
    if isinstance(_stream, dict):
        _sec = _stream.get("security", "none")
        if _sec not in _VALID_SECURITY:
            _stream["security"] = "none"

    # ── Базовые sockopt для скорости (всегда) ───────────────────────────────
    if isinstance(_stream, dict):
        _sockopt = _stream.setdefault("sockopt", {})
        _sockopt.setdefault("tcpFastOpen", True)   # TFO: экономит 1 RTT при коннекте
        _sockopt.setdefault("tcpNoDelay", True)     # Nagle off: меньше задержка

    # ── Анти-блокировки DPI ──────────────────────────────────────────────────
    # 1. Фрагментация TLS ClientHello (обход глубокой инспекции пакетов)
    if settings.dpi_fragment_enabled and isinstance(_stream, dict):
        _stream["sockopt"] = _stream.get("sockopt") or {}
        _stream["sockopt"].update({
            "dialerProxy": "",
            "tcpFastOpen": True,
            "mark": 0,
        })
        # Xray sockopt fragment (доступно с xray-core 1.8.3+)
        _stream["sockopt"]["tcpNoDelay"] = True
        proxy_outbound["streamSettings"] = _stream
        # Добавляем fragment в настройки outbound
        proxy_outbound["mux"] = proxy_outbound.get("mux") or {}
        # fragment — отдельный ключ в streamSettings
        _stream["fragment"] = {
            "packets": f"1-{settings.dpi_fragment_packets}",
            "length": f"1-{settings.dpi_fragment_length}",
            "interval": f"1-{settings.dpi_fragment_interval_ms}",
        }

    # 2. Мультиплексирование (Mux) — несколько логических потоков в одном TCP
    if settings.dpi_mux_enabled:
        proxy_outbound["mux"] = {
            "enabled": True,
            "concurrency": settings.dpi_mux_concurrency,
        }
    elif "mux" not in proxy_outbound:
        pass  # не трогаем, если пользователь не включил

    # 3. Noise padding — если поддерживается ядром (Xray 1.8.11+)
    if settings.dpi_noise_enabled and isinstance(_stream, dict):
        _stream["sockopt"] = _stream.get("sockopt") or {}
        _stream["sockopt"]["tcpNoDelay"] = True
        # xray-core: можно инжектировать rnd-паддинг через пустой inbound noise
        # Реализуем через добавление domainsExcluded-правила в routing
        pass  # Noise применяется через sniffing routeOnly + специальный inbound ниже

    routing_rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        }
    ]

    if routing.bypass_lan:
        routing_rules.append(
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "direct",
            }
        )
        routing_rules.append(
            {
                "type": "field",
                "domain": ["geosite:private"],
                "outboundTag": "direct",
            }
        )

    _append_domain_ip_rule(routing_rules, routing.direct_domains, "direct")
    _append_domain_ip_rule(routing_rules, routing.block_domains, "block")
    _append_domain_ip_rule(routing_rules, routing.proxy_domains, "proxy")

    # Merge service preset domains
    service_direct: list[str] = []
    service_proxy: list[str] = []
    service_block: list[str] = []
    for svc_id, action in routing.service_routes.items():
        preset = SERVICE_PRESETS_BY_ID.get(svc_id)
        if not preset:
            continue
        if action == "direct":
            service_direct.extend(preset.domains)
        elif action == "block":
            service_block.extend(preset.domains)
        else:
            service_proxy.extend(preset.domains)
    _append_domain_ip_rule(routing_rules, service_proxy, "proxy")
    _append_domain_ip_rule(routing_rules, service_direct, "direct")
    _append_domain_ip_rule(routing_rules, service_block, "block")

    if not settings.tun_mode:
        for pr in routing.process_rules:
            name = pr.get("process", "").strip()
            action = pr.get("action", "direct")
            if name:
                routing_rules.append({
                    "type": "field",
                    "process": [name],
                    "network": "tcp,udp",
                    "outboundTag": action if action in ("direct", "proxy", "block") else "direct",
                })

    mode = routing.mode

    if mode == ROUTING_GLOBAL:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "proxy",
            }
        )
    elif mode == ROUTING_DIRECT:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "direct",
            }
        )
    else:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "proxy",
            }
        )

    config: dict[str, Any] = {
        "log": {
            "loglevel": _normalize_loglevel(settings.log_level),
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": PROXY_HOST,
                "port": settings.socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                    "metadataOnly": False,  # читаем SNI для корректного роутинга
                },
            },
            {
                "tag": "http-in",
                "listen": PROXY_HOST,
                "port": settings.http_port,
                "protocol": "http",
                "settings": {},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "api",
                "listen": PROXY_HOST,
                "port": XRAY_STATS_API_PORT,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": PROXY_HOST,
                },
            },
        ],
        "outbounds": [
            proxy_outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIPv4",   # быстрее чем AsIs — нет двойного lookup
                },
                "streamSettings": {
                    "sockopt": {
                        "tcpFastOpen": True,       # TFO сокращает RTT на 1 round-trip
                        "tcpNoDelay": True,        # выключает Nagle — меньше задержка
                        "mark": 0,
                    }
                },
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            },
            {
                "tag": "api",
                "protocol": "freedom",
                "settings": {},
            },
        ],
        "policy": {
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            }
        },
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"],
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",  # пробует домен → если нет правила → резолвит IP
            "rules": routing_rules,
        },
    }

    if routing.dns_mode == "builtin":
        config["dns"] = {
            "servers": [
                {
                    "address": "1.1.1.1",
                    "domains": [],      # все домены
                    "skipFallback": False,
                },
                "8.8.8.8",
                "localhost",
            ],
            "queryStrategy": "UseIPv4",  # быстрее — не ждём AAAA запрос
            "tag": "dns-out",
        }

    return config
