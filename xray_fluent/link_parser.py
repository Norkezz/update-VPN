from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .models import Node


class LinkParseError(ValueError):
    pass


def parse_links_text(text: str) -> tuple[list[Node], list[str]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    nodes: list[Node] = []
    errors: list[str] = []

    for idx, line in enumerate(lines, start=1):
        try:
            node = parse_single(line)
            nodes.append(node)
        except Exception as exc:
            errors.append(f"Line {idx}: {exc}")

    return nodes, errors


def parse_single(raw: str) -> Node:
    text = raw.strip()
    if not text:
        raise LinkParseError("empty input")

    if text.startswith("{"):
        return _parse_json_outbound(text)

    scheme = urlsplit(text).scheme.lower()
    if scheme == "vless":
        return _parse_vless(text)
    if scheme == "vmess":
        return _parse_vmess(text)
    if scheme == "trojan":
        return _parse_trojan(text)
    if scheme == "ss":
        return _parse_shadowsocks(text)
    if scheme in {"socks", "socks5"}:
        return _parse_socks(text)
    if scheme in {"http", "https"}:
        return _parse_http_proxy(text)

    raise LinkParseError(f"unsupported scheme: {scheme or 'unknown'}")


def _first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    if not values:
        return default
    return values[0]


def _decode_b64(data: str) -> str:
    data = data.strip()
    data += "=" * ((4 - len(data) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(data.encode("utf-8"))
    except Exception:
        raw = base64.b64decode(data.encode("utf-8"))
    return raw.decode("utf-8")


def _clean_name(name: str, fallback: str) -> str:
    value = unquote(name).strip()
    return value if value else fallback


def _to_bool(value: str) -> bool:
    return str(value).lower() in {"1", "true", "yes", "on"}


def _build_stream_settings(params: dict[str, str], default_network: str = "tcp", default_security: str = "none") -> dict[str, Any]:
    network = (params.get("type") or params.get("net") or default_network or "tcp").lower()
    security = (params.get("security") or params.get("tls") or default_security or "none").lower()
    if security == "none" and params.get("tls") == "tls":
        security = "tls"

    stream: dict[str, Any] = {
        "network": network,
        "security": security,
    }

    host = params.get("host")
    path = params.get("path")

    if network == "ws":
        ws_settings: dict[str, Any] = {}
        if path:
            ws_settings["path"] = path
        if host:
            ws_settings["headers"] = {"Host": host}
        stream["wsSettings"] = ws_settings
    elif network in {"http", "h2"}:
        http_settings: dict[str, Any] = {}
        if host:
            http_settings["host"] = [h.strip() for h in host.split(",") if h.strip()]
        if path:
            http_settings["path"] = path
        stream["httpSettings"] = http_settings
    elif network == "grpc":
        # gRPC deprecated — мигрируем на xhttp (stream-up H2) согласно xray 25.x release notes
        grpc_settings: dict[str, Any] = {}
        service_name = params.get("serviceName")
        if service_name:
            grpc_settings["serviceName"] = service_name
        authority = params.get("authority")
        if authority:
            grpc_settings["authority"] = authority
        mode = params.get("mode")
        if mode == "multi":
            grpc_settings["multiMode"] = True
        stream["grpcSettings"] = grpc_settings
        # Также записываем xhttpSettings для новых версий xray
        stream["network"] = "xhttp"
        xhttp_settings: dict[str, Any] = {"mode": "stream-up"}
        if service_name:
            xhttp_settings["path"] = f"/{service_name}"
        if authority:
            xhttp_settings["host"] = authority
        stream["xhttpSettings"] = xhttp_settings
    elif network == "quic":
        stream["quicSettings"] = {
            "security": params.get("quicSecurity") or "none",
            "key": params.get("key") or "",
            "header": {"type": params.get("headerType") or "none"},
        }
    elif network == "kcp":
        stream["kcpSettings"] = {
            "header": {"type": params.get("headerType") or "none"},
        }

    if security == "tls":
        tls_settings: dict[str, Any] = {}
        sni = params.get("sni")
        if sni:
            tls_settings["serverName"] = sni
        alpn = params.get("alpn")
        if alpn:
            tls_settings["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
        fp = params.get("fp")
        if fp:
            tls_settings["fingerprint"] = fp
        if "allowInsecure" in params:
            tls_settings["allowInsecure"] = _to_bool(params.get("allowInsecure", "false"))
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        reality_settings: dict[str, Any] = {}
        sni = params.get("sni")
        if sni:
            reality_settings["serverName"] = sni
        fp = params.get("fp")
        if fp:
            reality_settings["fingerprint"] = fp
        pbk = params.get("pbk")
        if pbk:
            reality_settings["publicKey"] = pbk
        sid = params.get("sid")
        if sid:
            reality_settings["shortId"] = sid
        spx = params.get("spx")
        if spx:
            reality_settings["spiderX"] = spx
        stream["realitySettings"] = reality_settings

    return stream


def _parse_vless(link: str) -> Node:
    parsed = urlsplit(link)
    query = {k: v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    params = {k: _first(query, k) for k in query}

    user_id = unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 443

    if not user_id or not server:
        raise LinkParseError("invalid vless link")

    user: dict[str, Any] = {
        "id": user_id,
        "encryption": params.get("encryption") or "none",
    }
    flow = params.get("flow")
    if flow:
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": _build_stream_settings(params, default_network="tcp", default_security=params.get("security", "none")),
    }

    name = _clean_name(parsed.fragment, f"vless-{server}:{port}")
    return Node(
        name=name,
        scheme="vless",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_vmess(link: str) -> Node:
    encoded = link[len("vmess://") :]
    payload = json.loads(_decode_b64(encoded))

    server = str(payload.get("add") or "")
    port = int(payload.get("port") or 443)
    user_id = str(payload.get("id") or "")
    if not server or not user_id:
        raise LinkParseError("invalid vmess link")

    security = str(payload.get("tls") or "none").lower()
    params = {
        "net": str(payload.get("net") or "tcp"),
        "type": str(payload.get("net") or "tcp"),
        "security": "tls" if security in {"tls", "reality"} else "none",
        "host": str(payload.get("host") or ""),
        "path": str(payload.get("path") or ""),
        "sni": str(payload.get("sni") or payload.get("host") or ""),
        "alpn": str(payload.get("alpn") or ""),
        "fp": str(payload.get("fp") or ""),
        "serviceName": str(payload.get("serviceName") or ""),
    }

    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": port,
                    "users": [
                        {
                            "id": user_id,
                            "alterId": int(payload.get("aid") or 0),
                            "security": str(payload.get("scy") or "auto"),
                        }
                    ],
                }
            ]
        },
        "streamSettings": _build_stream_settings(params, default_network=params["net"], default_security=params["security"]),
    }

    name = _clean_name(str(payload.get("ps") or ""), f"vmess-{server}:{port}")
    return Node(
        name=name,
        scheme="vmess",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_trojan(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}

    password = unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 443
    if not password or not server:
        raise LinkParseError("invalid trojan link")

    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": server,
                    "port": port,
                    "password": password,
                }
            ]
        },
        "streamSettings": _build_stream_settings(params, default_network="tcp", default_security=params.get("security", "tls")),
    }

    name = _clean_name(parsed.fragment, f"trojan-{server}:{port}")
    return Node(
        name=name,
        scheme="trojan",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_shadowsocks(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)

    method = ""
    password = ""
    server = parsed.hostname or ""
    port = parsed.port or 8388

    if parsed.username and parsed.password:
        method = unquote(parsed.username)
        password = unquote(parsed.password)
    elif parsed.username and not parsed.password:
        decoded = _decode_b64(parsed.username)
        if ":" not in decoded:
            raise LinkParseError("invalid shadowsocks credentials")
        method, password = decoded.split(":", 1)
    else:
        decoded = _decode_b64(parsed.netloc)
        parsed_decoded = urlsplit(f"ss://{decoded}")
        if parsed_decoded.username and parsed_decoded.password and parsed_decoded.hostname:
            method = unquote(parsed_decoded.username)
            password = unquote(parsed_decoded.password)
            server = parsed_decoded.hostname
            port = parsed_decoded.port or 8388
        else:
            raise LinkParseError("invalid shadowsocks link")

    if not method or not password or not server:
        raise LinkParseError("invalid shadowsocks link")

    plugin = _first(query, "plugin")
    outbound_server: dict[str, Any] = {
        "address": server,
        "port": port,
        "method": method,
        "password": password,
    }
    if plugin:
        outbound_server["plugin"] = plugin

    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [outbound_server],
        },
    }

    name = _clean_name(parsed.fragment, f"ss-{server}:{port}")
    return Node(
        name=name,
        scheme="ss",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_socks(link: str) -> Node:
    parsed = urlsplit(link)
    server = parsed.hostname or ""
    port = parsed.port or 1080
    if not server:
        raise LinkParseError("invalid socks link")

    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    server_item: dict[str, Any] = {
        "address": server,
        "port": port,
    }
    if user:
        server_item["users"] = [{"user": user, "pass": password}]

    outbound = {
        "protocol": "socks",
        "settings": {"servers": [server_item]},
    }

    name = _clean_name(parsed.fragment, f"socks-{server}:{port}")
    return Node(
        name=name,
        scheme="socks",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_http_proxy(link: str) -> Node:
    parsed = urlsplit(link)
    server = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not server:
        raise LinkParseError("invalid http proxy link")

    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    server_item: dict[str, Any] = {
        "address": server,
        "port": port,
    }
    if user:
        server_item["users"] = [{"user": user, "pass": password}]

    outbound = {
        "protocol": "http",
        "settings": {"servers": [server_item]},
    }

    name = _clean_name(parsed.fragment, f"http-{server}:{port}")
    return Node(
        name=name,
        scheme="http",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_json_outbound(text: str) -> Node:
    payload = json.loads(text)

    outbound: dict[str, Any]
    if "protocol" in payload:
        outbound = dict(payload)
    elif isinstance(payload.get("outbounds"), list) and payload["outbounds"]:
        outbound = dict(payload["outbounds"][0])
    else:
        raise LinkParseError("JSON must contain `protocol` or `outbounds`")

    protocol = str(outbound.get("protocol") or "custom")
    tag = str(outbound.get("tag") or protocol)
    server = ""
    port = 0

    settings = outbound.get("settings") or {}
    if protocol in {"vless", "vmess"}:
        vnext = (settings.get("vnext") or [{}])[0]
        server = str(vnext.get("address") or "")
        port = int(vnext.get("port") or 0)
    elif protocol in {"trojan", "shadowsocks", "socks", "http"}:
        servers = (settings.get("servers") or [{}])[0]
        server = str(servers.get("address") or "")
        port = int(servers.get("port") or 0)

    return Node(
        name=f"json-{tag}",
        scheme=protocol,
        server=server,
        port=port,
        link=text,
        outbound=outbound,
    )
