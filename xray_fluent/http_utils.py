"""Shared HTTP utilities with SSL error resilience."""

from __future__ import annotations

import ssl
import urllib.request
from urllib.request import Request


def _make_ssl_context() -> ssl.SSLContext:
    """Create an SSL context tolerant of abrupt server-side connection closes.

    OpenSSL 3.x raises UNEXPECTED_EOF_WHILE_READING when the remote
    doesn't send close_notify.  Setting OP_IGNORE_UNEXPECTED_EOF avoids that.
    """
    ctx = ssl.create_default_context()
    # Available since OpenSSL 3.0 / Python 3.10+
    if hasattr(ssl, "OP_IGNORE_UNEXPECTED_EOF"):
        ctx.options |= ssl.OP_IGNORE_UNEXPECTED_EOF
    return ctx


_ssl_ctx = _make_ssl_context()


def urlopen(request: Request | str, *, timeout: float = 15):
    """Drop-in replacement for urllib.request.urlopen with SSL fix."""
    return urllib.request.urlopen(request, timeout=timeout, context=_ssl_ctx)


def build_opener(*handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    """Build opener that uses the patched SSL context."""
    https_handler = urllib.request.HTTPSHandler(context=_ssl_ctx)
    return urllib.request.build_opener(https_handler, *handlers)
