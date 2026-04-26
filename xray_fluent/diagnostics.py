from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import zipfile

from .models import AppState


REDACT_KEYS = {
    "id",
    "password",
    "pass",
    "token",
    "publicKey",
    "privateKey",
    "shortId",
    "sid",
    "uuid",
}


def _redact(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if key in REDACT_KEYS:
                redacted[key] = "***"
            else:
                redacted[key] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def export_diagnostics(zip_path: Path, state: AppState, logs: list[str]) -> Path:
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    safe_state = _redact(state.to_dict())
    meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("state_redacted.json", json.dumps(safe_state, ensure_ascii=True, indent=2))
        archive.writestr("meta.json", json.dumps(meta, ensure_ascii=True, indent=2))
        archive.writestr("recent_logs.txt", "\n".join(logs[-2000:]))

    return zip_path
