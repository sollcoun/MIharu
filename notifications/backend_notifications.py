"""Central notification backend provider.

The client sends only an alert event. The shared Telegram bot token remains
on the server. This module is intentionally small so the backend contract can
be versioned independently from the scanner.
"""
from __future__ import annotations

import json
import os
import platform
import urllib.error
import urllib.request
from typing import Any

from installation import get_installation_id


class BackendNotificationError(RuntimeError):
    pass


class BackendNotificationProvider:
    name = "Notification backend"

    def __init__(self, base_url: str | None = None, enrollment_token: str | None = None):
        self.base_url = (base_url or os.environ.get("DISK_DIAGNOSTIC_BACKEND_URL", "")).strip().rstrip("/")
        self.enrollment_token = (enrollment_token or os.environ.get("DISK_DIAGNOSTIC_ENROLLMENT_TOKEN", "")).strip()
        if not self.base_url:
            raise BackendNotificationError("Backend URL не настроен")

    def send(self, message: str) -> None:
        payload: dict[str, Any] = {
            "schema_version": 1,
            "installation_id": get_installation_id(),
            "event_type": "security_alert",
            "message": message,
            "platform": "windows",
            "hostname": platform.node() or None,
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "Miharu/1"}
        if self.enrollment_token:
            headers["Authorization"] = f"Bearer {self.enrollment_token}"
        request = urllib.request.Request(
            f"{self.base_url}/api/v1/notifications/events",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                body = response.read().decode("utf-8", errors="replace")
                if response.status < 200 or response.status >= 300:
                    raise BackendNotificationError(f"Backend HTTP {response.status}")
                if body:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict) and parsed.get("ok") is False:
                        raise BackendNotificationError(str(parsed.get("error") or "Backend rejected event"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise BackendNotificationError(f"Backend HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BackendNotificationError(f"Backend connection error: {exc}") from exc
        except ValueError as exc:
            raise BackendNotificationError("Backend вернул некорректный JSON") from exc