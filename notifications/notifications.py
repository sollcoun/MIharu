"""Notification subsystem.

Providers are intentionally separated from scan/risk logic so Telegram can be
replaced by a central backend, email, webhook, etc. without touching the
security engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


@dataclass(slots=True)
class NotificationResult:
    success: bool
    message: str
    sent: bool = False


class NotificationProvider(Protocol):
    name: str

    def send(self, message: str) -> None:
        ...


class NotificationManager:
    def __init__(self, provider: NotificationProvider | None = None):
        self.provider = provider

    def send_async(
        self,
        message: str,
        on_done: Callable[[NotificationResult], None] | None = None,
    ) -> None:
        if self.provider is None:
            if on_done:
                on_done(NotificationResult(False, "Уведомления не настроены", sent=False))
            return

        import threading

        def run() -> None:
            try:
                self.provider.send(message)
                result = NotificationResult(True, f"{self.provider.name}: отправлено", sent=True)
            except Exception as exc:  # network errors must never break scanning
                result = NotificationResult(False, f"{self.provider.name}: {exc}", sent=False)
            if on_done:
                on_done(result)

        threading.Thread(target=run, name="notification-worker", daemon=True).start()
