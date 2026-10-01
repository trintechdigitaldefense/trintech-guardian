"""
Alerting module for TrinTech-Guardian.
Webhook + Telegram with basic rate limiting to avoid spam.
"""

import json
import time
import urllib.request
from typing import Optional, Dict, Any


class AlertDispatcher:
    """Sends threat alerts via webhook and/or Telegram with rate limiting."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        telegram_bot_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
        enabled: bool = True,
        min_interval_seconds: int = 30,
        max_per_hour: int = 40,
    ):
        self.webhook_url = webhook_url
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        self.enabled = enabled
        self.min_interval_seconds = min_interval_seconds
        self.max_per_hour = max_per_hour
        self._last_sent: Dict[str, float] = {}
        self._hour_bucket: list = []

    def _allow(self, key: str) -> bool:
        now = time.time()
        last = self._last_sent.get(key, 0)
        if now - last < self.min_interval_seconds:
            return False
        self._hour_bucket = [t for t in self._hour_bucket if now - t < 3600]
        if len(self._hour_bucket) >= self.max_per_hour:
            print("[ALERT] Hourly rate limit reached — suppressing alert")
            return False
        return True

    def _mark_sent(self, key: str) -> None:
        now = time.time()
        self._last_sent[key] = now
        self._hour_bucket.append(now)

    def send(
        self,
        title: str,
        body: str,
        severity: str = "HIGH",
        extra: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not self.enabled:
            return False
        key = f"{severity}:{title}:{(extra or {}).get('attacker_ip', '')}"
        if not self._allow(key):
            return False
        ok = False
        payload = {
            "title": title,
            "body": body,
            "severity": severity,
            "source": "TrinTech-Guardian",
            "extra": extra or {},
        }
        if self.webhook_url and self._post_webhook(payload):
            ok = True
        if self.telegram_bot_token and self.telegram_chat_id:
            text = self._format_telegram(title, body, severity, extra)
            if self._post_telegram(text):
                ok = True
        if ok:
            self._mark_sent(key)
        return ok

    def _post_webhook(self, payload: dict) -> bool:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "TrinTech-Guardian/1.3"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            print(f"[ALERT] Webhook failed: {e}")
            return False

    def _post_telegram(self, text: str) -> bool:
        try:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            data = json.dumps({
                "chat_id": self.telegram_chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            print(f"[ALERT] Telegram failed: {e}")
            return False

    def _format_telegram(self, title, body, severity, extra) -> str:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "NORMAL": "🟢"}.get(severity, "⚠️")
        lines = [f"{icon} <b>{title}</b>", f"<b>Severity:</b> {severity}", body]
        if extra:
            for k, v in extra.items():
                lines.append(f"<b>{k}:</b> {v}")
        lines.append("\n<code>TrinTech-Guardian</code>")
        return "\n".join(lines)

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "webhook_configured": bool(self.webhook_url),
            "telegram_configured": bool(self.telegram_bot_token and self.telegram_chat_id),
            "min_interval_seconds": self.min_interval_seconds,
            "max_per_hour": self.max_per_hour,
            "sent_last_hour": len(self._hour_bucket),
        }
