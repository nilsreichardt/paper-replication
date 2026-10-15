from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any

import requests


LOGGER = logging.getLogger(__name__)


class HookbinClient:
    base_url = "http://127.0.0.1:8787"
    api_url = "http://127.0.0.1:8787/api"

    def __init__(self, session: requests.Session | None = None) -> None:
        self.base_url = os.environ.get("PWNHUNTER_HOOKBIN_URL", self.base_url).rstrip("/")
        self.api_url = f"{self.base_url}/api"
        self._session = session or requests.Session()

    def create_bin(self) -> dict[str, str]:
        bin_id = str(uuid.uuid4())[:12]

        return {
            "id": bin_id,
            "url": f"{self.base_url}/{bin_id}",
            "console_url": f"{self.base_url}/console/{bin_id}",
            "api_url": f"{self.api_url}/{bin_id}",
        }

    def get_logs(self, bin_id: str) -> list[dict[str, Any]]:
        try:
            response = self._session.get(f"{self.api_url}/{bin_id}", timeout=10)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            LOGGER.debug(f"Could not fetch logs from {bin_id}")
            return []

        if not response.ok:
            return []

        try:
            data = response.json()
        except ValueError:
            return []

        if isinstance(data, dict):
            logs = data.get("logs") or data.get("items") or []
            if isinstance(logs, list):
                return logs

        return []

    def get_logs_as_text(self, bin_id: str) -> str:
        logs = self.get_logs(bin_id)
        if not logs:
            return ""
        return self._logs_to_text(logs)

    def wait_for_logs_as_text(
        self,
        bin_id: str,
        timeout: float = 300.0,
        poll_interval: float = 5.0,
    ) -> str:
        logs = self.wait_for_logs(
            bin_id=bin_id,
            timeout=timeout,
            poll_interval=poll_interval,
        )
        if not logs:
            return ""
        return self._logs_to_text(logs)

    @staticmethod
    def _logs_to_text(logs: list[Any]) -> str:
        parts: list[str] = []
        for log in logs:
            if isinstance(log, dict):
                body = log.get("body")
                if not body:
                    body = log.get("bodyText")
                if isinstance(body, str):
                    parts.append(body)
                elif isinstance(body, list):
                    parts.append("".join(str(b) for b in body))
            elif isinstance(log, str):
                parts.append(log)

        return "".join(parts)

    def wait_for_logs(
        self,
        bin_id: str,
        timeout: float = 300.0,
        poll_interval: float = 5.0,
    ) -> list[dict[str, Any]]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            logs = self.get_logs(bin_id)
            if logs:
                return logs
            time.sleep(poll_interval)
        return []


class HookbinError(RuntimeError):
    pass
