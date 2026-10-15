from __future__ import annotations

import logging
import json
from urllib import error as urllib_error
from urllib import request as urllib_request


def send_slack_message(
    *,
    webhook_url: str | None,
    message: str,
    logger: logging.Logger | None = None,
) -> bool:
    normalized_webhook_url = (webhook_url or "").strip()
    if not normalized_webhook_url:
        if logger is not None:
            logger.debug(
                "Skipping Slack notification because SLACK_WEBHOOK_URL is not configured."
            )
        return False

    payload_bytes = json.dumps({"text": message}).encode("utf-8")
    request = urllib_request.Request(
        normalized_webhook_url,
        data=payload_bytes,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(request, timeout=10) as response:
            status = getattr(response, "status", None)
            if status is not None and not (200 <= int(status) < 300):
                if logger is not None:
                    logger.warning(
                        "Slack webhook returned unexpected status code %s.", status
                    )
                return False
    except (urllib_error.URLError, ValueError) as exc:
        if logger is not None:
            logger.warning("Failed to send Slack notification: %s", exc)
        return False

    if logger is not None:
        logger.info("Slack notification sent to configured webhook.")
    return True
