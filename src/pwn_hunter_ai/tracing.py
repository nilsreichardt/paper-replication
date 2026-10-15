from __future__ import annotations

import logging
import threading
from typing import Any


LOGGER = logging.getLogger(__name__)
_GOOGLE_GENAI_INSTRUMENTED = False
_GOOGLE_GENAI_INSTRUMENT_LOCK = threading.Lock()


class NoopTracer:
    def flush(self) -> None:
        return None


class LangfuseTracer:
    def __init__(self, public_key: str, secret_key: str, host: str | None = None) -> None:
        try:
            from langfuse import Langfuse
        except ImportError as exc:
            raise RuntimeError(
                "langfuse is not installed. Install project dependencies first."
            ) from exc

        kwargs: dict[str, Any] = {
            "public_key": public_key,
            "secret_key": secret_key,
        }
        if host:
            kwargs["host"] = host
        self._client = Langfuse(**kwargs)
        _instrument_google_genai()

    def flush(self) -> None:
        try:
            self._client.flush()
        except Exception:
            LOGGER.exception("Failed to flush Langfuse traces.")


def _instrument_google_genai() -> None:
    global _GOOGLE_GENAI_INSTRUMENTED
    if _GOOGLE_GENAI_INSTRUMENTED:
        return

    with _GOOGLE_GENAI_INSTRUMENT_LOCK:
        if _GOOGLE_GENAI_INSTRUMENTED:
            return
        try:
            from openinference.instrumentation.google_genai import GoogleGenAIInstrumentor
        except ImportError as exc:
            raise RuntimeError(
                "openinference-instrumentation-google-genai is not installed. "
                "Install project dependencies first."
            ) from exc

        instrumentor = GoogleGenAIInstrumentor()
        try:
            instrumentor.instrument()
        except Exception as exc:
            # Be defensive against double-instrumentation when tests or callers initialize tracing repeatedly.
            if "already instrumented" not in str(exc).lower():
                raise
        _GOOGLE_GENAI_INSTRUMENTED = True


def build_tracer(
    *,
    public_key: str | None,
    secret_key: str | None,
    host: str | None,
):
    if not public_key or not secret_key:
        return NoopTracer()
    return LangfuseTracer(public_key=public_key, secret_key=secret_key, host=host)
