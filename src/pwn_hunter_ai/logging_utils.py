from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import logging
from pathlib import Path
import re
import shlex
import threading
from typing import Iterator, Sequence


def configure_logging(log_file: Path, log_level: str, verbose: bool) -> None:
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    root_logger.setLevel(logging.DEBUG)

    formatter = _build_formatter()
    context_filter = _AttackLogContextFilter()

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(_resolve_level(log_level))
    file_handler.setFormatter(formatter)
    file_handler.addFilter(context_filter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else _resolve_level(log_level))
    console_handler.setFormatter(formatter)
    console_handler.addFilter(context_filter)

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


_SENSITIVE_OPTION_NAMES = {
    "--github-token",
    "--github-tokens-user-a",
    "--github-tokens-user-b",
    "--gemini-api-key",
}
_SENSITIVE_OPTION_PATTERN = re.compile(r"(token|key|secret|password)", re.IGNORECASE)


def format_command_for_logging(prog: str, argv: Sequence[str]) -> str:
    sanitized_args = _sanitize_command_args(argv)
    return shlex.join([prog, *sanitized_args])


def _sanitize_command_args(argv: Sequence[str]) -> list[str]:
    sanitized: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--":
            sanitized.append(token)
            sanitized.extend(argv[index + 1 :])
            break
        if token.startswith("--"):
            option, separator, _value = token.partition("=")
            if separator and _is_sensitive_option(option):
                sanitized.append(f"{option}=<redacted>")
                index += 1
                continue
            sanitized.append(token)
            if _is_sensitive_option(option) and index + 1 < len(argv):
                sanitized.append("<redacted>")
                index += 2
                continue
            index += 1
            continue
        sanitized.append(token)
        index += 1
    return sanitized


def _is_sensitive_option(option: str) -> bool:
    return option in _SENSITIVE_OPTION_NAMES or bool(
        _SENSITIVE_OPTION_PATTERN.search(option)
    )


@dataclass(slots=True)
class _AttackLogContext:
    worker_id: int
    repository_name: str


_ATTACK_LOG_CONTEXT: ContextVar[_AttackLogContext | None] = ContextVar(
    "attack_log_context",
    default=None,
)


class _AttackLogContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        context = _ATTACK_LOG_CONTEXT.get()
        if context is None:
            record.attack_context_prefix = ""
            record.attack_worker_id = None
            return True

        record.attack_worker_id = context.worker_id
        repository = context.repository_name or "unknown-repository"
        record.attack_context_prefix = (
            f"[worker-{context.worker_id} repo={repository}] "
        )
        return True


class _WorkerLogFilter(logging.Filter):
    def __init__(self, worker_id: int) -> None:
        super().__init__()
        self._worker_id = worker_id

    def filter(self, record: logging.LogRecord) -> bool:
        return getattr(record, "attack_worker_id", None) == self._worker_id


class AttackParallelLogManager:
    def __init__(
        self,
        *,
        base_log_file: Path,
        log_level: str,
        worker_count: int,
    ) -> None:
        self._base_log_file = base_log_file
        self._log_level = log_level
        self._worker_count = max(0, worker_count)
        self._enabled = self._worker_count > 1
        self._root_logger = logging.getLogger()
        self._thread_lock = threading.Lock()
        self._thread_worker_ids: dict[int, int] = {}
        self._next_worker_id = 1
        self._handlers: list[logging.Handler] = []

    def __enter__(self) -> AttackParallelLogManager:
        if not self._enabled:
            return self

        formatter = _build_formatter()
        context_filter = _AttackLogContextFilter()
        for worker_id in range(1, self._worker_count + 1):
            worker_log_file = _derive_worker_log_file(self._base_log_file, worker_id)
            worker_log_file.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(worker_log_file, encoding="utf-8")
            handler.setLevel(_resolve_level(self._log_level))
            handler.setFormatter(formatter)
            handler.addFilter(context_filter)
            handler.addFilter(_WorkerLogFilter(worker_id))
            self._root_logger.addHandler(handler)
            self._handlers.append(handler)
            self._root_logger.info(
                "Parallel attack worker %s log file: %s",
                worker_id,
                worker_log_file,
            )

        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        for handler in self._handlers:
            self._root_logger.removeHandler(handler)
            handler.close()
        self._handlers.clear()

    @contextmanager
    def worker_scope(self, repository_name: str) -> Iterator[int | None]:
        if not self._enabled:
            yield None
            return

        worker_id = self._assign_worker_id_for_current_thread()
        token = _ATTACK_LOG_CONTEXT.set(
            _AttackLogContext(worker_id=worker_id, repository_name=repository_name)
        )
        try:
            yield worker_id
        finally:
            _ATTACK_LOG_CONTEXT.reset(token)

    def _assign_worker_id_for_current_thread(self) -> int:
        thread_id = threading.get_ident()
        with self._thread_lock:
            worker_id = self._thread_worker_ids.get(thread_id)
            if worker_id is not None:
                return worker_id
            worker_id = self._next_worker_id
            self._thread_worker_ids[thread_id] = worker_id
            self._next_worker_id += 1
            if self._next_worker_id > self._worker_count:
                self._next_worker_id = self._worker_count
            return worker_id


def _derive_worker_log_file(base_log_file: Path, worker_id: int) -> Path:
    suffix = base_log_file.suffix
    return base_log_file.with_name(f"{base_log_file.stem}-{worker_id}{suffix}")


def _build_formatter() -> logging.Formatter:
    return logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(attack_context_prefix)s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _resolve_level(log_level: str) -> int:
    return getattr(logging, log_level.upper(), logging.INFO)
