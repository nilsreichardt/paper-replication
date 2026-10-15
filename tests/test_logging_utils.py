from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import logging
import threading

from pwn_hunter_ai.logging_utils import (
    AttackParallelLogManager,
    configure_logging,
    format_command_for_logging,
)


def test_attack_parallel_log_manager_writes_merged_and_worker_logs(tmp_path: Path) -> None:
    main_log = tmp_path / "attack.log"
    configure_logging(main_log, "INFO", verbose=False)
    logger = logging.getLogger("tests.parallel-logging")
    barrier = threading.Barrier(2)

    with AttackParallelLogManager(
        base_log_file=main_log,
        log_level="INFO",
        worker_count=2,
    ) as log_manager:

        def _emit(repository_name: str) -> None:
            with log_manager.worker_scope(repository_name):
                barrier.wait(timeout=5)
                logger.info("processing repository")

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(_emit, "owner/repo-a"),
                executor.submit(_emit, "owner/repo-b"),
            ]
            for future in futures:
                future.result()

    merged_content = main_log.read_text(encoding="utf-8")
    assert "[worker-" in merged_content
    assert "repo=owner/repo-a" in merged_content
    assert "repo=owner/repo-b" in merged_content
    assert "processing repository" in merged_content

    worker_1_log = tmp_path / "attack-1.log"
    worker_2_log = tmp_path / "attack-2.log"
    assert worker_1_log.exists()
    assert worker_2_log.exists()

    worker_combined = worker_1_log.read_text(encoding="utf-8") + worker_2_log.read_text(
        encoding="utf-8"
    )
    assert "repo=owner/repo-a" in worker_combined
    assert "repo=owner/repo-b" in worker_combined


def test_format_command_for_logging_redacts_sensitive_values() -> None:
    rendered = format_command_for_logging(
        "pwnhunter",
        [
            "ai-enumerate",
            "--input",
            "input.json",
            "--gemini-api-key",
            "real-key",
            "--github-token=ghp_secret",
            "--parallel-jobs",
            "4",
        ],
    )
    assert "--gemini-api-key '<redacted>'" in rendered
    assert "--github-token=<redacted>" in rendered
    assert "real-key" not in rendered
    assert "ghp_secret" not in rendered
