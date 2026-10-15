from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnhunter",
        description="PwnHunter CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    ai_enumerate_parser = subparsers.add_parser(
        "ai-enumerate",
        help="Verify pull_request_target Pwn Request risks with GitHub API context and Gemini.",
        description="Verify pull_request_target Pwn Request risks with GitHub API context and Gemini.",
    )
    ai_enumerate_parser.add_argument(
        "--input", required=True, help="Path to the input enumeration JSON file."
    )
    ai_enumerate_parser.add_argument(
        "--output", required=True, help="Path to the output JSON file."
    )
    ai_enumerate_parser.add_argument(
        "--failure-output",
        help="Path to the restart JSON file containing only repositories that failed preparation or AI analysis. Defaults to <output>.failures.json.",
    )
    ai_enumerate_parser.add_argument(
        "--parallel-jobs",
        type=int,
        default=3,
        help="Number of repositories to analyze in parallel. Defaults to 3.",
    )
    ai_enumerate_parser.add_argument(
        "--github-token",
        help="GitHub token(s), comma-separated. Defaults to GITHUB_TOKEN from the environment or .env.",
    )
    ai_enumerate_parser.add_argument(
        "--gemini-api-key",
        help="Gemini API key. Defaults to GEMINI_API_KEY from the environment or .env.",
    )
    ai_enumerate_parser.add_argument(
        "--gemini-batch",
        action="store_true",
        help="Use the Gemini Batch API for analysis. Only enabled when this flag is passed.",
    )
    ai_enumerate_parser.add_argument(
        "--output-only-vulnerable",
        action="store_true",
        help="Only output repositories and risks classified as vulnerable.",
    )
    ai_enumerate_parser.add_argument(
        "--log-file",
        default="ai-enumerate.log",
        help="Path to the log file. Defaults to ai-enumerate.log.",
    )
    ai_enumerate_parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level for file and console output. Defaults to INFO.",
    )
    ai_enumerate_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    search_parser = subparsers.add_parser(
        "search",
        help="Run GitHub code search and write the matching repositories to a file.",
        description="Run GitHub code search, shard past GitHub's 1000-result cap, and write unique repositories to a file.",
    )
    search_parser.add_argument(
        "query",
        nargs="?",
        help='GitHub code search query, for example: "pull_request_target path:.github/workflows lang:yaml".',
    )
    search_parser.add_argument(
        "--output",
        required=True,
        help="Path to the output text file.",
    )
    search_parser.add_argument(
        "--github-token",
        help="GitHub token(s), comma-separated. Defaults to GITHUB_TOKEN from the environment or .env.",
    )
    search_parser.add_argument(
        "--parallel-jobs",
        type=int,
        default=1,
        help="Number of search shards to fetch in parallel. Defaults to 1.",
    )
    search_parser.add_argument(
        "--min-file-size",
        type=int,
        default=0,
        help="Lower bound used for size-based search partitioning. Defaults to 0 bytes.",
    )
    search_parser.add_argument(
        "--max-file-size",
        type=int,
        default=1_000_000,
        help="Upper bound used for automatic size-based sharding. Defaults to 1000000 bytes.",
    )
    search_parser.add_argument(
        "--brute-force",
        action="store_true",
        help="Bypass recursive sharding and search every file size from --min-file-size to --max-file-size one byte at a time.",
        default=False,
    )
    search_parser.add_argument(
        "--max-results-per-shard",
        type=int,
        default=1_000,
        help="Maximum reported GitHub results allowed in a shard before further splitting. Defaults to 1000.",
    )
    search_parser.add_argument(
        "--snapshot-file",
        help="Path to a snapshot JSON file used to persist progress during a search run.",
    )
    search_parser.add_argument(
        "--resume-snapshot",
        help="Resume a previous search run from the given snapshot JSON file.",
    )
    search_parser.add_argument(
        "--log-file",
        default="search.log",
        help="Path to the log file. Defaults to search.log.",
    )
    search_parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level for file and console output. Defaults to INFO.",
    )
    search_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    attack_parser = subparsers.add_parser(
        "attack",
        help="Prepare owned forks and metadata for manual vulnerability validation.",
        description="Prepare owned forks and metadata for manual vulnerability validation.",
    )
    attack_parser.add_argument(
        "--input",
        required=True,
        help=(
            "Path to the attack input JSON file. Supports ai-enumerate output JSON "
            "and raw gato-x enumeration JSON."
        ),
    )
    attack_parser.add_argument(
        "--output", required=True, help="Path to the output JSON file."
    )
    attack_parser.add_argument(
        "--artifacts-dir",
        default="attack-artifacts",
        help="Directory for cloned workspaces and attack handoff artifacts. Defaults to attack-artifacts.",
    )
    attack_parser.add_argument(
        "--skip",
        help="Comma-separated repository full names to skip, for example OWNER1/REPO1,OWNER2/REPO2.",
    )
    attack_parser.add_argument(
        "--learning-file",
        help="Path to an existing LEARNING.md/LEARNINGS.md file to seed run-level learnings. Defaults to ./LEARNING.md when present.",
    )
    attack_parser.add_argument(
        "--agent-provider",
        choices=("openhands", "gemini-cli"),
        default="gemini-cli",
        help="AI agent provider for attack execution. Defaults to gemini-cli.",
    )
    attack_parser.add_argument(
        "--agent-model",
        default="gemini-3-flash-preview",
        help="Provider model for Gemini CLI. Defaults to gemini-3-flash-preview.",
    )
    attack_parser.add_argument(
        "--parallel-jobs",
        type=int,
        default=1,
        help="Number of repositories to prepare in parallel. Defaults to 1.",
    )
    attack_parser.add_argument(
        "--max-retries",
        type=int,
        default=5,
        help="Maximum number of supervised retries to plan for. Defaults to 5.",
    )
    attack_parser.add_argument(
        "--github-tokens-user-a",
        help="User A GitHub token(s), comma-separated. Defaults to GITHUB_TOKENS_USER_A.",
    )
    attack_parser.add_argument(
        "--github-tokens-user-b",
        help="User B GitHub token(s), comma-separated. Defaults to GITHUB_TOKENS_USER_B.",
    )
    attack_parser.add_argument(
        "--user-b-token-concurrency",
        type=int,
        default=1,
        help="Maximum number of concurrent repositories per User B token. Defaults to 1.",
    )
    attack_parser.add_argument(
        "--reset-forks",
        action="store_true",
        help="Delete existing forks before recreating them.",
    )
    attack_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Prepare local artifacts without launching optional external helpers.",
    )
    attack_parser.add_argument(
        "--launch-agent",
        action="store_true",
        help="Attempt to launch the selected agent runtime for the prepared workspace.",
    )
    attack_parser.add_argument(
        "--auto-execute",
        action="store_true",
        help="Automatically run the full attack loop: run agent, commit, create PR, monitor workflow, and check hookbin.",
    )
    attack_parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Compatibility flag only. Host-only mode is always enabled.",
    )
    attack_parser.add_argument(
        "--agent-timeout",
        type=int,
        default=1500,
        help="Timeout in seconds for selected agent to complete. Defaults to 1500 (25 minutes).",
    )
    attack_parser.add_argument(
        "--workflow-timeout",
        type=int,
        default=3600,
        help="Timeout in seconds to wait for GitHub Actions workflow. Defaults to 3600 (1 hour).",
    )
    attack_parser.add_argument(
        "--skip-permission-log-read",
        action="store_true",
        help="Skip reading existing workflow logs for default GITHUB_TOKEN permission detection before opening a probe PR.",
    )
    attack_parser.add_argument(
        "--delete-workspace-after-processing",
        action="store_true",
        help="Delete the cloned workspace directory after each repository is processed, while keeping other attack artifacts.",
    )
    attack_parser.add_argument(
        "--openhands-host",
        default="127.0.0.1",
        help="Host for the optional OpenHands local server. Defaults to 127.0.0.1.",
    )
    attack_parser.add_argument(
        "--openhands-start-port",
        type=int,
        default=3000,
        help="Starting port for optional OpenHands local servers. Defaults to 3000.",
    )
    attack_parser.add_argument(
        "--gemini-api-key",
        help="Gemini API key for human review pre-check before attack execution. Defaults to GEMINI_API_KEY.",
    )
    attack_parser.add_argument(
        "--billing",
        choices=("oauth", "api"),
        default="oauth",
        help=(
            "Billing mode for Gemini usage during attack auto-execute. "
            "Use oauth (default) to use signed-in Gemini CLI account, or api to use API key billing."
        ),
    )
    attack_parser.add_argument(
        "--generate-security-report",
        action="store_true",
        help=(
            "Ask the controller to run a report follow-up that creates REPORT.md and "
            "persists it under security-reports. Disabled by default."
        ),
    )
    attack_parser.add_argument(
        "--log-file",
        default="attack.log",
        help="Path to the merged log file. Defaults to attack.log. When attack parallel workers are used, per-worker logs are also written as <stem>-<worker>.log.",
    )
    attack_parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level for file and console output. Defaults to INFO.",
    )
    attack_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    attack_cleanup_parser = subparsers.add_parser(
        "attack-cleanup",
        help="Delete prepared forks and/or local attack artifacts from a previous attack output file.",
        description="Delete prepared forks and/or local attack artifacts from a previous attack output file.",
    )
    attack_cleanup_parser.add_argument(
        "--input", required=True, help="Path to the prepared attack JSON file."
    )
    attack_cleanup_parser.add_argument(
        "--github-token",
        help="GitHub token used for cleanup. Defaults to the first token in GITHUB_TOKENS_USER_A.",
    )
    attack_cleanup_parser.add_argument(
        "--delete-forks",
        action="store_true",
        help="Delete User A and User B forks recorded in the attack output.",
    )
    attack_cleanup_parser.add_argument(
        "--delete-artifacts",
        action="store_true",
        help="Delete local artifact directories recorded in the attack output.",
    )
    attack_cleanup_parser.add_argument(
        "--log-file",
        default="attack-cleanup.log",
        help="Path to the log file. Defaults to attack-cleanup.log.",
    )
    attack_cleanup_parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level for file and console output. Defaults to INFO.",
    )
    attack_cleanup_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    pr_target_history_parser = subparsers.add_parser(
        "pr-target-history",
        help="Scan recent commits and report workflow-file removals of pull_request_target.",
        description="Read a text file of repositories, inspect commits from the last N days, and write a JSON report for workflow files where pull_request_target was removed.",
    )
    pr_target_history_parser.add_argument(
        "--input",
        required=True,
        help="Path to a text file containing one repository per line.",
    )
    pr_target_history_parser.add_argument(
        "--output",
        required=True,
        help="Path to the output JSON report.",
    )
    pr_target_history_parser.add_argument(
        "--days",
        type=int,
        required=True,
        help="Number of days of commit history to scan.",
    )
    pr_target_history_parser.add_argument(
        "--parallel-jobs",
        type=int,
        default=1,
        help="Number of repositories to analyze in parallel. Defaults to 1.",
    )
    pr_target_history_parser.add_argument(
        "--github-token",
        help="GitHub token(s), comma-separated. Defaults to GITHUB_TOKEN from the environment or .env.",
    )
    pr_target_history_parser.add_argument(
        "--log-file",
        default="pr-target-history.log",
        help="Path to the log file. Defaults to pr-target-history.log.",
    )
    pr_target_history_parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level for file and console output. Defaults to INFO.",
    )
    pr_target_history_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    review_parser = subparsers.add_parser(
        "review",
        help="Start a local website to review AI analysis and referenced workflows.",
        description="Start a local website to review AI analysis and referenced workflows.",
    )
    review_parser.add_argument(
        "--input",
        required=True,
        help="Path to the review JSON file. Supports ai-enumerate output, attack output, and enumeration input.",
    )
    review_parser.add_argument(
        "--github-token",
        help="GitHub token(s), comma-separated. Defaults to GITHUB_TOKEN from the environment or .env.",
    )
    review_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface for the local web server. Defaults to 127.0.0.1.",
    )
    review_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for the local web server. Defaults to 8765.",
    )
    review_parser.add_argument(
        "--log-file",
        default="review.log",
        help="Path to the log file. Defaults to review.log.",
    )
    review_parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level for file and console output. Defaults to INFO.",
    )
    review_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    return parser
