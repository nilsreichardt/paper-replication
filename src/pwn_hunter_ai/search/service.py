from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
import re
from threading import Lock
import time

from pwn_hunter_ai.github_client import GitHubClient


LOGGER = logging.getLogger(__name__)

_LANG_QUALIFIER_PATTERN = re.compile(r"(?<!\S)lang:(?P<value>[^\s]+)")
_SIZE_QUALIFIER_PATTERN = re.compile(r"(?<!\S)size:")
_EXACT_SIZE_QUALIFIER_PATTERN = re.compile(r"(?<!\S)size:(?P<lower>\d+)\.\.(?P<upper>\d+)")
_DEFAULT_MAX_RESULTS_PER_SHARD = 1000
_PARALLEL_SNAPSHOT_INTERVAL_SECONDS = 5.0


class SearchShardingError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SizeShard:
    base_query: str
    count: int
    lower: int | None = None
    upper: int | None = None

    @property
    def query(self) -> str:
        if self.lower is None or self.upper is None:
            return self.base_query
        return GitHubCodeSearchService._append_size_qualifier(self.base_query, self.lower, self.upper)

    @property
    def is_exact_size(self) -> bool:
        if self.lower is not None and self.upper is not None:
            return self.lower == self.upper
        return has_exact_size_qualifier(self.base_query)


@dataclass(frozen=True, slots=True)
class SearchSnapshot:
    query: str
    min_file_size: int
    max_file_size: int
    max_results_per_shard: int
    brute_force: bool
    count_cache: dict[str, int]
    repositories: list[str]
    pending_shards: list[SizeShard]
    current_shards: list[SizeShard]
    current_shard: SizeShard | None = None
    next_page: int = 1


class GitHubCodeSearchService:
    def __init__(
        self,
        github_client: GitHubClient,
        *,
        min_file_size: int = 0,
        max_file_size: int = 1_000_000,
        max_results_per_shard: int = _DEFAULT_MAX_RESULTS_PER_SHARD,
        brute_force: bool = False,
    ) -> None:
        self._github_client = github_client
        self._min_file_size = min_file_size
        self._max_file_size = max_file_size
        self._max_results_per_shard = max_results_per_shard
        self._brute_force = brute_force
        self._count_cache: dict[str, int] = {}

    def collect_repositories(
        self,
        query: str | None,
        *,
        parallel_jobs: int = 1,
        snapshot_path: Path | None = None,
        resume_snapshot_path: Path | None = None,
    ) -> list[str]:
        snapshot = self._load_snapshot(resume_snapshot_path) if resume_snapshot_path else None
        if snapshot is not None:
            if query is not None:
                normalized_query = normalize_code_search_query(query)
                if normalized_query != snapshot.query:
                    raise SearchShardingError(
                        "The provided query does not match the snapshot query."
                    )
            normalized_query = snapshot.query
            if snapshot.min_file_size != self._min_file_size:
                raise SearchShardingError(
                    "The provided snapshot was created with a different --min-file-size value."
                )
            if snapshot.max_file_size != self._max_file_size:
                raise SearchShardingError(
                    "The provided snapshot was created with a different --max-file-size value."
                )
            if snapshot.max_results_per_shard != self._max_results_per_shard:
                raise SearchShardingError(
                    "The provided snapshot was created with a different "
                    "--max-results-per-shard value."
                )
            if snapshot.brute_force != self._brute_force:
                raise SearchShardingError(
                    "The provided snapshot was created with a different --brute-force setting."
                )
            self._count_cache = dict(snapshot.count_cache)
            shards = deque(snapshot.pending_shards)
            for active_shard in reversed(snapshot.current_shards):
                shards.appendleft(active_shard)
            repositories: set[str] = set(snapshot.repositories)
            current_shard = snapshot.current_shard
            next_page = snapshot.next_page
        else:
            if query is None:
                raise SearchShardingError("A query is required unless --resume-snapshot is provided.")
            normalized_query = normalize_code_search_query(query)
            shards = deque(self._build_shards(normalized_query))
            repositories = set()
            current_shard = None
            next_page = 1

        self._save_snapshot(
            snapshot_path,
            query=normalized_query,
            repositories=repositories,
            pending_shards=shards,
            current_shards=[],
            current_shard=current_shard,
            next_page=next_page,
        )

        if(not self._brute_force):
            LOGGER.info(f"Created {len(shards)} shards for the query: {normalized_query}")
            for shard in shards:
                LOGGER.info(f"Shard: {shard.query} with {shard.count} results")
        LOGGER.info(
            "Starting repository collection with parallel_jobs=%s across %s queued shard(s).",
            parallel_jobs,
            len(shards) + (1 if current_shard is not None else 0),
        )

        if parallel_jobs == 1:
            self._collect_repositories_sequential(
                normalized_query,
                repositories,
                shards,
                current_shard=current_shard,
                next_page=next_page,
                snapshot_path=snapshot_path,
            )
        else:
            self._collect_repositories_parallel(
                normalized_query,
                repositories,
                shards,
                initial_shard=current_shard,
                snapshot_path=snapshot_path,
                parallel_jobs=parallel_jobs,
            )

        if snapshot_path is not None and snapshot_path.exists():
            snapshot_path.unlink()

        return sorted(repositories)

    def _collect_repositories_sequential(
        self,
        query: str,
        repositories: set[str],
        shards: deque[SizeShard],
        *,
        current_shard: SizeShard | None,
        next_page: int,
        snapshot_path: Path | None,
    ) -> None:
        shard_index = 0
        while current_shard is not None or shards:
            shard = current_shard or shards.popleft()
            current_shard = shard
            shard_index += 1
            LOGGER.info(
                "Fetching shard %s/%s with up to %s reported result(s) for %s",
                shard_index,
                shard_index + len(shards),
                shard.count,
                shard.query,
            )
            self._save_snapshot(
                snapshot_path,
                query=query,
                repositories=repositories,
                pending_shards=shards,
                current_shards=[],
                current_shard=current_shard,
                next_page=next_page,
            )
            completed, replacement_shards, next_page = self._fetch_shard_pages(
                shard,
                repositories,
                start_page=next_page,
                snapshot_path=snapshot_path,
                snapshot_query=query,
                pending_shards=shards,
                current_shards=[],
            )
            if replacement_shards is not None:
                shards.extendleft(reversed(replacement_shards))
                current_shard = None
                next_page = 1
                shard_index -= 1
                self._save_snapshot(
                    snapshot_path,
                    query=query,
                    repositories=repositories,
                    pending_shards=shards,
                    current_shards=[],
                    current_shard=None,
                    next_page=next_page,
                )
                continue
            if completed:
                current_shard = None
                next_page = 1
                self._save_snapshot(
                    snapshot_path,
                    query=query,
                    repositories=repositories,
                    pending_shards=shards,
                    current_shards=[],
                    current_shard=None,
                    next_page=next_page,
                )

    def _collect_repositories_parallel(
        self,
        query: str,
        repositories: set[str],
        shards: deque[SizeShard],
        *,
        initial_shard: SizeShard | None,
        snapshot_path: Path | None,
        parallel_jobs: int,
    ) -> None:
        pending_lock = Lock()
        repositories_lock = Lock()
        in_flight: dict[Future[tuple[bool, SizeShard, list[SizeShard] | None]], SizeShard] = {}
        last_snapshot_at = 0.0

        if initial_shard is not None:
            shards.appendleft(initial_shard)

        def save_snapshot(*, force: bool = False) -> None:
            nonlocal last_snapshot_at
            if snapshot_path is None:
                return
            now = time.time()
            if not force and now - last_snapshot_at < _PARALLEL_SNAPSHOT_INTERVAL_SECONDS:
                return
            with pending_lock:
                pending_snapshot = deque(shards)
                active_shards = list(in_flight.values())
            with repositories_lock:
                repositories_snapshot = set(repositories)
            self._save_snapshot(
                snapshot_path,
                query=query,
                repositories=repositories_snapshot,
                pending_shards=pending_snapshot,
                current_shards=active_shards,
                current_shard=None,
                next_page=1,
            )
            last_snapshot_at = now

        def submit_next(executor: ThreadPoolExecutor) -> None:
            with pending_lock:
                if not shards:
                    return
                shard = shards.popleft()
                in_flight[
                    executor.submit(self._fetch_shard_to_completion, shard, repositories, repositories_lock)
                ] = shard
            LOGGER.debug(
                "Submitted shard to worker pool (%s in flight) with up to %s reported result(s) for %s",
                len(in_flight),
                shard.count,
                shard.query,
            )

        with ThreadPoolExecutor(max_workers=parallel_jobs, thread_name_prefix="search-shard") as executor:
            while shards and len(in_flight) < parallel_jobs:
                submit_next(executor)
            save_snapshot(force=True)

            while in_flight:
                completed, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
                for future in completed:
                    in_flight.pop(future)
                    _completed, completed_shard, replacement_shards = future.result()
                    if replacement_shards is not None:
                        with pending_lock:
                            shards.extendleft(reversed(replacement_shards))
                        LOGGER.info(
                            "Restarting shard with %s smaller size range(s) for %s.",
                            len(replacement_shards),
                            completed_shard.query,
                        )
                    save_snapshot()
                    while True:
                        with pending_lock:
                            if not shards or len(in_flight) >= parallel_jobs:
                                break
                        submit_next(executor)
                    save_snapshot()
            save_snapshot(force=True)

    def _fetch_shard_to_completion(
        self,
        shard: SizeShard,
        repositories: set[str],
        repositories_lock: Lock,
    ) -> tuple[bool, SizeShard, list[SizeShard] | None]:
        LOGGER.debug(
            "Worker starting shard with up to %s reported result(s) for %s",
            shard.count,
            shard.query,
        )
        _, replacement_shards, _ = self._fetch_shard_pages(
            shard,
            repositories,
            start_page=1,
            repositories_lock=repositories_lock,
        )
        LOGGER.debug(
            "Worker finished shard for %s%s",
            shard.query,
            f" and queued {len(replacement_shards)} replacement shard(s)" if replacement_shards else "",
        )
        return True, shard, replacement_shards

    def _fetch_shard_pages(
        self,
        shard: SizeShard,
        repositories: set[str],
        *,
        start_page: int,
        snapshot_path: Path | None = None,
        snapshot_query: str | None = None,
        pending_shards: deque[SizeShard] | None = None,
        current_shards: list[SizeShard] | None = None,
        repositories_lock: Lock | None = None,
    ) -> tuple[bool, list[SizeShard] | None, int]:
        for page in range(start_page, 11):
            response = self._github_client.search_code(shard.query, page=page, per_page=100)
            total_count = response.get("total_count")
            if (
                isinstance(total_count, int)
                and total_count > self._max_results_per_shard
                and not shard.is_exact_size
            ):
                replacement_shards = self._split_live_shard(shard, total_count)
                return False, replacement_shards, 1

            items = response.get("items", [])
            page_repository_count = 0
            new_repository_count = 0

            if repositories_lock is None:
                for item in items:
                    repo_name = item.get("repository", {}).get("full_name")
                    if repo_name:
                        page_repository_count += 1
                        if repo_name not in repositories:
                            new_repository_count += 1
                        repositories.add(repo_name)
            else:
                with repositories_lock:
                    for item in items:
                        repo_name = item.get("repository", {}).get("full_name")
                        if repo_name:
                            page_repository_count += 1
                            if repo_name not in repositories:
                                new_repository_count += 1
                            repositories.add(repo_name)

            LOGGER.info(
                "Fetched %s repository entrie(s) from page %s for %s (%s new unique repositories).",
                page_repository_count,
                page,
                shard.query,
                new_repository_count,
            )
            next_page = page + 1
            if snapshot_path is not None and snapshot_query is not None and pending_shards is not None:
                self._save_snapshot(
                    snapshot_path,
                    query=snapshot_query,
                    repositories=repositories,
                    pending_shards=pending_shards,
                    current_shards=current_shards if current_shards is not None else [shard],
                    current_shard=shard,
                    next_page=next_page,
                )
            if len(items) < 100:
                return True, None, 1

        return True, None, 11

    def _build_shards(self, query: str) -> list[SizeShard]:
        if _SIZE_QUALIFIER_PATTERN.search(query):
            if self._brute_force:
                raise SearchShardingError(
                    "--brute-force cannot be used with an explicit size: qualifier."
                )
            total_count = self._search_code_count(query)
            if total_count > self._max_results_per_shard and not has_exact_size_qualifier(query):
                raise SearchShardingError(
                    "Queries with an explicit size: qualifier must already fit within "
                    f"{self._max_results_per_shard} code results."
                )
            return [SizeShard(base_query=query, count=total_count)]

        if self._brute_force:
            return self._build_bruteforce_shards(query)

        total_count = self._search_code_count(query)
        LOGGER.info("GitHub reports %s matching code result(s) for query: %s", total_count, query)
        if total_count == 0:
            return []
        if total_count <= self._max_results_per_shard:
            return [SizeShard(base_query=query, count=total_count)]
        return self._split_range(query, self._min_file_size, self._max_file_size, total_count)

    def _build_bruteforce_shards(self, query: str) -> list[SizeShard]:
        return [
            SizeShard(base_query=query, count=0, lower=size, upper=size)
            for size in range(self._min_file_size, self._max_file_size + 1)
        ]

    def _split_range(
        self,
        query: str,
        lower: int,
        upper: int,
        count: int,
        *,
        refresh_counts: bool = False,
    ) -> list[SizeShard]:
        if count <= self._max_results_per_shard or lower == upper:
            return [SizeShard(base_query=query, count=count, lower=lower, upper=upper)]
        if lower > upper:
            raise SearchShardingError(
                "A single file-size bucket still exceeds GitHub's "
                f"{self._max_results_per_shard}-result limit. "
                "Add more qualifiers to the query so it can be partitioned further."
            )

        midpoint = (lower + upper) // 2
        left_query = self._append_size_qualifier(query, lower, midpoint)
        right_query = self._append_size_qualifier(query, midpoint + 1, upper)
        left_count = self._search_code_count(left_query, refresh=refresh_counts)
        right_count = self._search_code_count(right_query, refresh=refresh_counts)
        LOGGER.info(
            "Split size:%s..%s (%s results) into size:%s..%s (%s) and size:%s..%s (%s).",
            lower,
            upper,
            count,
            lower,
            midpoint,
            left_count,
            midpoint + 1,
            upper,
            right_count,
        )
        return self._split_range(
            query,
            lower,
            midpoint,
            left_count,
            refresh_counts=refresh_counts,
        ) + self._split_range(
            query,
            midpoint + 1,
            upper,
            right_count,
            refresh_counts=refresh_counts,
        )

    def _split_live_shard(self, shard: SizeShard, count: int) -> list[SizeShard]:
        if shard.lower is None or shard.upper is None:
            raise SearchShardingError(
                "GitHub search result count grew beyond 1000 during pagination for a query without a size range. "
                "Add more qualifiers to the query so it can be partitioned further."
            )
        LOGGER.info(
            "Shard count grew from %s to %s during pagination; restarting with smaller size ranges for %s.",
            shard.count,
            count,
            shard.query,
        )
        return self._split_range(shard.base_query, shard.lower, shard.upper, count, refresh_counts=True)

    @staticmethod
    def _append_size_qualifier(query: str, lower: int, upper: int) -> str:
        return f"{query} size:{lower}..{upper}"

    def _search_code_count(self, query: str, *, refresh: bool = False) -> int:
        if not refresh:
            cached = self._count_cache.get(query)
            if cached is not None:
                return cached
        count = self._github_client.search_code_count(query)
        self._count_cache[query] = count
        return count

    def _load_snapshot(self, snapshot_path: Path) -> SearchSnapshot:
        payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
        return SearchSnapshot(
            query=payload["query"],
            min_file_size=int(payload.get("min_file_size", 0)),
            max_file_size=payload["max_file_size"],
            max_results_per_shard=payload.get(
                "max_results_per_shard",
                _DEFAULT_MAX_RESULTS_PER_SHARD,
            ),
            brute_force=bool(payload.get("brute_force", False)),
            count_cache={key: int(value) for key, value in payload.get("count_cache", {}).items()},
            repositories=sorted(set(payload.get("repositories", []))),
            pending_shards=[SizeShard(**shard) for shard in payload.get("pending_shards", [])],
            current_shards=[SizeShard(**shard) for shard in payload.get("current_shards", [])],
            current_shard=(
                SizeShard(**payload["current_shard"])
                if payload.get("current_shard") is not None
                else None
            ),
            next_page=max(int(payload.get("next_page", 1)), 1),
        )

    def _save_snapshot(
        self,
        snapshot_path: Path | None,
        *,
        query: str,
        repositories: set[str],
        pending_shards: deque[SizeShard],
        current_shards: list[SizeShard],
        current_shard: SizeShard | None,
        next_page: int,
    ) -> None:
        if snapshot_path is None:
            return
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "query": query,
            "min_file_size": self._min_file_size,
            "max_file_size": self._max_file_size,
            "max_results_per_shard": self._max_results_per_shard,
            "brute_force": self._brute_force,
            "count_cache": self._count_cache,
            "repositories": sorted(repositories),
            "pending_shards": [asdict(shard) for shard in pending_shards],
            "current_shards": [asdict(shard) for shard in current_shards],
            "current_shard": asdict(current_shard) if current_shard is not None else None,
            "next_page": next_page,
        }
        snapshot_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def normalize_code_search_query(query: str) -> str:
    return _LANG_QUALIFIER_PATTERN.sub(lambda match: f"language:{match.group('value')}", query).strip()


def has_exact_size_qualifier(query: str) -> bool:
    match = _EXACT_SIZE_QUALIFIER_PATTERN.search(query)
    if match is None:
        return False
    return match.group("lower") == match.group("upper")
