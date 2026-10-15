from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Condition, Lock


@dataclass(frozen=True, slots=True)
class AttackTokenLease:
    target_repository: str
    user_a_token: str
    user_b_token: str
    lease_id: int = 0


@dataclass(frozen=True, slots=True)
class AttackTokenQuarantineEvent:
    token_role: str
    token_owner: str | None
    token_display: str
    reason_code: str
    reason: str
    failure_count: int
    repository_name: str
    stage: str


@dataclass(frozen=True, slots=True)
class AttackTokenAvailabilityEvent:
    status: str
    missing_roles: tuple[str, ...]
    user_a_count: int
    user_b_count: int
    trigger: str


class AttackTokenBroker:
    def __init__(
        self,
        *,
        user_a_tokens: list[str],
        user_b_tokens: list[str],
        user_b_max_parallel_per_token: int = 1,
        token_login_resolver: Callable[[str], str | None] | None = None,
        token_quarantine_threshold: int = 3,
        on_token_quarantined: Callable[[AttackTokenQuarantineEvent], None] | None = None,
        on_token_availability_changed: Callable[[AttackTokenAvailabilityEvent], None]
        | None = None,
    ) -> None:
        if not user_a_tokens:
            raise ValueError("At least one User A token is required.")
        if not user_b_tokens:
            raise ValueError("At least one User B token is required.")
        if user_b_max_parallel_per_token < 1:
            raise ValueError("User B token concurrency must be at least 1.")
        if token_quarantine_threshold < 1:
            raise ValueError("Token quarantine threshold must be at least 1.")

        self._user_a_tokens = list(dict.fromkeys(user_a_tokens))
        self._user_b_tokens = list(dict.fromkeys(user_b_tokens))
        if not self._user_b_tokens:
            raise ValueError("At least one unique User B token is required.")
        self._user_b_max_parallel_per_token = user_b_max_parallel_per_token
        self._user_a_index = 0
        self._user_b_index = 0
        self._leased_user_b_token_counts: dict[str, int] = {
            token: 0 for token in self._user_b_tokens
        }
        self._repository_assignments: dict[str, tuple[str, str]] = {}
        self._token_login_resolver = token_login_resolver
        self._token_login_cache: dict[str, str | None] = {}
        self._token_quarantine_threshold = token_quarantine_threshold
        self._on_token_quarantined = on_token_quarantined
        self._on_token_availability_changed = on_token_availability_changed
        self._token_failure_counts: dict[tuple[str, str], int] = {}
        self._quarantined_tokens: set[str] = set()
        self._active_leases: dict[int, AttackTokenLease] = {}
        self._next_lease_id = 1
        self._restart_required_repositories: set[str] = set()
        self._repository_token_exclusions: dict[str, set[str]] = {}
        self._waiting_for_tokens = False
        self._waiting_missing_roles: tuple[str, ...] = ()
        self._lock = Lock()
        self._condition = Condition(self._lock)

    @property
    def user_a_capacity(self) -> int:
        with self._condition:
            return self._eligible_user_a_count_locked()

    @property
    def user_b_capacity(self) -> int:
        with self._condition:
            return (
                self._eligible_user_b_count_locked()
                * self._user_b_max_parallel_per_token
            )

    def reserve(self, target_repository: str) -> AttackTokenLease:
        with self._condition:
            existing_assignment = self._get_active_assignment(target_repository)
            if existing_assignment is not None:
                user_a_token, user_b_token = existing_assignment
                user_b_token = self._wait_for_specific_user_b_token(user_b_token)
                return self._build_lease_locked(
                    target_repository=target_repository,
                    user_a_token=user_a_token,
                    user_b_token=user_b_token,
                )

            excluded_tokens = self._repository_token_exclusions.get(
                target_repository, set()
            )
            user_a_token = self._wait_for_user_a_token(
                excluded_tokens=excluded_tokens,
            )
            user_b_token = self._wait_for_user_b_token(
                excluded_tokens=excluded_tokens,
            )
            self._repository_assignments[target_repository] = (
                user_a_token,
                user_b_token,
            )
            self._repository_token_exclusions.pop(target_repository, None)
            return self._build_lease_locked(
                target_repository=target_repository,
                user_a_token=user_a_token,
                user_b_token=user_b_token,
            )

    def reserve_for_owners(
        self,
        target_repository: str,
        *,
        user_a_owner: str | None = None,
        user_b_owner: str | None = None,
        require_owner_match: bool = False,
    ) -> AttackTokenLease:
        with self._condition:
            existing_assignment = self._get_active_assignment(target_repository)
            if existing_assignment is not None:
                user_a_token, user_b_token = existing_assignment
                if (
                    require_owner_match
                    and user_a_owner
                    and self._token_owner(user_a_token) != user_a_owner
                ):
                    raise RuntimeError(
                        f"Sticky User A token for repository `{target_repository}` does not match required owner `{user_a_owner}`."
                    )
                if (
                    require_owner_match
                    and user_b_owner
                    and self._token_owner(user_b_token) != user_b_owner
                ):
                    raise RuntimeError(
                        f"Sticky User B token for repository `{target_repository}` does not match required owner `{user_b_owner}`."
                    )
                user_b_token = self._wait_for_specific_user_b_token(user_b_token)
                return self._build_lease_locked(
                    target_repository=target_repository,
                    user_a_token=user_a_token,
                    user_b_token=user_b_token,
                )

            excluded_tokens = self._repository_token_exclusions.get(
                target_repository, set()
            )
            user_a_token = self._wait_for_user_a_token(
                preferred_owner=user_a_owner,
                require_owner_match=require_owner_match,
                excluded_tokens=excluded_tokens,
            )

            if (
                require_owner_match
                and user_b_owner
                and not self._has_user_b_token_for_owner(
                    user_b_owner,
                    excluded_tokens=excluded_tokens,
                )
                and self._eligible_user_b_count_locked() > 0
            ):
                raise RuntimeError(
                    f"No available User B token matches required owner `{user_b_owner}`."
                )

            user_b_token = self._wait_for_user_b_token(
                preferred_owner=user_b_owner,
                require_owner_match=require_owner_match,
                excluded_tokens=excluded_tokens,
            )
            self._repository_assignments[target_repository] = (
                user_a_token,
                user_b_token,
            )
            self._repository_token_exclusions.pop(target_repository, None)
            return self._build_lease_locked(
                target_repository=target_repository,
                user_a_token=user_a_token,
                user_b_token=user_b_token,
            )

    def release(self, lease: AttackTokenLease) -> None:
        with self._condition:
            self._active_leases.pop(lease.lease_id, None)
            if lease.user_b_token in self._leased_user_b_token_counts:
                current_count = self._leased_user_b_token_counts[lease.user_b_token]
                if current_count > 0:
                    self._leased_user_b_token_counts[lease.user_b_token] = current_count - 1
            self._condition.notify_all()

    def refresh_tokens(
        self,
        *,
        user_a_tokens: list[str],
        user_b_tokens: list[str],
        trigger: str = "refresh",
    ) -> None:
        availability_event: AttackTokenAvailabilityEvent | None = None
        with self._condition:
            previous_user_a_tokens = set(self._user_a_tokens)
            previous_user_b_tokens = set(self._user_b_tokens)
            next_user_a_tokens = list(dict.fromkeys(user_a_tokens))
            next_user_b_tokens = list(dict.fromkeys(user_b_tokens))
            removed_tokens = (
                previous_user_a_tokens - set(next_user_a_tokens)
            ) | (previous_user_b_tokens - set(next_user_b_tokens))

            self._user_a_tokens = next_user_a_tokens
            self._user_b_tokens = next_user_b_tokens
            self._user_a_index = (
                self._user_a_index % len(self._user_a_tokens)
                if self._user_a_tokens
                else 0
            )
            self._user_b_index = (
                self._user_b_index % len(self._user_b_tokens)
                if self._user_b_tokens
                else 0
            )

            next_counts: dict[str, int] = {}
            for token in self._user_b_tokens:
                next_counts[token] = self._leased_user_b_token_counts.get(token, 0)
            for token, count in self._leased_user_b_token_counts.items():
                if token in next_counts or count <= 0:
                    continue
                next_counts[token] = count
            self._leased_user_b_token_counts = next_counts

            if removed_tokens:
                self._mark_invalidated_repositories_for_tokens_locked(removed_tokens)
            self._drop_unavailable_assignments_locked()
            availability_event = self._update_wait_state_locked(trigger=trigger)
            self._condition.notify_all()

        if (
            availability_event is not None
            and self._on_token_availability_changed is not None
        ):
            self._on_token_availability_changed(availability_event)

    def list_user_b_tokens(self) -> list[str]:
        with self._condition:
            return [
                token
                for token in self._user_b_tokens
                if token not in self._quarantined_tokens
            ]

    def consume_repository_restart_request(self, repository_name: str) -> bool:
        with self._condition:
            if repository_name not in self._restart_required_repositories:
                return False
            self._restart_required_repositories.discard(repository_name)
            return True

    def report_preparation_token_failure(
        self,
        *,
        token: str,
        token_role: str,
        repository_name: str,
        stage: str,
        reason: str,
    ) -> AttackTokenQuarantineEvent | None:
        reason_code = self._classify_token_failure_reason(reason)
        if reason_code is None:
            return None

        availability_event: AttackTokenAvailabilityEvent | None = None
        with self._condition:
            failure_key = (token, reason_code)
            next_count = self._token_failure_counts.get(failure_key, 0) + 1
            self._token_failure_counts[failure_key] = next_count

            if token in self._quarantined_tokens:
                return None

            threshold = (
                1
                if reason_code in {"account_suspended", "bad_credentials"}
                else self._token_quarantine_threshold
            )
            if next_count < threshold:
                return None

            self._quarantined_tokens.add(token)
            self._mark_invalidated_repositories_for_tokens_locked({token})
            token_display = self._mask_token(token)
            event = AttackTokenQuarantineEvent(
                token_role=token_role,
                token_owner=self._token_owner(token),
                token_display=token_display,
                reason_code=reason_code,
                reason=reason,
                failure_count=next_count,
                repository_name=repository_name,
                stage=stage,
            )
            self._drop_unavailable_assignments_locked()
            availability_event = self._update_wait_state_locked(trigger="quarantine")
            self._condition.notify_all()

        if (
            availability_event is not None
            and self._on_token_availability_changed is not None
        ):
            self._on_token_availability_changed(availability_event)
        if self._on_token_quarantined is not None:
            self._on_token_quarantined(event)
        return event

    def _reserve_user_a_token(
        self,
        preferred_owner: str | None = None,
        *,
        excluded_tokens: set[str] | None = None,
    ) -> str | None:
        token_count = len(self._user_a_tokens)
        for offset in range(token_count):
            candidate_index = (self._user_a_index + offset) % token_count
            candidate = self._user_a_tokens[candidate_index]
            if candidate in self._quarantined_tokens:
                continue
            if excluded_tokens and candidate in excluded_tokens:
                continue
            if preferred_owner and self._token_owner(candidate) != preferred_owner:
                continue
            self._user_a_index = (candidate_index + 1) % token_count
            return candidate
        return None

    def _reserve_user_b_token(
        self,
        preferred_owner: str | None = None,
        *,
        excluded_tokens: set[str] | None = None,
    ) -> str | None:
        token_count = len(self._user_b_tokens)
        for offset in range(token_count):
            candidate_index = (self._user_b_index + offset) % token_count
            candidate = self._user_b_tokens[candidate_index]
            if candidate in self._quarantined_tokens:
                continue
            if excluded_tokens and candidate in excluded_tokens:
                continue
            lease_count = self._leased_user_b_token_counts.get(candidate, 0)
            if lease_count >= self._user_b_max_parallel_per_token:
                continue
            if preferred_owner and self._token_owner(candidate) != preferred_owner:
                continue
            self._user_b_index = (candidate_index + 1) % token_count
            self._leased_user_b_token_counts[candidate] = lease_count + 1
            return candidate
        return None

    def _wait_for_user_a_token(
        self,
        *,
        preferred_owner: str | None = None,
        require_owner_match: bool = False,
        excluded_tokens: set[str] | None = None,
    ) -> str:
        while True:
            user_a_token = self._reserve_user_a_token(
                preferred_owner=preferred_owner,
                excluded_tokens=excluded_tokens,
            )
            if user_a_token is not None:
                return user_a_token

            if require_owner_match and preferred_owner:
                if self._eligible_user_a_count_locked() < 1:
                    self._emit_wait_state_locked(trigger="reserve")
                    self._condition.wait()
                    continue
                raise RuntimeError(
                    f"No User A token matches required owner `{preferred_owner}`."
                )

            if self._eligible_user_a_count_locked() < 1:
                self._emit_wait_state_locked(trigger="reserve")
                self._condition.wait()
                continue

            self._condition.wait()

    def _wait_for_user_b_token(
        self,
        *,
        preferred_owner: str | None = None,
        require_owner_match: bool = False,
        excluded_tokens: set[str] | None = None,
    ) -> str:
        while True:
            user_b_token = self._reserve_user_b_token(
                preferred_owner=preferred_owner,
                excluded_tokens=excluded_tokens,
            )
            if user_b_token is not None:
                return user_b_token

            if not require_owner_match:
                fallback = self._reserve_user_b_token(excluded_tokens=excluded_tokens)
                if fallback is not None:
                    return fallback
                if self._eligible_user_b_count_locked() < 1:
                    self._emit_wait_state_locked(trigger="reserve")
            elif not self._has_eligible_user_b_token(
                preferred_owner=preferred_owner,
                excluded_tokens=excluded_tokens,
            ):
                if self._eligible_user_b_count_locked() < 1:
                    self._emit_wait_state_locked(trigger="reserve")
                    self._condition.wait()
                    continue
                raise RuntimeError(
                    "No non-quarantined User B token matches the requested owner."
                )

            self._condition.wait()

    def _reserve_specific_user_b_token(self, token: str) -> str | None:
        if token in self._quarantined_tokens:
            return None
        lease_count = self._leased_user_b_token_counts.get(token)
        if lease_count is None:
            return None
        if lease_count >= self._user_b_max_parallel_per_token:
            return None
        self._leased_user_b_token_counts[token] = lease_count + 1
        return token

    def _wait_for_specific_user_b_token(self, token: str) -> str:
        while True:
            reserved = self._reserve_specific_user_b_token(token)
            if reserved is not None:
                return reserved
            self._condition.wait()

    def _has_user_b_token_for_owner(
        self,
        owner: str,
        *,
        excluded_tokens: set[str] | None = None,
    ) -> bool:
        for token in self._user_b_tokens:
            if token in self._quarantined_tokens:
                continue
            if excluded_tokens and token in excluded_tokens:
                continue
            if self._token_owner(token) == owner:
                return True
        return False

    def _has_eligible_user_b_token(
        self,
        preferred_owner: str | None = None,
        *,
        excluded_tokens: set[str] | None = None,
    ) -> bool:
        for token in self._user_b_tokens:
            if token in self._quarantined_tokens:
                continue
            if excluded_tokens and token in excluded_tokens:
                continue
            if preferred_owner and self._token_owner(token) != preferred_owner:
                continue
            return True
        return False

    def _eligible_user_a_count_locked(self) -> int:
        return sum(
            1 for token in self._user_a_tokens if token not in self._quarantined_tokens
        )

    def _eligible_user_b_count_locked(self) -> int:
        return sum(
            1 for token in self._user_b_tokens if token not in self._quarantined_tokens
        )

    def _token_owner(self, token: str) -> str | None:
        if token in self._token_login_cache:
            return self._token_login_cache[token]
        if self._token_login_resolver is None:
            owner = None
        else:
            owner = self._token_login_resolver(token)
        self._token_login_cache[token] = owner
        return owner

    def _get_active_assignment(self, target_repository: str) -> tuple[str, str] | None:
        assignment = self._repository_assignments.get(target_repository)
        if assignment is None:
            return None
        user_a_token, user_b_token = assignment
        if not self._assignment_is_active_locked(
            target_repository,
            user_a_token,
            user_b_token,
        ):
            self._repository_assignments.pop(target_repository, None)
            return None
        return assignment

    def _assignment_is_active_locked(
        self,
        repository_name: str,
        user_a_token: str,
        user_b_token: str,
    ) -> bool:
        excluded_tokens = self._repository_token_exclusions.get(repository_name, set())
        if user_a_token in self._quarantined_tokens or user_b_token in self._quarantined_tokens:
            return False
        if excluded_tokens and (
            user_a_token in excluded_tokens or user_b_token in excluded_tokens
        ):
            return False
        if user_a_token not in self._user_a_tokens or user_b_token not in self._user_b_tokens:
            return False
        return True

    def _drop_unavailable_assignments_locked(self) -> None:
        active_assignments: dict[str, tuple[str, str]] = {}
        for repo_name, assignment in self._repository_assignments.items():
            user_a_token, user_b_token = assignment
            if not self._assignment_is_active_locked(
                repo_name,
                user_a_token,
                user_b_token,
            ):
                continue
            active_assignments[repo_name] = assignment
        self._repository_assignments = active_assignments

    def _build_lease_locked(
        self,
        *,
        target_repository: str,
        user_a_token: str,
        user_b_token: str,
    ) -> AttackTokenLease:
        lease = AttackTokenLease(
            target_repository=target_repository,
            user_a_token=user_a_token,
            user_b_token=user_b_token,
            lease_id=self._next_lease_id,
        )
        self._active_leases[lease.lease_id] = lease
        self._next_lease_id += 1
        return lease

    def _mark_invalidated_repositories_for_tokens_locked(self, tokens: set[str]) -> None:
        if not tokens:
            return
        for lease in self._active_leases.values():
            if lease.user_a_token not in tokens and lease.user_b_token not in tokens:
                continue
            self._restart_required_repositories.add(lease.target_repository)
            exclusions = self._repository_token_exclusions.setdefault(
                lease.target_repository, set()
            )
            exclusions.update({lease.user_a_token, lease.user_b_token})

    def _emit_wait_state_locked(self, *, trigger: str) -> None:
        event = self._update_wait_state_locked(trigger=trigger)
        if (
            event is not None
            and self._on_token_availability_changed is not None
        ):
            self._on_token_availability_changed(event)

    def _update_wait_state_locked(
        self,
        *,
        trigger: str,
    ) -> AttackTokenAvailabilityEvent | None:
        missing_roles: list[str] = []
        if self._eligible_user_a_count_locked() < 1:
            missing_roles.append("user_a")
        if self._eligible_user_b_count_locked() < 1:
            missing_roles.append("user_b")
        normalized_missing_roles = tuple(missing_roles)
        if normalized_missing_roles:
            if (
                self._waiting_for_tokens
                and self._waiting_missing_roles == normalized_missing_roles
            ):
                return None
            self._waiting_for_tokens = True
            self._waiting_missing_roles = normalized_missing_roles
            return AttackTokenAvailabilityEvent(
                status="waiting",
                missing_roles=normalized_missing_roles,
                user_a_count=self._eligible_user_a_count_locked(),
                user_b_count=self._eligible_user_b_count_locked(),
                trigger=trigger,
            )

        if not self._waiting_for_tokens:
            return None
        self._waiting_for_tokens = False
        self._waiting_missing_roles = ()
        return AttackTokenAvailabilityEvent(
            status="recovered",
            missing_roles=(),
            user_a_count=self._eligible_user_a_count_locked(),
            user_b_count=self._eligible_user_b_count_locked(),
            trigger=trigger,
        )

    @staticmethod
    def _classify_token_failure_reason(reason: str) -> str | None:
        lowered = reason.lower()
        if "sorry. your account was suspended" in lowered:
            return "account_suspended"
        if "bad credentials" in lowered:
            return "bad_credentials"
        if "you cannot fork this repository at this time" in lowered:
            return "fork_denied"
        return None

    @staticmethod
    def _mask_token(token: str) -> str:
        if len(token) <= 8:
            return "*" * len(token)
        return f"{token[:4]}...{token[-4:]}"
