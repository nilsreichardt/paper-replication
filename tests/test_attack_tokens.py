import threading
import time

import pytest

from pwn_hunter_ai.attack.tokens import (
    AttackTokenAvailabilityEvent,
    AttackTokenBroker,
    AttackTokenQuarantineEvent,
)


def test_attack_token_broker_reuses_user_a_and_exclusively_leases_user_b() -> None:
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1", "token-b2"],
    )

    lease_one = broker.reserve("owner/repo-one")
    lease_two = broker.reserve("owner/repo-two")

    assert lease_one.user_a_token == "token-a1"
    assert lease_two.user_a_token == "token-a2"
    assert lease_one.user_b_token == "token-b1"
    assert lease_two.user_b_token == "token-b2"

    broker.release(lease_one)
    lease_three = broker.reserve("owner/repo-three")

    assert lease_three.user_b_token == "token-b1"


def test_attack_token_broker_rotates_user_a_tokens_with_wraparound() -> None:
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1"],
    )

    observed: list[str] = []
    for index in range(5):
        lease = broker.reserve(f"owner/repo-a-{index}")
        observed.append(lease.user_a_token)
        broker.release(lease)

    assert observed == ["token-a1", "token-a2", "token-a1", "token-a2", "token-a1"]


def test_attack_token_broker_rotates_user_b_tokens_across_sequential_reservations() -> None:
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1"],
        user_b_tokens=["token-b1", "token-b2", "token-b3"],
    )

    observed: list[str] = []
    for index in range(6):
        lease = broker.reserve(f"owner/repo-{index}")
        observed.append(lease.user_b_token)
        broker.release(lease)

    assert observed == [
        "token-b1",
        "token-b2",
        "token-b3",
        "token-b1",
        "token-b2",
        "token-b3",
    ]


def test_attack_token_broker_reserve_for_owners_picks_matching_tokens() -> None:
    owners = {
        "token-a1": "owner-a1",
        "token-a2": "owner-a2",
        "token-b1": "owner-b1",
        "token-b2": "owner-b2",
    }
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1", "token-b2"],
        token_login_resolver=lambda token: owners.get(token),
    )

    lease = broker.reserve_for_owners(
        "owner/repo",
        user_a_owner="owner-a2",
        user_b_owner="owner-b2",
        require_owner_match=True,
    )

    assert lease.user_a_token == "token-a2"
    assert lease.user_b_token == "token-b2"


def test_attack_token_broker_keeps_sticky_tokens_for_same_repository() -> None:
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1", "token-b2"],
    )

    first = broker.reserve("owner/repo")
    broker.release(first)

    second = broker.reserve("owner/repo")
    broker.release(second)

    assert second.user_a_token == first.user_a_token
    assert second.user_b_token == first.user_b_token

    other_repo = broker.reserve("owner/repo-other")
    broker.release(other_repo)

    assert other_repo.user_a_token != first.user_a_token
    assert other_repo.user_b_token != first.user_b_token


def test_attack_token_broker_sticky_tokens_survive_owner_based_reservations() -> None:
    owners = {
        "token-a1": "owner-a",
        "token-a2": "owner-a",
        "token-b1": "owner-b",
        "token-b2": "owner-b",
    }
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1", "token-b2"],
        token_login_resolver=lambda token: owners.get(token),
    )

    first = broker.reserve("owner/repo")
    broker.release(first)

    second = broker.reserve_for_owners(
        "owner/repo",
        user_a_owner="owner-a",
        user_b_owner="owner-b",
        require_owner_match=True,
    )
    broker.release(second)

    assert second.user_a_token == first.user_a_token
    assert second.user_b_token == first.user_b_token


def test_attack_token_broker_allows_parallel_leases_on_same_user_b_token() -> None:
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1"],
        user_b_max_parallel_per_token=2,
    )

    lease_one = broker.reserve("owner/repo-one")
    lease_two = broker.reserve("owner/repo-two")

    assert lease_one.user_b_token == "token-b1"
    assert lease_two.user_b_token == "token-b1"

    broker.release(lease_one)
    broker.release(lease_two)


def test_attack_token_broker_waits_for_available_user_b_slot() -> None:
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1"],
        user_b_tokens=["token-b1"],
        user_b_max_parallel_per_token=1,
    )
    first_lease = broker.reserve("owner/repo-one")
    started = threading.Event()
    acquired = threading.Event()
    observed: dict[str, str] = {}

    def _reserve_second() -> None:
        started.set()
        lease = broker.reserve("owner/repo-two")
        observed["token"] = lease.user_b_token
        broker.release(lease)
        acquired.set()

    thread = threading.Thread(target=_reserve_second, daemon=True)
    thread.start()

    assert started.wait(timeout=1.0)
    time.sleep(0.1)
    assert not acquired.is_set()

    broker.release(first_lease)

    assert acquired.wait(timeout=1.0)
    assert observed["token"] == "token-b1"
    thread.join(timeout=1.0)


def test_attack_token_broker_quarantines_token_after_repeated_fork_denials() -> None:
    events: list[AttackTokenQuarantineEvent] = []
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1"],
        token_login_resolver=lambda token: {
            "token-a1": "owner-a1",
            "token-a2": "owner-a2",
            "token-b1": "owner-b1",
        }.get(token),
        on_token_quarantined=events.append,
    )

    event = None
    for index in range(3):
        event = broker.report_preparation_token_failure(
            token="token-a1",
            token_role="user_a",
            repository_name=f"owner/repo-{index}",
            stage="ensure_user_a_fork",
            reason="GitHub API request failed for /repos/owner/repo/forks: 403 You cannot fork this repository at this time",
        )

    assert event is not None
    assert event.token_role == "user_a"
    assert event.token_owner == "owner-a1"
    assert event.reason_code == "fork_denied"
    assert event.failure_count == 3
    assert len(events) == 1

    lease = broker.reserve("owner/repo-next")
    broker.release(lease)

    assert lease.user_a_token == "token-a2"


def test_attack_token_broker_quarantines_suspended_token_immediately() -> None:
    events: list[AttackTokenQuarantineEvent] = []
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1"],
        user_b_tokens=["token-b1", "token-b2"],
        token_login_resolver=lambda token: {
            "token-a1": "owner-a1",
            "token-b1": "owner-b1",
            "token-b2": "owner-b2",
        }.get(token),
        on_token_quarantined=events.append,
    )

    event = broker.report_preparation_token_failure(
        token="token-b1",
        token_role="user_b",
        repository_name="owner/repo",
        stage="get_authenticated_user",
        reason="GitHub API request failed for /user: 403 Sorry. Your account was suspended",
    )

    assert event is not None
    assert event.reason_code == "account_suspended"
    assert event.failure_count == 1
    assert len(events) == 1

    lease = broker.reserve("owner/repo-next")
    broker.release(lease)

    assert lease.user_b_token == "token-b2"


def test_attack_token_broker_quarantines_bad_credentials_immediately() -> None:
    events: list[AttackTokenQuarantineEvent] = []
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1"],
        token_login_resolver=lambda token: {
            "token-a1": "owner-a1",
            "token-a2": "owner-a2",
            "token-b1": "owner-b1",
        }.get(token),
        on_token_quarantined=events.append,
    )

    event = broker.report_preparation_token_failure(
        token="token-a1",
        token_role="user_a",
        repository_name="owner/repo",
        stage="get_repo_metadata",
        reason="GitHub API request failed for /repos/owner/repo: 401 Bad credentials",
    )

    assert event is not None
    assert event.reason_code == "bad_credentials"
    assert event.failure_count == 1
    assert len(events) == 1

    lease = broker.reserve("owner/repo-next")
    broker.release(lease)

    assert lease.user_a_token == "token-a2"


def test_attack_token_broker_marks_repository_for_restart_when_refresh_removes_active_tokens() -> None:
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1", "token-a2"],
        user_b_tokens=["token-b1", "token-b2"],
    )
    lease = broker.reserve("owner/repo")

    broker.refresh_tokens(
        user_a_tokens=["token-a2"],
        user_b_tokens=["token-b2"],
        trigger="test_refresh",
    )

    assert broker.consume_repository_restart_request("owner/repo") is True
    broker.release(lease)

    replacement = broker.reserve("owner/repo")
    broker.release(replacement)

    assert replacement.user_a_token == "token-a2"
    assert replacement.user_b_token == "token-b2"


def test_attack_token_broker_waits_for_refresh_when_all_user_b_tokens_are_unavailable() -> None:
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1"],
        user_b_tokens=["token-b1"],
    )

    broker.report_preparation_token_failure(
        token="token-b1",
        token_role="user_b",
        repository_name="owner/repo",
        stage="get_authenticated_user",
        reason="GitHub API request failed for /user: 403 Sorry. Your account was suspended",
    )

    started = threading.Event()
    acquired = threading.Event()
    observed: dict[str, str] = {}

    def _reserve_after_refresh() -> None:
        started.set()
        lease = broker.reserve("owner/repo-next")
        observed["token"] = lease.user_b_token
        broker.release(lease)
        acquired.set()

    thread = threading.Thread(target=_reserve_after_refresh, daemon=True)
    thread.start()

    assert started.wait(timeout=1.0)
    time.sleep(0.1)
    assert not acquired.is_set()

    broker.refresh_tokens(
        user_a_tokens=["token-a1"],
        user_b_tokens=["token-b2"],
        trigger="test_refresh",
    )

    assert acquired.wait(timeout=1.0)
    assert observed["token"] == "token-b2"
    thread.join(timeout=1.0)


def test_attack_token_broker_emits_waiting_and_recovered_events() -> None:
    events: list[AttackTokenAvailabilityEvent] = []
    broker = AttackTokenBroker(
        user_a_tokens=["token-a1"],
        user_b_tokens=["token-b1"],
        on_token_availability_changed=events.append,
    )

    broker.refresh_tokens(
        user_a_tokens=[],
        user_b_tokens=[],
        trigger="test_wait",
    )
    broker.refresh_tokens(
        user_a_tokens=["token-a1"],
        user_b_tokens=["token-b1"],
        trigger="test_recover",
    )

    assert [event.status for event in events] == ["waiting", "recovered"]
    assert events[0].missing_roles == ("user_a", "user_b")
