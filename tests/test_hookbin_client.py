from __future__ import annotations

from pwn_hunter_ai.attack.hookbin_client import HookbinClient


class _FakeResponse:
    def __init__(self, payload, ok: bool = True) -> None:
        self._payload = payload
        self.ok = ok

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, payload) -> None:
        self._payload = payload

    def get(self, _url: str, timeout: int = 10):  # noqa: ARG002
        return _FakeResponse(self._payload)


def test_get_logs_as_text_reads_body_text_from_items() -> None:
    session = _FakeSession(
        {
            "binId": "abc",
            "items": [
                {"method": "GET", "bodyText": None},
                {
                    "method": "PUT",
                    "bodyText": '"github_token":{"value":"ghs_foo","isSecret":true}',
                },
            ],
        }
    )
    client = HookbinClient(session=session)

    logs = client.get_logs_as_text("abc")

    assert '"github_token":{"value":"ghs_foo","isSecret":true}' in logs


def test_get_logs_as_text_falls_back_to_body_field() -> None:
    session = _FakeSession({"logs": [{"body": "secret-body"}]})
    client = HookbinClient(session=session)

    logs = client.get_logs_as_text("abc")

    assert logs == "secret-body"


def test_wait_for_logs_as_text_uses_polled_logs(monkeypatch) -> None:
    session = _FakeSession({"logs": []})
    client = HookbinClient(session=session)

    monkeypatch.setattr(
        client,
        "wait_for_logs",
        lambda *_args, **_kwargs: [{"bodyText": "delayed-secret"}],
    )

    logs = client.wait_for_logs_as_text("abc", timeout=1, poll_interval=0.01)

    assert logs == "delayed-secret"


def test_get_logs_keeps_entries_with_empty_body() -> None:
    session = _FakeSession({"logs": [{"method": "GET", "bodyText": None}]})
    client = HookbinClient(session=session)

    logs = client.get_logs("abc")

    assert len(logs) == 1
