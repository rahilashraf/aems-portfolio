import http.server
import threading
from collections.abc import Iterator

import pytest

from scripts import healthcheck


class TestResolveProbeHost:
    def test_uses_first_allowed_host(self) -> None:
        env = {"DJANGO_ALLOWED_HOSTS": "api.example.org,admin.example.org"}
        assert healthcheck.resolve_probe_host(env) == "api.example.org"

    def test_strips_whitespace_and_subdomain_wildcard_dot(self) -> None:
        env = {"DJANGO_ALLOWED_HOSTS": "  .example.org , api.example.org"}
        assert healthcheck.resolve_probe_host(env) == "example.org"

    def test_skips_empty_and_wildcard_entries(self) -> None:
        env = {"DJANGO_ALLOWED_HOSTS": ",*, api.example.org"}
        assert healthcheck.resolve_probe_host(env) == "api.example.org"

    @pytest.mark.parametrize("value", ["", " , ", "*"])
    def test_rejects_missing_or_unusable_hosts(self, value: str) -> None:
        with pytest.raises(ValueError, match="no usable host"):
            healthcheck.resolve_probe_host({"DJANGO_ALLOWED_HOSTS": value})

    def test_rejects_unset_variable(self) -> None:
        with pytest.raises(ValueError, match="no usable host"):
            healthcheck.resolve_probe_host({})


class _HostCheckingHandler(http.server.BaseHTTPRequestHandler):
    """Mimics Django host validation: 200 only for the expected Host and path."""

    expected_host = "api.example.org"

    def do_GET(self) -> None:
        ok = self.headers.get("Host") == self.expected_host and self.path == "/health/live/"
        self.send_response(200 if ok else 400)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        """Silence request logging."""


@pytest.fixture
def server_port() -> Iterator[int]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _HostCheckingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


class TestProbe:
    def test_succeeds_when_host_header_is_allowed(self, server_port: int) -> None:
        assert healthcheck.probe("api.example.org", port=server_port) is True

    def test_fails_when_host_header_is_rejected(self, server_port: int) -> None:
        assert healthcheck.probe("127.0.0.1", port=server_port) is False

    def test_fails_when_nothing_is_listening(self, server_port: int) -> None:
        # Bind-and-release a port so nothing listens there.
        server = http.server.HTTPServer(("127.0.0.1", 0), _HostCheckingHandler)
        closed_port = server.server_address[1]
        server.server_close()

        assert healthcheck.probe("api.example.org", port=closed_port, timeout=1) is False


class TestMain:
    def test_returns_0_when_probe_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []

        def fake_probe(host: str) -> bool:
            seen.append(host)
            return True

        monkeypatch.setattr(healthcheck, "probe", fake_probe)

        assert healthcheck.main({"DJANGO_ALLOWED_HOSTS": "api.example.org"}) == 0
        assert seen == ["api.example.org"]

    def test_returns_1_when_probe_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(healthcheck, "probe", lambda host: False)

        assert healthcheck.main({"DJANGO_ALLOWED_HOSTS": "api.example.org"}) == 1

    def test_returns_1_without_usable_host(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert healthcheck.main({"DJANGO_ALLOWED_HOSTS": ""}) == 1
        assert "no usable host" in capsys.readouterr().err

    def test_reads_process_environment_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DJANGO_ALLOWED_HOSTS", "api.example.org")
        monkeypatch.setattr(healthcheck, "probe", lambda host: host == "api.example.org")

        assert healthcheck.main() == 0
