"""Тесты проверки готовности изнутри контейнера."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webdeception_cp import config, healthcheck


class _Handler(BaseHTTPRequestHandler):
    """Отвечает кодом, заданным в атрибуте сервера."""

    def do_GET(self) -> None:
        status: int = self.server.status  # type: ignore[attr-defined]
        self.send_response(status)
        if status in (301, 302):
            self.send_header("Location", "/elsewhere")
        self.end_headers()
        self.wfile.write(b"x\n")

    def log_message(self, format: str, *args: object) -> None:
        """Молчим: вывод тестов — для результатов, а не для журнала сервера."""


@pytest.fixture
def server() -> Iterator[HTTPServer]:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.status = 200  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()


def _port(httpd: HTTPServer) -> int:
    return int(httpd.server_address[1])


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, True),
        (503, False),
        # Редирект на «здоровый» адрес не должен засчитываться как здоровье.
        (302, False),
    ],
)
def test_probe_reflects_status(server: HTTPServer, status: int, expected: bool) -> None:
    server.status = status  # type: ignore[attr-defined]

    assert healthcheck.probe("127.0.0.1", _port(server)) is expected


def test_probe_fails_when_nobody_listens() -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    # Сокет закрыт — адрес гарантированно никто не слушает.

    assert healthcheck.probe("127.0.0.1", port) is False


def test_probe_respects_timeout() -> None:
    """Зависший сервис — провал проверки, а не зависшая проверка."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()  # принимаем соединение в очередь, но никогда не отвечаем

        start = time.monotonic()
        result = healthcheck.probe("127.0.0.1", sock.getsockname()[1], timeout=0.3)
        elapsed = time.monotonic() - start

    assert result is False
    assert elapsed < 2.0


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("0.0.0.0", "127.0.0.1"),  # noqa: S104
        ("::", "::1"),
        ("::1", "::1"),
        ("localhost", "localhost"),
    ],
)
def test_target_replaces_wildcard_with_loopback(host: str, expected: str) -> None:
    cfg = config.load({"CP_HOST": host, "CP_PORT": "8123"}.get)

    assert healthcheck.target(cfg) == (expected, 8123)


def test_main_returns_zero_when_ready(server: HTTPServer) -> None:
    env = {"CP_HOST": "127.0.0.1", "CP_PORT": str(_port(server))}

    assert healthcheck.main(env.get) == 0


def test_main_returns_one_when_not_ready(server: HTTPServer) -> None:
    server.status = 503  # type: ignore[attr-defined]
    env = {"CP_HOST": "127.0.0.1", "CP_PORT": str(_port(server))}

    assert healthcheck.main(env.get) == 1


def test_main_never_returns_two() -> None:
    """В проверке здоровья Docker код 2 зарезервирован — даже при ошибке конфигурации."""
    assert healthcheck.main({"CP_PORT": "70000"}.get) == 1
