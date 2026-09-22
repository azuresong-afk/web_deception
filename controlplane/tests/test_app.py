"""Тесты HTTP-приложения control plane."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from webdeception_cp.app import create_app
from webdeception_cp.config import Config


def make_config(*, enable_docs: bool = False) -> Config:
    return Config(host="127.0.0.1", port=8000, log_level=logging.INFO, enable_docs=enable_docs)


@pytest.fixture
def client() -> TestClient:
    """Клиент без запуска lifespan: приложение ещё не готово.

    TestClient выполняет обработчики запуска только внутри `with`. Это даёт
    удобный способ проверить состояние «жив, но не готов» — то самое, в котором
    сервис находится во время старта и во время остановки.
    """
    return TestClient(create_app(make_config()))


@pytest.fixture
def started_client() -> Iterator[TestClient]:
    """Клиент с выполненным запуском: приложение готово."""
    with TestClient(create_app(make_config())) as started:
        yield started


def test_healthz_answers_even_before_startup(client: TestClient) -> None:
    """Живость не зависит от готовности.

    Если бы зависела, оркестратор убивал бы сервис во время долгого старта
    и во время корректной остановки — то есть ровно тогда, когда его трогать
    нельзя.
    """
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.text == "ok\n"


def test_readyz_is_not_ready_before_startup(client: TestClient) -> None:
    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.text == "not ready\n"


def test_readyz_is_ready_after_startup(started_client: TestClient) -> None:
    response = started_client.get("/readyz")

    assert response.status_code == 200
    assert response.text == "ready\n"


@pytest.mark.parametrize("path", ["/", "/metrics", "/admin", "/healthz/../etc/passwd"])
def test_unknown_paths_return_plain_404(started_client: TestClient, path: str) -> None:
    response = started_client.get(path)

    assert response.status_code == 404
    # Ответ по умолчанию был бы JSON {"detail": "Not Found"}. Мы его заменили:
    # поле detail способно содержать текст из запроса, а форма ответа выдаёт
    # используемый фреймворк.
    assert response.text == "not found\n"
    assert response.headers["content-type"].startswith("text/plain")


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_only_get_is_allowed(started_client: TestClient, method: str) -> None:
    response = getattr(started_client, method)("/healthz")

    assert response.status_code == 405
    assert response.text == "method not allowed\n"
    # Заголовок Allow из стандарта HTTP сохраняется: он говорит клиенту,
    # что именно здесь разрешено, и не раскрывает ничего лишнего.
    assert "allow" in response.headers


def test_api_documentation_is_disabled_by_default(started_client: TestClient) -> None:
    """Карта API не публикуется, пока её явно не включили.

    FastAPI по умолчанию открывает /docs, /redoc и /openapi.json — полный
    список эндпоинтов с параметрами и структурами данных.
    """
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert started_client.get(path).status_code == 404


def test_api_documentation_can_be_enabled_explicitly() -> None:
    with TestClient(create_app(make_config(enable_docs=True))) as started:
        assert started.get("/docs").status_code == 200
        assert started.get("/openapi.json").status_code == 200


@pytest.mark.parametrize("path", ["/healthz", "/readyz", "/nothing-here"])
def test_security_headers_on_every_response(started_client: TestClient, path: str) -> None:
    response = started_client.get(path)

    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", ["/healthz", "/readyz", "/nothing-here"])
def test_responses_do_not_reveal_the_stack(started_client: TestClient, path: str) -> None:
    """Прямая проверка меры против угрозы T5.

    Заголовок server добавляет uvicorn, и мы его отключаем при запуске.
    В тестовом клиенте сервера нет, поэтому здесь проверяется вторая часть:
    ни название продукта, ни фреймворк не просачиваются в тело и заголовки.
    """
    response = started_client.get(path)

    haystack = " ".join(
        [response.text, *response.headers.keys(), *response.headers.values()]
    ).lower()

    for word in ("uvicorn", "fastapi", "starlette", "deception", "python"):
        assert word not in haystack
