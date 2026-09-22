"""Тесты точки входа control plane."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import pytest

from webdeception_cp.__main__ import main


@pytest.fixture(autouse=True)
def restore_root_logger() -> Iterator[None]:
    root = logging.getLogger()
    handlers = root.handlers[:]
    level = root.level
    try:
        yield
    finally:
        root.handlers = handlers
        root.setLevel(level)


class FakeRunner:
    """Заглушка вместо uvicorn.run: запоминает аргументы, сервер не поднимает."""

    def __init__(self) -> None:
        self.called = False
        self.kwargs: dict[str, Any] = {}

    def __call__(self, _app: Any, **kwargs: Any) -> None:
        self.called = True
        self.kwargs = kwargs


def test_invalid_configuration_stops_startup() -> None:
    """Неверная конфигурация — отказ стартовать, а не запуск «как получится».

    Код 2 отличает ошибку настройки от ошибки работы, так же как в сенсоре.
    """
    runner = FakeRunner()

    code = main(getenv={"CP_PORT": "70000"}.get, run=runner)

    assert code == 2
    assert not runner.called, "сервер не должен запускаться при неверной конфигурации"


def test_server_is_started_with_protective_settings() -> None:
    """Проверка структуры, а не поведения.

    Три настройки ниже — меры защиты, и их отключение не меняет ни одного
    ответа сервиса. Обнаружить такую пропажу поведенческим тестом нельзя,
    поэтому проверяем сами аргументы запуска.
    """
    runner = FakeRunner()

    code = main(getenv={"CP_HOST": "127.0.0.1", "CP_PORT": "8123"}.get, run=runner)

    assert code == 0
    assert runner.called

    assert runner.kwargs["host"] == "127.0.0.1"
    assert runner.kwargs["port"] == 8123

    # Журнал доступа uvicorn печатает строку запроса вместе с параметрами,
    # а в параметрах встречаются токены сброса пароля и коды подтверждения.
    assert runner.kwargs["access_log"] is False

    # Заголовок "server: uvicorn" сообщает атакующему используемый стек (T5).
    assert runner.kwargs["server_header"] is False

    # Своё логирование не отдаём на откуп uvicorn.
    assert runner.kwargs["log_config"] is None
