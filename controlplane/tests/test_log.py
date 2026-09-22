"""Тесты структурированного логирования."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest

from webdeception_cp import log


@pytest.fixture(autouse=True)
def restore_root_logger() -> Iterator[None]:
    """Возвращает корневой логгер в исходное состояние после теста.

    log.setup намеренно удаляет чужие обработчики, поэтому без восстановления
    он сломал бы захват логов в остальных тестах.
    """
    root = logging.getLogger()
    handlers = root.handlers[:]
    level = root.level
    try:
        yield
    finally:
        root.handlers = handlers
        root.setLevel(level)


def format_record(**kwargs: Any) -> dict[str, Any]:
    """Прогоняет одну запись через наш форматтер и возвращает разобранный JSON."""
    defaults: dict[str, Any] = {
        "name": "test",
        "level": logging.INFO,
        "pathname": __file__,
        "lineno": 1,
        "msg": "сообщение",
        "args": (),
        "exc_info": None,
    }
    defaults.update(kwargs)
    record = logging.LogRecord(**defaults)
    for key, value in kwargs.get("extra", {}).items():
        setattr(record, key, value)

    parsed: dict[str, Any] = json.loads(log.JsonFormatter().format(record))
    return parsed


def test_record_is_valid_json_with_expected_fields() -> None:
    parsed = format_record()

    assert parsed["msg"] == "сообщение"
    assert parsed["level"] == "info"
    assert parsed["logger"] == "test"
    # Время в формате ISO с зоной: лог читает машина, и разночтений быть не должно.
    assert parsed["time"].endswith("+00:00")


def test_cyrillic_is_not_escaped() -> None:
    """Кириллица должна остаться читаемой.

    При ensure_ascii=True сообщение превращается в \\uXXXX, и лог становится
    нечитаемым ровно тогда, когда его открывают — при разборе инцидента.
    """
    formatted = log.JsonFormatter().format(
        logging.LogRecord("test", logging.INFO, __file__, 1, "атака", (), None)
    )

    assert "атака" in formatted


def test_extra_fields_are_merged() -> None:
    parsed = format_record(extra={"fields": {"host": "127.0.0.1", "port": 8000}})

    assert parsed["host"] == "127.0.0.1"
    assert parsed["port"] == 8000


def test_exception_is_recorded() -> None:
    try:
        raise ValueError("сломалось")
    except ValueError:
        import sys

        parsed = format_record(exc_info=sys.exc_info(), level=logging.ERROR)

    assert "ValueError" in parsed["error"]


def test_setup_replaces_existing_handlers() -> None:
    """Чужие обработчики удаляются, иначе сообщение печатается дважды.

    uvicorn и библиотеки добавляют свои обработчики в корневой логгер,
    и без очистки один и тот же лог уходит и в нашем формате, и в чужом.
    """
    root = logging.getLogger()
    root.addHandler(logging.NullHandler())

    log.setup(logging.WARNING)

    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, log.JsonFormatter)
    assert root.level == logging.WARNING
