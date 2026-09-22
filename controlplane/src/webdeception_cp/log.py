"""Структурированное логирование control plane.

Формат — одна JSON-строка на сообщение, вывод в stderr. stderr, а не stdout,
потому что stdout зарезервирован под данные; JSON, потому что логи будет
читать машина, а не только человек.

Что сюда НИКОГДА не попадает: тела запросов и ответов, заголовки
Authorization, Cookie и Set-Cookie, токены и пароли в любом виде.
Это запрет из CLAUDE.md, и на шаге 6 он станет правилом Semgrep,
проверяемым в CI, а не обещанием в комментарии.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    """Превращает запись лога в одну строку JSON.

    Почему не готовая библиотека: форматтер занимает двадцать строк, а каждая
    зависимость — это чужой код в нашем контейнере и ещё одна позиция в списке,
    который придётся проверять при каждой новой уязвимости. Правило проекта
    требует обосновывать каждую зависимость; здесь обоснования нет.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname.lower(),
            "msg": record.getMessage(),
            "logger": record.name,
        }

        # Дополнительные поля передаются одним словарём под ключом "fields":
        # logger.info("...", extra={"fields": {"host": ...}}). Один ключ вместо
        # произвольных имён — чтобы случайно не перезаписать служебные атрибуты
        # записи лога, например "message" или "levelname".
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)

        if record.exc_info is not None:
            payload["error"] = self.formatException(record.exc_info)

        # ensure_ascii=False, иначе кириллица в логе превращается в \uXXXX
        # и лог становится нечитаемым ровно тогда, когда он нужен.
        return json.dumps(payload, ensure_ascii=False)


def setup(level: int) -> None:
    """Настраивает корневой логгер.

    Существующие обработчики удаляются: uvicorn и библиотеки добавляют свои,
    и без очистки одно сообщение печатается дважды — один раз нашим форматом,
    один раз чужим.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
