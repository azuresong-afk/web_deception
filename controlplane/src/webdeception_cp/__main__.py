"""Точка входа control plane: python -m webdeception_cp.

Почему запускаем через свой модуль, а не командой `uvicorn webdeception_cp.app`:
нам нужно сначала прочитать и проверить конфигурацию и только потом поднимать
сервер. При запуске через uvicorn напрямую конфигурация читалась бы уже внутри
работающего сервера, и неверное значение давало бы запущенный, но нерабочий
сервис вместо честного отказа стартовать.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from typing import Any

import uvicorn

from webdeception_cp import config, log
from webdeception_cp.app import create_app
from webdeception_cp.version import VERSION

#: Функция запуска сервера. Вынесена в параметр по той же причине, что
#: и чтение переменных окружения: чтобы тест мог проверить, с какими
#: настройками мы запускаем uvicorn, не поднимая настоящий сервер.
#: Проверяются не абстрактные аргументы, а конкретные меры защиты —
#: выключенный журнал доступа и отсутствие заголовка server.
ServerRunner = Callable[..., Any]


def main(getenv: config.Getenv | None = None, run: ServerRunner = uvicorn.run) -> int:
    """Возвращает код завершения процесса: 0, 1 или 2."""
    try:
        cfg = config.load(getenv)
    except config.ConfigError as error:
        # Логгер ещё не настроен: его уровень берётся из конфигурации,
        # которую как раз не удалось прочитать. Пишем напрямую в stderr.
        #
        # Код 2 отличает ошибку конфигурации от ошибки работы — это видно
        # в docker compose и systemd сразу, без чтения логов. Так же
        # устроен сенсор: одинаковое поведение компонентов экономит время
        # в тот момент, когда его меньше всего.
        sys.stderr.write(f"ошибка конфигурации: {error}\n")
        return 2

    log.setup(cfg.log_level)
    logger = logging.getLogger("webdeception_cp")

    # Предупреждения не останавливают запуск, но обязаны остаться в логе:
    # при разборе инцидента должно быть видно, что рискованная настройка
    # была сделана осознанно.
    for warning in cfg.warnings():
        logger.warning(warning)

    logger.info(
        "control plane запускается",
        extra={"fields": {"host": cfg.host, "port": cfg.port, "version": VERSION}},
    )

    run(
        create_app(cfg),
        host=cfg.host,
        port=cfg.port,
        # Не даём uvicorn подменить настроенное нами логирование.
        log_config=None,
        # Журнал доступа uvicorn выключен намеренно. Он печатает строку
        # запроса целиком, вместе со строкой параметров, а в параметрах
        # регулярно встречаются токены сброса пароля, ключи и коды
        # подтверждения. Правила проекта запрещают логировать токены
        # в любом виде. Свой журнал доступа с заранее выбранными полями
        # появится на этапе 3, когда будет что записывать.
        access_log=False,
        # uvicorn по умолчанию отдаёт заголовок "server: uvicorn",
        # то есть сообщает атакующему используемый стек (угроза T5).
        server_header=False,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
