"""Проверка готовности control plane изнутри контейнера.

Запуск: python -m webdeception_cp.healthcheck

Зачем отдельная команда, если в образе есть Python: в финальном образе нет
curl и wget — это сознательное решение, чтобы атакующий, получивший выполнение
кода в контейнере, не нашёл там готовых сетевых инструментов. Проверка должна
работать тем, что в образе уже есть, то есть самим приложением.

Устроено так же, как `sensor healthcheck`, и возвращает только 0 или 1:
в проверке здоровья Docker код 2 зарезервирован.
"""

from __future__ import annotations

import http.client
import sys

from webdeception_cp import config

TIMEOUT_SECONDS = 2.0

# Наш ответ — "ready\n". Предел нужен не из недоверия к себе, а потому, что
# чтение без предела — привычка, которая однажды окажется там, где ответ
# пришлёт уже не наш сервер.
_MAX_BODY_BYTES = 1024


def target(cfg: config.Config) -> tuple[str, int]:
    """Куда подключаться, чтобы проверить сервис с этой конфигурацией.

    «Все интерфейсы» — адрес для прослушивания, а не для подключения,
    поэтому заменяется на локальный.
    """
    host = cfg.host
    if host in ("", "0.0.0.0"):  # noqa: S104 — сравниваем, а не привязываемся
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    return host, cfg.port


def probe(host: str, port: int, timeout: float = TIMEOUT_SECONDS) -> bool:
    """Одна проверка /readyz. True — сервис готов.

    Используется http.client, а не urllib: urllib по умолчанию следует
    редиректам, а проверке здоровья нельзя «уходить» по чужому указанию.
    http.client редиректы не выполняет вовсе.
    """
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", "/readyz")
        response = connection.getresponse()
        response.read(_MAX_BODY_BYTES)
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()

    return response.status == 200


def main(getenv: config.Getenv | None = None) -> int:
    """Возвращает 0, если сервис готов, иначе 1."""
    try:
        cfg = config.load(getenv)
    except config.ConfigError as error:
        sys.stderr.write(f"healthcheck: ошибка конфигурации: {error}\n")
        return 1

    host, port = target(cfg)
    if not probe(host, port):
        sys.stderr.write("healthcheck: control plane не готов\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
