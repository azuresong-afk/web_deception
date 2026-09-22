"""Чтение и проверка конфигурации control plane.

Устроено так же, как в сенсоре, и по тем же причинам: только переменные
окружения, полная проверка значений, отказ стартовать при неверной
конфигурации. Одинаковые правила в обоих компонентах — это не эстетика:
разные правила означают, что при разборе инцидента нужно помнить, какой
компонент ведёт себя как.

Отличие от сенсора только в форме адреса: uvicorn принимает хост и порт
по отдельности, и разбирать строку "host:port", чтобы тут же её разделить,
было бы лишним шагом, на котором можно ошибиться.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address

# Слушаем только локальный интерфейс, пока не сказано иное. Control plane
# хранит профили атакующих и журнал аудита — открывать его наружу
# по умолчанию недопустимо.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_LOG_LEVEL = logging.INFO

_LOG_LEVELS: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})

#: Источник переменных окружения. Передаётся параметром, чтобы тесты
#: не меняли окружение процесса: такие тесты нельзя запускать параллельно
#: и они незаметно влияют друг на друга.
Getenv = Callable[[str], str | None]


class ConfigError(Exception):
    """Неверная конфигурация. Останавливает запуск с кодом возврата 2."""


@dataclass(frozen=True, slots=True)
class Config:
    """Конфигурация control plane на текущем этапе.

    frozen=True делает объект неизменяемым: конфигурацию читают из разных
    мест, и возможность её случайно поправить на ходу — источник ошибок,
    которые воспроизводятся раз в месяц и не ловятся тестами.
    """

    host: str
    port: int
    log_level: int
    enable_docs: bool

    def warnings(self) -> list[str]:
        """Предупреждения о конфигурации, которая корректна, но рискованна.

        Не ошибки: запретить привязку ко всем интерфейсам нельзя, в оркестраторе
        иначе не работает. Но решение обязано остаться в логе, чтобы при разборе
        инцидента было видно, что порт открыли осознанно.
        """
        out: list[str] = []

        if not _is_loopback(self.host):
            out.append(
                f"control plane привязан к {self.host!r} и доступен не только "
                "с локальной машины: он хранит профили атакующих и журнал аудита, "
                "поэтому порт должен быть закрыт файрволом или сетевой политикой"
            )

        if self.port == 0:
            out.append(
                "порт равен 0: он будет выбран случайно при каждом запуске; "
                "это допустимо только в тестах"
            )

        if self.enable_docs:
            out.append(
                "включена интерактивная документация API (/docs, /openapi.json): "
                "она публикует полный список эндпоинтов и их параметров — "
                "готовую карту для атакующего; допустимо только в разработке"
            )

        return out


def load(getenv: Getenv | None = None) -> Config:
    """Читает конфигурацию, поднимая ConfigError при любом неверном значении."""
    get: Getenv = os.environ.get if getenv is None else getenv

    return Config(
        host=_parse_host(get("CP_HOST")),
        port=_parse_port(get("CP_PORT")),
        log_level=_parse_log_level(get("CP_LOG_LEVEL")),
        enable_docs=_parse_bool("CP_ENABLE_DOCS", get("CP_ENABLE_DOCS"), default=False),
    )


def _parse_host(raw: str | None) -> str:
    if raw is None or not raw.strip():
        return DEFAULT_HOST

    host = raw.strip()

    if " " in host or "\t" in host:
        raise ConfigError(f"CP_HOST: имя хоста содержит пробелы: {host!r}")

    host = _strip_brackets(host)

    # Двоеточие в значении — либо голый адрес IPv6, где двоеточия естественны,
    # либо частая ошибка переноса конфигурации из сенсора, где адрес задаётся
    # одной строкой "host:port". Различить их можно единственным надёжным
    # способом: попробовать разобрать значение как IP-адрес.
    #
    # Этот случай поймал тест: первая версия проверки отвергала совершенно
    # корректный адрес ::1, потому что в нём есть двоеточия.
    if ":" in host and not _is_ip_address(host):
        raise ConfigError(
            f"CP_HOST: ожидается только хост без порта, получено {host!r}; "
            "порт задаётся переменной CP_PORT"
        )

    return host


def _strip_brackets(host: str) -> str:
    """Убирает скобки вокруг адреса IPv6: "[::1]" становится "::1".

    В форме "host:port" адрес IPv6 обязан быть в скобках, иначе двоеточия
    адреса не отличить от разделителя порта. Здесь порт задаётся отдельно,
    скобки не нужны, но администратор вполне может их написать по привычке.
    """
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _parse_port(raw: str | None) -> int:
    if raw is None or not raw.strip():
        return DEFAULT_PORT

    value = raw.strip()

    # Проверяем посимвольно, а не полагаемся на int(). Python принимает
    # подчёркивания внутри чисел: int("8_000") вернёт 8000. Для настройки,
    # пришедшей извне, такая вольность не нужна — она только маскирует опечатки.
    if not value.isdigit():
        raise ConfigError(f"CP_PORT: ожидается целое неотрицательное число, получено {raw!r}")

    port = int(value)
    if port > 65535:
        raise ConfigError(f"CP_PORT: порт вне диапазона 0-65535: {port}")

    return port


def _parse_log_level(raw: str | None) -> int:
    if raw is None or not raw.strip():
        return DEFAULT_LOG_LEVEL

    level = _LOG_LEVELS.get(raw.strip().lower())
    if level is None:
        allowed = ", ".join(sorted(_LOG_LEVELS))
        raise ConfigError(f"CP_LOG_LEVEL: неизвестный уровень {raw!r}, допустимы: {allowed}")

    return level


def _parse_bool(name: str, raw: str | None, *, default: bool) -> bool:
    if raw is None or not raw.strip():
        return default

    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False

    # Непонятное значение — ошибка, а не «считаем за false». Опечатка вроде
    # CP_ENABLE_DOCS=fasle молча дала бы безопасное поведение, и администратор
    # никогда бы не узнал, что его настройка не работает. Сегодня это безобидно,
    # а для флага, который что-то включает, — уже нет.
    raise ConfigError(f"{name}: ожидается true или false, получено {raw!r}")


def _is_loopback(host: str) -> bool:
    """Доступен ли адрес только с локальной машины."""
    if host == "localhost":
        return True

    try:
        return ip_address(_strip_brackets(host)).is_loopback
    except ValueError:
        # Не IP-адрес: имя хоста намеренно не резолвим. Обращение к DNS
        # в момент старта может зависнуть на таймауте резолвера.
        return False
