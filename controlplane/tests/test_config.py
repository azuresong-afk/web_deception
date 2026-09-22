"""Тесты конфигурации control plane."""

from __future__ import annotations

import logging

import pytest

from webdeception_cp import config


def env(**values: str) -> config.Getenv:
    """Источник переменных окружения из словаря.

    Ни один тест не трогает окружение процесса: тесты, меняющие глобальное
    состояние, нельзя запускать параллельно, и они незаметно влияют друг
    на друга — такие тесты со временем перестают ловить ошибки.
    """
    return values.get


def test_defaults() -> None:
    cfg = config.load(env())

    # Значения по умолчанию — часть модели безопасности, а не удобство:
    # тот, кто просто запустил control plane и ничего не настраивал,
    # не должен получить открытый наружу сервис с картой своего API.
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 8000
    assert cfg.log_level == logging.INFO
    assert cfg.enable_docs is False
    assert cfg.warnings() == []


def test_reads_environment() -> None:
    cfg = config.load(
        env(
            # Пробелы вокруг значения — частый результат копирования в .env.
            CP_HOST="  0.0.0.0  ",
            CP_PORT=" 9000 ",
            CP_LOG_LEVEL="DEBUG",
            CP_ENABLE_DOCS="yes",
        )
    )

    assert cfg.host == "0.0.0.0"  # noqa: S104 — проверяем разбор значения, а не рекомендуем его
    assert cfg.port == 9000
    assert cfg.log_level == logging.DEBUG
    assert cfg.enable_docs is True


@pytest.mark.parametrize(
    ("variables", "expected_fragment"),
    [
        ({"CP_PORT": "восемь"}, "целое неотрицательное"),
        ({"CP_PORT": "-1"}, "целое неотрицательное"),
        # Python принимает подчёркивания внутри чисел: int("8_000") == 8000.
        # Для значения, пришедшего извне, такая вольность только маскирует опечатку.
        ({"CP_PORT": "8_000"}, "целое неотрицательное"),
        ({"CP_PORT": "70000"}, "вне диапазона"),
        ({"CP_HOST": "127.0.0.1:8000"}, "без порта"),
        ({"CP_HOST": "local host"}, "пробелы"),
        ({"CP_LOG_LEVEL": "verbose"}, "неизвестный уровень"),
        ({"CP_ENABLE_DOCS": "fasle"}, "true или false"),
    ],
)
def test_rejects_invalid_values(variables: dict[str, str], expected_fragment: str) -> None:
    with pytest.raises(config.ConfigError) as error:
        config.load(env(**variables))

    message = str(error.value)
    assert expected_fragment in message

    # Сообщение обязано называть переменную окружения: иначе его бесполезно
    # читать в логе контейнера, где не видно, что именно администратор задал.
    for name in variables:
        assert name in message


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("TRUE", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("off", False),
    ],
)
def test_parses_boolean_values(raw: str, expected: bool) -> None:
    assert config.load(env(CP_ENABLE_DOCS=raw)).enable_docs is expected


@pytest.mark.parametrize(
    ("variables", "expected_count", "expected_fragment"),
    [
        ({"CP_HOST": "127.0.0.1"}, 0, ""),
        ({"CP_HOST": "localhost"}, 0, ""),
        ({"CP_HOST": "::1"}, 0, ""),
        ({"CP_HOST": "0.0.0.0"}, 1, "не только с локальной машины"),  # noqa: S104
        ({"CP_HOST": "10.1.2.3"}, 1, "не только с локальной машины"),
        ({"CP_HOST": "control-plane.internal"}, 1, "не только с локальной машины"),
        ({"CP_PORT": "0"}, 1, "только в тестах"),
        ({"CP_ENABLE_DOCS": "true"}, 1, "карту для атакующего"),
    ],
)
def test_warnings(variables: dict[str, str], expected_count: int, expected_fragment: str) -> None:
    warnings = config.load(env(**variables)).warnings()

    assert len(warnings) == expected_count
    if expected_fragment:
        assert expected_fragment in " ".join(warnings)


def test_config_is_immutable() -> None:
    """Конфигурацию нельзя изменить после чтения.

    Иначе появляется класс ошибок, которые воспроизводятся раз в месяц:
    один участок кода поправил настройку на ходу, другой этого не ожидал.
    """
    cfg = config.load(env())

    with pytest.raises((AttributeError, TypeError)):
        # mypy прав: присваивание запрещено. Именно это тест и доказывает.
        cfg.host = "0.0.0.0"  # type: ignore[misc]  # noqa: S104
