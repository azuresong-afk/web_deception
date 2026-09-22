"""Проверка сообщений коммитов по соглашению Conventional Commits.

Два режима:
    python3 scripts/check_commit_msg.py --file .git/COMMIT_EDITMSG
        для хука commit-msg: проверяет одно сообщение до создания коммита;
    python3 scripts/check_commit_msg.py --range
        для CI: проверяет все коммиты pull request, диапазон берётся
        из переменных окружения BASE_SHA и HEAD_SHA.

Зачем формат. Первая строка вида «тип(область): описание» делает историю
машинно-читаемой: из неё собирается changelog и следующий номер версии
(feat — минорная, fix — патч, «!» — мажорная). И человек, листающий историю
при разборе инцидента, сразу видит, что было исправлением безопасности,
а что — правкой документации.

Проверяется только первая строка: тело сообщения — свободный текст.

Только стандартная библиотека: у проверки не должно быть своей цепочки поставки.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable

TYPES = (
    "feat",
    "fix",
    "docs",
    "style",
    "refactor",
    "perf",
    "test",
    "build",
    "ci",
    "chore",
    "revert",
)

# Длина — ради читаемости в `git log --oneline` и в списках PR. Предел
# с запасом: Dependabot пишет длинные строки вида «build(deps): bump
# github.com/... from 2.13.2 to 2.14.0 in /tools/golangci-lint», и отклонять
# его обновления из-за стиля было бы хуже, чем длинная строка в истории.
MAX_SUBJECT = 120

_CONVENTIONAL = re.compile(
    r"^(?P<type>" + "|".join(TYPES) + r")"
    r"(?:\((?P<scope>[a-z0-9][a-z0-9._/-]*)\))?"
    r"(?P<breaking>!)?"
    r": (?P<description>\S.*)$"
)

# Сообщения, которые создаёт сам git: откат коммита и слияние веток.
# Требовать от них формата значило бы заставлять вручную переписывать
# то, что git сформулировал правильно.
_GIT_GENERATED = re.compile(r'^(Revert ".+"|Merge .+)$')

_SHA = re.compile(r"^[0-9a-f]{40}$")


def subject_of(message: str) -> str:
    """Первая значимая строка сообщения.

    Строки-комментарии git (начинаются с «#») пропускаются так же, как их
    пропускает сам git при создании коммита.
    """
    for line in message.splitlines():
        if line.startswith("#"):
            continue
        if line.strip():
            return line.rstrip()
    return ""


def problems(subject: str) -> list[str]:
    """Что не так с первой строкой. Пустой список — всё в порядке."""
    if not subject:
        return ["пустое сообщение коммита"]

    found: list[str] = []
    if len(subject) > MAX_SUBJECT:
        found.append(f"первая строка длиннее {MAX_SUBJECT} символов ({len(subject)})")

    if not (_CONVENTIONAL.match(subject) or _GIT_GENERATED.match(subject)):
        found.append(
            "первая строка не в формате «тип(область): описание»; "
            f"допустимые типы: {', '.join(TYPES)}"
        )
    return found


def commit_subjects(base: str, head: str, cwd: str | None = None) -> list[tuple[str, str]]:
    """Короткие SHA и первые строки коммитов между base и head, без слияний.

    cwd — каталог репозитория; по умолчанию текущий.
    """
    for name, value in (("BASE_SHA", base), ("HEAD_SHA", head)):
        if not _SHA.match(value):
            raise ValueError(f"{name} не похож на SHA коммита: {value!r}")

    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git не найден")

    completed = subprocess.run(  # noqa: S603 — аргументы фиксированы и проверены выше
        # Разделитель — символ 0x1f, которого не бывает в тексте сообщений.
        # --no-merges: коммиты слияния создаёт git или GitHub, не автор PR.
        [git, "log", "--no-merges", "--format=%h%x1f%s", f"{base}..{head}"],
        check=True,
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    result: list[tuple[str, str]] = []
    for line in completed.stdout.splitlines():
        sha, _, subject = line.partition("\x1f")
        result.append((sha, subject))
    return result


def report(items: Iterable[tuple[str, str]], write: Callable[[str], object]) -> int:
    """Печатает найденные проблемы и возвращает их количество.

    Первая строка коммита — текст, который выбрал автор PR, то есть в том
    числе атакующий. Её нельзя печатать в лог CI как есть: строка вида
    «::add-mask::...» или «::error::...» в начале строки лога — это команда
    раннеру GitHub Actions, а не текст. Поэтому текст выводится через repr():
    он оказывается в кавычках, со спецсимволами в экранированном виде,
    и никогда не начинает строку лога.
    """
    count = 0
    for sha, subject in items:
        for problem in problems(subject):
            count += 1
            write(f"  коммит {sha}: {problem}\n    строка: {subject!r}\n")
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", help="файл с сообщением коммита (хук commit-msg)")
    mode.add_argument("--range", action="store_true", help="коммиты PR из BASE_SHA и HEAD_SHA")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, encoding="utf-8") as fh:  # noqa: PTH123 — путь передаёт git
            items = [("новый", subject_of(fh.read()))]
    else:
        try:
            items = commit_subjects(os.environ.get("BASE_SHA", ""), os.environ.get("HEAD_SHA", ""))
        except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
            # Не удалось получить коммиты — это провал проверки, а не повод
            # считать, что проверять нечего.
            sys.stderr.write(f"не удалось получить список коммитов: {error}\n")
            return 1

    count = report(items, sys.stderr.write)
    if count:
        sys.stderr.write(
            "\nФормат: тип(область): описание — например «fix(sensor): закрыть тело ответа».\n"
            "Подробно — CONTRIBUTING.md, раздел «Сообщения коммитов».\n"
        )
        return 1

    if args.range:
        sys.stdout.write(f"проверено коммитов: {len(items)}, все в формате Conventional Commits\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
