"""Какие задания CI запускать — по списку файлов, изменённых в pull request.

Вызывается первым заданием workflow .github/workflows/ci.yml. Результат
пишется в $GITHUB_OUTPUT как go=true/false, python=..., containers=...

Зачем. Монорепозиторий должен оставаться быстрым (ADR-0008): правка
в документации не должна ждать сборки образов, правка в Python — тестов Go.
Но экономия времени не должна стоить пропущенной проверки, поэтому правила
ниже устроены так, что любая неопределённость ведёт к запуску всего:

- push в main — проверяется всё: это то, что уходит в продукт;
- изменён Makefile или workflow — проверяется всё: они управляют проверками;
- не удалось получить список изменений — проверяется всё.

Это обратная логика по сравнению с сенсором. Сенсор при сбое пропускает
трафик (fail-open), потому что для него безопасно — не мешать клиенту.
Для проверок безопасно обратное: при сомнении проверить всё (fail-closed).
Правильное поведение при сбое определяется тем, что именно защищаемо.

Только стандартная библиотека: у CI-скрипта не должно быть своей цепочки поставки.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable

# Какие каталоги относятся к какому заданию. Один файл может запускать
# несколько заданий: исходники сенсора нужны и тестам Go, и сборке образа.
GROUPS: dict[str, tuple[str, ...]] = {
    "go": ("sensor/", "tools/golangci-lint/", "tools/actionlint/", "tools/govulncheck/"),
    "python": ("controlplane/", "scripts/"),
    "containers": (
        "deploy/",
        "sensor/",
        "controlplane/",
        "scripts/",
        ".dockerignore",
        # Образы сканеров hadolint и Trivy.
        "tools/scanners/",
    ),
}

# Изменение этих файлов запускает всё: они определяют, что и как проверяется.
RUN_EVERYTHING: tuple[str, ...] = ("Makefile", ".github/workflows/")

_SHA = re.compile(r"^[0-9a-f]{40}$")


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    """Шаблон с «/» на конце — каталог, без него — точное имя файла.

    Простое сравнение начала строки здесь ошибочно: "Makefile.bak" начинается
    с "Makefile". Ошибку поймал тест. В этом скрипте она безвредна — лишний
    запуск, — но та же логика в списке «что можно пропустить» тихо отключала
    бы проверки.
    """
    return any(
        path.startswith(pattern) if pattern.endswith("/") else path == pattern
        for pattern in patterns
    )


def classify(paths: Iterable[str]) -> dict[str, bool]:
    """Для каждого задания — нужно ли его запускать."""
    result = dict.fromkeys(GROUPS, False)
    for path in paths:
        if _matches(path, RUN_EVERYTHING):
            return dict.fromkeys(GROUPS, True)
        for job, patterns in GROUPS.items():
            if _matches(path, patterns):
                result[job] = True
    return result


def changed_files(base: str, head: str) -> list[str]:
    """Файлы, изменённые в ветке относительно точки её ответвления от base."""
    # SHA приходят из события GitHub, но всё равно проверяются: в аргументы
    # git не должно попасть ничего, кроме сорока шестнадцатеричных символов.
    # Строка вида "--output=/etc/..." оказалась бы опцией git, а не SHA.
    for name, value in (("BASE_SHA", base), ("HEAD_SHA", head)):
        if not _SHA.match(value):
            raise ValueError(f"{name} не похож на SHA коммита: {value!r}")

    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git не найден")

    # Три точки: изменения в ветке с момента ответвления, а не разница
    # с текущим состоянием main, куда тем временем могли влить чужое.
    completed = subprocess.run(  # noqa: S603 — аргументы фиксированы и проверены выше
        [git, "diff", "--name-only", f"{base}...{head}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


def decide(
    env: dict[str, str],
    diff: Callable[[str, str], list[str]] = changed_files,
) -> tuple[dict[str, bool], str]:
    """Решение и его причина — причина попадает в лог CI."""
    everything = dict.fromkeys(GROUPS, True)

    if env.get("GITHUB_EVENT_NAME") != "pull_request":
        return everything, "не pull request: проверяется всё"

    try:
        files = diff(env.get("BASE_SHA", ""), env.get("HEAD_SHA", ""))
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        return everything, f"список изменений не получен ({error}): проверяется всё"

    return classify(files), f"изменено файлов: {len(files)}"


def main() -> int:
    decision, reason = decide(dict(os.environ))

    sys.stdout.write(f"{reason}\n")
    for job, run in decision.items():
        sys.stdout.write(f"  {job:<11} {'запускать' if run else 'пропустить'}\n")

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fh:  # noqa: PTH123 — путь задаёт GitHub
            for job, run in decision.items():
                fh.write(f"{job}={'true' if run else 'false'}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
