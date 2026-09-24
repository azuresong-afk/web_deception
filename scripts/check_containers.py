"""Проверка политики контейнеров: правила из CLAUDE.md как код.

Запуск: make lint (или напрямую: python scripts/check_containers.py).

Зачем. Правила «не запускать контейнеры от root» и «не использовать образы
с тегом latest» записаны в CLAUDE.md. Пока их соблюдение держится на памяти
того, кто пишет конфигурацию, оно держится до первой спешки. Этот скрипт
превращает правила в проверку, которая падает, — и тогда они соблюдаются
независимо от того, помнит о них кто-нибудь или нет.

Что проверяется в docker compose (по нормализованной модели от самого Docker,
а не разбором YAML вручную — так учитываются якоря, профили и значения
по умолчанию ровно так, как их увидит Docker):
    C1  образ без собственной сборки закреплён по digest
    C2  нигде нет тега latest
    C3  процесс работает не от root
    C4  сброшены все capabilities Linux
    C5  запрещено повышение привилегий
    C6  порты публикуются только на локальный адрес хоста
    C7  заданы лимиты памяти и числа процессов (сдерживание DoS, угроза T3)
    C8  исходники сборки из git в compose (контекст или дополнительный
        контекст) закреплены по полному SHA коммита, а не по ветке или тегу

Что проверяется в Dockerfile:
    D1  каждый базовый образ закреплён по digest
    D2  нигде нет тега latest
    D3  финальная стадия переключается на пользователя с числовым UID, не 0
    D4  директива "# syntax=" либо отсутствует, либо закреплена по digest
    D5  нет ADD с загрузкой по сети: такой файл не проверяется ничем.
        Исключение одно — git-репозиторий по полному SHA коммита: сборка
        сама проверяет, что получила именно этот коммит
    D6  финальная стадия построена на distroless: в образе продукта нет shell,
        менеджера пакетов и утилит (ADR-0020)

Каталог deploy/docker — только образы продукта, поэтому D6 действует на все
Dockerfile в нём. Учебные цели (ADR-0019) — намеренно уязвимые приложения
со своим стеком — живут в deploy/demo и проверяются всеми правилами, кроме D6.

Только стандартная библиотека Python: у проверки безопасности не должно
быть собственной цепочки поставки.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Пути от корня репозитория, а не от текущего каталога: проверка должна
# давать один и тот же результат, откуда бы её ни запустили.
ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "deploy" / "compose" / "compose.yaml"
# Сканеры безопасности подчиняются тем же правилам, что и продукт:
# они видят весь исходный код.
SCANNERS_COMPOSE_FILE = ROOT / "tools" / "scanners" / "compose.yaml"
COMPOSE_FILES = (COMPOSE_FILE, SCANNERS_COMPOSE_FILE)
DOCKERFILES_DIR = ROOT / "deploy" / "docker"
DEMO_DIR = ROOT / "deploy" / "demo"

_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
# Префикс, а не список конкретных образов: distroless бывает static, cc,
# python3 и другие, и любой из них удовлетворяет правилу.
_DISTROLESS_PREFIX = "gcr.io/distroless/"
# Git-ссылка в контексте сборки: https://…/repo.git#<ref> или git@…:repo#<ref>.
# Закреплённой считается только ссылка на полный SHA коммита (40 шестнадцатеричных
# знаков), с необязательным подкаталогом после двоеточия.
_GIT_CONTEXT = re.compile(r"^(https?://|git@|git://|ssh://)")
_PINNED_GIT_REF = re.compile(r"#[0-9a-f]{40}(:[^#]*)?$")
_ROOT_USERS = frozenset({"", "0", "root"})
_LOCAL_HOST_IPS = frozenset({"127.0.0.1", "::1"})


@dataclass(frozen=True)
class Violation:
    where: str
    rule: str
    message: str

    def __str__(self) -> str:
        return f"{self.where}: [{self.rule}] {self.message}"


# --------------------------------------------------------------- compose ---


def check_compose(model: dict[str, Any], label: str = "compose") -> list[Violation]:
    """Проверяет нормализованную модель docker compose."""
    violations: list[Violation] = []
    services = model.get("services")
    if not isinstance(services, dict):
        return [Violation(label, "C0", "в модели нет раздела services")]

    for name, service in sorted(services.items()):
        where = f"{label}: сервис {name}"
        violations.extend(_check_service(where, service))

    return violations


def _check_service(where: str, service: dict[str, Any]) -> list[Violation]:
    out: list[Violation] = []
    image = str(service.get("image", ""))
    builds_locally = "build" in service

    # C1. Образ, который мы собираем сами, проверяется через его Dockerfile.
    if not builds_locally and not _DIGEST.search(image):
        out.append(Violation(where, "C1", f"образ {image!r} не закреплён по digest"))

    # C8. Ветку или тег автор чужого репозитория может переписать, и в следующей
    # сборке окажется код, которого никто не видел. Коммит по SHA переписать нельзя.
    if builds_locally:
        build = service.get("build") or {}
        contexts = [str(build.get("context", ""))]
        contexts += [str(v) for v in (build.get("additional_contexts") or {}).values()]
        for ctx in contexts:
            if _GIT_CONTEXT.match(ctx) and not _PINNED_GIT_REF.search(ctx):
                out.append(
                    Violation(
                        where,
                        "C8",
                        f"исходники сборки {ctx!r} не закреплены по полному SHA коммита",
                    )
                )

    # C2.
    if _has_latest_tag(image):
        out.append(Violation(where, "C2", f"образ {image!r} использует тег latest"))

    # C3. Пустой user означает «как в образе», а у многих образов это root.
    user = str(service.get("user", ""))
    if user.split(":", 1)[0] in _ROOT_USERS:
        out.append(
            Violation(where, "C3", "не задан user или задан root; укажите числовой UID явно")
        )

    # C4.
    cap_drop = service.get("cap_drop") or []
    if "ALL" not in [str(c).upper() for c in cap_drop]:
        out.append(Violation(where, "C4", "capabilities не сброшены: нужно cap_drop: [ALL]"))

    # C5.
    security_opt = [str(o).replace("=", ":") for o in service.get("security_opt") or []]
    if "no-new-privileges:true" not in security_opt:
        out.append(
            Violation(where, "C5", 'не запрещено повышение привилегий: "no-new-privileges:true"')
        )

    # C6. Пустой host_ip — это привязка ко всем интерфейсам хоста.
    for port in service.get("ports") or []:
        host_ip = str(port.get("host_ip", ""))
        if host_ip not in _LOCAL_HOST_IPS:
            shown = host_ip or "все интерфейсы"
            out.append(
                Violation(
                    where,
                    "C6",
                    f"порт {port.get('published')} опубликован на {shown}, а не на 127.0.0.1",
                )
            )

    # C7.
    for limit in ("mem_limit", "pids_limit"):
        if not service.get(limit):
            out.append(Violation(where, "C7", f"не задан {limit}"))

    return out


# ------------------------------------------------------------ Dockerfile ---


def check_dockerfile(where: str, text: str, *, product: bool = True) -> list[Violation]:
    """Проверяет текст одного Dockerfile.

    product=False — Dockerfile учебной цели: все правила, кроме D6.
    """
    out: list[Violation] = []

    # D4. Директива syntax читается только из самого начала файла.
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            break
        match = re.match(r"#\s*syntax\s*=\s*(\S+)", stripped)
        if match and not _DIGEST.search(match.group(1)):
            directive = match.group(1)
            out.append(
                Violation(where, "D4", f"директива syntax {directive!r} не закреплена по digest")
            )

    # Имя стадии → базовый образ, от которого она в итоге построена.
    # Нужно для D6: финальная стадия может начинаться с FROM другой стадии,
    # и тогда смотреть надо на образ, с которого началась та.
    stages: dict[str, str] = {}
    final_user: str | None = None
    final_base = ""

    for instruction, args in _instructions(text):
        if instruction == "FROM":
            final_user = None  # USER действует только внутри своей стадии
            image, alias = _parse_from(args)
            is_stage_reference = image.lower() in stages or image == "scratch"
            final_base = stages.get(image.lower(), image)
            if not is_stage_reference and not _DIGEST.search(image):
                out.append(
                    Violation(where, "D1", f"базовый образ {image!r} не закреплён по digest")
                )
            if _has_latest_tag(image):
                out.append(Violation(where, "D2", f"базовый образ {image!r} использует тег latest"))
            if alias:
                stages[alias.lower()] = final_base

        elif instruction == "USER":
            final_user = args.strip()

        elif instruction == "ADD":
            out.extend(_check_add_sources(where, args))

    # D6 — только для образов продукта; учебным целям shell разрешён.
    if product:
        out.extend(_check_distroless(where, final_base))

    # D3.
    if final_user is None:
        out.append(Violation(where, "D3", "в финальной стадии нет USER — процесс будет root"))
    else:
        uid = final_user.split(":", 1)[0]
        if not uid.isdigit() or uid == "0":
            out.append(
                Violation(
                    where,
                    "D3",
                    f"USER {final_user!r}: нужен числовой UID, отличный от 0 "
                    "(Kubernetes runAsNonRoot не может проверить имя)",
                )
            )

    return out


def _check_add_sources(where: str, args: str) -> list[Violation]:
    """D5: ADD по сети — только из git по полному SHA коммита."""
    tokens = [t for t in args.split() if not t.startswith("--")]
    out: list[Violation] = []
    for source in tokens[:-1]:  # последний аргумент — куда копировать
        if not _GIT_CONTEXT.match(source):
            continue  # локальный файл: его содержимое — в нашем репозитории
        if _is_git_source(source) and _PINNED_GIT_REF.search(source):
            continue
        out.append(
            Violation(
                where,
                "D5",
                f"ADD {source!r}: по сети разрешён только git-репозиторий "
                "по полному SHA коммита — содержимое остального ничем не проверяется",
            )
        )
    return out


def _is_git_source(source: str) -> bool:
    """Источник — git-репозиторий, а не файл по HTTP.

    Сборка отличает git по тем же признакам: схема git:// или ssh://, адрес
    вида git@host:repo или путь, оканчивающийся на .git. Иначе ссылка
    http://сайт/архив.tar#<40 знаков> прошла бы как «закреплённая», хотя
    скачивается обычным HTTP без всякой проверки.
    """
    if source.startswith(("git@", "git://", "ssh://")):
        return True
    return source.split("#", 1)[0].endswith(".git")


def _check_distroless(where: str, final_base: str) -> list[Violation]:
    """D6: финальная стадия образа продукта построена на distroless."""
    # scratch тоже без shell, но в нём нет и сертификатов, и пользователя
    # nonroot — ради единообразия требуем именно distroless.
    if final_base and not final_base.startswith(_DISTROLESS_PREFIX):
        return [
            Violation(
                where,
                "D6",
                f"финальная стадия построена на {final_base!r}, а не на distroless: "
                "в образе останутся shell и менеджер пакетов",
            )
        ]
    # Отладочные варианты distroless (теги debug, debug-nonroot) содержат
    # busybox с shell в /busybox/sh. Они для локальной отладки, не для образа
    # продукта: формально distroless, по сути — снова образ с shell.
    if _is_distroless_debug(final_base):
        return [
            Violation(
                where,
                "D6",
                f"финальная стадия построена на отладочном варианте {final_base!r}: "
                "в нём есть shell (/busybox/sh)",
            )
        ]
    return []


def _instructions(text: str) -> list[tuple[str, str]]:
    """Разбивает Dockerfile на инструкции с учётом переносов строк и комментариев."""
    result: list[tuple[str, str]] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buffer and (not line or line.startswith("#")):
            continue
        if line.startswith("#"):
            continue  # комментарий внутри многострочной инструкции
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        buffer += line
        parts = buffer.split(None, 1)
        if parts:
            result.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buffer = ""
    return result


def _parse_from(args: str) -> tuple[str, str | None]:
    """Возвращает образ и имя стадии из аргументов FROM."""
    tokens = [t for t in args.split() if not t.startswith("--")]
    image = tokens[0] if tokens else ""
    alias = tokens[2] if len(tokens) >= 3 and tokens[1].upper() == "AS" else None
    return image, alias


def _is_distroless_debug(image: str) -> bool:
    name = image.split("@", 1)[0]
    last_segment = name.rsplit("/", 1)[-1]
    _, _, tag = last_segment.partition(":")
    return tag.startswith("debug")


def _has_latest_tag(image: str) -> bool:
    name = image.split("@", 1)[0]
    last_segment = name.rsplit("/", 1)[-1]
    return last_segment.endswith(":latest")


# ------------------------------------------------------------------ запуск ---


def load_compose_model(compose_file: Path) -> dict[str, Any]:
    """Нормализованная модель compose от самого Docker, со всеми профилями."""
    # Путь к docker всё равно берётся из PATH: это инструмент разработчика
    # на его собственной машине, где PATH под его контролем. Явный поиск нужен
    # ради понятной ошибки вместо трассировки FileNotFoundError.
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit("docker CLI не найден: он нужен, чтобы получить модель compose")

    completed = subprocess.run(  # noqa: S603 — аргументы фиксированы, shell не используется
        [
            docker,
            "compose",
            "-f",
            str(compose_file),
            "--profile",
            "*",
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    model: dict[str, Any] = json.loads(completed.stdout)
    return model


def main() -> int:
    violations: list[Violation] = []
    for compose_file in COMPOSE_FILES:
        label = str(compose_file.relative_to(ROOT))
        violations.extend(check_compose(load_compose_model(compose_file), label))
    dockerfiles = sorted(DOCKERFILES_DIR.glob("*.Dockerfile"))
    for path in dockerfiles:
        where = str(path.relative_to(ROOT))
        violations.extend(check_dockerfile(where, path.read_text(encoding="utf-8")))
    demo_dockerfiles = sorted(DEMO_DIR.glob("*/Dockerfile"))
    for path in demo_dockerfiles:
        where = str(path.relative_to(ROOT))
        text = path.read_text(encoding="utf-8")
        violations.extend(check_dockerfile(where, text, product=False))
    dockerfiles += demo_dockerfiles

    for violation in violations:
        sys.stderr.write(f"{violation}\n")

    if violations:
        sys.stderr.write(f"\nнарушений политики контейнеров: {len(violations)}\n")
        return 1

    sys.stdout.write(
        f"политика контейнеров соблюдена: {len(COMPOSE_FILES)} compose-файла "
        f"и {len(dockerfiles)} Dockerfile\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
