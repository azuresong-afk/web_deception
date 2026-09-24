# Образ control plane.
#
# Как и у сенсора: без строки "# syntax=..." (незакреплённый образ-интерпретатор
# с Docker Hub), сборка в две стадии, базовые образы по digest.
#
# Рантайм — distroless (ADR-0020): в образе только интерпретатор Python
# и библиотеки, без которых он не запустится. Нет shell, менеджера пакетов,
# perl и прочих утилит — ни для атакующего, получившего выполнение кода,
# ни для сканера уязвимостей, который находил в них 44 уязвимости HIGH
# без исправлений (риск R5).

# ---------------------------------------------------------------- сборка ---
# Официальный образ Python той же минорной версии, что и в рантайме (3.13).
# Патч-версии различаются: здесь свежая 3.13.x, в рантайме — 3.13 из Debian 13.
# Это допустимо: внутри одной минорной версии совпадают и формат байткода .pyc,
# и двоичный интерфейс (ABI), под который собраны пакеты с машинным кодом
# вроде pydantic-core. Другая минорная версия (3.12, 3.14) уже несовместима.
FROM python:3.13-slim-trixie@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0 AS build

# uv с проверкой контрольных сумм. --only-binary запрещает сборку из исходников:
# сборка из исходников — это исполнение чужого setup-кода во время установки.
COPY deploy/docker/requirements-build.txt /tmp/requirements-build.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
        -r /tmp/requirements-build.txt

# UV_PYTHON_DOWNLOADS=never — использовать Python из образа и ничего не скачивать.
ENV UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

WORKDIR /app
COPY controlplane/pyproject.toml controlplane/uv.lock ./

# Зависимости ставятся не в виртуальное окружение, а в обычный каталог.
# Виртуальное окружение привязано к пути интерпретатора, на котором создано
# (здесь /usr/local/bin/python3.13), а в рантайме Python лежит в /usr/bin.
# Каталогу с пакетами путь интерпретатора безразличен.
#
# uv export — список зависимостей строго по uv.lock, с хешем каждого файла.
# --require-hashes — установка откажется от файла, хеш которого не совпал.
# --no-dev — без pytest, mypy, ruff: инструменты разработки в продакшене
# только расширяют поверхность атаки. --only-binary — снова без сборки
# из исходников. --compile-bytecode — заранее скомпилировать .pyc: в рантайме
# файловая система только для чтения, и Python не сможет создать кеш сам.
RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt \
        --output-file /tmp/requirements.txt \
 && uv pip install --no-deps --require-hashes --only-binary :all: \
        --compile-bytecode --target /app/deps -r /tmp/requirements.txt

COPY controlplane/src ./src
RUN python -m compileall -q ./src

# -------------------------------------------------------------- рантайм ---
# Тег nonroot — вариант образа, где пользователь по умолчанию 65532, а не root.
# Мы всё равно задаём USER явно ниже: проверка политики контейнеров (D3)
# требует числовой UID в самом Dockerfile, а не в чужом образе.
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:8ee214843129f43e2ebf5e0ca9f2e4e6d8292143d1b8a6787f169b5898578884

# Файлы приложения принадлежат root и доступны только для чтения. Процесс
# приложения работает от непривилегированного пользователя и не может изменить
# собственный код: атакующий, получивший выполнение кода, не закрепится
# подменой файлов.
COPY --from=build /app/deps /app/deps
COPY --from=build /app/src /app/src

# PYTHONPATH — где искать наш код и зависимости (вместо виртуального окружения).
# PYTHONSAFEPATH — не добавлять в пути поиска модулей текущий каталог. Без него
# `python -m` сначала ищет модули в рабочем каталоге, и файл с именем
# стандартного модуля, оказавшийся там, был бы импортирован вместо настоящего.
ENV PYTHONPATH="/app/src:/app/deps" \
    PYTHONSAFEPATH=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
USER 65532:65532

# Проверка здоровья — модуль на Python, а не curl: в образе нет ни curl,
# ни shell, и форма CMD ["..."] запускает программу напрямую, без shell.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/bin/python3", "-m", "webdeception_cp.healthcheck"]

ENTRYPOINT ["/usr/bin/python3", "-m", "webdeception_cp"]
