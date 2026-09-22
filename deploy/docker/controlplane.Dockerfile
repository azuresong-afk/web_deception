# Образ control plane.
#
# Как и у сенсора: без строки "# syntax=..." (незакреплённый образ-интерпретатор
# с Docker Hub), сборка в две стадии, базовые образы по digest.

# ---------------------------------------------------------------- сборка ---
FROM python:3.12-slim-trixie@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS build

# uv с проверкой контрольных сумм. --only-binary запрещает сборку из исходников:
# сборка из исходников — это исполнение чужого setup-кода во время установки.
COPY deploy/docker/requirements-build.txt /tmp/requirements-build.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
        -r /tmp/requirements-build.txt

# UV_COMPILE_BYTECODE — заранее скомпилировать .pyc: в рантайме файловая система
# будет только для чтения, и Python не сможет создать кеш сам.
# UV_PYTHON_DOWNLOADS=never — использовать Python из образа и ничего не скачивать.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# --frozen — установка строго по uv.lock: без пересчёта версий и с проверкой
# контрольной суммы каждого пакета. --no-dev — без pytest, mypy, ruff:
# инструменты разработки в продакшене только расширяют поверхность атаки.
COPY controlplane/pyproject.toml controlplane/uv.lock ./
RUN uv sync --frozen --no-dev

COPY controlplane/src ./src
RUN python -m compileall -q ./src

# -------------------------------------------------------------- рантайм ---
FROM python:3.12-slim-trixie@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

# pip удаляется из рантайма. Зависимости уже установлены на стадии сборки,
# а оставленный pip — готовый инструмент для атакующего, получившего выполнение
# кода: одна команда, и в контейнере любые его утилиты. Найдено при проверке
# собранного образа: из окружения приложения pip не виден, но в базовом
# образе он лежит отдельно.
#
# Отдельный системный пользователь без домашнего каталога и без shell входа.
# Числовой UID — по той же причине, что у сенсора (runAsNonRoot в Kubernetes).
RUN python -m pip uninstall --yes --quiet pip \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

# Файлы приложения принадлежат root и доступны только для чтения. Процесс
# приложения работает от пользователя app и не может изменить собственный код:
# атакующий, получивший выполнение кода, не закрепится подменой файлов.
COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/src /app/src

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
USER 10001:10001

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-m", "webdeception_cp.healthcheck"]

ENTRYPOINT ["python", "-m", "webdeception_cp"]
