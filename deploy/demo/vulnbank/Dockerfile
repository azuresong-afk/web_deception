# Образ учебной цели VulnBank (ADR-0019).
#
# Это НЕ образ продукта. VulnBank — намеренно уязвимое банковское приложение
# на Flask, за которым проверяется сенсор. Уязвимости внутри приложения —
# ожидаемы, ради них его и берут. Задача этого файла — чтобы они не вышли
# за пределы контейнера (угроза T16).
#
# Штатный Dockerfile автора не используется: в нём образ по тегу, установка
# зависимостей без проверки хешей, запуск от root и каталог загрузок с правами
# 777. Здесь то же приложение собирается по правилам проекта:
#   - исходники — по полному SHA коммита (контекст vulnbank-src в compose);
#   - базовый образ — по digest;
#   - зависимости — только готовые колёса с проверкой хешей;
#   - процесс — не от root.
#
# Python 3.12, а не 3.13, как у продукта: VulnBank закрепил psycopg2-binary
# 2.9.9, для которого нет готовых колёс под 3.13, а собирать его из исходников
# значило бы исполнять чужой код сборки.

# ---------------------------------------------------------------- сборка ---
FROM python:3.12-slim-trixie@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS build

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
        --target /deps -r /tmp/requirements.txt

# -------------------------------------------------------------- рантайм ---
FROM python:3.12-slim-trixie@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

# Пользователь с записью в /etc/passwd: отладчик Werkzeug при старте ищет
# имя пользователя по UID. pip удаляется: зависимости уже установлены,
# а pip — готовый инструмент для того, кто получит выполнение кода.
RUN python -m pip uninstall --yes --quiet pip \
 && groupadd --system --gid 10001 vulnbank \
 && useradd --system --uid 10001 --gid vulnbank --no-create-home \
        --shell /usr/sbin/nologin vulnbank

COPY --from=build /deps /deps

# Исходники приходят из именованного контекста vulnbank-src — репозитория
# автора, закреплённого в compose по SHA коммита. Файлы принадлежат root:
# процесс приложения не может изменить собственный код.
#
# Исключение hadolint DL3022 — только на эту строку. Правило требует, чтобы
# COPY --from ссылался на стадию FROM, и ловит опечатки в имени стадии.
# Здесь ссылка на именованный контекст сборки BuildKit, о котором hadolint
# не знает; опечатку в его имени не пропустит сама сборка («not found»).
# Обход через FROM vulnbank-src нарушил бы правило D1 (образ по digest).
# hadolint ignore=DL3022
COPY --from=vulnbank-src . /app

ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
USER 10001:10001
EXPOSE 5000

# Автор запускает приложение через start.sh, который ждёт базу командой
# pg_isready. Здесь это делает compose (depends_on: service_healthy),
# и клиент PostgreSQL в образе не нужен.
CMD ["python", "app.py"]
