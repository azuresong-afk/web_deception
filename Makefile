# Makefile — единая точка входа для всех проверок и команд проекта.
#
# Зачем он нужен: команды запуска линтеров, тестов и сканеров должны быть
# одинаковыми на вашей машине, у меня и в CI. Если они расходятся, появляется
# классическая ситуация «локально зелено, в CI красно» — и доверие к проверкам
# пропадает, а вместе с ним и польза от них.
#
# `make security` запускает все проверки безопасности, кроме CodeQL: его
# анализ требует большой загрузки и выполняется только в CI.

GO ?= go
UV ?= uv
SENSOR_DIR := sensor
CP_DIR := controlplane
BIN_DIR := bin
COMPOSE := docker compose -f deploy/compose/compose.yaml

# Инструменты Go запускаются из модулей в tools/: версия каждого и контрольные
# суммы всех его зависимостей закреплены в go.sum, поэтому у вас, у меня
# и в CI это один и тот же бинарник. Первый запуск собирает инструмент
# (около минуты), дальше он берётся из кеша сборки Go.
#
# У каждого инструмента свой модуль. В общем модуле Go выбирает для общей
# зависимости максимальную из нужных версий — так golangci-lint притянул
# новую YAML-библиотеку, с которой actionlint перестал компилироваться.
GOLANGCI := $(GO) tool -modfile=../tools/golangci-lint/go.mod golangci-lint

# Сканеры в контейнерах: версии образов, ограничения и отключённая сеть
# описаны в tools/scanners/compose.yaml. UID и GID передаются, чтобы
# сканеры работали не от root и создавали файлы от имени пользователя.
# SCANNER_RUN_ARGS — дополнительные аргументы docker compose run, например
# сертификат корпоративного прокси с перехватом TLS.
SCANNER_RUN_ARGS ?=
SCANNERS := SCANNER_UID=$$(id -u) SCANNER_GID=$$(id -g) \
	docker compose -f tools/scanners/compose.yaml run --rm --quiet-pull $(SCANNER_RUN_ARGS)

# База уязвимостей Go. Переменная — чтобы можно было указать зеркало там,
# где официальный адрес закрыт (например, в корпоративной сети с прокси).
GOVULNDB ?= https://vuln.go.dev

# Минимальное покрытие кода сенсора тестами, в процентах.
#
# Покрытие измеряет «какие строки выполнились», а не «что проверено»:
# высокий порог заставляет писать тесты ради процентов, и такие тесты
# создают ложную уверенность. Порог — сигнализация о крупных непроверенных
# кусках, а не цель. Для Python порог выше (80 %) и задан в pyproject.toml:
# Python не проверяет типы при запуске, и тесты берут на себя часть работы,
# которую в Go делает компилятор.
COVERAGE_MIN ?= 70

# Версия сборки: ближайший тег git, иначе короткий хеш коммита.
# Видна только в логах — в HTTP-ответы версия не попадает (угроза T5).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION_PKG := github.com/azuresong-afk/web_deception/sensor/internal/version

.DEFAULT_GOAL := help

.PHONY: help deps fmt fmt-go fmt-py lint lint-go lint-py lint-containers lint-workflows \
        security security-secrets security-go security-py security-sast \
        security-containers security-dockerfiles security-images \
        test test-go test-py test-scripts test-hooks hooks \
        build run-sensor run-cp clean secrets images check-images smoke smoke-events dev dev-demo dev-vulnbank \
        dev-ps dev-logs dev-down dev-reset vulnbank-requirements

help: ## Показать список доступных команд
	@echo "Web-Deception — доступные команды:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

deps: ## Установить зависимости control plane по lock-файлу
	cd $(CP_DIR) && $(UV) sync --all-groups

# Git не устанавливает хуки из репозитория автоматически — иначе клонирование
# чужого репозитория запускало бы чужой код. Поэтому включаются явно, один раз
# на клон. Настройка пишется в .git/config этого клона и никуда не уходит.
hooks: ## Включить git-хуки: секреты и формат перед коммитом, формат сообщения
	git config core.hooksPath .githooks
	@echo "Хуки включены: .githooks/pre-commit и .githooks/commit-msg"

fmt: fmt-go fmt-py ## Отформатировать весь код

fmt-go:
	cd $(SENSOR_DIR) && $(GOLANGCI) fmt ./...

fmt-py:
	cd $(CP_DIR) && $(UV) run ruff format . ../scripts
	cd $(CP_DIR) && $(UV) run ruff check --fix . ../scripts

lint: lint-go lint-py lint-containers lint-workflows ## Формат, стиль, типы, политика контейнеров, workflow

lint-go:
	@echo "==> sensor: golangci-lint (включая gofmt, go vet, gosec)"
	@cd $(SENSOR_DIR) && $(GOLANGCI) run ./...
	@echo "==> go.mod и go.sum соответствуют коду"
	@# tidy -diff падает, если go.mod или go.sum нужно поправить: в репозиторий
	@# не должна попасть зависимость, которой нет в go.sum, и лишняя, которой
	@# не пользуется код.
	@cd $(SENSOR_DIR) && $(GO) mod tidy -diff
	@for tool in golangci-lint actionlint gitleaks govulncheck; do \
		(cd tools/$$tool && $(GO) mod tidy -diff) || exit 1; \
	done

lint-py:
	@echo "==> control plane и scripts: ruff"
	@cd $(CP_DIR) && $(UV) run ruff check . ../scripts
	@cd $(CP_DIR) && $(UV) run ruff format --check . ../scripts
	@echo "==> control plane и scripts: mypy"
	@cd $(CP_DIR) && $(UV) run mypy
	@cd $(CP_DIR) && $(UV) run mypy --strict ../scripts

# Workflow GitHub Actions — тоже код, причём с правами на репозиторий:
# опечатка в условии или в permissions тихо ослабляет CI.
lint-workflows:
	@echo "==> workflow: actionlint"
	@# Запуск из каталога модуля: -modfile требует go.mod в текущем каталоге,
	@# а в корне репозитория его нет. Файлы workflow передаются явно.
	@cd tools/actionlint && $(GO) tool actionlint ../../.github/workflows/*.yml

# Правила CLAUDE.md про контейнеры как проверка: digest вместо тегов, не root,
# сброшенные capabilities, порты только на 127.0.0.1. Нужен docker CLI.
lint-containers:
	@echo "==> политика контейнеров"
	@$(UV) run --project $(CP_DIR) python scripts/check_containers.py

test: test-go test-py test-scripts ## Прогнать все тесты с проверкой покрытия

test-go:
	@echo "==> sensor: go test -race"
	@cd $(SENSOR_DIR) && $(GO) test -race -covermode=atomic -coverprofile=coverage.out ./...
	@cd $(SENSOR_DIR) && $(GO) tool cover -func=coverage.out | tail -1
	@cd $(SENSOR_DIR) && $(GO) tool cover -func=coverage.out \
		| awk -v min=$(COVERAGE_MIN) '/^total:/ { gsub("%", "", $$3); \
			if ($$3 + 0 < min) { printf "покрытие %.1f%% ниже порога %d%%\n", $$3, min; exit 1 } }'

test-py:
	@echo "==> control plane: pytest"
	@cd $(CP_DIR) && $(UV) run pytest --cov --cov-report=term-missing

test-scripts:
	@echo "==> scripts: unittest"
	@$(UV) run --project $(CP_DIR) python -m unittest discover -s scripts

# Хуки проверяются по-настоящему: во временном репозитории делаются коммиты
# с секретом, с неотформатированным кодом и с плохим сообщением. Нужен Go
# (для gitleaks), поэтому в CI этот тест идёт в задании Go.
test-hooks:
	@echo "==> git-хуки: интеграционный тест"
	@python3 scripts/hooks_test.py

build: ## Собрать бинарник сенсора в bin/
	@mkdir -p $(BIN_DIR)
	cd $(SENSOR_DIR) && $(GO) build \
		-trimpath \
		-ldflags "-s -w -X $(VERSION_PKG).Version=$(VERSION)" \
		-o ../$(BIN_DIR)/sensor ./cmd/sensor
	@echo "Собрано: $(BIN_DIR)/sensor (версия $(VERSION))"

# Адрес приложения для make run-sensor. Сенсор без него не стартует:
# значения по умолчанию в самом сенсоре нет намеренно (ADR-0021).
SENSOR_UPSTREAM_URL ?= http://127.0.0.1:3000
# Файл событий для make run-sensor. Каталог /var/lib/sensor есть только
# в образе; при запуске на машине разработчика события пишутся сюда.
# Каталог в .gitignore: в событиях адреса клиентов.
SENSOR_EVENTS_FILE ?= $(CURDIR)/.run/events.jsonl

run-sensor: ## Запустить сенсор: 127.0.0.1:8080 → SENSOR_UPSTREAM_URL, служебный 127.0.0.1:9090, события в .run/
	@mkdir -p -m 700 "$(dir $(SENSOR_EVENTS_FILE))"
	cd $(SENSOR_DIR) && SENSOR_LISTEN_ADDR=127.0.0.1:8080 SENSOR_UPSTREAM_URL=$(SENSOR_UPSTREAM_URL) \
		SENSOR_EVENTS_FILE=$(SENSOR_EVENTS_FILE) $(GO) run ./cmd/sensor

run-cp: ## Запустить control plane на 127.0.0.1:8000
	cd $(CP_DIR) && PYTHONPATH=src $(UV) run python -m webdeception_cp

# --- Проверки безопасности -------------------------------------------------

security: security-secrets security-go security-py security-sast security-containers ## Проверки безопасности: секреты, уязвимости, SAST, образы

# gitleaks по всей истории git, а не только по текущим файлам: удалённый
# в следующем коммите секрет остаётся в истории навсегда. --redact скрывает
# найденные значения в выводе — логи CI публичного репозитория видны всем.
security-secrets:
	@echo "==> секреты в истории git: gitleaks"
	@cd tools/gitleaks && $(GO) tool gitleaks git --config ../../.gitleaks.toml \
		--redact --no-banner ../..

# govulncheck проверяет не просто «есть ли уязвимая версия в зависимостях»,
# а «вызывает ли наш код уязвимую функцию» — анализ достижимости. Падает
# только на реально достижимых уязвимостях, остальные упоминает для сведения.
# Стандартная библиотека Go тоже проверяется: уязвимость в net/http
# сенсора — это уязвимость сенсора.
security-go:
	@echo "==> уязвимости Go: govulncheck"
	@cd $(SENSOR_DIR) && $(GO) tool -modfile=../tools/govulncheck/go.mod govulncheck \
		-db $(GOVULNDB) ./...

# pip-audit проверяет ВСЕ зависимости из uv.lock, включая группу разработки:
# инструменты разработки исполняются в CI и на машинах разработчиков, и уязвимость
# в них — тоже путь внутрь. Проверка идёт по экспорту lock-файла с контрольными
# суммами, ничего не устанавливая (--disable-pip).
CP_REQUIREMENTS := $(CP_DIR)/.requirements-audit.txt
security-py:
	@echo "==> уязвимости Python: pip-audit"
	@cd $(CP_DIR) && $(UV) export --frozen --all-groups --no-emit-project \
		--format requirements.txt --quiet -o .requirements-audit.txt
	@cd $(CP_DIR) && $(UV) run pip-audit --requirement .requirements-audit.txt \
		--require-hashes --disable-pip --strict --progress-spinner off
	@rm -f $(CP_REQUIREMENTS)

# Собственные правила Semgrep из tools/semgrep/rules. Сначала тесты самих
# правил: каждое обязано сработать на примерах нарушений и промолчать
# на корректном коде. Правило без такого теста может не работать вовсе
# и всё равно показывать «чисто». Потом — проверка кода проекта.
# --metrics=off: Semgrep по умолчанию отправляет статистику использования.
SEMGREP_FLAGS := --metrics=off --disable-version-check
security-sast:
	@echo "==> собственные правила Semgrep: тесты правил"
	@$(SCANNERS) semgrep --test $(SEMGREP_FLAGS) tools/semgrep/rules
	@echo "==> собственные правила Semgrep: код проекта"
	@$(SCANNERS) semgrep scan --config tools/semgrep/rules $(SEMGREP_FLAGS) --error --quiet .

security-containers: security-dockerfiles images security-images

security-dockerfiles:
	@echo "==> Dockerfile: hadolint"
	@$(SCANNERS) hadolint --no-color deploy/docker/sensor.Dockerfile deploy/docker/controlplane.Dockerfile \
		deploy/demo/vulnbank/Dockerfile

# Trivy сканирует уже собранные образы (make images). Образы передаются
# ему файлами, а не через сокет Docker: сокет — это полный контроль над хостом.
#
# Политика: проверка падает на уязвимостях HIGH и CRITICAL, для которых есть
# исправление. Уязвимости без исправления показываются в сводке, но не валят
# проверку: обновиться не на что, а постоянно красный CI приучает его не
# читать. Это осознанно принятый риск — см. ADR-0016.
TRIVY_FLAGS := image --scanners vuln --severity HIGH,CRITICAL --no-progress
security-images:
	@mkdir -p bin/images .cache/trivy
	@docker save webdeception/sensor:dev -o bin/images/sensor.tar
	@docker save webdeception/controlplane:dev -o bin/images/controlplane.tar
	@echo "==> образы: Trivy, сводка HIGH и CRITICAL, включая без исправлений"
	@$(SCANNERS) trivy $(TRIVY_FLAGS) --table-mode summary --input /src/bin/images/sensor.tar
	@$(SCANNERS) trivy $(TRIVY_FLAGS) --table-mode summary --skip-db-update --input /src/bin/images/controlplane.tar
	@echo "==> образы: Trivy, проверка — уязвимости с доступным исправлением"
	@$(SCANNERS) trivy $(TRIVY_FLAGS) --ignore-unfixed --exit-code 1 --skip-db-update --input /src/bin/images/sensor.tar
	@$(SCANNERS) trivy $(TRIVY_FLAGS) --ignore-unfixed --exit-code 1 --skip-db-update --input /src/bin/images/controlplane.tar
	@rm -f bin/images/sensor.tar bin/images/controlplane.tar

# --- Локальный стек в docker compose ---------------------------------------

secrets: ## Создать локальные секреты (существующие не перезаписываются)
	@sh scripts/gen-secrets.sh

# Профиль demo нужен и здесь: сенсор объявлен в нём вместе с учебной целью,
# и без профиля compose его образ не собрал бы.
images: ## Собрать образы сенсора и control plane
	VERSION=$(VERSION) $(COMPOSE) --profile demo build

# Образы продукта без shell и утилит (ADR-0020). Правило D6 в make lint
# проверяет Dockerfile; эта проверка — то, что на самом деле оказалось
# в собранном образе. Каждую программу пытаемся запустить: Docker возвращает
# код 127, если её в образе нет. Любой другой код — провал: 0 значит,
# что программа есть и выполнилась, 125 — что образа нет и проверять нечего.
PRODUCT_IMAGES := webdeception/sensor:dev webdeception/controlplane:dev
# /busybox/sh — shell в отладочных вариантах distroless (теги debug).
FORBIDDEN_IN_IMAGES := /bin/sh /bin/bash /bin/dash /bin/ash /bin/busybox /busybox/sh \
	/usr/bin/perl /usr/bin/apt-get /usr/bin/pip /usr/bin/curl /usr/bin/wget

check-images: ## Убедиться, что в собранных образах продукта нет shell и утилит
	@for img in $(PRODUCT_IMAGES); do \
		for prog in $(FORBIDDEN_IN_IMAGES); do \
			docker run --rm --network none --entrypoint "$$prog" "$$img" >/dev/null 2>&1; \
			rc=$$?; \
			if [ "$$rc" -ne 127 ]; then \
				echo "$$img: $$prog — код $$rc, ожидался 127 (программы в образе нет)"; \
				exit 1; \
			fi; \
		done; \
	done
	@echo "==> в образах продукта нет shell, perl, apt, pip, curl и wget"

# Сквозная проверка: запросы к обоим сенсорам доходят до своих учебных целей,
# и клиент получает их страницы. Это единственная проверка, что сенсор работает
# как прокси в настоящем стеке, с нашими ограничениями контейнеров и сетей,
# и что обе цели вообще собираются и запускаются.
smoke: ## Поднять стек с обеими учебными целями за сенсорами, проверить путь запроса, остановить
	$(MAKE) dev-demo
	$(MAKE) dev-vulnbank
	curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/readyz
	curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8080/ | grep -q "OWASP Juice Shop"
	@echo "==> запрос через сенсор дошёл до Juice Shop"
	curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8081/ | grep -q "VulnBank"
	@echo "==> запрос через сенсор дошёл до VulnBank"
	$(MAKE) smoke-events
	$(MAKE) check-images
	$(MAKE) dev-reset

# Попытка CONNECT должна стать событием в файле внутри контейнера. Так
# проверяется весь путь: права каталога в образе, том, буфер, запись.
# В образе нет shell и cat, поэтому файл забираем через docker compose cp
# (он отдаёт tar) и распаковываем в stdout.
smoke-events:
	@test "$$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
		--request CONNECT --request-target 10.0.0.1:22 http://127.0.0.1:8080)" = 405
	@for i in 1 2 3 4 5; do \
		$(COMPOSE) --profile demo cp sensor-juice:/var/lib/sensor/events.jsonl - 2>/dev/null \
			| tar -xO | grep -q '"type":"request.connect_rejected"' && break; \
		if [ "$$i" -eq 5 ]; then echo "событие о CONNECT не появилось в файле событий"; exit 1; fi; \
		sleep 1; \
	done
	@echo "==> попытка CONNECT записана в файл событий"

dev: secrets ## Поднять control plane, PostgreSQL и NATS и дождаться готовности
	VERSION=$(VERSION) $(COMPOSE) up --build --detach --wait
	@$(COMPOSE) ps

dev-demo: secrets ## То же плюс OWASP Juice Shop за сенсором на 127.0.0.1:8080
	VERSION=$(VERSION) $(COMPOSE) --profile demo up --build --detach --wait
	@$(COMPOSE) --profile demo ps

# Учебная цель VulnBank (ADR-0019) — отдельный профиль, а не часть demo:
# её образ собирается из исходников автора, и первый запуск заметно дольше.
# В CI она проверяется вместе с Juice Shop в make smoke.
dev-vulnbank: secrets ## То же, что dev, плюс VulnBank за сенсором на 127.0.0.1:8081
	VERSION=$(VERSION) $(COMPOSE) --profile demo-vulnbank up --build --detach --wait
	@$(COMPOSE) --profile demo-vulnbank ps

# Команды ниже видят сервисы всех профилей: иначе dev-down оставил бы
# работать учебную цель, поднятую другой командой.
ALL_PROFILES := --profile demo --profile demo-vulnbank

dev-ps: ## Состояние контейнеров и их проверок здоровья
	$(COMPOSE) $(ALL_PROFILES) ps

dev-logs: ## Логи всех сервисов
	$(COMPOSE) $(ALL_PROFILES) logs --follow --tail=100

dev-down: ## Остановить стек; данные базы сохраняются
	$(COMPOSE) $(ALL_PROFILES) down

dev-reset: ## Остановить стек и удалить данные базы
	$(COMPOSE) $(ALL_PROFILES) down --volumes

# Список зависимостей VulnBank с хешами. Пересобирать при смене коммита
# VulnBank (см. deploy/demo/README.md). --only-binary — только готовые колёса:
# сборка из исходников исполняла бы чужой код.
vulnbank-requirements: ## Пересобрать deploy/demo/vulnbank/requirements.txt с хешами
	cd deploy/demo/vulnbank && $(UV) pip compile requirements.in \
		--generate-hashes --universal --python-version 3.12 --only-binary :all: \
		--custom-compile-command "make vulnbank-requirements" -o requirements.txt

clean: ## Удалить артефакты сборки и отчёты о покрытии
	rm -rf $(BIN_DIR) $(SENSOR_DIR)/coverage.out $(CP_DIR)/.coverage
