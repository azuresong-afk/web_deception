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
        test test-go test-py test-scripts \
        build run-sensor run-cp clean secrets images smoke dev dev-demo dev-ps dev-logs \
        dev-down dev-reset

help: ## Показать список доступных команд
	@echo "Web-Deception — доступные команды:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

deps: ## Установить зависимости control plane по lock-файлу
	cd $(CP_DIR) && $(UV) sync --all-groups

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

build: ## Собрать бинарник сенсора в bin/
	@mkdir -p $(BIN_DIR)
	cd $(SENSOR_DIR) && $(GO) build \
		-trimpath \
		-ldflags "-s -w -X $(VERSION_PKG).Version=$(VERSION)" \
		-o ../$(BIN_DIR)/sensor ./cmd/sensor
	@echo "Собрано: $(BIN_DIR)/sensor (версия $(VERSION))"

run-sensor: ## Запустить сенсор на 127.0.0.1:9090
	cd $(SENSOR_DIR) && $(GO) run ./cmd/sensor

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
	@$(SCANNERS) hadolint --no-color deploy/docker/sensor.Dockerfile deploy/docker/controlplane.Dockerfile

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

images: ## Собрать образы сенсора и control plane
	VERSION=$(VERSION) $(COMPOSE) build

smoke: ## Поднять стек, убедиться в готовности, остановить и удалить данные
	$(MAKE) dev
	curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/readyz
	$(MAKE) dev-reset

dev: secrets ## Поднять весь стек и дождаться готовности всех сервисов
	VERSION=$(VERSION) $(COMPOSE) up --build --detach --wait
	@$(COMPOSE) ps

dev-demo: secrets ## То же плюс OWASP Juice Shop на 127.0.0.1:3000
	VERSION=$(VERSION) $(COMPOSE) --profile demo up --build --detach --wait
	@$(COMPOSE) --profile demo ps

dev-ps: ## Состояние контейнеров и их проверок здоровья
	$(COMPOSE) --profile demo ps

dev-logs: ## Логи всех сервисов
	$(COMPOSE) --profile demo logs --follow --tail=100

dev-down: ## Остановить стек; данные базы сохраняются
	$(COMPOSE) --profile demo down

dev-reset: ## Остановить стек и удалить данные базы
	$(COMPOSE) --profile demo down --volumes

clean: ## Удалить артефакты сборки и отчёты о покрытии
	rm -rf $(BIN_DIR) $(SENSOR_DIR)/coverage.out $(CP_DIR)/.coverage
