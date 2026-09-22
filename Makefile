# Makefile — единая точка входа для всех проверок и команд проекта.
#
# Зачем он нужен: команды запуска линтеров, тестов и сканеров должны быть
# одинаковыми на вашей машине, у меня и в CI. Если они расходятся, появляется
# классическая ситуация «локально зелено, в CI красно» — и доверие к проверкам
# пропадает, а вместе с ним и польза от них.
#
# Цели `security` появится на шаге 6. Пока её нет намеренно: цель, которая
# ничего не делает и печатает «успех», опаснее отсутствующей.

GO ?= go
UV ?= uv
SENSOR_DIR := sensor
CP_DIR := controlplane
BIN_DIR := bin
COMPOSE := docker compose -f deploy/compose/compose.yaml

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

.PHONY: help deps fmt fmt-go fmt-py lint lint-go lint-py lint-containers \
        test test-go test-py test-scripts \
        build run-sensor run-cp clean secrets dev dev-demo dev-ps dev-logs dev-down dev-reset

help: ## Показать список доступных команд
	@echo "Web-Deception — доступные команды:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Появится по ходу этапа 1:"
	@echo "  security     gitleaks, semgrep, govulncheck,"
	@echo "               pip-audit, trivy                    (шаг 6)"

deps: ## Установить зависимости control plane по lock-файлу
	cd $(CP_DIR) && $(UV) sync --all-groups

fmt: fmt-go fmt-py ## Отформатировать весь код

fmt-go:
	cd $(SENSOR_DIR) && $(GO) fmt ./...

fmt-py:
	cd $(CP_DIR) && $(UV) run ruff format . ../scripts
	cd $(CP_DIR) && $(UV) run ruff check --fix . ../scripts

lint: lint-go lint-py lint-containers ## Проверить формат, стиль, типы и политику контейнеров

lint-go:
	@echo "==> sensor: gofmt"
	@unformatted="$$(cd $(SENSOR_DIR) && gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "Файлы не отформатированы, запустите make fmt:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "==> sensor: go vet"
	@cd $(SENSOR_DIR) && $(GO) vet ./...
	@echo "OK. Полный линтер golangci-lint подключается в CI на шаге 5."

lint-py:
	@echo "==> control plane и scripts: ruff"
	@cd $(CP_DIR) && $(UV) run ruff check . ../scripts
	@cd $(CP_DIR) && $(UV) run ruff format --check . ../scripts
	@echo "==> control plane и scripts: mypy"
	@cd $(CP_DIR) && $(UV) run mypy
	@cd $(CP_DIR) && $(UV) run mypy --strict ../scripts

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

# --- Локальный стек в docker compose ---------------------------------------

secrets: ## Создать локальные секреты (существующие не перезаписываются)
	@sh scripts/gen-secrets.sh

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
