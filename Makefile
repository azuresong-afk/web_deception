# Makefile — единая точка входа для всех проверок и команд проекта.
#
# Зачем он нужен: команды запуска линтеров, тестов и сканеров должны быть
# одинаковыми на вашей машине, у меня и в CI. Если они расходятся, появляется
# классическая ситуация «локально зелено, в CI красно» — и доверие к проверкам
# пропадает, а вместе с ним и польза от них.
#
# Целей `security` и `dev` здесь пока нет намеренно: проверок и стека ещё
# не существует, а цель, которая ничего не делает и печатает «успех»,
# опаснее отсутствующей цели.

GO ?= go
SENSOR_DIR := sensor
BIN_DIR := bin

# Минимальное покрытие кода сенсора тестами, в процентах.
#
# Порог намеренно умеренный. Покрытие измеряет «какие строки выполнились»,
# а не «что проверено»: высокий порог заставляет писать тесты ради процентов,
# и такие тесты создают ложную уверенность. Порог здесь — сигнализация
# о крупных непроверенных кусках, а не цель сама по себе.
COVERAGE_MIN ?= 70

# Версия сборки: ближайший тег git, иначе короткий хеш коммита.
# Подставляется в бинарник и видна только в логах — в HTTP-ответы
# версия не попадает никогда (угроза T5).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION_PKG := github.com/azuresong-afk/web_deception/sensor/internal/version

.DEFAULT_GOAL := help

# .PHONY говорит make, что это имена команд, а не файлов. Без этого
# `make test` сломается в тот день, когда в корне появится каталог `test`:
# make решит, что цель уже собрана, и ничего не запустит.
.PHONY: help fmt lint test build run-sensor clean

help: ## Показать список доступных команд
	@echo "Web-Deception — доступные команды:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Появятся по ходу этапа 1:"
	@echo "  dev            поднять весь стек локально          (шаг 4)"
	@echo "  security       gitleaks, semgrep, govulncheck,"
	@echo "                 pip-audit, trivy                    (шаг 6)"

fmt: ## Отформатировать код Go
	cd $(SENSOR_DIR) && $(GO) fmt ./...

lint: ## Проверить форматирование и типовые ошибки Go
	@echo "==> gofmt: проверка форматирования"
	@unformatted="$$(cd $(SENSOR_DIR) && gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "Файлы не отформатированы, запустите make fmt:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "==> go vet: поиск типовых ошибок"
	@cd $(SENSOR_DIR) && $(GO) vet ./...
	@echo "OK. Полный линтер golangci-lint подключается в CI на шаге 5."

test: ## Прогнать тесты с детектором гонок и проверить покрытие
	@echo "==> go test -race"
	@cd $(SENSOR_DIR) && $(GO) test -race -covermode=atomic -coverprofile=coverage.out ./...
	@echo "==> покрытие"
	@cd $(SENSOR_DIR) && $(GO) tool cover -func=coverage.out | tail -1
	@cd $(SENSOR_DIR) && $(GO) tool cover -func=coverage.out \
		| awk -v min=$(COVERAGE_MIN) '/^total:/ { gsub("%", "", $$3); \
			if ($$3 + 0 < min) { printf "покрытие %.1f%% ниже порога %d%%\n", $$3, min; exit 1 } }'

build: ## Собрать бинарник сенсора в bin/
	@mkdir -p $(BIN_DIR)
	cd $(SENSOR_DIR) && $(GO) build \
		-trimpath \
		-ldflags "-s -w -X $(VERSION_PKG).Version=$(VERSION)" \
		-o ../$(BIN_DIR)/sensor ./cmd/sensor
	@echo "Собрано: $(BIN_DIR)/sensor (версия $(VERSION))"

run-sensor: ## Запустить сенсор локально на 127.0.0.1:9090
	cd $(SENSOR_DIR) && $(GO) run ./cmd/sensor

clean: ## Удалить артефакты сборки и отчёты о покрытии
	rm -rf $(BIN_DIR) $(SENSOR_DIR)/coverage.out
