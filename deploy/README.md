# Развёртывание

```
docker/sensor.Dockerfile          образ сенсора: distroless, ~4 МБ, без shell
docker/controlplane.Dockerfile    образ control plane: python slim без pip
docker/requirements-build.txt     uv для сборки, с контрольными суммами
compose/compose.yaml              весь стек для локальной разработки
compose/nats.conf                 своя конфигурация NATS вместо файла из образа
compose/secrets/                  локальные секреты; создаются `make secrets`, в git не попадают
```

Запуск — из корня репозитория: `make dev`, `make dev-demo`, `make dev-down`.
Как устроены сети, какие правила действуют для каждого контейнера и почему —
в [docs/guide.md](../docs/guide.md#локальный-стек-docker-compose) и
[ADR-0014](../docs/adr/0014-containers.md).

Правила проверяются автоматически в `make lint` скриптом
[scripts/check_containers.py](../scripts/check_containers.py): образы по digest,
не root, сброшенные capabilities, порты только на 127.0.0.1, лимиты ресурсов.

Helm-чарты и продакшен-манифесты появятся на этапе 10.
