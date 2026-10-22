include .env
export

CLUSTER_NAME ?= sso-k3s-cluster

.PHONY: up down build ps logs clean init-topics up-prod down-prod benchmark chaos-test k3s-install k3s-up k3s-down k3s-status k3s-apply k3s-benchmark k3s-chaos

up: ## Поднять весь Dev-стек с масштабированием (3x Rust, 3x Go, Frontend, Gateway)
	docker compose up -d --build --scale identity-service=3 --scale user-notification-service=3

down: ## Остановить Dev-стек
	docker compose down

build: ## Собрать все Docker образы
	docker compose build

ps: ## Статус контейнеров
	docker compose ps

logs: ## Логи всех сервисов
	docker compose logs -f

clean: ## Сброс всех данных и томов
	docker compose down -v

init-topics: ## Создать топики в Redpanda
	docker exec sso_redpanda rpk topic create identity.events -p 3 || true
	docker exec sso_redpanda rpk topic create delivery.email -p 3 || true
	docker exec sso_redpanda rpk topic create delivery.telegram -p 3 || true
	docker exec sso_redpanda rpk topic create delivery.dlq -p 1 || true
	docker exec sso_redpanda rpk topic create cloudops.commands -p 3 || true

benchmark: ## Настоящий стресс-бенчмарк: 100 параллельных соединений на 15 секунд до насыщения (Bombardier)
	docker run --rm --network sso_platform_net alpine/bombardier -c 100 -d 15s http://gateway/health

benchmark-oidc: ## Стресс-бенчмарк OIDC discovery эндпоинта под нагрузкой
	docker run --rm --network sso_platform_net alpine/bombardier -c 100 -d 15s http://gateway/.well-known/openid-configuration

chaos-test: ## Запустить Chaos-тест с аварийным убийством контейнера
	node scripts/tests/chaos-test.js

up-prod: ## Запустить изолированный Prod-стек (порты закрыты, только Gateway)
	docker compose -f docker-compose.prod.yml up -d --build

down-prod: ## Остановить Prod-стек
	docker compose -f docker-compose.prod.yml down

# ==============================================================
# k3s / Kubernetes команды (через k3d в Docker Desktop)
# ==============================================================
k3s-install: ## Проверить установку k3d
	@which k3d > /dev/null 2>&1 || (which ~/go/bin/k3d > /dev/null 2>&1) || (echo "k3d не найден. Скачивание..." && curl -sLo /tmp/k3d https://github.com/k3d-io/k3d/releases/download/v5.9.0/k3d-linux-amd64 && install -m 755 /tmp/k3d ~/go/bin/k3d)

k3s-up: k3s-install ## Поднять локальный кластер k3s в Docker и применить манифесты
	@k3d cluster list | grep -q $(CLUSTER_NAME) || k3d cluster create $(CLUSTER_NAME) --port 8088:80@loadbalancer --agents 2
	@echo "Загрузка собранных Docker-образов в кластер k3s..."
	k3d image import sso_platform-identity-service:latest -c $(CLUSTER_NAME)
	k3d image import sso_platform-user-notification-service:latest -c $(CLUSTER_NAME)
	k3d image import sso_platform-frontend:latest -c $(CLUSTER_NAME)
	@echo "Применение манифестов k3s..."
	kubectl apply -f k3s/
	@echo "Ожидание готовности инфраструктуры (PostgreSQL, Redpanda)..."
	@kubectl wait --namespace sso-platform --for=condition=ready pod -l app=postgres --timeout=60s || true
	@kubectl wait --namespace sso-platform --for=condition=ready pod -l app=redpanda --timeout=60s || true
	@echo "Инициализация топиков Kafka внутри k3s..."
	@kubectl exec -n sso-platform deployment/redpanda -- rpk topic create identity.events delivery.email delivery.telegram -p 3 2>/dev/null || true
	@echo "Кластер k3s запущен! Ingress доступен на http://localhost:8088"

k3s-apply: ## Переприменить k3s манифесты
	kubectl apply -f k3s/

k3s-status: ## Просмотр состояния подов и сервисов в k3s
	kubectl get pods,svc,ingress,hpa -n sso-platform -o wide

k3s-down: ## Удалить локальный кластер k3s
	k3d cluster delete $(CLUSTER_NAME)

k3s-benchmark: ## Прогнать бенчмарк по K8s/k3s Ingress (порт 8088)
	BENCHMARK_URL="http://localhost:8088/.well-known/openid-configuration" node scripts/tests/benchmark.js

k3s-chaos: ## Запустить Chaos-тест в k3s (удаление пода Kubernetes под нагрузкой)
	CHAOS_URL="http://localhost:8088/.well-known/openid-configuration" node scripts/tests/chaos-test.js
