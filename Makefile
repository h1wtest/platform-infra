include .env
export

.PHONY: up down ps logs clean init-topics

up: ## Поднять всю инфраструктуру в фоне
	docker compose up -d

down: ## Остановить контейнеры (данные сохраняются)
	docker compose down

clean: ## Полный сброс: остановить и УДАЛИТЬ все тома с данными
	docker compose down -v

ps: ## Статус контейнеров
	docker compose ps

logs: ## Просмотр логов всех сервисов
	docker compose logs -f

init-topics: ## Создать базовые топики Kafka для нашей архитектуры
	docker exec sso_redpanda rpk topic create identity.events -p 3
	docker exec sso_redpanda rpk topic create delivery.email -p 3
	docker exec sso_redpanda rpk topic create delivery.telegram -p 3
	docker exec sso_redpanda rpk topic create delivery.dlq -p 1
	docker exec sso_redpanda rpk topic create cloudops.commands -p 3