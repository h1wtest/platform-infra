# Универсальная микросервисная платформа аккаунтов и подписок

Дата: 2026-10-24.
Статус: дизайн утверждён для реализации пользователем в архивированном контексте текущей задачи; реализация выполнена в task worktrees, идёт интегрированная локальная приёмка. Это не утверждение о завершении всех gates или готовности публикации; финальные статусы/evidence сверяет integration owner.
Рабочая ветка документации: `feat/generic-subscription-platform`.

## 1. Цель и полный объём

Публичный, воспроизводимый исходный шаблон: пользователь копирует согласованные репозитории, задаёт собственные домены/брендинг/секреты и получает работающие регистрацию/SSO, ЛК, RBAC/админку, каталог, оплату NOWPayments, подписки, рефералку, email/Telegram. Rust, Go, Kafka-совместимый брокер и React обязательны. Это не перенос бизнес-бренда Triwhales и не библиотечный каркас с отсутствующими обработчиками.

В объём входят все восемь требований:
1. Email/password, подтверждение адреса, восстановление, TOTP/recovery codes, активные сессии/устройства, отзыв одной/остальных/всех сессий, существующий собственный OAuth/OIDC.
2. Профиль/ЛК, состояние аккаунта, собственные подписки и платежи, безопасность, уведомления, реферальный код, локализация.
3. OWNER, ADMIN, SUPPORT; права назначаются ролям и исполняются сервером; административные экраны и операции.
4. Каталог продуктов подписки, неизменяемые опубликованные версии и предложения, цены/длительность, локализованные описания/возможности, редактор и публикация.
5. Checkout/попытки оплаты/NOWPayments, подпись webhook, независимая сверка, идемпотентность, административное разрешение спорных платежей и ручное подтверждение/отклонение.
6. Покупка/продление/отмена/возобновление/upgrade/downgrade/доплата/истечение/доступ; компенсации днями и закрытие администратором.
7. Реферальная привязка при регистрации, комиссии, общие/индивидуальные ставки с историей, баланс, ручные выплаты.
8. Email/Telegram: подписочные/security/admin и принимаемые внешние readiness/trading-события; категории/каналы/язык/локализованные шаблоны; двусторонне подтверждаемая привязка/отвязка Telegram; durable retry.

### Явно вне объёма

Нет AWS, торгового движка, provisioning, выпуска сертификатов, private releases, облачного hosting/deploy, кошелька, автоматических реферальных переводов, новостей, багрепортов, обсуждений, автосписания с криптокошелька, микрофронтендов. Подписка — оплаченный временной доступ к именованному продукту; её покупка не создаёт внешние ресурсы.

Readiness/trading в пункте 8 не вырезаются: реализуется защищённый версионированный HTTP ingress событий и их Kafka/notification обработка, без самих внешних систем. Проверяется реальный ingress→Kafka→delivery путь с тестовым внешним отправителем; это не доказательство интеграции с отсутствующим торговым движком.

## 2. Проверенная исходная точка

| Репозиторий | Зафиксированный main |
|---|---|
| platform-infra | 39f8a3cd04807af6166a347f86f4de3133c7be6b |
| platform-contracts | f354498b360121d18f5c48d4b578ae8e004a8415 |
| identity-service | bdd0a396eabd288cd17f4ad29951995e7c4fb013 |
| user-notification-service | 50c8120c7219b90af3e2f6c64184fa060257b544 |
| frontend | 96ee3c3e08011a98296ad71b009e6f4117f59dc0 |
| admin-cloud-service | 2c479d1aa11a71c08b4789e40d5d0eae67b67d34 |

Изучены не только README: `identity-service/src/auth.rs`, `src/auth/internal.rs`, `src/oauth.rs`, `src/domain/security.rs`, миграции; Go `internal/profile`, `internal/platform/migrate.go`; схемы контрактов; frontend и Helm lifecycle. Проверен живой HTTPS discovery с CA: Authorization Code, refresh_token, S256, RS256 и JWKS уже объявлены. Это подтверждает доступность discovery, не новый полный сертификационный прогон OAuth.

Уже есть authoritative SQL identity, Argon2id, MFA/recovery, email verification/reset, сессии, OAuth/OIDC/refresh reuse; отдельные profile/notification/worker/admin процессы и БД, Kafka inbox/outbox/quarantine, UI и независимые Helm-релизы. Не переписывать эти механизмы ради нового шаблона. Нужны расширения и новые приёмочные проверки.

Текущие недостатки относительно задания: роли `super_admin/admin/support/user` вместо выбранной модели; нет управления ролями/их permissions; отсутствуют commerce-домены и полная i18n; Telegram связывается webhook `/start` без второго подтверждения сайта и нет полного unlink-протокола; сессии имеют current marker, но нет отдельного revoke-others и last-active нуждается в проверке фактического обновления. `admin-cloud-service` содержит документацию, реальный admin/audit бинарник находится в Go-репозитории — не создавать фиктивный второй backend.

Шаблон монолита для правил анализировался на `Triwhales/trade-helper-website@ebff7e145b9186bbcaa8d8686b8540818d56c379`. Не копировать его provisioning-зависимости или распределённо воспроизводить общие SQL-транзакции.

## 3. Решение по архитектуре и альтернативы

Рассмотрены:
- Один расширяемый commerce/backend: проще локальные транзакции, но нарушает требование независимых бизнес-сервисов. Отклонён.
- Сервис на каждую таблицу/технический шаг: больше сетевых отказов и синхронных цепочек без самостоятельной бизнес-ответственности. Отклонён.
- Независимые владельцы бизнес-состояния с HTTP-командами/запросами и Kafka-событиями: выбран.

### Владение и репозитории

| Владелец | Язык/репозиторий | Authoritative данные |
|---|---|---|
| identity | Rust, существующий identity-service | Пользователи/пароли/MFA, challenges, сессии, OAuth grants/clients/consents, staff assignments, roles/permissions, auth audit/outbox |
| profile | Go, существующий user-notification-service cmd/profile | Профиль, locale, notification preferences/locale, Telegram binding и handshake/update dedup; собственный outbox/inbox |
| notification | Go, тот же репозиторий cmd/notification + cmd/worker | Notification events/templates/delivery plans/jobs/attempts, inbox/outbox/replay/quarantine; одна БД владельца, API и worker отдельно |
| admin/audit | Go, существующий cmd/admin | Санитизированная audit projection, журнал административных команд; не бизнес-таблицы других сервисов |
| catalog | Go, новый локальный catalog-service | Products/plans, draft/published revisions, immutable offers/translations/features, archive, outbox |
| billing | Go, новый локальный billing-service | Orders, payment attempts/provider evidence, reconciliation, paid decisions, durable fulfillment workflow/admin decisions, inbox/outbox |
| subscription | Go, новый локальный subscription-service | Subscriptions, prepared actions/quotes/reservations, periods/changes, compensation operations, entitlement, inbox/outbox |
| referral | Go, новый локальный referral-service | Accounts/codes/attribution, historical rates, commission/payout ledger and reservations, inbox/outbox |
| frontend | React/TypeScript, существующий frontend | UI, локализованные ресурсы; не бизнес-истина |
| contracts/infra | существующие platform-contracts/platform-infra | Версионированные wire contracts; bootstrap/Helm/CI/приёмка |

Новые имена — выбранные локальные репозитории, не утверждение об уже созданных GitHub repositories. Публикация/изменение remote, push, PR и merge — только с отдельным разрешением. На этапе реализации новые локальные репозитории и ветки создаются в изолированном task workspace. Существующий Go multi-command repo остаётся multi-repo packaging choice, не совместной БД или единым выпуском сервисов. Разделение его на дополнительные remote repo не является prerequisite и не должно занимать место реализации функций.

Один PostgreSQL cluster локально допустим, но отдельная DB, migration/runtime роли, migrations, backup и connection pool каждому владельцу. Межсервисные SELECT/JOIN/foreign key, общий бизнес ORM/package и доступ к чужим таблицам запрещены. Notification API/worker — два процесса одного владельца, не два доменных сервиса.

### Паттерны

- Бизнес-правила/состояния отдельно от HTTP/Kafka/SQL/provider adapters; явные constructors и DI, ports принадлежат потребителю.
- Feature-oriented Go: `cmd/api`, `cmd/worker` если действительно нужен отдельный delivery deployment; `internal/<feature>/{domain,application,postgres,http}`. Не создавать четыре пустых слоя для простого query. SQL migrations отдельными checksum/version файлами.
- Rust сохраняет текущие domain/application/adapters, явные Result и bounded CPU hashing.
- State machines с enum/transition rules; optimistic expected_version, уникальные constraints, row locks в локальных транзакциях.
- Transactional Outbox + transactional Inbox; durable orchestrated fulfillment в billing. Без 2PC и универсального workflow framework.
- CQRS только по необходимости: read projection ЛК не разрешает доступ; entitlement всегда спрашивается у subscription authority.
- Provider adapters имеют ограниченные deadlines/response size/egress, persisted unknown outcomes. Не добавлять mesh, event sourcing и универсальный shared бизнес-framework.

## 4. Протоколы, контракты и последовательность доставки

Сохраняем существующие HTTPS JSON API и JSON Schema 2020-12 с генерируемыми Go/Rust DTO; не вводить одновременно gRPC/Protobuf. Добавить TypeScript wire types/проверяемый API-клиент для frontend из того же реестра. Схемы бизнес-публичных API и OpenAPI доступны отдельно от приватных endpoints. Техническая общая библиотека может содержать TLS/telemetry/inbox codecs, но не бизнес-таблицы и domain-сервисы.

Текущие strict v1 immutable: новые поля/типы в `events-v1.json` несовместимы. Ввести `events-v2`/`internal-http-v2`, новые consumer groups, topic ACL и проверяемый coordinated cutover. v2 envelope: schema_version, event_id(UUIDv7), event_type, producer, aggregate_type/id, aggregate_version(int64>=1), occurred_at(UTC RFC3339), correlation_id/causation_id, traceparent, typed payload либо encrypted_payload. Ровно один вариант тела. Версия агрегата назначается его владельцем под локальной блокировкой; разные producers не создают фиктивный общий порядок.

Topic families: `identity.events.v2`, `profile.events.v2`, `catalog.events.v1`, `billing.events.v1`, `subscription.events.v1`, `referral.events.v1`, `external.events.v1`, `notification.commands.v2`, `platform.dlq.v2`. По 6 partitions локально; key=aggregate UUID, replication3 на текущем стенде. Не менять partitions retained topics молча. Команды fulfillment передаются событием `billing.payment_accepted` со стабильным action/order ID; subscription отвечает `subscription.action_applied|action_rejected`; billing завершает workflow и публикует `billing.order_fulfilled|fulfillment_review_required`.

Payload несёт immutable snapshot, не указатель на producer DB. События публичны лишь для разрешённых workload consumers, не Интернету; минимизация PII обязательна. Reset/verification tokens только в purpose-encrypted notification commands, не audit. Kafka ACL exact producer/topic/group; отдельные credentials; consumer commits offset после inbox+effects COMMIT. Outbox relay ждёт broker ack, не обгоняет предыдущий aggregate version; retries at-least-once. Гэп версии блокирует effects агрегата и запускает owner replay/snapshot recovery, а не принимает более новое состояние по часам. Poison — durable encrypted quarantine + metadata DLQ; dependency outage не poison.

v1→v2 cutover: сначала развернуть поддерживающих оба формата consumers; применить additive owner migration, сохранить event_id при перепубликации, backfill durable source state; перевести producers и проверить end offsets всех v1 partitions/receipts. После drain/окна независимого выпуска удалить старые handlers/ACL/config/types в отдельном согласованном cutover, не оставлять постоянных aliases. Не удалять сохранённые события ради зелёной миграции. Выпуск старой версии, не понимающей новую БД/wire, блокируется.

## 5. Безопасность, SSO и роли

### Identity и сессии

Сохранить работающие email/password/TOTP/recovery и OAuth/OIDC. Пароль 12–1024 bytes, Argon2id вне async loop, bounded permits. Email normalized; recovery не раскрывает существование пользователя. Challenges hashed/short-lived/single-use, MFA secret purpose-encrypted; попытки защищены persistent rate limits. Password reset/change и ban атомарно отзывают identity sessions, связанные OAuth grants и refresh families.

Session API: current-first, id, device label/browser/OS (best effort UA parsing, unknown явно unknown), raw UA/IP по правилам приватности, created_at/expires_at/last_active_at/current. last_active обновляется rate-limited (не чаще 60 s), не выдумывается по list response. DELETE own session, POST revoke-others (сохраняет current), DELETE all (включает current) идемпотентны. Два пользователя не могут отзывать/читать сессии друг друга.

Браузер: Secure/HttpOnly/SameSite cookie, exact Origin + CSRF на мутациях, токены не в localStorage, JWKS algorithm/issuer/audience/nonce/state/PKCE verification. OIDC access token для конкретного клиента не становится platform admin credential.

SSO admin management: OWNER регистрирует public/confidential clients с exact HTTPS redirect, ограниченными scopes и явной first-party trusted policy либо user consent screen; third-party без consent запрещён. Secret показывается один раз, хранится hash, rotation/revoke аудитируются. Не добавлять implicit/password grants. Реальный сторонний standard consumer проверяет code/refresh/reuse; наличие discovery не равно OAuth2.1/OIDC certification.

### RBAC

Staff roles ровно OWNER, ADMIN, SUPPORT; canonical wire slugs `owner`, `admin`, `support`, UI labels в верхнем регистре. Обычный authenticated user имеет intrinsic own-resource permissions без staff роли. Role→permission — persisted binding; действия сервера проверяют permission+scope+ownership, не UI label. Каталог permissions code-owned, произвольный permission string не даёт полномочий. OWNER-only invariant не переназначается редактированием permission map.

- OWNER: все операции; назначение staff ролей/permissions, OAuth clients, branding/integration settings и bootstrap ownership.
- ADMIN: пользователи/ban/sessions, каталог/publish, платежное review/manual decisions, subscriptions/compensation, referral rates/payout decisions, templates/notification replay и audit. Не управляет staff правами и OAuth clients, не меняет секреты, не блокирует/меняет OWNER.
- SUPPORT: read-only безопасный user/subscription/payment/delivery status; отзыв сессий обычного пользователя со свежим MFA и причиной. Нет provider raw evidence, rates/payout/finance mutations, staff changes, template publishing.

Permission families: `users:{read,write}`, `users:sessions:revoke`, `roles:{read,write,assign}`, `catalog:{read,write,publish}`, `billing:{read,resolve}`, `subscriptions:{read,write,compensate,close}`, `referrals:{read,rates:write,payouts:decide}`, `notifications:{read,templates:write,replay}`, `audit:read`, `oauth:clients:write`. Все административные permissions требуют MFA, проверенного в последние 15 min; security-sensitive role/client/secret mutations дополнительно password reauth<=5 min. Это повторно проверяет принимающий domain service, admin UI/API не становится root proxy.

Миграция: `super_admin`→OWNER, `admin`→ADMIN, `support`→SUPPORT; `user` удаляется из staff bindings после перехода own-resource policy. Сохраняются users/sessions/audit, старые applied migration bytes не меняются. Удаление/понижение/ban последнего активного OWNER запрещены под serializing lock. Bootstrap не повышает существующего обычного пользователя молча; повтор не меняет пароль. Concurrent demotions и self-escalation покрываются PostgreSQL regression.

Identity остаётся единственным RBAC authority; TLS workload identity и отдельные tokens scopes для каждого нового сервиса. Нет общего admin token для всех. Live introspection fail-closed, cache не продлевает revoked credential. Нет обещания глобальной атомарности удалённого role revoke и уже исполняемой транзакции: начатая и авторизованная команда может завершиться; новые admission после revoke отклоняются. TTL удалённого authorization decision максимум 5 s и независимый domain recheck перед command admission, request-bound decision не переиспользуется другой командой.

## 6. Профиль, ЛК и локализация

Profile владеет display_name/avatar_url/phone, website_locale и notification_locale/preferences/Telegram binding; identity владеет проверенным email. Смена email проходит identity verification и событие, не PATCH профиля с новым адресом.

ЛК: overview account verification/MFA, список своих subscriptions с paid period/status/next change/entitlements, payment/order history and checkout recovery, security/sessions, profile/settings, notification preferences/linking/history metadata, referrals/code/balance/payout requests. Не показывать provisioning/release/download/TE панели.

Начальные полноценные locale EN/RU, архитектура translation keys и registry для добавления языка без бизнес-кода. Fallback requested→default EN; даты/числа через Intl, сервер UTC, деньги API decimal strings. `Accept-Language` до входа, persisted locale после; отдельный notifications locale. Нет hardcoded русского/английского в server errors: стабильный code и клиентский translation key, provider raw errors не отображаются. Переключение языка сохраняет form/state и не меняет identity.

Overview — bounded parallel HTTPS composition на стороне profile API с отдельными authenticated calls billing/subscription/referral, без прямого SQL. Частичный ответ сообщает per-section unavailable/pending; не возвращает 0 balance/empty subscriptions вместо сбоя. Только GET own queries; profile не принимает billing mutations. Entitlement не вычисляется по overview cache. UI скрытой вкладки не poll, authoritative refresh на focus/online, abort/stale generation guards на logout/account change. 390px/desktop, keyboard/errors/empty/pending/failed/permission denied/expiry проверяются на реальном UI.

## 7. Каталог и денежные правила

Product — именованный предмет временного доступа с устойчивым key. Plan принадлежит product и имеет upgrade_rank внутри него; offers одной plan revision задают варианты duration_days/price. Опубликованная revision с EN/RU name/description/features и offers immutable; новая правка создаёт draft. Lifecycle DRAFT→PUBLISHED→ARCHIVED. Draft validation, preview и publish optimistic expected_version; архив запрещает новые покупки, но не меняет оплаченные периоды/открытые committed reservations. Доступные ранее published revisions сохраняются для audit/history.

Единая расчётная валюта шаблона USDT, 6 decimal places; локальный allowlist pay_currency USDTTRC20/USDTBSC, возможность оператору явно настроить поддержанные провайдером сети через config. Provider asset quantities с иной точностью сохраняются exact decimal, не принудительно округляются до USDT6. Нет обменника/мультивалютного ledger. Go int64 micros (предел явно проверяется), BigInt для промежуточных умножений/сравнений; SQL numeric с проверенными пределами. Float32/64/JS Number для денег и при разборе provider JSON запрещены. JSON numbers провайдера читаются losslessly (`json.Number`), подпись проверяется provider-compatible canonical JSON без float roundtrip, duplicate keys rejected. HTTP representation и signed bytes проверяются fixtures official API.

Длительность day=86400 s, UTC; расчёт по integer seconds. price>0, duration_days 1..3650; price_micros 1..9_000_000_000_000; rate_bps 0..10000; промежуточные операции проверяются на overflow. Ранги смены тарифа и цена за секунду сравниваются точными cross-products; несовместимый/экономически обратный переход отклоняется. Бесплатные trial/валюты/произвольные скидки не добавляются.

## 8. Заказы, NOWPayments и durable fulfillment

Billing принимает checkout только от verified user. Сначала получает immutable catalog offer snapshot по authenticated HTTPS и подготавливает action в subscription authority со стабильным operation_id; нет доверия price/duration/owner из браузера. Subscription локально сериализует операции по user+product и резервирует action против собственной version. Prepared action включает owner/product/subscription (если есть), kind, exact offer/snapshot hash, period/cost/quote, version, deadline. Initial action reserve исключает две одновременные initial purchases одного product, другие продукты независимы. Reservation lease до provider create — 15 min; после durable provider-start она не освобождается простым TTL: billing должен доказать неоплаченный terminal outcome или передать paid action. При CREATE_UNKNOWN/зависшем workflow сохраняется recovery fence; автоматически очистить и создать второй счёт нельзя. Сбой между локальными prepare/attach восстанавливается тем же operation_id через status/retry, abandoned pre-provider prepare можно отменить после доказательства отсутствия provider-start.

Provider-start handshake: billing сначала сохраняет локальный START_INTENT для attempt, затем идемпотентно переводит subscription reservation в STARTED со своим attempt ID и fencing version, только после подтверждённого STARTED вызывает NOWPayments. При потере ответа читает reservation status, не вызывает provider наугад. Worker cancellation/provider dispatch сериализуются lease/row lock; после отмены lease старый dispatcher не имеет права послать новый HTTP create. Subscription TTL может освободить только PREPARED; STARTED снимается explicit unpaid/review resolution. Crash после STARTED до HTTP оставляет recoverable fence, не разрешает два конкурирующих заказа.

Billing сохраняет order+attempt+idempotency hash до provider call. Idempotency key scoped user+operation, тот же key с другим body→409. Только одна nonterminal action/order на product; повторный checkout возвращает существующую операцию, не новый счёт. Повтор provider create после неопределённого network outcome запрещён до доказательства состояния: CREATE_UNKNOWN сохраняется, recovery через provider lookup/evidence или admin review. Не приписывать NOWPayments идемпотентность POST /payment без документированного подтверждения. Повторная известная попытка допустима лишь когда предыдущая не оплачена/не ambiguous и action reservation разрешает её.

Provider webhook: отдельный узкий публичный endpoint без browser session/CSRF, bounded body, HMAC-SHA512 sorted canonical JSON, constant-time compare; invalid/missing→401, malformed→400. Быстро durable-save и 2xx (целевой ответ<=3 s), не ожидать provider GET/Kafka внутри callback. Provider API HTTPS, allowlisted base, redirects disabled, x-api-key не утекает в URL/log; timeouts/429 backoff persistent и rate limits по текущей документации.

Воркер независимо GET /payment/{id}, сверяет merchant order/attempt, provider ID/currency/network/amount/parent-payment linkage с сохранённым snapshot. `finished` само по себе не означает достаточную сумму: настройки NOWPayments могут помечать underpayment finished. `partially_paid`, wrong asset/network, amount mismatch, unknown status, late settlement, конфликт ownership/quote→REVIEW_REQUIRED, доступ автоматически не даётся. Waiting/confirming/confirmed/sending не финальное исполнение; full finished+matching authoritative evidence→accepted. Переплата фиксируется, применяется только цена заказа, автоматический refund/bonus не создаётся. Ошибка/timeout GET→pending retry, а не decline. Поздняя доплата/повторный paid event не даёт вторую subscription; каждый provider root transaction уникален и распределение payments immutable.

Локальные payment evidence/accepted decision/outbox коммитятся атомарно. Billing workflow: PAYMENT_PENDING→PAYMENT_ACCEPTED→FULFILLMENT_PENDING→FULFILLED; отдельные REVIEW_REQUIRED/CANCELLED/EXPIRED. Subscription по `billing.payment_accepted` обрабатывает prepared action ровно один раз логически и пишет своё applied/rejected event. Billing подтверждает receipt через inbox и закрывает заказ. Kafka/subscription outage оставляет деньги принятыми и видимый fulfillment pending, не теряет платёж и не заявляет несуществующую активацию. Rejected action сохраняет paid факт и review; automatic refund отсутствует.

Админ: detail/evidence, reverify, accept underpayment/manual settlement/decline review, retry fulfillment; required reason, expected_version, idempotency и fresh MFA. Manual approval требует сохранённого monetary evidence либо явно введённой внешней оплаты (amount/network/reference, без вызова API переводов); принимается как исключение и публикует тот же accepted command. Отказ не стирает реально полученные деньги. Ручное rejected не маскируется provider failed. Проведённую оплату нельзя отменить простым toggle.

NOWPayments sources (прочитаны при проектировании):
- https://nowpayments.zendesk.com/hc/en-us/articles/21395546303389-IPN-and-how-to-setup
- https://nowpayments.zendesk.com/hc/en-us/articles/18395434917149-Payment-statuses
- https://nowpayments.zendesk.com/hc/en-us/articles/21345824322717-API-and-endpoint-description
Официальная документация местами неоднозначна по JSON number/string и canonicalization; adapter fixtures и настоящий sandbox acceptance обязательны, не догадки.

## 9. Подписки и entitlement

Можно иметь разные product subscriptions; одновременно одна active/pending subscription на user+product. Initial accepted payment запускает paid period в момент фактического subscription COMMIT, не в момент долгого ожидания Kafka; duration snapshot не теряется. Entitlement: ACTIVE, start<=database_now<end, не closed, и live identity не banned. Проверяется subscription HTTP endpoint; outage→503/deny, не stale allow. Feature keys из published snapshot — данные продукта, не administrative permissions.

Продление только собственной ACTIVE неистёкшей подписки, без конфликтующей pending change. Новый конец old_end+duration; cancel_at_period_end очищается только явным resume/renew confirmation. После EXPIRED новый initial/restart purchase создаёт новый оплаченный период без оплаты пропущенных дней. Expiry scheduler атомарно применяет boundary transitions, но entitlement сам сравнивает end и не ждёт cron.

Cancel означает прекратить доступ по окончании paid period, без refund и без немедленного отзыва уже оплаченного времени. Resume снимает cancel пока period active. В шаблоне нет автосписаний: renewal — явная новая оплата. Existing paid upgrade/action не уничтожается cancel-командой; конфликт→409 либо сохраняемый review.

Upgrade внутри одного product, duration bucket совместим, target rank и exact price/sec выше. Quote живёт<=5 min и не позже current end. Доплата=ceil((target_price/target_duration-current_price/current_duration)*remaining_seconds), точная рациональная арифметика до финального округления вверх в USDT micros. После accepted payment период end не меняется, target plan применяется; canonical action хранит quote время/конец/версии. Provider confirmed after quote deadline/end→review, не несанкционированное продление. Compensation или другой version change инвалидирует незавершённый quote; уже принятые деньги остаются review.

Downgrade с меньшим rank/price-sec назначается на конец текущего периода, не возвращает деньги. Клиент видит next plan. Само расписание — конфигурация подписки, не вечно открытая paid action reservation: последующее renewal подготавливается с ожидаемой версией и snapshot этого target. Продление целевого варианта можно оплатить заранее; активация target и нового периода происходит на старом end. Если оплаты нет, на boundary EXPIRED и никакого бесплатного периода. Cancel/изменение scheduled downgrade после оплаты конфликтует; нельзя потерять оплаченный snapshot. Смена между несравнимыми duration buckets требует нового period при boundary, не угадываем курс доплаты.

Компенсация: preview freezes exact subscription IDs, expected versions, reason, days 1..3650 и totals; apply idempotent operation_id под locks, только ACTIVE неистёкшие subscriptions. Повтор не добавляет дни дважды; конфликт version отображается по recipient и требует нового preview, не молчаливый пересчёт. Удлиняет end/сдвигает scheduled boundary, не создаёт комиссию. Admin close немедленно CLOSED и entitlement denied, сохраняет историю/paid evidence и reason; refund считается внешней ручной операцией, не обещается перевод.

## 10. Реферальная программа

Referral-service создаёт account/code по регистрации (inbox+account atomically); существующие users backfill из paginated identity API, не чтением identity SQL. Собственный код random nonsequential, unique; self-referral и повторное назначение запрещены. Referral code input только при регистрации, никогда произвольный referrer_user_id от браузера.

Если код отсутствует, identity регистрирует без зависимости referral. С кодом identity заранее генерирует user_id/registration_id, вызывает idempotent referral attribution preparation: проверенный code→immutable claim с target user_id/referrer/rate policy metadata, deadline и стабильным claim_id. Invalid code→явная ошибка, dependency outage→503 до регистрации, не молчаливая потеря атрибуции. Identity сохраняет claim_id в собственной registration transaction/outbox. Referral привязывает claim только по authenticated identity registration event с совпадающими IDs/occurred_at до deadline; запоздалое Kafka arrival допустимо, claim history не удаляется по TTL пока возможен replay. Abandoned claims не начисляют ничего. Повтор регистрации не меняет первый referrer.

Глобальная initial ставка 0 bps до явного admin решения; индивидуальный override nullable→global. Только append-only effective rate history, с expected version и UTC effective_at=COMMIT, без backdating. Ставка замораживается при checkout, явно показывается в commission quote: billing до provider-start получает idempotent referral quote по order/action ID и цене; referral сохраняет attribution/rate/eligible sale amount snapshot. No-referral также явный результат. Изменение ставки не меняет уже созданный checkout. При недоступности referral новый checkout не вызывает provider; существующая оплаченная операция уже имеет quote и её fulfillment не зависит от доступности referral. Quote потребляется асинхронно по authoritative `billing.order_fulfilled`; отменённый/неисполненный order не начисляет комиссию. Manual settlement без checkout сначала создаёт такой же audited quote по явно зафиксированной текущей ставке, не выдумывает прошлую ставку.

Commission=floor(eligible_sale_micros*rate_bps/10000), eligible amount = paid order consideration (initial/renew/upgrade actual charge), без provider fees/overpayment и без компенсаций днями. Уникальность commission source order_id, повторное событие не начисляет снова. Возврат/исправление принятой оплаты оформляется отдельной audited reversal entry, не удалением ledger. Если средства уже выплачены, reversal может создать debt; доступно к payout=max(0,earned-reversed-paid-reserved), debt отображается отдельно, не обнуляется.

Payout request резервирует весь положительный available balance, minimum1 micro, wallet network+address canonical/validated under выбранные сети, immutable amount/address/idempotency. Конкурирующие заявки не тратят один баланс дважды. Только ADMIN/OWNER, свежий MFA и reason: PENDING→PAID (фиксирует reference/date внешнего перевода) либо REJECTED (освобождает reservation). Никакой отправки средств из приложения. Администратор не может заменить адрес/сумму существующей заявки или дважды решить её. До решения можно отменить свою PENDING заявку с освобождением reservation.

## 11. Уведомления, Telegram и внешние события

Не переносить существующие preferences/bindings в новую БД без необходимости: profile остаётся владельцем, notification делает current authenticated recipient-policy lookup перед каждой provider attempt/unsent part. Это сохраняет unlink/роль/ban/preference semantics без общей DB. Notification владеет языковыми шаблонами/event/delivery, immutable выбранной template revision для job; отключение канала и смена binding проверяются свежими, старый job не доставляется в новый чужой chat.

Категории subscription/security/trading/admin. Email и Telegram для subscription/security; trading и обязательные staff admin alerts — Telegram. Транзакционные email verification/password reset не отключаются preferences и идут только текущему target verified flow. Staff alerts только текущим staff с нужной permission; потеря роли прекращает unsent delivery. По умолчанию subscription/security email ON, Telegram OFF до binding, trading OFF; staff requirement не включает пользователю канал без подтверждённого chat.

Язык уведомлений независим от website locale. Template event-specific typed variables allowlist; EN/RU subject/body редактируются и публикуются атомарно с expected_version. Missing required locale/unknown variable/unsafe URL→400; HTML escaping и CRLF stripping, запрещены javascript/data links. Security email render не раскрывает reset token в history/logs. История — только безопасные metadata и статус, admin replay только terminal failed, audited reason.

Link: authenticated website begin→one-use hashed token expiry10min→secret-authenticated private-chat Bot API /start→candidate binding→explicit website confirmation от того же identity session/user. До последнего шага linked=false. Один chat↔один user, conflicts не воруют существующий binding; replay update_id/token не меняет состояние. Unlink начинается с сайта с fresh reauth, Bot confirmation одноразовой кнопкой завершается atomically binding_version++; до подтверждения UI показывает pending. Force support reset отдельная permission, fresh MFA, reason и audit, никогда принимает arbitrary chat ID.

Использовать существующий Telegram webhook mode с exact secret header и узким gateway route; не включать polling одновременно. getMe/sendMessage запросы с CA verification/no redirects, токен redacted даже из URL/network errors; без credentials channel unavailable, не fake success. Отдельный delivery worker, leased jobs/attempts/next_attempt/jitter; provider 429 учитывает retry_after. Revocation/preferences checked after lease перед send. Уже начатую внешнюю доставку нельзя отозвать, accepted/local commit crash может дублировать сообщение; exactly-once SMTP/Telegram не обещать.

External ingress `POST /internal/v1/external-events`: integration-specific random credential, TLS, signature SHA256 HMAC over timestamp+nonce+raw body, constant-time verify, freshness<=120s, persisted replay nonce/event_id. Integration allowlist event_types+product scope; sender не назначает произвольного recipient: service проверяет user/subscription ownership через authoritative APIs, trading требует ACTIVE entitlement, readiness может адресовать существующую подписку в её разрешённом состоянии. Неверный sender/scope→403, stale/signature→401, unknown kind/body→400, временная authority outage→503, durable accepted→202. Profile owns narrow ingress adapter and its outbox; новое integration право не даёт доступ к reset/MFA commands. Kafka published IDs стабильны; producer registration конфигурационный, не произвольная public webhook URL.

## 12. Эксплуатация и публичный шаблон

Сохранить имеющийся k3d/Helm lifecycle и независимый release каждого владельца/worker. Добавить новые DB owners, migrations, exact Kafka ACL/group/topics, CA-certified internal HTTPS, per-service introspection credentials, gateway routes, resource limits, probes, dashboards и backups. No deployment/host-fault injection в рамках проектирования. Реализация проходит на изолированном local stand; существующий пользовательский namespace/PVC/секреты не сбрасываются.

Configuration: публичные brand/name/logo/help URL/locales/canonical origins отделены от секретов; template defaults example.invalid/localhost, не Triwhales домены/аккаунты/ARN. Owner `.env.example` без usable credentials; локальный bootstrap создаёт purpose-separated secrets один раз и не меняет их при restart. Совместимые source SHAs и image digests сохраняются workspace manifest, не floating main. Независимый service CI требует pinned contracts commit. MIT LICENSE и SPDX для собственного нового кода/явно выбранной template публикации; dependencies сохраняют свои лицензии, не переписывать license стороннего кода. Копирование исходников монолита с неустановленной лицензией запрещено; переносить описанные правила собственной реализацией.

README с prerequisites/one-path bootstrap/migrations/start/check, описанием внешних gates, security/secret handling, backup/replay/recovery и точными curl/UI примерами. Перед публичным выпуском redacted full-history secret scan; реальные `.env`, bot/API keys, payment evidence, backups, session cookies и acceptance artifacts никогда не Git/Docker context/CI artifact. Существующая политика отключённых vulnerability scanners не меняется без отдельного решения пользователя; отсутствие сканирования не означает отсутствие уязвимостей.

Observability: redacted structured logs, W3C traces HTTP→outbox→Kafka→consumer→job, метрики payment unknown/review/reconciliation/fulfillment lag, subscription expiry/action lag, referral debt/payout reservations, delivery attempts, outbox/inbox/consumer lag, DB/HTTP. Audit доменных действий записывается локально с business mutation+outbox, затем aggregate audit projection; audit service outage не теряет local audit и не превращает его в distributed synchronous transaction. UI/админка не показывают секретные provider payloads, логи никогда сырые URL/token/body.

## 13. Приёмка и границы доказательств

Каждая задача имеет feature regression на consumer-visible invariant, real owner DB integration, actual API/worker/UI smoke; вызов mock adapter не доказывает provider integration. Локальный deterministic provider fixture допускается только как маркированный fixture отрицательных/гонок/timeout случаев, никогда production fallback. Настоящие NOWPayments sandbox create/status/IPN и Telegram bot private-chat link/unlink/send обязательны для provider acceptance. Без соответствующих credentials/public HTTPS callback выполняется всё достижимое, capability остаётся unavailable и внешний gate OPEN; credential values нельзя запрашивать в публичном чате/коммитить.

Матрица: duplicate/reordered events, concurrent actions/webhooks/admin decisions, crash after provider accept before commit, consumer restart/rebalance, Kafka/DB/provider outage/recovery, lost create response, over/under/late/wrong-network payments, quote expiration/change conflict, compensation/reversal/payout races, last OWNER protection, revoked sessions across new services, malicious template/locale/CSRF/ownership inputs. Деструктивные проверки только на disposable task-owned данных. Whole-host/Docker Desktop fault запрещён по существующей политике.

В UI фактически пройти все 8 функциональных разделов в EN/RU на desktop и390px, роли OWNER/ADMIN/SUPPORT/user, empty/loading/pending/failed/forbidden, logout/account switch. Не закрывать frontend по API tests. Проверить fresh clone bootstrap/повторный bootstrap/перезапуск/backups+restore в отдельные БД; zero compiler/lint errors, поведенческие проверки и independent review. Не заявлять cloud/production/HA/OIDC certification по локальным результатам.

## 14. Исполнение и контрольная точка

Реестр конкретных deliverables/зависимостей/acceptance: `docs/superpowers/plans/2026-10-24-generic-subscription-platform-task-register.md`.

Утверждение дизайна и реализация owner slices уже состоялись; exact implementation plans использованы для dependency waves. Текущая контрольная точка — real local API/worker/UI/отказная приёмка, независимое ревью и финальная сверка source/image/provenance. Состояние и ограничения отражаются в реестре задач и `docs/handoff.md`; сохраняются все критерии раздела13. V03 остаётся OPEN при отсутствии current-task реальных provider credentials/public callback, независимо от старой Telegram evidence или успешного deterministic fixture. Публикация remote repos/веток, push/PR/merge/deploy, cloud/production и реальные переводы не следуют из утверждения архитектуры; нужны отдельные разрешения. Финальные commit/image identities не придумываются до freeze и доказанной сверки.
