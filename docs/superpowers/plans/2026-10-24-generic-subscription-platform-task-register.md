# Универсальная платформа — реестр задач и порядок реализации

Дата: 2026-10-24. Статус: проект на утверждение, все новые задачи OPEN.
Спецификация: `docs/superpowers/specs/2026-10-24-generic-subscription-platform-design.md`.
Это план результатов/зависимостей/приёмки, не ложный отчёт о готовых функциях и не заменитель subsystem implementation plans с exact кодом. Не начинать код до утверждения дизайна. Уже существующее не переписывать: добавить недостающие правила и доказать регрессиями.

## Общие условия каждой задачи

- Owner DB и миграции, runtime/migration credentials раздельны; ни одного запроса в чужую БД.
- Generated contract producer+consumer updates вместе; no unversioned v1 wire edit.
- Локальные бизнес-mutation/audit/outbox атомарны, Kafka inbox/effects атомарны; persisted leases/idempotency/unknown outcomes.
- Никаких секретов в Git/log/history/UI, fake unavailable-provider success, пустых обработчиков или framework-only deliverables.
- На задачу: source/contract docs, meaningful behavioral regressions, реальный API/worker smoke, для UI реальный browser scenario. Review после законченного logical block; CI/формат/lint/build один раз после волны, не одновременно с общими edits.
- Изолированные task worktrees, собственная branch на repo, LF/UTF-8. Коммиты локально; push/новые remote repos/PR/merge/deploy только по отдельному разрешению.
- NOWPayments sandbox и Telegram external gates записываются отдельно; fixtures не закрывают provider gate.

## Волны и зависимости

1. W0: C01 контракты и C02 owner runtime/migrations/CI convention; deployment сопровождение I01 развивается вместе с реальными сервисами, не выдаётся за feature.
2. W1 независимо: S01–S03 identity/SSO; R01–R03 RBAC; C03–C04 каталог; P01 profile locales и N01 preferences/templates. Общие identity edits имеют одного integration owner.
3. W2: F01 attribution, F02 rates/quotes; U01–U02 subscription authority/prepare; B01–B03 billing/provider. Provider-start разрешён только после prepare+commission quote contracts.
4. W3: U03 consumer lifecycle → B04 durable fulfillment integration → U04–U05 changes/compensation; F03–F04 commissions/payout; N02–N04 delivery/link/external ingress. UI задачи идут после работающих API своего slice.
5. W4: P02–P04 полный ЛК, A01–A03 админка, I02 fresh-template bootstrap, V01–V04 интегрированная приёмка/отказы/реальные провайдеры/независимое ревью.

Параллельные executable slices не правят одновременно одну migration/contract/infra registry; shared prerequisite выполняется перед fan-out. Реестр покрывает полный объём; порядок не уменьшает scope.

## 0. Архитектурные prerequisites

### C01 — Версионированные контракты платформы
Репозиторий: platform-contracts. Depends: утверждённый дизайн.
Результат: schemas `events-v2.json`, `internal-http-v2.json`, отдельные business schemas catalog/billing/subscription/referral/notifications, endpoint inventory/OpenAPI, Go/Rust DTO и frontend wire types; exact envelope/event key/version, error/idempotency/pagination semantics, compatibility gates и release manifest pin.
Проверка: old v1 schema остаётся byte-compatible; invalid unknown/missing/nullable/money/UUID fields rejected; producer→serialized bytes→consumer roundtrip; secret command не проходит public-event validator; regenerated outputs clean и новые event kinds не разрешают произвольный payload.

### C02 — Повторно используемый технический runtime без общего бизнес-ядра
Репозитории: user-notification-service, новые catalog-service/billing-service/subscription-service/referral-service, platform-infra.
Результат: реальные локальные Go modules с owner migrations/version/checksum locks, TLS+identity client, request context, outbox/inbox/lease/metrics, Docker/CI. Существующий inline Go migration v1 не переписывается: append-only migration runner принимает его marker и выполняет новые versioned SQL.
Проверка: wrong-owner DB и checksum mismatch блокируют запуск; runtime не делает DDL; empty schema live200/ready503; после настоящей миграции ready200; restart сохраняет данные; неполученный identity decision не разрешает действие.
Готовность C02 отдельно не означает готовность бизнес-функций; каждый новый сервис закрывается только вместе со своим functional slice.

## 1. Регистрация, безопасность и собственный ID

### S01 — Сессии и устройства: закончить существующие API
Репозиторий identity-service; контракты/frontend. Depends C01.
Результат: created/expiry/last_active/current, best-effort browser/OS/device labels и unknown; current-first, revoke-one/revoke-others/revoke-all; обновление last_active не чаще60s, no synthetic activity on listing. Сохранить действующие password/MFA/email/recovery paths.
Проверка: два реальных пользователя/три сессии; foreign session denied, others сохраняет current, all/current revokes immediate across services, повтор идемпотентен; timestamp не увеличивается от list и не теряется при restart. Не подменять отзыв скрытием UI.

### S02 — Полная локализованная account-security приёмка
Репозитории identity/frontend/infra. Depends S01/P01.
Результат: формы registration→verification, forgot/reset/change, reauth, TOTP setup/confirm/disable/replacement/recovery codes one-time display; понятные EN/RU error/pending/expired/replay states. Email template locale проходит от registration/identity flow до delivery command, без изменения v1.
Проверка: Mailpit реальный reset/verification, actual TOTP/recovery replay denial, abandoned setup не меняет active secret; reset/change отзывает сессии; browser reload/назад/logout не раскрывает recovery secret и не восстанавливает предыдущий account state.

### S03 — Управляемый собственный OAuth/OIDC
Репозитории identity/frontend/contracts. Depends R01–R03.
Результат: сохранить текущие Code+S256/JWKS/refresh; OWNER-only client registration/rotation/revoke с exact redirect/scopes, explicit trusted first-party либо consent screen для third-party, record grants/revoke. UI branding не меняет issuer незаметно.
Проверка: standard external consumer, public/confidential client, consent deny, wrong client/redirect/verifier/nonce, refresh concurrent/reuse, client revoke; OAuth audience нельзя использовать для platform/admin API. Secret single display/hash only; нет OAuth2.1 certification claim.

## 2. Профиль и многоязычный ЛК

### P01 — Локаль профиля и translation infrastructure
Репозитории profile/frontend/contracts. Depends C01/C02.
Результат: website_locale отдельно от notification_locale; EN/RU complete translations, fallback/default registry, Intl dates/decimal string money formatting; stable server error codes. Profile update сохраняет partial/null semantics; verified email остаётся identity-owned.
Проверка: locale persists reload/login, change notification language не меняет website locale; unknown locale fallback, no missing translation keys in visible flows; patch omitted/null/empty имеют разные результаты, чужой user_id не выбирает профиль.

### P02 — Overview и собственные списки
Репозитории profile/frontend; Depends B04/U03/F03/N01.
Результат: account/verification/MFA summary, subscriptions/period/actions, order/payment history, referral summary с независимыми unavailable/pending sections; bounded HTTPS composition без foreign SQL. Страницы list/detail с cursor pagination и ownership.
Проверка: user A не читает B; timeout одного owner не становится нулевым balance/empty history; expired period не отображается как active entitlement; request старого account не записывает response в новый UI.

### P03 — Покупка и управление подпиской в ЛК
Репозиторий frontend. Depends C04/B04/U03/U04/U05.
Результат: public catalog→checkout→payment progress/recovery; renew/cancel/resume/upgrade quote/scheduled downgrade; no provisioning/TE sections. Понятные payment accepted vs fulfillment pending vs active, late payment/review и frozen prices.
Проверка: browser выполняет покупку/продление/смены на реальном локальном API, повтор click не создаёт второй order; refresh возвращает durable progress; 390px/keyboard/EN/RU, deadline/403/503/empty branches.

### P04 — Security, notifications и referrals UI
Репозиторий frontend. Depends S02/N02/F04.
Результат: sessions/security, locale/channel/category settings, link+site confirmation/unlink+bot confirmation, own notification history metadata, referral code/link/balance/payout request/history.
Проверка: реальные API persistence, Bot external gate отдельно; clipboard/error states, own cancellation, masked/reference display; logout clears sensitive local state и visible-tab polling прекращается в background.

## 3. OWNER, ADMIN, SUPPORT и административный доступ

### R01 — Миграция role model и permission matrix
Репозиторий identity/contracts. Depends C01.
Результат: owner/admin/support wire slugs с UI labels OWNER/ADMIN/SUPPORT, own-resource intrinsic user policy, append-only seed migration, strict permission registry, role binding/version and permission assignment API. super_admin/admin/support/user migrate по спецификации без потери users/audit.
Проверка: реальная PostgreSQL migration на populated baseline, nonstaff no admin, SUPPORT read/session-only, ADMIN finance/catalog/templates но no staff/client/secret/OWNER mutation; last OWNER и concurrent demotions/ban protected; arbitrary permission/wildcard не повышает права.

### R02 — Авторизация всех новых сервисов
Репозитории identity/все consumer services/contracts. Depends R01/C02.
Результат: отдельные workload identities/tokens/scopes, current actor+permission/MFA+Origin/CSRF проверяется owner до command admission; ownership из identity, не body. No stale role projection as access authority; bounded decision lifetime and unknown outcome semantics documented.
Проверка: role revoke/ban/session revoke прекращает новые admission на catalog/billing/subscription/referral/notification/admin; dependency outage→503/deny, forged actor/service token/bearer audience denied; active in-flight command semantics не выдается за global atomic revoke.

### R03 — Управление staff и permissions в UI
Репозитории identity/admin/frontend. Depends R01/R02.
Результат: OWNER screens role assignment/role permissions/permission catalog; current role+MFA account state, no UI-only gate. Bootstrap owner serialized и не overwrites password/elevates existing ordinary account.
Проверка: actual browser OWNER assign→new staff sees allowed features→revoke denies backend; ADMIN/SUPPORT direct HTTP denied на role edits; stale version409/last owner409, audit local+Kafka.

### A01 — Админка пользователей и аудит
Репозитории существующий cmd/admin/frontend. Depends R03/S01.
Результат: безопасные user search/detail, ban/unban/revoke user sessions, staff access, audit pagination и причины действий; admin API только оркестрирует owner APIs и хранит command requested/succeeded/denied/unknown. admin-cloud-service README отражает единственный реальный runtime, не второй dummy deployment.
Проверка: staff permission matrix, timeouts не становятся success; same command status recovered по ID, provider/credential body не попадает audit/export; SUPPORT не видит private evidence.

### A02 — Админка каталога и финансов
Репозитории admin/frontend и domain owners. Depends C04/B04/U05/F04.
Результат: draft/preview/publish/archive, payment evidence/reverify/manual review, subscription period/compensation preview/apply/close, referral rates/individual overrides/payout decision. Каждая mutation идёт в свой owner; required reason/idempotency/version.
Проверка: actual browser admin scenarios + direct forbidden requests, stale forms409; repeated confirm не выдаёт второй срок/commission/payment decision/payout; published history immutable.

### A03 — Админка уведомлений и шаблона
Репозитории admin/notification/profile/frontend. Depends N01–N04/R02.
Результат: EN/RU templates editor, safe variable insert/preview/publish, delivery/quarantine/replay, Telegram support reset with narrow permission, публичный brand/help/locale config без секретов.
Проверка: malformed placeholders/HTML/CRLF/unsafe links rejected/escaped; replay только terminal failed; support reset cannot bind arbitrary chat, current roles reevaluated перед send; branding не ослабляет CSP/origin/issuer.

## 4. Каталог подписок

### C03 — Catalog authority, immutable versions и offers
Новый repo catalog-service. Depends C01/C02.
Результат: product key, plan+rank, localized draft revisions/features/offers (price/duration), DRAFT/PUBLISHED/ARCHIVED; own SQL transactions/outbox/version constraints, read current catalog и read exact immutable offer snapshot API.
Проверка: concurrent publish одна версия выигрывает; revision после publish не редактируется; архив запрещает новые purchases, retained snapshot/history читается; decimal/overflow/duration/locales bounds, no arbitrary provisioning fields.

### C04 — Catalog editor/publication end-to-end
Репозитории catalog/frontend/admin/infra. Depends C03/R02.
Результат: реальный editor→preview→publish→public catalog, sorting/empty states/archive, no fake fixture catalog runtime fallback; owner Helm/DB/ACL/backup.
Проверка: admin пишет данные, другой пользователь видит опубликованный immutable вариант через gateway; unpublished не покупается, stale expected_version409, permission denies и fresh deployment после restart сохраняет revision.

## 5. Заказы и NOWPayments

### B01 — Order и payment attempt ownership
Новый repo billing-service. Depends C03/U02/F02/R02.
Результат: order/action snapshot, scoped idempotency, pending product uniqueness, reserve prepare/status/cancel, referral quote before provider-start; persisted create intent/attempt, customer own history/detail/cancel-unpaid.
Проверка: concurrent double initial/renew/upgrade, same key same result/different body409; цена не из браузера; crash prepare→attach retries same operation, abandoned lease не освобождает started/unknown payment; разные products независимы.

### B02 — Настоящий NOWPayments adapter и webhook intake
Репозиторий billing. Depends B01.
Результат: lossless JSON money/signature canonicalization, bounded HMAC-SHA512 receiver durable evidence<=3s; create/status HTTPS allowlist/no redirects; immutable IDs/network/amount snapshots; CREATE_UNKNOWN durable recovery без blind retry.
Проверка: official canonical signature vectors, missing/wrong sig401, duplicate keys malformed400, precise decimals/large provider IDs, provider accepted+lost response not creates again, webhook before create-response correlated safely, wrong currency/root ownership→review. Fixture tests помечены fixture; real sandbox gate V03 отдельно.

### B03 — Reconciliation и административное payment review
Репозиторий billing/admin/frontend. Depends B02/R02.
Результат: durable retry/leases, provider independent GET verification, 429/timeout, duplicate/reorder monotonic evidence; underpaid/wrong-network/late/finished-but-insufficient→review; reverify/manual monetary evidence/accept/reject with reason/version/audit.
Проверка: missing webhook recovery, duplicates/out-of-order/parallel webhook+GET+admin, underpaid finished не исполняется; previous paid факт не стирается expired/cancelled; unknown state не approved; provider outage сохраняет work.

### B04 — Paid-to-subscription durable workflow
Репозитории billing/subscription/contracts/infra. Depends B03/U03.
Результат: accepted money+event transaction→subscription idempotent action apply→reply event→FULFILLED; rejection→durable review, operator retry/status; no distributed SQL transaction. Commission публикуется только fulfilled.
Проверка: real Kafka/две owner DB, crash на каждом commit/ack boundary, duplicate events дают один период, unavailable subscription/Kafka keeps payment accepted+pending; восстановление completes without admin SQL; rejected paid action виден и деньги не исчезают.

## 6. Подписки и права на продукт

### U01 — Subscription aggregate и entitlement authority
Новый repo subscription-service. Depends C01/C02/R02.
Результат: product-scoped subscription, paid periods/state/version, ACTIVE/EXPIRED/CLOSED, entitlement on DB time, feature snapshot, cursor history, expiry scheduler outbox. Не зависит от provisioning.
Проверка: exactly end denies без cron, boundary start/end tests, banned identity denies, owner outage503 not cached allow, two users/products isolation, restart stable history.

### U02 — Prepared actions и точные quotes
Репозиторий subscription. Depends U01/C03.
Результат: initial/renew/upgrade prepare with operation ID/expected version/hash/lease, durable provider-start fence/cancel/status, exact rational ceil proration; price/currency strings and bounded arithmetic.
Проверка: competing actions one admitted, retry idempotent, same key different snapshot409, expired quote/overflow/bad rank rejected; scope own user+product, pre-provider abandoned prepare can release but started/unknown cannot TTL-delete.

### U03 — Purchase/renew/cancel/resume/expiry
Репозиторий subscription. Depends B03/U02.
Результат: consume accepted action exactly-once logical, initial starts at commit, renewal adds duration old_end, cancel_at_end/resume, restart after expiry, events/replies/history.
Проверка: duplicate/late/reordered accepted events, renewal vs cancel/expiry, concurrent boundary scheduler, renewal not twice, no free unpaid period; payment pending visible until actual activation.

### U04 — Upgrade/downgrade boundaries
Репозиторий subscription/frontend. Depends U03/U02.
Результат: immediate paid upgrade same end; scheduled downgrade plus explicitly paid next period snapshot; switch-duration at boundary only; frozen economic snapshot/version and paid-action conflicts.
Проверка: exact proration rounding (including1micro and huge values), quote deadline/end, compensation/version invalidates quote, downgrade no credit/free time, paid next plan survives replay/restart and blocked cancel doesn't erase consideration.

### U05 — Компенсации и закрытие администратором
Репозиторий subscription/admin/frontend. Depends U03/R02.
Результат: preview freezes recipients+versions+reason/days, idempotent apply per-recipient status, extension/scheduled boundary shift, immediate close and audit/outbox; no automatic refund.
Проверка: repeated/parallel apply grants once, version conflict explicit, expired/closed not resurrected, close denies entitlement immediately, compensation never commissions and never silently changes paid action snapshot.

## 7. Реферальная программа

### F01 — Referral accounts/codes/registration attribution
Новый repo referral-service + identity. Depends C01/C02/R02.
Результат: unique random code per user, registration prepared claim bound to generated target IDs, immutable first referrer; identity registration event finalizes, old users backfill via identity API. Invalid code/error semantic explicit.
Проверка: self/referrer forgery/rebinding denied, dependency outage with provided code no silent lost attribution; delayed Kafka finalize accepts originally valid claim, abandoned claim no account/commission, duplicate backfill/event stable.

### F02 — Rate history и commission quotes
Репозиторий referral. Depends F01.
Результат: initial0bps, global/individual override history expected_version/now-only; immutable order/action quote frozen before provider-start, no-referral explicit result; API denies browser selecting arbitrary recipient.
Проверка: override→global restore, delayed/reordered fulfillment retains checkout rate, concurrent rates+quote well-defined,0/10000 bps and overflow, quote amount hash mismatch rejected.

### F03 — Commission ledger и balance
Репозиторий referral. Depends B04/F02.
Результат: inbox fulfillment→unique commission per order, floor micros, ledger reversal/debt, earned/reserved/paid/available safe queries. Initial/renew/upgrade eligible actual price, not overpayment or day grants.
Проверка: concurrent duplicate sources one commission, insufficient/failed/accepted-but-unfulfilled no earnings; reversal after payout creates debt not fictitious cash, precision integer fixtures, API ownership and persistent replay.

### F04 — Manual payout lifecycle
Репозиторий referral/admin/frontend. Depends F03/R02.
Результат: user request reserves entire available balance with immutable network/address/amount, own pending cancellation; admin PAID/REJECTED reason/reference/idempotency/version, no wallet transfer endpoint.
Проверка: simultaneous payout requests cannot overspend, double admin decision conflicts/idempotent, rejected/cancelled releases exactly once, wallet cannot change on decision, paid evidence immutable and real HTTP/UI role denials.

## 8. Email и Telegram

### N01 — Preferences, locale и template authority
Репозитории profile/notification/contracts. Depends P01/C01/C02.
Результат: subscription/security/trading/admin policy, separate notification locale, versioned EN/RU templates typed variables/escaping, transactional flow emails nondisablable; notification fresh policy lookup uses profile API not SQL.
Проверка: unknown variable/CRLF/unsafe URL, partial language edit409/400, locale fallback, email disabled stops optional not reset flow; stale profile/settings dependency defers job, not drop/success; retained encrypted jobs migrated without universal key.

### N02 — Подтверждаемая Telegram link/unlink
Репозитории profile/frontend/infra. Depends N01/S02.
Результат: website begin→private bot candidate→website final confirmation; unlink website→one-use bot confirm; hashed tokens/10min/update dedup/binding_version; narrow support reset. Существующий webhook mode сохранён, polling параллельно не запускается.
Проверка: real API states candidate не linked, чужой браузер/token/chat/update replay cannot hijack; old-binding job not sent to new chat; no credentials returns capability unavailable; actual bot interaction checked V03.

### N03 — Полный notification routing/delivery
Репозитории notification/worker/profile. Depends N01/N02/B04/U03/F03.
Результат: consume subscription/security/admin events, expiry reminders1/3days with version/end checks, current staff role policy, per-channel durable jobs, provider attempts/retry_after/backoff/ambiguity/replay, metadata history.
Проверка: real Kafka+Mailpit, duplicate one logical job, broker/SMTP outage/recovery, crash provider accepted→unknown attempt not fake sent, unsubscribe/unlink/ban/role removed before next send denies, expired reminders not resurrected.

### N04 — Generic external readiness/trading ingress
Репозитории profile/notification/contracts/infra. Depends N03/U01/R02.
Результат: authenticated HMAC timestamp/nonce/event_id ingress, integration allowlist and product scope, authoritative user/subscription ownership, replay-safe outbox→Kafka→delivery; readiness/trading localized templates. No TE/AWS infrastructure added.
Проверка: actual HTTP sender→Kafka→job/Telegram fixture, invalid/stale signature401, denied type/scope403, wrong owner/expired trading denied; integration не может публиковать password reset commands, duplicate event not duplicate logical delivery; no trading-engine integration claim.

## 9. Инфраструктура, публичный шаблон и итоговые gates

### I01 — Все владельцы в независимом Helm lifecycle
Репозиторий infra, вместе с функциональными задачами владельцев.
Результат: new DB owner roles, migration jobs, per-service HTTPS/workload credentials, exact topics/ACL/groups, gateway only public APIs/webhook, independent release/image selections, NetworkPolicy and provider HTTPS egress, backup/restore/reference hashes новых DB, metrics/traces/dashboards/alerts.
Проверка: owner cannot query other DB; untrusted pod denied, allowed request works, empty-schema readiness; rolling chosen service doesn't replace siblings, retained secrets unchanged, backup restore disposable proves all new owner data. Existing host/PVC not destroyed.

### I02 — Copy-and-run public template
Репозитории все, infra owns workspace manifest/operator guide.
Результат: pinned source manifest и checkout/bootstrap commands, neutral branding/origins/locales, owner-only .env.example, repeatable secret setup, MIT/LICENSE/security/contribution docs, CI provenance+secret scan, no Triwhales/AWS/runtime hardcode; no remote creation without permission.
Проверка: fresh isolated copies→bootstrap→migrate→real user/catalog/checkout/local fixture flow, repeated bootstrap preserves users/keys/data, missing external keys visible unavailable. No manual source edits required for documented config. Fixtures not shipped as enabled provider fallback.

### V01 — Полная API/Kafka/security/failure matrix
Depends C01/C02/C03/C04/S01/S02/S03/P01/P02/P03/P04/R01/R02/R03/A01/A02/A03/B01/B02/B03/B04/U01/U02/U03/U04/U05/F01/F02/F03/F04/N01/N02/N03/N04/I01/I02.
Результат: recorded real owner/API/Kafka evidence for all8 domains; concurrent payment/referral/roles/period races; lost response/duplicate/order/poison/replay/outage recovery, causal IDs through logs/traces, no source-text/echo tests.
Проверка: evidence source SHAs/images/contracts, actual persisted invariant counts/balances/periods; no source claim substitutes runtime. No Docker Desktop/whole-host fault.

### V02 — Полная UI-приёмка
Depends P03/P04/A01/A02/A03/I01.
Результат: browser scenarios EN/RU,390px/desktop, OWNER/ADMIN/SUPPORT/nonstaff; user purchase/lifecycle/history/referrals/notifications/security and admin mutation/read paths, empty/loading/errors/denied/expired/reload/account switch.
Проверка: реальные app routes/live APIs, observed persisted results и screenshots без секретов, no standalone mockup/demo acceptance; закрыть найденные баги, не скрывать исключения.

### V03 — Внешние provider gates
Depends B02/N02/N03.
Результат: настоящий NOWPayments sandbox create/status/signed callback и Telegram getMe/private-chat link+website confirm/unlink+bot confirm/business delivery. User supplies keys via ignored owner env and owns public HTTPS routing, no publishing secrets in chat. Email external provider optional; Mailpit proves SMTP business path, не внешнюю доставку.
Проверка: correlate provider IDs→orders/actions/jobs, recorded sanitized status/amount, sandbox funds only; missing credentials/callback keeps gate OPEN, not fake PASS; no live payouts/money transfers.

### V04 — Независимое ревью и готовность к публикации
Depends V01/V02 и явно записанный результат V03 (PASS либо OPEN с внешним prerequisite).
Результат: reviewer evidence-backed findings addressed, zero build/lint/type errors, all protocol/migration/callsite/docs consistent, task statuses with actual checks/SHAs and remaining external gates. Reviewer unavailable explicitly blocks review-ready, not all reachable engineering.
Проверка: reviewed per-repo commits, deterministic tests/full suite and smoke, retained secrets not in publish inputs, no unspecified stub; final owner authorizes remote repositories/push/PR separately. Production/HA/certification не заявляются.

## Критерий завершения всей разработки

Все8 требований реализованы end-to-end, локальные gates V01/V02 пройдены, independent review завершено. Настоящие provider gates V03 либо пройдены с evidence, либо явно OPEN из-за недоступных внешних prerequisites — в таком случае полная provider acceptance и publication-ready не объявляются. Внешний blocker не оправдывает отсутствие локального checkout/subscription/referral/API/UI кода.

## Контроль дизайна

На текущем шаге создаются только проект и этот реестр. После утверждения: exact implementation plans для owner slices (file/interface/test commands), затем implementation. Не называть документ уже выполненной разработкой и не помечать feature OPEN как DONE по одному commit документации.
