# Platform Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Implement the approved complete remediation specification in `docs/specs/2026-10-23-platform-remediation-design.md` and verify actual user-visible behavior.

**Architecture:** Rust identity owns authoritative authentication, sessions and OIDC; independent Go profile, notification and admin/audit commands own separate databases and consume versioned Kafka contracts. A TLS gateway, isolated Kubernetes namespace, durable storage, migrations, telemetry and automated acceptance exercise the complete system.

**Tech Stack:** Rust/Axum/SQLx/PostgreSQL, Go/net/http/pgx/franz-go, React/TypeScript, Kafka-compatible Redpanda, Kubernetes/k3d, Mailpit, OpenTelemetry/Prometheus.

## Global Constraints

- Preserve Rust + Go + Kafka + React. Existing code/layout may be replaced; no compatibility shims or misleading successful fallbacks.
- No cloud mutations, remote repository publication/push or destruction of existing data. Work on task branches, acceptance on isolated resources.
- Authoritative SQL change and outbox event are one transaction; processing has durable inbox/job state. At-least-once delivery is explicit; exactly-once SMTP is not claimed.
- Schema missing means not Ready. Outbound dependencies have finite deadlines; authentication is fail-closed.
- Read the full approved specification; every acceptance gate remains open until exercised. Real Telegram requires external credentials, never a fake pass.
- Agents skip tests/build/lint/format during concurrent implementation; integration owner performs regression runs and real smoke afterward. No independent commits during shared work.

## Shared integration contract

The controller writes `local://platform-remediation-contract.md` before dispatch. It pins routes, cookies, internal authentication, JSON event schema, service commands, environment names and infrastructure ports. All slices use it verbatim; changes require a message to the integration owner. Service ownership is independent by directories/repositories, not edits to shared files.

## Task 1: Identity and contracts

**Files:** Replace focused modules under `identity-service/src/`, extend ordered `identity-service/migrations/`, update Cargo/build/Dockerfile/env/README and `platform-contracts/` contract source and consumers. Remove obsolete gRPC or HTTP paths only on clean migration of all callers.
**Consumes:** PostgreSQL identity DSN, Kafka broker, signing keys, trusted internal identity credentials, gateway origin.
**Produces:** public auth/OIDC/session/MFA/password APIs; authenticated internal introspection/admin APIs; versioned durable events and sensitive delivery intents.

- [ ] Preserve failing-before evidence from audit: missing schema yields login 500 but health 200; inspect code paths for owner/revocation/MFA defects.
- [ ] Add behavior regressions for foreign session ownership, revoked access token, MFA setup/replay, authorization code/refresh reuse and invalid OAuth client/redirect.
- [ ] Implement transactional authoritative storage, migrations/ready contract, bounded Argon2, opaque browser sessions + CSRF, asymmetric OIDC/JWKS and standards-compliant flows, internal service authorization, RBAC and secure bootstrap-admin.
- [ ] Implement leased/ordered outbox with stable event IDs and keyed Kafka partitioning, trace context, retry visibility; no plaintext delivery secrets in public audit topics.
- [ ] Integration owner runs Rust checks/regressions after concurrent edits; exercise actual HTTP + OIDC consumer against real DB/broker and verify persistence/revocation.

## Task 2: Go service cutover

**Files:** `user-notification-service/cmd/{profile,notification,worker,admin}/main.go`, focused `internal/{profile,notification,audit,platform}/` packages, per-owner migrations, Dockerfiles/env/docs. Existing combined app is removed after replacing callers. `admin-cloud-service/README.md` records actual admin/audit ownership instead of an empty implied service.
**Consumes:** shared internal introspection/admin API, profile settings endpoint and contract events; separate DSNs and runtime identities.
**Produces:** `/api/v1/users/me`, settings, admin user/audit/delivery endpoints; independent commands and delivery workers.

- [ ] Add consumer-visible regressions for duplicate inbox event, failed SMTP retry, foreign identity/unauthorized admin, invalid input, poison quarantine and replay.
- [ ] Implement service-specific repositories with transactional inbox/projections/jobs; separate DB ownership; bounded request clients and reliable commit ordering.
- [ ] Implement email and genuine Telegram delivery with checked account linking, persisted leases/attempts/next_attempt_at and terminal states; missing Telegram credentials explicitly disable availability.
- [ ] Implement authenticated admin/audit API and protected replay/ban/unban commands; no direct identity SQL.
- [ ] Run Go test/race/vet and real API/SMTP/Kafka smoke under integration owner; verify a failed job remains recoverable and audit records expose no secrets.

## Task 3: Reproducible infrastructure, observability and CI

**Files:** `platform-infra/{Makefile,k3s,gateway,scripts,observability,docs}`, build/CI files only in other repositories after owner coordination.
**Consumes:** all service commands and shared environment/routes. Uses a new `sso-remediation` environment, leaves `sso-platform` untouched.
**Produces:** deterministic bootstrap/up/status/check/backup/restore commands, TLS/config secrets, durable storage, migration gate, monitoring and fail-closed acceptance scripts.

- [ ] Add real failing smoke assertions, e.g. schema gate: `curl -fkSs https://localhost:8448/api/v1/auth/ready` must fail before migrations and succeed after migrations.
- [ ] Pin toolchains/images; generate non-Git secrets and certificates, separate migration/runtime DB roles, init and migrate before deploy, fail on mandatory errors.
- [ ] Add PVC, safe stateful update, network policies, minimal accounts/RBAC, resource sizing, PDB/topology and correct HPA behavior. Remove permanent Dashboard cluster-admin bootstrap.
- [ ] Deploy OTLP collector/trace backend, Prometheus/dashboards/alerts; instrument business errors/latency, backlog age, lag and delivery attempts. Alert checks must inspect actual firing state.
- [ ] Implement disposable encrypted backup/restore verification and actual fault injection with observed failure/recovery, no success if injection failed.
- [ ] Add independent CI workflows that compile/test/scan/validate/build immutable images; remote publication requires explicit action/credentials.
- [ ] Run clean bootstrap twice, schema failure gate, persistence/restore/chaos and metric/trace/alert acceptance. Record measured rather than invented RPO/RTO and cloud prerequisites.

## Task 4: Frontend and standards consumer

**Files:** `frontend/src/{App,api,auth,components,...}`, CSS, package lock/build/container/docs.
**Consumes:** shared public APIs, browser session/CSRF, user/profile/admin and notification capability endpoints.
**Produces:** actual login/register/verification/recovery/MFA/sessions/profile/notification/admin UI and a real OIDC acceptance client, no localStorage tokens.

- [ ] Capture current frontend use of localStorage and missing real administrative paths as failing-before evidence.
- [ ] Replace auth handling with same-origin secure cookie + CSRF, explicit expiry/revocation handling and clear errors/loading states; preserve no unimplemented feature toggles.
- [ ] Implement profile/settings, MFA/recovery, sessions/password, Telegram linking status and admin users/audit/delivery replay, including negative permission states.
- [ ] Implement external standards OIDC consumer with signature/JWKS/iss/aud/nonce/PKCE and refresh validation rather than unsigned token decoding.
- [ ] Integration owner builds and opens actual UI through browser relay, exercises user/admin flows and inspects visible state at desktop/mobile widths.

## Task 5: Integrated acceptance and review

- [ ] Run final build/lint/test suite once after integration; fix causes with targeted regressions, never weaken acceptance.
- [ ] Run complete spec acceptance in disposable environment: email registration/profile/login, password reset/change, MFA and replay, two-user ownership, revoke/logout/ban across services, OIDC standards consumer, refresh races, event duplicates, relay concurrency, poison/replay and dependencies failing/recovering.
- [ ] Exercise stateful pod recreation, backup/restore content verification, realistic business-load latency/error/lag, forced termination recovery and alert/trace linkage.
- [ ] Independently review security/architecture and all changed repositories; unavailable reviewer remains a visible gate. Update docs/changelogs with actual commands/results and environmental limitations.
- [ ] Deliver exact exercised evidence, branch/workspace locations, external prerequisites (Telegram/AWS when absent), no claim of production acceptance from local k3d.
