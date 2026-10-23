# Local security closure implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Owner scope update:** image/dependency vulnerability scanning is removed entirely and must not run again. Earlier scan tasks below are completed historical investigation, not continuing acceptance criteria. Preserve patches, secrets/IaC/schema checks and behavioral verification. Finish current CI/publication without the excluded gate; Telegram remains credential-blocked.

**Scanner removal execution:** delete dependency/image scanner steps from five verification workflows, retain secret/configuration/functional/build gates; remove infra scan_images/image_archive and their six dedicated tests; update existing active docs and mark old reports historical; validate workflows/tests/runtime, peer-review and publish per-repository PRs. No vulnerability scanning may execute during this work. No patch or data rollback.

**Goal:** Close reachable local image-security and operator-permission defects, establish real Telegram prerequisites, and publish only verified infrastructure changes.

**Architecture:** Preserve existing Rust/Go/Kafka/PostgreSQL ownership and existing retained k3d cluster. Keep upstream-supported artifacts and exact inventories; bound CNPG operand permissions to sso-remediation while retaining narrowly required cluster resources and webhook management. Parent owns lifecycle integration, runtime execution and release decisions.

**Tech Stack:** Python stdlib, uv, Kubernetes/k3d, CloudNativePG1.30.1, Trivy0.76.1, Docker, GitHub Actions.

## Global Constraints

- Host automatic recovery and external hosting are excluded by the user. No host faults, Docker/WSL restart, cluster recreation, destructive storage action or unrequested Kubernetes upgrade.
- Vulnerability scanning and all-severity gates are removed by explicit owner instruction; retained historical reports do not imply current assessment or require reruns.
- No unstable Debian sid migration or organization-owned downstream distribution without an explicit support decision.
- Reuse isolated feat/platform-remediation worktree. No direct main pushes or merge with failing criteria.
- Credentials remain private; report Telegram presence booleans only. No real Telegram delivery claim without real bot/chat/flow.

## Task 1: Resolve image evidence and available genuine patches

**Files:** scripts/scan_images.py; components/grafana/Dockerfile and healthcheck.go; docs/security-images.md; scripts/cli.py image pins/build integration only if a verified candidate is selected.

- [x] Inspected retained exact scanner reports and primary advisory/vendor sources; no known failure rerun merely for confirmation.
- [x] Distinguished genuine patched candidates, package-version false matches and unavailable stable fixes. Residual identities retained in docs/security-images.md and protected raw reports.
- [x] Built genuine Grafana/Tempo/CNPG fixes, measured exact-image inventories, exercised retained and fresh monitoring runtime plus actual operator reconciliation.
- [x] Unsupported-distribution requirement remains explicit; no sid/backport distro or suppression adopted. Literal zero-finding release remains blocked by recorded vendor/advisory prerequisites.

## Task 2: Bound CNPG permissions

**Files:** new scripts/cnpg_operator.py if required; scripts/cli.py install_operator integration; scripts/tests/test_cnpg_operator.py; existing render/config validation paths where applicable.

- [x] Read authenticated release and official namespace-scoped installation support; retained required cluster-resource capabilities.
- [x] Observed real excessive cross-namespace secrets/exec/service authorization before change.
- [x] Implemented namespace-bound Roles/Bindings, bounded cluster rights, supported watch namespace and fail-closed privilege/binding/default-role validation.
- [x] Actual cross-namespace denial, three-instance retained-PVC reconciliation and encrypted four-database backup/disposable content-matching restore passed.

## Task 3: Telegram prerequisites

**Files:** active workspace `/home/bpqvg/dev/h1wtest-remediation`, canonical private `user-notification-service/.env` and runtime configuration read programmatically; existing Telegram handlers and acceptance tools only as needed. Earlier checks of `.local/secrets.json` are historical; it is no longer active configuration.

- [x] Inspected stored/environment/runtime token presence without exposing identifiers or credentials.
- [x] Owner subsequently supplied the real bot token; genuine private-chat Start/webhook linking, persisted preferences and exact-login-event Kafka/worker Telegram delivery passed. Sent job recorded one attempt; no synthetic webhook/direct test message substituted. Evidence in docs/acceptance.md and private .local/acceptance/telegram.json.
- [x] Recorded prerequisite without mocks and continued all reachable work.

## Task 4: Integrated verification and release

**Files:** docs/acceptance.md, docs/handoff.md, CHANGELOG.md, existing GitHub workflow.

- [x] Unit/config/schema checks, real operator authorization/reconciliation, backup/restore, normal build/up/check, actual health probes and post-up core/admin/browser acceptance executed; residual security gate correctly fails.
- [x] Independent read-only CNPG and artifact reviews completed; all actionable Critical/Important source findings corrected and re-reviewed. Specialist reviewer route failed configuration, general independent review route succeeded.
- [ ] Update existing evidence documents after smoke proof, remove owned throwaways, commit/push reviewed task branch and inspect actual remote CI.
- [ ] Merge the infrastructure PR only if all required gates pass. Otherwise report the exact residual IDs/prerequisites without expanding scope or claiming completion.
