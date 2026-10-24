# Generic subscription platform — current local implementation handoff

## Current task scope and authority — 2026-10-24

The generic platform design was approved for implementation in the archived conversation context. Work is implemented in isolated task worktrees under `/home/bpqvg/dev/h1wtest-worktrees/generic-subscription-platform`; current phase is integrated **local acceptance**, not a published release. The nine executable/source owners are platform-infra, platform-contracts, identity-service, user-notification-service, frontend, catalog-service, billing-service, subscription-service and referral-service. The tenth task directory, admin-cloud-service, documents the one actual runtime in user-notification-service/cmd/admin; it is not a second admin deployment.

Current local target is namespace `generic-subscriptions`, HTTPS `https://localhost:18448`, HTTP18089 and Mailpit38026. All canonical task credentials/private material and acceptance evidence belong to ignored `platform-infra/.generic-local`, with owner env under `.generic-local/owners/<repository>/.env`. No original namespace `sso-remediation`, retained PVC, original repository `.env` or old acceptance identity may be modified or reused as proof for this task. Generic PostgreSQL is a separate single-instance local acceptance database, explicitly not HA. Broker epoll networking is generic-only; original brokers and global sysctls remain unchanged.

Use `uv run --no-project python scripts/cli.py --profile generic --context k3d-sso-remediation <command>` from this task's platform-infra checkout; use separate explicit gateway/gateway-http/mailpit loopback forwards and trust only the task CA. Strict API context/TLS/namespace-UID guards remain enabled. A private kubeconfig selecting the verified loopback API may be used without changing original kubeconfig/current context. Do not run the historical default-profile commands below against the retained original stand as part of this acceptance.

Approval to implement is **not** permission for remote repository creation, push, PR, merge, publication, external deployment, cloud or production operations. The historical 2026-10-23 integration permission does not carry over. Verified implementation and correction blocks are committed locally on `feat/generic-subscription-platform`; no real transfer or whole-host fault occurred. Current image/source receipts remain private under `.generic-local`; final selection and source export must use those exact receipts, not a moving branch.

## Current local acceptance evidence — 2026-10-24

All eight functional domains have running implementations and exercised local API/worker/browser paths. The external provider gate remains **OPEN**; local acceptance is not publication-ready, production/HA or provider certification. The task register below the original requirements records each local result and the separate external prerequisite.

| Scope | Executed evidence |
|---|---|
| Contracts | Go suites, 21 Rust regressions, Clippy with warnings denied, 14 Python tests and eight compiled TypeScript regressions passed. Strict decimal/exponent rejection, optional omission/null semantics and actual cookie/status metadata are covered. |
| Identity | Actual PostgreSQL OAuth suite: 23 passed; current generic identity suite: 18 passed. Current permissions, MFA, last OWNER, own grant revocation, code/refresh races and original-actor SUPPORT recovery exercised. |
| Go owners | Full race/vet suites passed against disposable owner databases and TLS/SCRAM Kafka. Final correction runs include billing 7.571s, subscription 15.019s and shared Go owner suite 15.22s. |
| Frontend | 181 behavioral tests across 28 files, ESLint, TypeScript, Vite and generated-contract checks passed. Actual EN/RU desktop/390px flows covered OWNER/ADMIN/SUPPORT/ordinary users; screenshots contain no credentials. |
| Infrastructure | 238 regressions passed with three explicit opt-in/prerequisite skips; all nine workflows passed actionlint. Actual rendered Prometheus config and five alert rules validated. |
| Isolation | 30 actual checks passed in 281.33s: eight runtime DB owners, 56 foreign CONNECT denials, Kafka topic/group/producer matrices, encrypted quarantine, nine-owner TLS and same-pod causal NetworkPolicy denial. Hardened namespace/cluster baseline plus network smoke passed 35.05s. |
| Recovery | SMTP outage/recovery 40.70s; paid subscription-owner outage/recovery 61.77s; retained-PVC broker outage/recovery 76.46s. Exact original replicas restored; first failed harness attempts remain recorded separately. Three brokers subsequently reported healthy with zero leaderless/under-replicated partitions. |
| Paid renewal boundary | Actual HTTP/Kafka smoke passed 133.82s: controlled pre-prepare period timestamp fixture, real 100-second scheduler expiry during broker outage, immutable N+2 outcome, FULFILLED renewal, anchored period and exactly one renewal commission despite replay. No payment/state/version fabrication after prepare. |
| Notifications | Actual forgot-password flow honored notification RU/website EN and the reverse while optional emails were disabled. Portable seven-bit MIME receiver, actual SMTP/Mailpit, immutable replay, scoped HMAC ingress and readiness delivery passed. Real Telegram delivery is not claimed. |
| Administration | Real user ban/unban/session revocation, audit pagination, staff/permission changes, catalogue publication/archive, monetary-evidence review, compensation/close and manual payout rejection exercised. Temporary staff policies and template contents were restored. |
| Template concurrency | Actual insert-at-selection, real nonpublishing escaped preview, invalid-variable rejection and dirty revision4 versus remote revision5 conflict passed. Explicit reload adopted revision5; finally the exact original locales were restored as immutable revision6. |
| Overview | Real subscription-owner outage showed unavailable subscriptions rather than empty/stale access while account, orders and referral balance remained available; recovery returned the unchanged ACTIVE paid subscription. |
| Observability | Six actual checks/all nine causal operation traces and per-pod counter/histogram deltas passed 17.83s. Real AcceptanceProbe reached firing and exact original rules were restored, 50.67s; later query showed no test alert. |
| Backup | Authenticated encrypted eight-owner backup passed 44.27s; restore into unique disposable databases and source row-content digest comparisons passed 49.04s. Per-database snapshots, not a distributed atomic backup/PITR claim. |
| Sources | Ten local feature-repository commits plus six correction commits; exact staged-source directory scan (7.42MB) and all ten full histories passed redacted Gitleaks. Clean pinned nine-owner copy/bootstrap repeated without changing generated private material. Final source/image selection is recorded separately. |

**External OPEN:** current-task NOWPayments sandbox credentials/signed public callback and Telegram bot/private chat/public HTTPS link/unlink/send are unavailable. Fixture payments, Mailpit and local TLS protocol tests do not close this gate; historical Telegram receipts below do not apply to it. Trading delivery remains Telegram-only, with no SMTP substitute or real-transfer claim.

**Browser evidence limit:** true hidden-document state could not be observed through the available Chrome/CDP window controls. Actual visible idle produced no API polling; source/test visibility guards remain verified separately. No DOM override or synthetic hidden-state PASS was used.

Private evidence paths include `acceptance/final-renewal-01.json`, `acceptance/final-account-01.json`, `acceptance/final-template-browser.json`, fault/isolation/observability receipts and `backups/20261023T220133Z-2bbbfe4d/restore-verification.json`. Do not publish these private files, owner env, keys, cookies or raw provider payloads. Existing failed diagnostics are preserved; no vulnerability scanner was run or reintroduced.


Everything below is preserved **historical 2026-10-23 remediation material**. Its “current” wording, workspaces, URLs, permissions, scan outcomes, remote receipts, tests and external-provider observations apply only to that old checkpoint, not this generic implementation or its authorization.

## Historical 2026-10-23 remediation — preserved evidence, not current authorization

### Historical state at the 2026-10-23 checkpoint

Implementation workspace: `/home/bpqvg/dev/h1wtest-remediation`. The owner authorized integrating all prepared changes into each repository's `main` and synchronizing clean primary checkouts on 2026-10-23. Public organization: https://github.com/h1wtest . This authorization does not include deployment or cloud/production operations. Integration receipts: [identity PR3](https://github.com/h1wtest/identity-service/pull/3), [notifications PR3](https://github.com/h1wtest/user-notification-service/pull/3), [infrastructure PR2](https://github.com/h1wtest/platform-infra/pull/2); their current GitHub state and `origin/main` are authoritative.

Infrastructure PR2 includes both `fix/repository-env-telegram` and `feat/independent-helm-releases`: canonical owner env, genuine Telegram evidence, independent Helm releases and the registration-only benchmark. The live local stand has already adopted Helm ownership. Primary checkouts under `/home/bpqvg/dev/h1wtest` are synchronized to `main` only after their integration succeeds, using clean-worktree checks and fast-forward updates. Until the primary infrastructure checkout contains this Helm cutover, run lifecycle commands only from `/home/bpqvg/dev/h1wtest-remediation/platform-infra`; an old Python-only checkout must not write the same Helm-owned resources. Commands and recovery policy: README section "Независимые Helm-релизы и обновления". Namespace/operator bootstrap remains explicit; no cloud or production topology was deployed.

The following SHAs are the historical main baseline **before** the integration above, not a claim about current remote heads:

| Repository | Pre-integration main |
|---|---|
|platform-contracts|`f354498b360121d18f5c48d4b578ae8e004a8415`|
|frontend|`96ee3c3e08011a98296ad71b009e6f4117f59dc0`|
|user-notification-service|`e5c706e4d4ed6f121b9ae420387e872a9e3b1825`|
|identity-service|`e19ad30af2538b776e5e2f6a1ad97ea142013530`|
|admin-cloud-service|`2c479d1aa11a71c08b4789e40d5d0eae67b67d34`|
|platform-infra|`602e05fa9b8b4163146c38c9471845ef8f1396a1` (merged PR1)|

All six repositories already existed; no new empty repository or fictitious deployment was created. The independently deployed Go admin/audit command lives in `user-notification-service/cmd/admin`; `admin-cloud-service` documents that ownership rather than claiming a second executable.

Local UI: `https://localhost:8448`. Verify using `.local/ca.crt` explicitly. The OS trust store was not modified. Canonical credentials/private keys belong to ignored mode0600 `platform-infra/.env`, `identity-service/.env` and `user-notification-service/.env`; admin email/password live in identity env and Telegram credentials in Go env. `.local` retains derived PEM mounts and protected historical recovery archives, never active secrets.json. Legacy import preserves credentials/key bytes without rotation; missing owner env after initialization must fail closed. Back up all owner env privately; frontend receives no secrets. Real MFA is required. Never paste credentials into Git, tickets or logs.

Current acceptance scope is local development only. The user explicitly excluded whole-host automatic recovery and external-hosting requirements from current completion criteria. Historical failed host reports below remain evidence, not current acceptance blockers; no new host faults or cloud work are authorized.

The owner subsequently explicitly removed vulnerability scanning of images and dependencies from the entire ecosystem and from acceptance criteria. Do not run or reinstate these scanners. Preserve actual patched images/dependencies, RBAC/TLS/secret/configuration checks and behavioral tests. Historical scan results below are historical evidence only; scanner removal does not establish vulnerability absence.

### Historical executed application and remote checks

Permanent actual acceptance harness: `scripts/acceptance`; detailed commands and observations: `docs/acceptance.md`.

Exercised real registration/Mailpit verification/Kafka profiles; session ownership/revocation/logout/ban; MFA and recovery replay; password changes/reset; browser standards OIDC with RS256/JWKS/PKCE/nonce/state/refresh; administration; SMTP outage/retry/recovery; duplicate/poison/replay; database and broker privileges; untrusted NetworkPolicy denial; encrypted four-database backup/restore hashes; replacement faults; real delivery alert and five-service trace.

Final identity dependency changes passed strict Clippy, meaningful `cargo audit --deny warnings`, actual HTTP OTLP export/W3C regression and50 real PostgreSQL/TLS-Kafka/signing/OIDC/MFA/relay/readiness regressions. Maintained dependencies remove vulnerable RSA/protobuf and unmaintained PEM parsing; JWT10.4 and OpenTelemetry SDK0.32.1 address the later all-severity image findings. Remote identity push/PR runs `39922372881` / `39922377866` passed, including final immutable-image scanning; post-merge main workflow was dispatched.

Go commands passed real PostgreSQL/Kafka race tests, vet, four builds and source-provenance checks. x/sys0.44 addresses the actual final-image finding. All four final command images passed the remote all-severity gate. Main push/dispatch runs `39919978983` / `39919982057` passed.

Frontend35 behavioral tests, lint/format/typecheck/build and dependency audit passed. Exact musl/zlib security revisions were installed; full final-image gate passed remotely. Main push/dispatch runs `39917144305` / `39917147318` passed. Real desktop/mobile login/profile/security/nonadmin-denial/logout and signed OIDC/refresh were exercised. Browser UI used an isolated certificate exception; strict TLS API checks remain separate evidence.

Contracts generation, strict Go/Rust HTTP codecs, complete immutable-v1 compatibility, tests and complete source artifact passed. Main push/dispatch runs `39919640075` / `39919642448` passed. Service CI pins the approved immutable contracts commit `665c565bd0a00f30027b429129b22d91f99ef6b0`; later main changes only update verified Node24 workflow action pins.

### Historical whole Docker-host failure: automatic recovery FAILED; manual recovery verified

Two explicitly approved abrupt Docker Desktop WSL VM failures were executed. Both remain **FAIL**, not successful autonomous recovery:

1. Docker restart-policy startup left k3d nodes stopped with runtime `cgroup.procs` EBUSY. Existing-container startup and controlled broker process recovery were required.
2. Docker Desktop lost Ubuntu WSL integration (`Wsl/Service/0x8007274c`). A supported Docker Desktop restart restored integration, but dynamically reassigned cluster container IPs disagreed with retained etcd peer identities.

No further whole-host faults are authorized by this handoff. Do not reset/purge Docker, unregister WSL distributions, recreate the cluster, delete PVCs/topics/logs, or force etcd/broker recovery to make acceptance pass.

Manual recovery retained every existing container and volume. Original Kubernetes node addresses were restored as explicit static Docker IPAM reservations; all three nodes, API/etcd, PostgreSQL, applications and broker quorum recovered. Stale outbound broker channels were restored by one-at-a-time retained-PVC pod replacement with bidirectional peer checks. No leaderless or under-replicated partitions remained.

After recovery, run `98e7f41d18244ac7b30bc23a33a6dc3a` verified the **same pre-failure session**, committed profile/database marker, six acknowledged RF3 Kafka partition markers and46 sampled historical records at their original coordinates/hashes. Consumer groups were not modified. This proves those values survived; it is not all-record, physical-power-loss or independent-host HA certification. Owned DB/session/profile fixtures were cleaned; bounded24h Kafka acceptance records/topic metadata remain.

Evidence remains private in `.local/acceptance`: both failed host reports, correlated business evidence and broker diagnostics. `make check` subsequently passed; SSO returned HTTPS200 with explicit CA. Docker/Ubuntu integration and unrelated `dsh-hindsight` were running.

### Historical local release criteria

Vulnerability image/dependency scanning has been deleted by explicit owner instruction. Existing local source/image provenance, tests, secret checks, IaC/schema/monitoring validation and real business acceptance remain required. `docs/security-images.md` is an archived investigation, not an instruction to rerun scanners or a current merge blocker. Previously implemented genuine package/module/CA fixes remain selected; no security patch or access-control rollback accompanies this policy change.

CNPG permissions are now actually bounded: the retained original ClusterRole has only node/catalog reads and named own-webhook access; operand mutation uses a Role in sso-remediation. Real impersonated authorization permits owned secrets/exec/services and denies all three in kube-system/default. Operator namespace PKI/cache/leader permissions remain necessary. A peer review found and corrected local pull policy and webhook-secret renewal gaps. Live operator and all three injected instance managers use the patched image; original PVCs retained, all three PostgreSQL instances Ready. Repeat installation and encrypted four-database backup/disposable content-matching restore passed.

Grafana now ships complete signed, checksum-pinned Prometheus/Tempo plugins and disables startup downloads/updates. Actual retained-data dashboard plots and both datasource health checks passed; a fresh disposable emptyDir instance also queried real Prometheus samples and Tempo successfully without plugin downloads. Tempo's real cross-service trace was observed after its package patch. Telegram credentials were subsequently supplied by the owner: real private-chat Start/webhook linking, settings and an exact-login-event Kafka/worker delivery passed; private evidence is `.local/acceptance/telegram.json`.

Earlier infrastructure CI runs genuinely failed the former vulnerability gate. Those results are not relabeled; new workflows no longer include that owner-excluded gate. Current required checks must pass before integration. Existing Kubernetes1.35.5 nodes are retained; no node upgrade, host fault or external deployment is part of this local task.

### Historical other boundaries

- Genuine Telegram linking/login-alert delivery passed with a real bot/private chat and secret-authenticated webhook. Current webhook ingress is a temporary ngrok tunnel exposing only the webhook route; unattended tunnel availability is not certified. Bot API acceptance is not a human-read receipt.
- No AWS/production, independent-host/zone failure, PITR, OIDC certification or long-term RPO guarantee.
- Backups are authenticated encrypted logical snapshots. An active systemd user manager/host is required for the installed hourly timer; off-host durability is not established.

### Historical operator commands — not the generic task invocation

Use `make bootstrap`, `make build`, `make up`, `make check` from `platform-infra`. Start loopback operator forwards explicitly with `make mailpit`, `make prometheus`, `make grafana`, `make tempo`. `make restore-verify BACKUP=<specific complete path>` restores only unique disposable databases and compares source content. Missing/malformed arguments fail before cluster mutation.

Fault/rekey commands are maintenance actions, not health checks. Do not repeat whole-host injection after the observed integration failures. Preserve diagnostic failed Jobs and original failure reports instead of relabeling them successful.
