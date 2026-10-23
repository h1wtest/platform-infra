# Generic subscription platform — current local implementation handoff

## Current task scope and authority — 2026-10-24

The generic platform design was approved for implementation in the archived conversation context. Work is implemented in isolated task worktrees under `/home/bpqvg/dev/h1wtest-worktrees/generic-subscription-platform`; current phase is integrated **local acceptance**, not a published release. The nine executable/source owners are platform-infra, platform-contracts, identity-service, user-notification-service, frontend, catalog-service, billing-service, subscription-service and referral-service. The tenth task directory, admin-cloud-service, documents the one actual runtime in user-notification-service/cmd/admin; it is not a second admin deployment.

Current local target is namespace `generic-subscriptions`, HTTPS `https://localhost:18448`, HTTP18089 and Mailpit38026. All canonical task credentials/private material and acceptance evidence belong to ignored `platform-infra/.generic-local`, with owner env under `.generic-local/owners/<repository>/.env`. No original namespace `sso-remediation`, retained PVC, original repository `.env` or old acceptance identity may be modified or reused as proof for this task. Generic PostgreSQL is a separate single-instance local acceptance database, explicitly not HA. Broker epoll networking is generic-only; original brokers and global sysctls remain unchanged.

Use `uv run --no-project python scripts/cli.py --profile generic --context k3d-sso-remediation <command>` from this task's platform-infra checkout; use separate explicit gateway/gateway-http/mailpit loopback forwards and trust only the task CA. Strict API context/TLS/namespace-UID guards remain enabled. A private kubeconfig selecting the verified loopback API may be used without changing original kubeconfig/current context. Do not run the historical default-profile commands below against the retained original stand as part of this acceptance.

Approval to implement is **not** permission for remote repository creation, push, PR, merge, publication, external deployment, cloud or production operations. The historical 2026-10-23 main-integration permission and old PR receipts below do not carry over. No real payouts/money transfers or whole-host/Docker Desktop faults are authorized. Source commits, final selected image identities, synchronized digests and clean immutable export receipts remain pending the parent integration owner's final source freeze; none are fabricated here.

## Current evidence ledger — parent final reconciliation required

The parent tracker reported23/40tasks DONE at this documentation checkpoint; that is not an all-task completion statement and is not a fabricated per-task status map. This ledger records only received observations; the final task register/evidence reconciliation belongs to the parent after local gates finish.

| Scope | Received evidence / remaining requirement |
|---|---|
| Infrastructure regressions | Parent reported228tests PASS/3skip in48.393s before latest acceptance/documentation reconciliation; this is a dated checkpoint, not a blanket final-source pass. |
| Private build contexts | Actual Docker root+six backend override exports passed; private sentinel exclusion verified separately from source text inspection. |
| Generic state isolation | Separate namespace/owner store and original-stand restrictions reviewed; independent static isolation review reported no remaining Critical/Important findings in its scope. |
| PostgreSQL/Kafka | Parent observed local generic PostgreSQL Ready; all3generic brokers healthy with no leaderless/underreplicated partitions after scoped crash-counter diagnostic preservation and supported epoll recovery. No independent-host HA claim. |
| Backups | Parent observed encrypted8owner DB backup PASS44.27s; final restore/hash result and complete current runtime evidence require parent reconciliation. |
| API/UI/observability/fault matrix | Parent reports actual isolation30checks PASS281.33s and causal network guard PASS35.05s; new-email fresh-profile BrowserSecurity path passed. Per-pod observability6checks/all9trace services PASS17.83s after corrected Prometheus rollout24.74s, including all4business owner counter/histogram deltas across2Ready replicas, target coverage and fresh assigned lag. Remaining full UI/atomic fault matrices and task reconciliation are not closed by these receipts; fault smoke is not yet claimed. |
| V03 real providers | OPEN: current-task real NOWPayments sandbox keys/callback and real Telegram bot/chat/public HTTPS prerequisites are not established by this ledger. Deterministic fixture/Mailpit results do not close external provider acceptance. Historical Telegram evidence below does not prove the new task's V03. |
| Final source/publication | Final commits/images/provenance/history-secret review and clean export receipts pending; no remote publication operation authorized or claimed. |

Current acceptance criteria remain in the approved generic design/task register. Secret-bearing raw reports stay private; do not copy owner env, keys, callback tokens, private captures or provider payloads into this handoff. Parent should replace checkpoint statements only with exact current evidence; do not infer all gates PASS from worker readiness or prior-main history.

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
