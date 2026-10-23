# Local remediation and release handoff

## Current state

Working trees: `/home/bpqvg/dev/h1wtest-remediation`; branch `feat/platform-remediation`. Original clean main checkouts were fast-forwarded after reviewed merges. Public organization: https://github.com/h1wtest . No cloud or production operations occurred.

| Repository | Published main |
|---|---|
|platform-contracts|`524a6d86248517cd9e4ec4a88e11ac22c2ec99ca`|
|frontend|`317ddc7d75319e3505b99ed8234f71dd12f8da3a`|
|user-notification-service|`644ba45fab4c4550de5428fe02edda279f16a8de`|
|identity-service|`8092d4328e717d5669067ad70ee9c4311ad3a3f2`|
|admin-cloud-service|`2c479d1aa11a71c08b4789e40d5d0eae67b67d34`|
|platform-infra|[PR1](https://github.com/h1wtest/platform-infra/pull/1), security gate remains failing; not merged|

All six repositories already existed; no new empty repository or fictitious deployment was created. The independently deployed Go admin/audit command lives in `user-notification-service/cmd/admin`; `admin-cloud-service` documents that ownership rather than claiming a second executable.

Local UI: `https://localhost:8448`. Verify using `.local/ca.crt` explicitly. The OS trust store was not modified. Administrator credentials, signing material and service keys remain in ignored private `.local`; real MFA is required. Never paste them into Git, tickets or logs.

Current acceptance scope is local development only. The user explicitly excluded whole-host automatic recovery and external-hosting requirements from current completion criteria. Historical failed host reports below remain evidence, not current acceptance blockers; no new host faults or cloud work are authorized.

## Executed application and remote checks

Permanent actual acceptance harness: `scripts/acceptance`; detailed commands and observations: `docs/acceptance.md`.

Exercised real registration/Mailpit verification/Kafka profiles; session ownership/revocation/logout/ban; MFA and recovery replay; password changes/reset; browser standards OIDC with RS256/JWKS/PKCE/nonce/state/refresh; administration; SMTP outage/retry/recovery; duplicate/poison/replay; database and broker privileges; untrusted NetworkPolicy denial; encrypted four-database backup/restore hashes; replacement faults; real delivery alert and five-service trace.

Final identity dependency changes passed strict Clippy, meaningful `cargo audit --deny warnings`, actual HTTP OTLP export/W3C regression and50 real PostgreSQL/TLS-Kafka/signing/OIDC/MFA/relay/readiness regressions. Maintained dependencies remove vulnerable RSA/protobuf and unmaintained PEM parsing; JWT10.4 and OpenTelemetry SDK0.32.1 address the later all-severity image findings. Remote identity push/PR runs `39922372881` / `39922377866` passed, including final immutable-image scanning; post-merge main workflow was dispatched.

Go commands passed real PostgreSQL/Kafka race tests, vet, four builds and source-provenance checks. x/sys0.44 addresses the actual final-image finding. All four final command images passed the remote all-severity gate. Main push/dispatch runs `39919978983` / `39919982057` passed.

Frontend35 behavioral tests, lint/format/typecheck/build and dependency audit passed. Exact musl/zlib security revisions were installed; full final-image gate passed remotely. Main push/dispatch runs `39917144305` / `39917147318` passed. Real desktop/mobile login/profile/security/nonadmin-denial/logout and signed OIDC/refresh were exercised. Browser UI used an isolated certificate exception; strict TLS API checks remain separate evidence.

Contracts generation, strict Go/Rust HTTP codecs, complete immutable-v1 compatibility, tests and complete source artifact passed. Main push/dispatch runs `39919640075` / `39919642448` passed. Service CI pins the approved immutable contracts commit `665c565bd0a00f30027b429129b22d91f99ef6b0`; later main changes only update verified Node24 workflow action pins.

## Whole Docker-host failure: automatic recovery FAILED; manual recovery verified

Two explicitly approved abrupt Docker Desktop WSL VM failures were executed. Both remain **FAIL**, not successful autonomous recovery:

1. Docker restart-policy startup left k3d nodes stopped with runtime `cgroup.procs` EBUSY. Existing-container startup and controlled broker process recovery were required.
2. Docker Desktop lost Ubuntu WSL integration (`Wsl/Service/0x8007274c`). A supported Docker Desktop restart restored integration, but dynamically reassigned cluster container IPs disagreed with retained etcd peer identities.

No further whole-host faults are authorized by this handoff. Do not reset/purge Docker, unregister WSL distributions, recreate the cluster, delete PVCs/topics/logs, or force etcd/broker recovery to make acceptance pass.

Manual recovery retained every existing container and volume. Original Kubernetes node addresses were restored as explicit static Docker IPAM reservations; all three nodes, API/etcd, PostgreSQL, applications and broker quorum recovered. Stale outbound broker channels were restored by one-at-a-time retained-PVC pod replacement with bidirectional peer checks. No leaderless or under-replicated partitions remained.

After recovery, run `98e7f41d18244ac7b30bc23a33a6dc3a` verified the **same pre-failure session**, committed profile/database marker, six acknowledged RF3 Kafka partition markers and46 sampled historical records at their original coordinates/hashes. Consumer groups were not modified. This proves those values survived; it is not all-record, physical-power-loss or independent-host HA certification. Owned DB/session/profile fixtures were cleaned; bounded24h Kafka acceptance records/topic metadata remain.

Evidence remains private in `.local/acceptance`: both failed host reports, correlated business evidence and broker diagnostics. `make check` subsequently passed; SSO returned HTTPS200 with explicit CA. Docker/Ubuntu integration and unrelated `dsh-hindsight` were running.

## Security release remains BLOCKED

**The entire platform is not all-findings-clean or production-ready.** `docs/security-images.md` retains exact infrastructure findings and primary advisories. The gateway is genuinely patched and scanned with70 packages/zero findings; no severity filters, CVE ignores or inventory deletion are used in final image gates.

Supported PostgreSQL/Redpanda/K3s images retain unresolved findings. Grafana, Tempo and CNPG now use genuine security extensions integrated into content-addressed build/import/scan paths. The previously unscanned CNPG image's39 findings were fixed by rebuilding both shipped manager architectures with Go1.27.3/x/net0.60 and genuine Debian CA metadata. The final image including its separate readiness helper evaluates193packages with zero findings. Grafana/Tempo retain raw findings with separately recorded applicability evidence; no suppression or all-clean claim.

CNPG permissions are now actually bounded: the retained original ClusterRole has only node/catalog reads and named own-webhook access; operand mutation uses a Role in sso-remediation. Real impersonated authorization permits owned secrets/exec/services and denies all three in kube-system/default. Operator namespace PKI/cache/leader permissions remain necessary. A peer review found and corrected local pull policy and webhook-secret renewal gaps. Live operator and all three injected instance managers use the patched image; original PVCs retained, all three PostgreSQL instances Ready. Repeat installation and encrypted four-database backup/disposable content-matching restore passed.

Grafana now ships complete signed, checksum-pinned Prometheus/Tempo plugins and disables startup downloads/updates. Actual retained-data dashboard plots and both datasource health checks passed; a fresh disposable emptyDir instance also queried real Prometheus samples and Tempo successfully without plugin downloads. Tempo's real cross-service trace was observed after its package patch. Telegram bot token is absent in stored settings, environment and runtime Secret; real delivery remains a credential prerequisite.

Infrastructure remote CI actually ran: the first source-IaC failure was corrected by explicitly retaining Grafana UID472; the subsequent run reached immutable image scanning and failed on remaining real findings. Do not merge by weakening this gate. Existing Kubernetes nodes1.35.5 were not implicitly upgraded; configured bootstrap1.35.9 does not prove runtime maintenance or zero vulnerabilities.

## Other boundaries

- Genuine Telegram acceptance requires a real bot, private chat and reachable authenticated webhook; unavailable without these, no mock accepted.
- No AWS/production, independent-host/zone failure, PITR, OIDC certification or long-term RPO guarantee.
- Backups are authenticated encrypted logical snapshots. An active systemd user manager/host is required for the installed hourly timer; off-host durability is not established.

## Operator commands

Use `make bootstrap`, `make build`, `make up`, `make check` from `platform-infra`. Start loopback operator forwards explicitly with `make mailpit`, `make prometheus`, `make grafana`, `make tempo`. `make restore-verify BACKUP=<specific complete path>` restores only unique disposable databases and compares source content. Missing/malformed arguments fail before cluster mutation.

Fault/rekey commands are maintenance actions, not health checks. Do not repeat whole-host injection after the observed integration failures. Preserve diagnostic failed Jobs and original failure reports instead of relabeling them successful.
