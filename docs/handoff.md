# Local remediation handoff

## State and location

Approved specification: `docs/specs/2026-10-23-platform-remediation-design.md`. Changes are in isolated sibling worktrees at `/home/bpqvg/dev/h1wtest-remediation`, branch `feat/platform-remediation` in all six repositories. No commits, remote push, merge, cloud resources or production operations were performed.

Local UI: `https://localhost:8448`. Explicit CA: `.local/ca.crt`; system trust was not modified. Admin credentials and purpose/service keys remain in ignored mode0600 `.local/secrets.json`; administrative access requires real MFA. Do not paste these values into Git, tickets or logs.

Architecture: Rust identity; independent Go profile, notification API, delivery worker and admin/audit commands; React frontend; canonical event/internal HTTP contracts. `admin-cloud-service` documents cutover to the actual Go admin command, not a fictitious extra deployment.

## Executed local verification

Exact commands, measured results and corrected failures: `docs/acceptance.md`. Permanent rerunnable harness: `scripts/acceptance`; `make acceptance` is not a discovery-only test.

Exercised strict TLS; registration and actual Mailpit email; Kafka-created profiles; sessions/ownership/revocation/ban across services; MFA/recovery replay rejection; password reset/change; standards OIDC consumer, RSA/JWKS/PKCE/nonce/state/refresh races; administrator MFA/search/ban/unban/audit; actual SMTP outage/retry/recovery; duplicate/poison Kafka records; exact owned corrected replay; database privileges, broker ACLs and untrusted network denial; primary replacement with known committed value; encrypted backup/restore content comparison; timer-driven backup; actual delivery alert and a five-service correlated trace.

Final durable core after clean Mailpit/nginx rollout: **PASS, 21.44s**. Final Grafana distroless-slim UI loaded its provisioned dashboard, Prometheus/Tempo datasource health returned OK, and corrected sampled-lag panels displayed real series plus sample age. These are functional checks, not a CVE waiver.

| Local measurement | Result |
|---|---|
| Authenticated profile reads, eight workers/15s |10,174 successes, zero errors; p95 16.142ms|
| Login/profile/email delivery, ten unique users/two workers |10 successes, zero errors; group lag0; p95 login89.429ms/profile10.763ms/delivery517.696ms|
| Encrypted logical backup / verified disposable restore |4DB;20.66s /24.59s; source row-content hashes matched|
| Primary replacement |75.879s evidence/77.95s wall; known value preserved; new UID/primary; all3Ready|
| Identity replacement / broker replacement |13.33s /22.38s; real business probes; broker subsequently verified zero under-replicated/leaderless partitions|
| Actual timer-driven backup |05:06:11→05:06:32 local; Result=success, ExecMainStatus0|

These are bounded local acceptance measurements, not production capacity, host/zone HA, PITR or long-term RPO guarantees. Earlier failures, including initial timer lock collision and faulty chaos selector, remain documented rather than relabeled successful.

Application checks: strict Rust Clippy, real SQL/Kafka regressions and six RSA-format/rotation checks; Go1.26.10 vet/race/build plus actual disposable CI broker lifecycle; frontend lint/format/28 tests/typecheck/build and actual desktop/mobile/browser flows; contract generation/compatibility behavior tests. Meaningful application source/binary dependency scans passed. Empty scratch/zero-file scanner results were explicitly rejected until package inventories were available. Workflow syntax checked locally; remote GitHub jobs were not run.

## Security acceptance is BLOCKED

**The whole platform is not zero-HIGH, fully accepted or production-ready.** `docs/security-images.md` lists actual infrastructure scan reports and supported candidates. Clean Mailpit/nginx patches were deployed and reverified. PostgreSQL, Redpanda, Grafana and K3s still require patched supported upstream artifacts. No CVE suppressions, package-inventory deletion, severity weakening or inferred risk waiver were used.

Future bootstrap pins K3s1.35.9, reducing reported findings but not reaching zero. Existing1.35.5 nodes were not implicitly upgraded/deleted; data-preserving control-plane maintenance is a separate open gate. A source pin is not runtime upgrade proof.

## External prerequisites

- Telegram: genuine bot credentials, private test chat and reachable authenticated HTTPS webhook. Channel is honestly unavailable without them; mocked delivery was not accepted.
- Remote CI: authorized publication, accessible immutable contracts commit and `PLATFORM_CONTRACTS_REVISION`/dispatch input. Implementation approval does not authorize push or repository settings changes.
- AWS/production, independent host/zone failover, PITR and OIDC certification were not verified and are not claimed.

## Running the stand

From `platform-infra`: `make bootstrap`, `make build`, `make up`, `make check`. Operator port-forwards: `make mailpit`, `make prometheus`, `make grafana`, `make tempo`. Trust the CA explicitly; do not globally install an unreviewed root.

`make backup` / `make restore-verify BACKUP=<specific path>` create authenticated encrypted logical snapshots and compare disposable restored content. The installed hourly systemd user timer needs an active host/user manager; one successful trigger does not prove perpetual execution or off-host durability.

Fault commands serialize destructive operations, require a genuine business probe, verify controller-owned replacement UID/desired Ready replicas and broker health where applicable. Bootstrap/migrations/faults/restore verification do not reset existing data. Historical failed Jobs remain diagnostic, not current-service readiness failures.

Temporary verification containers and parent throwaway scripts/keys were removed after permanent harness integration. Owned verification browser tabs and temporary port-forwards were closed. The working Kubernetes stand, ignored local credentials, backups, durable acceptance state and hourly backup timer were retained. Start operator forwards explicitly when needed.
