# Local remediation acceptance

## Re-run

Run from `platform-infra`, after `make up`, with loopback port-forwards in separate terminals: `make mailpit`, `make prometheus`, `make tempo`. Never production/cloud. Requirements: uv, Python3.12+, OpenSSL, kubectl; the encrypted terminal-failure fixture additionally uses Node/OpenSSL crypto. All HTTP acceptance verifies TLS strictly against `.local/ca.crt`; no skip-verification fallback.

`make acceptance` runs TLS, full API, negative authorization, concurrent OAuth, events, broker ACL, database privilege and untrusted network gates sequentially. It creates unique disposable users. Secrets/state stay mode0600 under ignored `.local/acceptance/`; source scripts contain no account credentials. Full API mutates only its disposable users, including password/MFA/revocation. Repeated full runs create new unique users, not reset existing data.

```sh
make acceptance
make acceptance GATE=probe
make bootstrap-admin
make acceptance GATE=admin
make acceptance GATE=smtp-fault
make acceptance GATE=load
make acceptance GATE=business-load
make acceptance GATE=trace
make acceptance GATE=failure
make acceptance GATE=replay
make persistence
make chaos TARGET=identity-service PROBE='sh scripts/acceptance/probe.sh'
```

Individual gates: `e2e`, `negative`, `race`, `events`, `network`, `broker-acl`, `db-privileges`, `tls`. `ARGS='--mailpit http://127.0.0.1:28026 --state-directory /private/custom/path'` controls loopback mail/state, and `--ca` controls explicit trust file. Environment `ACCEPTANCE_DIRECTORY`, `ACCEPTANCE_MAILPIT`, `ACCEPTANCE_BASE` supported; dispatcher restricts origin to the isolated `https://localhost:8448` stand. `probe.sh` uses ignored state and explicit CA automatically. `admin` reads bootstrap admin credentials privately from `.local/secrets.json`, completes actual MFA and stores its TOTP secret only in ignored state.

For a previously enrolled administrator, preserve/provide its own mode0600 `admin-state.json`; missing state is an explicit prerequisite error, never a server MFA reset or DB secret extraction. Admin/replay share an owner-state flock, wait for the next real30s TOTP counter (bounded32s), atomically reserve it before request and never retry rejected factors. This prevents legitimate replay protection from being mistaken for application failure in sequential acceptance.

`events` publishes actual Kafka duplicate+malformed events, verifies durable inbox/jobs/quarantine and broker group offsets; `smtp-fault` scales actual Mailpit down/up under the shared fault lock and proves persisted retry/recovery. `failure` encrypts a deliberately invalid recipient intent using Node AES256-GCM with real job UUID AAD, inserts a unique disposable delivery job, observes genuine worker `invalid_recipient` terminal failure and actual `DeliveryFailed` firing. It is not proof of an external SMTP provider failure. `replay` requires preceding events+failure+admin fixtures, verifies corrected quarantine replay and authorized failed-job retry without inventing success. External Telegram credentials remain mandatory for genuine Telegram acceptance.

Poison replay is restricted to the exact acceptance-owned run UUID/Kafka topic+partition+offset/quarantine ID in ignored `poison.json`, captured from actual producer acknowledgement and durable quarantine. Neither replay entrypoint selects the first pending record; an unrelated older quarantine, missing ownership marker or changed coordinates fails closed without modification.

Load is eight concurrent authenticated profile readers for15s after a real login, threshold p95≤500ms, zero errors required (stricter than selected local target<1%). This is a **local acceptance target**, not a production SLO. Discovery-only load is not counted. Trace gate injects a real W3C trace into login and requires actual identity/outbox/Kafka/notification/provider spans from Tempo; no synthetic success.

`business-load` is a separate modest end-to-end workload:10fresh unique users,2workers, one real login/profile read per user, exact session ID→authoritative outbox event→persisted email delivery correlation, HTTP p95/error ratio, delivery end-to-end p95 and authoritative notification group lag0. HTTP targetp95<500ms/errors<1%, deliveryp95<90s; registration/email setup is untimed and rate limits are not bypassed. This complements the high-rate profile-only benchmark; it does not advertise production capacity.

## Exercised evidence — controller/Main, 2026-10-23

- Full strict-TLS API acceptance completed: registration→real Mailpit verification→profile, two-user foreign-session denial, revoked/logout sessions across services, MFA/recovery replay/pending setup, password change/reset, OIDC signature/issuer/audience/nonce/state/PKCE/code-once/refresh reuse. Concurrent OAuth redemption and independent browser standards-client OIDC+refresh were exercised separately.
- Admin actual MFA/API ban/unban and audit passed, including integrated admin browser. Real logged-out OIDC start→return_to→browser login→standards-client callback verified RS256 claims and refresh. At390px long-email logout measured68.8×38.5px, nowrap/no overflow; standalone checks were not substituted for these integrated paths.
- Real profile load:10174successful requests,0errors, p95=16.142ms,8workers/15s; no simultaneous failover claimed for that run.
- Durable `business-load` actually passed10fresh users/2workers:10successes0errors, loginp95=89.429ms, profilep95=10.763ms, exact-login email deliveryp95=517.696ms and authoritative notification lag0 after completion. Limits500/500/90000ms met without altering rate limits.
- Encrypted backup4DB20.66s, independent disposable restore/source-content hashes24.59s. Actual primary persistence replacement75.879s evidence/77.95s wall, all3Ready, new primary+UID and known value hash preserved. No independent-host/zone guarantee.
- Corrected identity chaos13.33s: victim was Ready Running deployment pod (not completed migration Job), replacement new UID/all desired HPA replicas Ready and real business probe before/after passed. Initial selector failure remained a failed gate until corrected; no success was inferred from surviving replicas.
- Broker replacement+business probe22.38s initially left10under-replicated partitions: not counted as full quorum recovery. Added authoritative `rpk cluster health` gate; subsequent actual report `is_healthy=true`, nodes[0,1,2], under-replicated/leaderless counts0 and empty nodes_down passed. Real duplicate+poison Kafka events delivered through SMTP after recovery. Future Redpanda chaos/startup requires that health report in addition to pod UID/Ready proof.
- Broker SASL/TLS denies profile/audit sensitive commands and profile authoritative produce. Untrusted pod denied identity/profile/DB; positive allowed service paths passed. All4runtime DB roles allowed own DML, denied DDL and cross-owner CONNECT.
- Actual trace `5f386eff540c1ad0ded536a04829e5dc` crossed five services and included `outbox.publish` and `delivery.email`.
- Actual terminal invalid-recipient worker failure caused live `DeliveryFailed` firing; first failure0→1 promtool regression passed.
- Strict Kubernetes/CNPG validation, monitoring configuration and Trivy rendered scan were exercised; successful Trivy result required98Kubernetes files/2352checks/HIGH0, not the earlier rejected zero-file scan. Application checks/scans are reported by each owner/controller; workflow presence is not execution proof.
- Hourly user timer installation and manual service execution20.98s succeeded. First hourly firing05:01failed explicitly on active fault lock; not claimed successful. After bounded300s backup lock wait fix, an owned one-off systemd user timer actually fired05:06:11 and invoked the **actual** backup service; finished05:06:32, Result=success/ExecMainStatus0,21.15s, backup`20261022T220612Z-4db5a1b1`. Hourly timer remains active for next06:00; long-term hourly reliability is not claimed from one trigger.

Initial failures are retained as evidence: namespace-injected operator apply, CNPG stripped version tag, API endpoint DNAT denial, asynchronous pod-policy realization, broker leader redirects, missing CA keyUsage, smart shutdown/cancellation overlap, selector including completed migration Jobs and first timer lock collision. Fixes do not weaken strict TLS, policies, data comparison or new-UID proof. Controller/Main subsequently ran the **integrated durable** `make acceptance` core successfully: TLS, fullAPI, negative, OAuthrace, events, brokerACL, DBprivileges and untrusted NetworkPolicy gates all passed. Infra12behavior tests passed; a subprocess stdout ResourceWarning in lock tests was corrected with explicit context-managed ownership and requires the controller’s strict warning rerun.

## Release-command revalidation — 2026-10-23

- Exercised actual Make targets: `bootstrap`, `status`, `check`, `bootstrap-admin`, `schedule-backups`, `repair-certificates`, `schema-gate`, `backup`, `restore-verify`, all four operator forwards, `acceptance`, `chaos` for identity/Redpanda, and `persistence`. The schema gate observed empty-schema live200/ready503, then migrated ready200. Backup `20261023T063000Z-a03fb9ab` restored all four databases with matching row-content hashes; restore command completed27.06s.
- Core acceptance passed23.06s; admin MFA/ban/unban/audit and ten-user business load passed with zero errors and authoritative lag0. Profile-only load observed8449successful requests/15.064s, zero errors, p95=19.234ms. Trace `d9b90a6d840649e5a526be0c1b3ee065` correlated actual login/outbox/Kafka/all five services/delivery. Actual SMTP outage/retry/recovery and poison-following-valid delivery passed.
- `make build` completed204.98s with content-addressed application and genuinely patched gateway images. `make up` and `make check` completed144.31s with existing PVCs retained. Existing Kubernetes1.35.5 versus configured1.35.9 remains an explicit maintenance gate, not an implicit upgrade claim.
- Expanded operator/image-identity suite:44tests passed. The gateway scan originally compared an OCI index digest with a config digest and failed; strict archive index→manifest→config verification corrected the mismatch without relaxing identity. Actual patched gateway inventory evaluated70packages with zero findings across all severities.
- Preparing whole-host verification found a real nullable PATCH bug: omitted fields and explicit null were conflated. Presence-aware profile updates now preserve omissions and persist explicit SQL NULL; PostgreSQL/race tests passed. Actual deployed fixture cleanup restored the original null, and a fresh fixture preserved the exact existing session/profile/database value before cleanup. This is prerequisite smoke, not whole-host outage evidence.
- Remote GitHub checks were actually executed. Contracts PR1 passed push/PR CI and merged to main `665c565bd0a00f30027b429129b22d91f99ef6b0`; consumers pin that published commit. Frontend's initial all-severity container check failed on musl/zlib, genuine package patches were applied, and subsequent checks passed. Service CI findings remain release blockers until corrected; workflow presence is not treated as execution proof.

## Broker durability and whole-host recovery

The first whole-Docker-VM fault (controller run258) remains **FAIL**. Manual existing-container start and the later original session/profile/database verification are separate evidence, not automatic full-host recovery. The old actual broker command contained `--unsafe-bypass-fsync=true`; `write_caching_default=false` alone never enabled real fsync. Initial health reported14leaderless partitions with all nodes up/0under-replicated; later per-node views disagreed. Neither pod Ready nor that aggregate report proves quorum or preservation of acknowledged Kafka records.

Source correction: `redpanda.developer_mode:false`, no `rpk start --mode`, explicit `--unsafe-bypass-fsync=false`. `--mode=production` is **not** a supported `rpk redpanda start` mode. `--overprovisioned` only relaxes CPU scheduling; `--check=false` skips rpk's host preflight, not the broker's memory/disk checks or fsync. The512MiB/1core process is a constrained local deployment, **not vendor-supported production sizing** (vendor requirements remain2physical cores and2GiB/core). The26.2source throws below per-shard reservations+128MiB, but merely logs below1GiB; the exact pinned-image smoke must establish that the configured512MiB actually boots. There is no invented `--relax-min-memory` flag. If a future pinned binary rejects the memory budget, raise actual resources and rerun the real smoke; never re-enable developer mode or disable features to evade it.

Node-only listeners, TLS, seeds, identity and developer mode stay in `/tmp/redpanda.yaml`. Cluster properties are loaded from adjacent `/tmp/.bootstrap.yaml` only for first startup; existing `config_cache.yaml`/controller configuration remains authoritative on retained PVCs. `topics()` applies schema-validated central setters/getters for existing clusters before application startup: Admin auth, Kafka authorization, bootstrap superuser, RF3 user/internal topics, auto-create false, `write_caching_default:disabled` (overrides even `write.caching=true`),3group partitions and256MiB minimum free space. The latter replaces the unsafe dev10MiB floor without adopting the production5GiB default, which exceeds the4GiB local PVC. Existing group partitions are not resized. No TLS/SCRAM/ACL, retention, topic data, metrics policy or PVC is removed.

Primary references: [26.2mode/fsync behavior](https://docs.redpanda.com/streaming/current/reference/rpk/rpk-redpanda/rpk-redpanda-mode/), [26.2start presets](https://docs.redpanda.com/streaming/current/reference/rpk/rpk-redpanda/rpk-redpanda-start/), [central-vs-node placement](https://docs.redpanda.com/streaming/current/manage/cluster-maintenance/cluster-property-configuration/), [write-cache enum](https://docs.redpanda.com/streaming/current/reference/properties/cluster-properties/#write_caching_default), [production sizing](https://docs.redpanda.com/streaming/current/deploy/redpanda/manual/production/requirements/). Public GitHub lookup during investigation exposed26.2.2but returned404for26.2.5: [available26.2startup source](https://github.com/redpanda-data/redpanda/blob/v26.2.2/src/go/rpk/pkg/cli/redpanda/start.go), [memory guard](https://github.com/redpanda-data/redpanda/blob/v26.2.2/src/v/syschecks/syschecks.cc), [bootstrap precedence](https://github.com/redpanda-data/redpanda/blob/v26.2.2/src/v/cluster/config_manager.cc). Do not label that source exact26.2.5; controller observed the actual pinned binary's `--unsafe-bypass-fsync arg (=0)` in `--help-seastar`. Functional boot, not source similarity, closes the pinned-binary behavior gate.

Controller-run regression (not executed by the implementation worker):

```sh
uv run --no-project python -m unittest discover -s scripts/tests -p 'test_broker_durability.py'
RUN_REDPANDA_BOOT_CONTRACT=1 uv run --no-project python -m unittest discover -s scripts/tests -p 'test_broker_durability.py'
```

Controller run292executed all3broker tests successfully in3.26s, including the actual pinned512MiB broker/TLS/SCRAM/produce/consume/flush smoke. It does not convert failed host run258into PASS. A later retained-cluster setter attempt stopped before any broker rollout because `rpk cluster config get superusers` returns YAML (`- bootstrap`), not JSON; `configure_brokers()` now verifies typed values through authenticated Admin JSON instead of parsing YAML. Controller run298subsequently exercised that corrected retained-cluster policy path successfully. Later source-suite results are tracked separately by the controller, not inferred from this earlier3test run.

The opt-in test runs the **actual pinned rpk and broker** using the rendered launch command,512MiB process budget, real TLS/SCRAM and authenticated Admin. Its isolated network/disposable anonymous data volume never mounts retained cluster data. Only standalone discovery/RF1 are substituted. It asks for topic write caching, then proves cluster-wide disabling via real Raft state, produces with `acks=all`, consumes the exact committed value and requires `flushed_offset>=commit_index` with no unsafe/developer preset. This is a startup/durable-ack contract, not a power-cut test or physical-disk guarantee. A shared Docker/WSL VM and its storage stack remain one failure domain; hardware/VM fsync honesty and backups remain prerequisites.

### Read-only diagnosis before any broker restart

Preserve `.local/acceptance/broker-host-recovery-diagnostic.json`, original failed host report, complete broker startup/current logs, pod UID/IP/PVC bindings, pre-outage producer acknowledgements and consumer offsets. Never truncate logs to make a report pass. The captured controller state had identical start/applied/committed/dirty155on all3brokers; sampled identity partition0had committed/flushed93and current voters on broker0. This rules out neither another damaged partition nor loss of records lacking a pre-crash baseline. At capture, broker0had fresh peer status while brokers1/2reported peer ages near660seconds. Current DNS and OpenSSL TLS success do not establish health of an already-running Seastar resolver/RPC client.

Controller run299subsequently observed fresh bidirectional0↔1peer status after replacing **only broker1** with the durable boot and the same retained PVC:0→1age0ms,1→0age99ms; both reported fresh peer2status, whereas2's outbound peers remained stale near1596seconds. All3controller committed indices matched161. This demonstrates that broker1process replacement restored its outbound RPC; it does **not** establish kernel routing or DNS caching as the specific root cause. Broker2was then replaced under OnDelete with its PVC retained; controller run300completed in27.38s with `is_healthy:true`, all3nodes, no nodes down and0leaderless/under-replicated partitions. Controller run301then replaced broker0last and passed Ready/full-health gates. The controller read `/proc/1/cmdline` on **all3running brokers** and observed explicit `--unsafe-bypass-fsync=false`, then restored RollingUpdate and verified all3updated; run304`make check` passed in5seconds. All PVCs were retained and no data reset occurred. This is successful **manual retained-data broker recovery and durable configuration rollout**, not successful automatic whole-host recovery. The second VM fault with acknowledged Kafka baselines was not yet executed at this entry; original failed host-fault and pre-recovery evidence remain unchanged.

```sh
k() { kubectl --context k3d-sso-remediation -n sso-remediation "$@"; }
k get pods -l app=redpanda -o wide
k get pvc
k get endpointslice -l kubernetes.io/service-name=redpanda -o json
for source in 0 1 2; do
  k logs "redpanda-$source" --timestamps
  k exec "redpanda-$source" -- rpk cluster health --format json
  k exec "redpanda-$source" -- rpk cluster config status
  k exec "redpanda-$source" -- rpk -X brokers=localhost:29092 topic describe identity.events.v1 -p --format json
  k exec "redpanda-$source" -- rpk -X brokers=localhost:29092 group describe notification-v1 --format json
  for target in 0 1 2; do
    if [ "$source" = "$target" ]; then continue; fi
    host="redpanda-$target.redpanda.sso-remediation.svc.cluster.local"
    k exec "redpanda-$source" -- getent ahostsv4 "$host"
    k exec "redpanda-$source" -- sh -ec 'exec timeout 10 openssl s_client -connect "$1:33145" -servername "$1" -CAfile /run/tls/ca.crt -verify_hostname "$1" -verify_return_error -brief </dev/null' sh "$host"
  done
done
```

Check all6directed DNS/TCP/TLS paths, actual EndpointSlice IPs and network-policy/node routing. Within each broker (credentials remain in its environment; do not enable shell tracing), authenticated **GET only** diagnostic calls are:

```sh
for source in 0 1 2; do
  for path in /v1/node_config /v1/debug/controller_status /v1/debug/is_node_isolated /v1/partitions /v1/debug/partition_leaders_table /v1/debug/partition/kafka/identity.events.v1/0; do
    k exec "redpanda-$source" -- sh -ec 'printf '\''user = "%s:%s"\n'\'' "$RPK_USER" "$RPK_PASS" | exec curl --config - --fail --silent --show-error --max-time 10 --url "http://127.0.0.1:9645$1"' sh "$path"
  done
  for target in 0 1 2; do
    if [ "$source" = "$target" ]; then continue; fi
    k exec "redpanda-$source" -- sh -ec 'printf '\''user = "%s:%s"\n'\'' "$RPK_USER" "$RPK_PASS" | exec curl --config - --fail --silent --show-error --max-time 10 --url "http://127.0.0.1:9645/v1/debug/peer_status/$1"' sh "$target"
  done
done
```

`/v1/partitions` is local replicas only. For **each** leaderless namespace/topic/partition returned by the local partition lists, query `/v1/partitions/<namespace>/<topic>/<partition>` and singular `/v1/debug/partition/<namespace>/<topic>/<partition>` on all3brokers. The latter gathers replica `raft_state.term`, voter configuration, `commit_index`, `flushed_offset`, follower match/heartbeat state and log start/dirty/committed offsets. Compare the same NTP across replicas and the original Kafka producer/consumer baseline. Raft offsets include control records and are not directly interchangeable with Kafka offsets. Rising terms, fresh TLS but stale peer ages favor RPC recovery investigation; checksum/truncation/I/O errors, missing majority logs or regression below a known acknowledged Kafka offset require preserving disks and an explicit data-loss incident. One sampled healthy partition does not certify all partitions.

### Guarded retained-PVC cutover and recovery conditions

Do not run an automatic StatefulSet rollout into unresolved quorum failure. First pass the isolated boot contract and capture diagnostics. For the observed asymmetric client failure, a single targeted process/pod replacement can reset DNS/RPC state while preserving all broker logs; it is not forced partition recovery. Keep the two other brokers and all PVCs intact. No supported DNS/RPC-reset signal was established; `reset_leaders` is unrelated and is not a remedy. The source reconnect path re-resolves DNS on new connections, but uses a process-local Seastar resolver, not glibc/OpenSSL.

1. Apply **only** the broker ConfigMap and StatefulSet rendered from current source, temporarily setting StatefulSet `updateStrategy` to `OnDelete`. This prevents an automatic second replacement while health is unresolved. Do not apply unrelated images or delete a PVC. Runtime central policy must be getter-verified on the controller; `.bootstrap.yaml` alone deliberately does not overwrite existing cache.
2. For this captured case, controller0was intact and broker1had stale outbound status. Replace **only** `redpanda-1` gracefully using the commands below. Require a new UID with the same PVC, exact new startup fsync flag, `developer_mode:false`, no ignored node/cluster properties, same controller history and fresh bidirectional peer status. If it does not rejoin, stop: do not delete broker0or cascade restarts.
3. With a recovered0+1majority and diagnostics showing intact replica histories, replace broker2only if still required. After health is fully green, replace broker0last to remove the remaining dev-mode process. Between replacements require all3nodes, no down nodes and0leaderless/under-replicated partitions, except the explicitly recorded single recovery step from the pre-existing outage. Restore the normal RollingUpdate strategy only after all3have the new revision and full health. Never present TCP Ready as that gate.

```sh
k patch statefulset redpanda --type merge -p '{"spec":{"updateStrategy":{"type":"OnDelete","rollingUpdate":null}}}'
# Apply the current rendered broker-only ConfigMap/StatefulSet with the same OnDelete strategy.
k get pod redpanda-1 -o json
k delete pod redpanda-1 --wait=true --timeout=120s
k wait --for=condition=Ready pod/redpanda-1 --timeout=300s
k logs redpanda-1 --timestamps
k exec redpanda-0 -- rpk cluster health --format json
# Run the per-node peer/controller/NTP checks above before deciding on another replacement.
```

The comment is a mandatory operator-reviewed render step, not permission to run `make up` against an unhealthy cluster. Exact source-render apply from `platform-infra` (the operator must already have selected the approved recovery step):

```sh
uv run --no-project python -c 'import sys; sys.path.insert(0,"scripts"); import cli, manifests; items=[x for x in manifests.infrastructure(cli.load_images(),cli.STATE,cli.ROOT/"observability") if (x["kind"],x["metadata"]["name"]) in (("ConfigMap","redpanda-config"),("StatefulSet","redpanda"))]; [x["spec"].update(updateStrategy={"type":"OnDelete"}) for x in items if x["kind"]=="StatefulSet"]; cli.apply(items)'
```

Set and verify **only** the retained cluster policy, without creating topics/users or replaying messages, before the selected restart:

```sh
uv run --no-project python -c 'import sys; sys.path.insert(0,"scripts"); import cli; cli.configure_brokers()'
```

This uses validated `rpk cluster config set` and typed JSON from `/v1/cluster_config?include_defaults=true`; `rpk cluster config get` emits YAML and is not a JSON parser input. Credentials are fed to in-pod curl on stdin, never supplied in the host command line.

After proven recovery, the same process is used for ordinal2then0only when their gates permit. Finally `k patch statefulset redpanda --type merge -p '{"spec":{"updateStrategy":{"type":"RollingUpdate","rollingUpdate":{"partition":0}}}}'`, `k rollout status statefulset/redpanda --timeout=300s`, authenticated `rpk cluster config status` (no unknown/invalid/restart), all3health reports and the original broker/business offset/value probes must pass. Preserve the original failed report even after a later successful host fault.

Forbidden without separate explicit data-loss approval: topic deletion, PVC deletion, data-directory/cache/controller-log removal, force recovery/reconfiguration, unclean leader election, offset rewinds, WAL/topic truncation or replacing business fixtures with newly created values. [Forced partition recovery](https://docs.redpanda.com/streaming/current/manage/cluster-maintenance/partition-recovery/) can discard acknowledged records and is inappropriate while all3existing replicas are recoverable. If an actual record-loss baseline is established, no source flag or restart reconstructs it: keep original evidence and request authorization for recovery from a known broker backup or authoritative outbox history; DB backups alone do not contain the broker log. Full-host durability remains unproven until the controller repeats the real VM fault and verifies original session/profile/database values **and** known acknowledged Kafka records/offsets plus full quorum health without unrecorded manual intervention.

## External boundaries

Telegram Bot API credentials/chat/public webhook absent: external gate open, no mocked delivery accepted. AWS/cloud not deployed or queried. No production acceptance, PITR or independent-host/zone HA claim. Remote publication into h1wtest and real CI runs are explicitly authorized by the current request and tracked separately from local runtime results; remaining image findings are not waived by publication.
