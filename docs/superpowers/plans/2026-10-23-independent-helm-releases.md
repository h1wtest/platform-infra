# Independent Helm Releases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Independently install, update and recover each current application with Helm, preserving the existing local Kubernetes data and security boundaries, and prove successful and failed rolling updates against real business requests.

**Architecture:** Helm owns persistent application/infrastructure objects; Python retains local cluster bootstrap, authenticated operator installation, credential generation, DB/Kafka provisioning and bounded operational Jobs. A reusable service chart has distinct releases for identity-service, profile-service, notification-service, notification-worker, admin-audit-service, frontend and gateway. Separate infrastructure releases own platform configuration/networking, PostgreSQL operand, Redpanda, Mailpit and individual monitoring components. Existing objects are explicitly adopted only after inventory/ownership checks; no delete/recreate migration or competing apply path.

**Tech Stack:** Python stdlib, pinned Helm 4.3.1 (Linux amd64 archive SHA256 0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b), k3d/k3s, kubectl, existing CNPG and application images.

## Execution evidence

Implementation and source-level independent review completed; runnable evidence and residual verification limits are recorded in `docs/acceptance.md`, section Independent Helm delivery. Final deterministic suite:174tests, one opt-in broker skip; actual rolling:885authenticated requests,0failures. Fifteen separate releases installed without original resource/PVC UID changes. Canonical release images and completed rollout, readiness failure recovery and business-probe rejection are exercised; infrastructure/data rollback is not claimed.

The missing `release` command was demonstrated by a failing boundary regression before implementation. Chart/runner artifacts were written in independent slices and tested at integration rather than each receiving an isolated preimplementation red run; no claim of per-function TDD proof is made. Populated legacy rekey is covered by deterministic archive/retry contracts, not a live legacy dataset. Existing HTTP/Kafka handlers were inspected and ordinary rolling exercised, not an exhaustive in-flight Kafka/external-provider termination fault matrix. No canary/blue-green, production EC2 deployment or remote CI was executed.

## Global Constraints

- Worktree: /home/bpqvg/dev/h1wtest-remediation/platform-infra; branch feat/independent-helm-releases, baseline dd4f880d2f07 (resolve full SHA in local evidence). No push, PR, merge or production/cloud operations.
- All operations explicitly bind k3d-sso-remediation context and sso-remediation namespace. Never use current-context defaults.
- Preserve all DBs, PVs, PVCs, broker identities, CA/private keys, owner .env, CNPG RBAC hardening and authenticated operator artifact.
- Kubernetes custom resources/CRDs retain their lifecycle; CNPG controller-generated objects are never adopted. Namespace/bootstrap operator ownership remains explicit outside Helm.
- Helm manifests and values containing credentials stay private; no secrets in argv/stdout/error messages, no debug/dry-run output publication. Helm release Secrets are credential-bearing and must be treated accordingly.
- Default APIs: two replicas, maxUnavailable=0, maxSurge=1, finite progress deadline, minReadySeconds, graceful termination and bounded wait. Worker remains independently versioned; Kafka consumer group does not imply percent-based canary.
- HPA owns live replicas: Helm upgrade must not reset a scaled service to two.
- Retain PVCs/CNPG operands against Helm uninstall; no automatic destructive rollback of infrastructure or migrations. Return application configuration only; migrations use expand/contract policy.
- Canary, blue-green, service mesh, cloud deployment and production topology are excluded from this implementation. Helm is not proof of EC2/control-plane HA.
- Existing source provenance remains enforced for full builds; single-service release accepts only verified content-addressed local images or digest-pinned registry references. No implicit latest tag or sibling upgrades.

## Files and Interfaces

- charts/platform-service: actual Deployment/Service/ServiceAccount/PDB/HPA templates with typed values, no list-of-resources passthrough.
- charts/platform-config, charts/platform-postgres, charts/platform-redpanda, charts/platform-mailpit, charts/platform-monitoring: actual owned resource templates; monitoring chart installed once per component.
- scripts/release_values.py: Python values assembly (images, credentials, file contents, network discovery), not duplicate persistent workload manifests. `release_specs(images, state, root)` returns `{release: {'chart': chart_name, 'values': dict}}`; ordering exposed in `RELEASE_ORDER`, `APPLICATION_RELEASES`.
- scripts/helm_release.py: Helm command runner and render/install/update/history/recovery, explicit adoption gate, locking-compatible methods. `render(runtime, release, spec) -> list[dict]`, `deploy(runtime, release, spec, *, adopt=False, timeout=240, rollback=False)`; errors redact credential-bearing output. `service_deployment(runtime, name, images)` renders selected Deployment for existing disposable Jobs/schema checks.
- scripts/cli.py: full up uses ordered releases; `release --service NAME --image IMMUTABLE --probe COMMAND [--timeout SECONDS]` updates only one preinstalled app; `releases` reports history/status; `helm-adopt` is explicit adoption of original local inventory, never blanket --take-ownership.
- scripts/manifests.py: retain only operational resource, secret, pod helpers and constants; remove obsolete persistent workload generators.
- scripts/render.py: static validation renders actual charts using ephemeral secrets, no parallel legacy manifests.
- scripts/rekey.py, scripts/schema_gate.py, scripts/api_network.py: migrate persistent ownership paths and rendering consumers; operational temporary Jobs remain direct apply.
- scripts/bootstrap-tools.sh, .github/workflows/verify.yml, Makefile: pin Helm and exercise real chart rendering in CI/local commands.
- scripts/acceptance/rolling.py: real original-service rollout/failure/recovery gate with bounded continuous business probes, UID/image/endpoint evidence, no standalone fake service.
- Existing README.md, CHANGELOG.md, docs/acceptance.md, docs/handoff.md: final exercised behavior, limits, commands and evidence.

## Task 1: Charts and Values Cutover

- [ ] Read persistent generators and all consumers before editing; baseline suite currently 129 tests, 1 skip.
- [ ] Add real chart rendering behavior regressions for image selection, Secret references, HPA replica ownership, retention and disjoint release ownership; demonstrate missing chart/render failure before implementation.
- [ ] Move persistent object definitions into named charts, retaining original names/selectors/ports/security/PVC configuration. Helm templates must be the single persistent manifest source.
- [ ] Provide independent release values, specific app env/credential references, service-specific credential/config revisions rather than restarting every app for unrelated owner changes.
- [ ] Migrate old manifest-based behavior tests to rendered artifact contracts only where they protect real credential/durability boundaries; remove implementation-shape tests rather than re-pin them.

## Task 2: Release Lifecycle and Safe Adoption

- [ ] Prove fail-closed ownership conflicts, mutable-image rejection, invalid arguments and duplicate ownership boundaries with deterministic behavior tests; no mock echo/wiring tests.
- [ ] Install checksum-pinned Helm locally and add identical CI bootstrap.
- [ ] Implement protected values/render files, release history/status, bounded waits, and explicit adoption of only known original resources. Reject conflicting owners, foreign namespaces and operator-managed children before metadata changes.
- [ ] Application upgrade waits for readiness and reverts configuration on rollout failure. Business probe failure also restores previous successful application revision; command still fails and preserves diagnostic evidence. No migration rollback.
- [ ] One-service release derives from its current Helm values, changes only selected immutable image and verified source record, runs only its DB-owner migration where needed, and never rebuilds/reapplies siblings.
- [ ] Document pending/failed release recovery and repeat adoption behavior without hiding previous failed evidence.

## Task 3: Integrate Existing Commands and Compatibility Rules

- [ ] Replace full-up persistent apply calls with ordered deploys; keep cluster/operator bootstrap and provisioning barriers before dependent workloads.
- [ ] Replace bootstrap-admin/schema-gate rendering consumers with real chart output; route final persistent secret rekey updates through owning release.
- [ ] Adapt render/static validation, Make targets, CI and prerequisites; run full existing suite once after concurrent implementation settles.
- [ ] Verify actual service HTTP/Kafka shutdown behavior; change only if required for rolling safety. Record session/API/event backward compatibility and expand/contract migration policy.

## Task 4: Runtime Acceptance and Review

- [ ] Run current real business probe before changes; preserve baseline object/PVC identity evidence privately.
- [ ] Explicitly adopt existing original local resources; verify stable resource/PVC UIDs and no data loss, then run full up/check/probe.
- [ ] Run a selected service update with a distinct real image plus continuous authenticated requests. Assert new image and pod UIDs, old image removed, siblings unchanged and requests successful.
- [ ] Inject a non-ready selected revision, observe failed bounded upgrade while original ready endpoints serve business requests, restore previous good application state and prove command reports failure.
- [ ] Exercise post-readiness business-probe failure recovery separately; retain evidence that migration/data rollback is not claimed.
- [ ] Exercise independent CLI release/history and core acceptance paths, chart lint/schema/monitoring validation as applicable. No production topology claims.
- [ ] Independent reviewer inspects contracts/security/ownership/recovery; address concrete findings and rerun affected proof.
- [ ] Update existing docs/changelog with observed results and exact limitations, remove throwaway scaffolds after proof. Leave branch local unless publication separately authorized.
