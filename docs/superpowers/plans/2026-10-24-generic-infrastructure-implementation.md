# Generic platform infrastructure implementation plan

**Goal:** deploy and exercise the eight approved independent owner runtimes locally without modifying the original stand or data.
**Approved spec:** ../specs/2026-10-24-generic-subscription-platform-design.md. User approved 2026-10-24.
**Constraints:** no production/cloud, push/remote/PR/merge; no host faults; strict TLS and owner DB isolation; immutable v1; fixtures clearly distinguished from provider acceptance.

## Interfaces and ownership

Parent: task status, integration/verification, isolated runtime acceptance scripts in scripts/acceptance/generic_*.py, system fixture setup and final docs/evidence.
Infrastructure delivery slice: scripts/{manifests,env_secrets,security_material,cli,release_values,render,broker_security,release_control,cluster_identity,credential_guard}.py, charts/, observability/, regression files. It consumes local://generic-platform-integration.md. Maintain current default stand identity for existing users; add explicitly isolated generic local mode/namespace/ports with fail-closed ownership, never silently mutate original cluster. Preferred acceptance namespace on existing local cluster is explicit distinct `generic-subscriptions` and loopback HTTPS18448/HTTP18089 so no extra whole-cluster host operation is necessary; CLI generic mode must not run original cluster-identity baselining on another namespace. Existing default behavior retained, no universal safety bypass. New persisted secrets/migrations belong task workspace.
Template packaging slice: scripts/workspace.py, workspace.sources.json, scripts/tests/test_workspace.py, root .gitignore/.gitattributes/LICENSE/SECURITY.md/CONTRIBUTING.md and neutral config.example.json; no changes to delivery slice files. Resolves exact source revisions before checkout, refuses dirty/existing destinations, never executes source-supplied code when only resolving manifest. Local source overrides validated, no secret copied. Actual developer workflow obtains all repositories alongside; owner-only env generation remains delivery slice.

## Task 1: Delivery and owner isolation

- Add first behavioral regression for generic namespace/credential scope (rendered objects/services and owner env actual generated files; no source text assertions).
- Add four app tuples catalog8006/subscription8008/referral8009/billing8007 and owners to DB/migration/backup, generated TLS materials and separate purpose keys/tokens/broker credentials.
- Separate optional provider inputs from required generated credentials; NOWPAYMENTS_API_KEY/IPN_SECRET only billing owner env, no runtime success fallback. Workload allowlist tokens map exact producer/readers, identity recognizes each owner separately.
- Extend gateway longest-prefix public routes for catalog/billing/subscription/referral plus identity roles/client and templates/profile subroutes. /internal stays private except exact Telegram webhook; external integrations internal authenticated ingress reachable only authorized integration ingress policy.
- Versioned topic inventory and exact producer/consumer/group ACL, v1 drain compatibility explicit; worker egress no consumer plaintext bypass.
- Extend existing platform-service charts and network policy least privilege, provider HTTPS egress only authorized components, per-service readiness and deployment lifecycle, fresh render and CLI tests; no duplicate manifest convention.
- Build map new per-repo Dockerfile and existing shared modules, contract tree digest update parent after contracts stable; no floating source release.
- No deployment/tests/build mid-flight by agent. Parent runs tests+Helm render+actual isolated stand after all owners compile. Functional tests validate DB isolation and failure outcomes.

## Task 2: Copyable source workspace

- Regression: pinned-source manifest missing/duplicate/nonhex/dirty destination rejects before clone; local-only overrides never copy ignored secrets/build outputs.
- Implement manifest version1 entries {name,url,revision} with lowercase40 SHA, known owner directory whitelist, HTTPS GitHub URL; `resolve` reads remote exact main SHAs and produces file ONLY on explicit command, not bootstrapping floating main; `checkout` clones exact detached revision into new directory only and records selected sources.
- Current unpushed new repos cannot have invented remote URL/SHA. Manifest template marks a source local while development and exported pinned release manifest includes only actual published inputs; command fail-closed with precise unpublished source error. No fake ready public release before publication authorized.
- Add docs/licenses/security/contribution/neutral brand config preserving third-party licensing; parent runs CLI actual temporary destination smoke using local Git fixture (not application-feature proof).

## Verification commands (parent integration owner)

`uv run --no-project python -m unittest discover -s scripts/tests -p 'test_*.py'`
`uv run --no-project python scripts/render.py --output .local/render-generic.json` with explicit generic profile
`helm template ...` via existing render pipeline; schema/IaC checks as existing CI conventions.
Real runtime: generated disposable owner credentials, actual PostgreSQL/Kafka, new owner binaries/APIs, actual UI browser; no mock provider replaces NOWPayments external sandbox or actual Telegram gate.
