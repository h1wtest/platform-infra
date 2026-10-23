# Full local acceptance and GitHub publication implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or executing-plans to implement task-by-task.

**Goal:** Exercise every published Make command, remediate security findings without hiding them, run real GitHub CI, prove local whole-stack outage recovery, and publish reviewed changes to main in the h1wtest organization.

**Architecture:** Retain the approved six-repository architecture and independent runtime services. Work only in existing isolated feat/platform-remediation worktrees. Parent owns integration, live stand mutations, publication and outage injection; agents own disjoint source changes.

**Tech Stack:** Rust identity, Go services/contracts, React frontend, uv/Python operator CLI, k3d/K3s, CNPG, Redpanda and GitHub Actions.

## Global constraints

- No cloud or production operations. No secret publication; scan actual versionable files and Git history before push.
- All findings means retain inventories/severities and fail release gates for remaining vulnerabilities; never suppress no-fix findings or erase package metadata.
- Repository publication/main integration is explicitly requested in this turn. Use reviewed PRs and remote checks, not force-push or direct writes to main. Preserve unrelated original checkouts.
- Existing stand data/PVCs must survive tests. Backup before fault injection. Physical-host failure cannot be claimed from stopping one pod or three node containers.
- Record every command as exercised, prerequisite-blocked, or intentionally not applicable; no dry-run-only success.

## Task 1: Operator command completeness

Files: platform-infra/Makefile, scripts/cli.py, scripts/acceptance/run.py and command-specific modules; platform-contracts/Makefile; application READMEs/workflows.

Inventory every Make target, CLI command, argument, default, documented procedure and tool version. Reproduce broken public invocations before minimal fixes. Validate mandatory arguments before any stand mutation. Ensure every runnable target is PHONY and required operator actions are reachable. Run actual targets after integration; supervise forwards and stop only owned processes. Exercise stop/start only during serialized outage verification. Record failures/recovery and verify data unchanged.

## Task 2: Security remediation

Files: platform-infra/scripts/scan_images.py, scripts/cli.py pins, private .local/image-scans reports; actual component build definitions if patched source builds are necessary.

Read every report/advisory, fixed-version field and target identity. Distinguish OS packages and embedded Go modules. Verify upstream tags/source commits and supported runtime compatibility; evaluate patched image/source builds without inventing hashes. Build/scan genuine candidates with nonzero package inventory. For replacements, exercise workload-specific behavior before cutover, preserve PVC compatibility and rescan deployed exact artifacts. Never relabel an unresolved finding fixed; retain precise missing upstream prerequisite when no actual patch exists.

## Task 3: Remote CI and publication

Files: all five .github/workflows/verify.yml files, contracts revision linkage and repository documentation.

Verify organization/repository inventory and authorization. Contracts publish first so dependent workflows consume a real immutable commit. Secret-scan staged versionable trees and history before commits/push. Set the already-required contracts revision to the published SHA. Push task branches and open per-repository PRs; execute GitHub workflows and inspect failed job logs, correct root causes and rerun. Run independent review before merge; merge only passing/approved changes. Verify remote main SHAs and exact workflow conclusions, then sync original local main checkouts without overwriting user edits. Create a repository only for an actual missing independently owned repository, never for a deployment command alone.

## Task 4: Whole-host/local outage verification

Files: existing acceptance harness and operator fault lifecycle modules where behavior is missing; ignored private evidence.

Create encrypted backup, committed known-value markers and application session/profile evidence first. Use an external Windows observer for any WSL-host interruption. Isolate the SSO host boundary from unrelated Docker workloads; if physical Windows/Docker host shutdown would interrupt unrelated processes, obtain explicit scope approval before that action. Record before/during/after API availability, host/node identities, PVC contents and recovery times. Assert the API really becomes unavailable during total outage, then all controllers/quorum and saved values/sessions recover. Report exact scope: crash/power-loss versus graceful restart, virtual host versus physical host. Clean only owned disposable markers after proof.

## Task 5: Final details and main verification

Exercise boundary scenarios in permanent acceptance suites, desktop/mobile user/admin/OIDC surface, invalid/missing arguments, first bootstrap versus existing data and repeated operations. Run final integrated smoke after all source/pin changes. Update docs/changelogs and evidence with exact observed commands, workflow URLs, main SHAs and unresolved blockers. Remove own temporary scaffolds only after durable tooling is integrated. Do not mark the overall task complete with remaining findings or unexecuted host scope.
