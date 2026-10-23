# Contributing

## Development sources

Use an isolated Git worktree and a dedicated branch. Keep all nine owner repositories alongside one another, as listed in `workspace.sources.json`. The current manifest is explicitly local development: it is not a promise that the new repositories are remotely published or clone-ready. Publication, pushes, pull requests, merges, and deployments require the repository owner's authorization.

Use Python 3.12+ and `uv` for Python tooling. The workspace CLI additionally requires Git. The README lists the separate container, Kubernetes, and language prerequisites for running the complete platform. Do not run source-provided bootstrap/build hooks while merely resolving source references.

For an immutable fresh-copy rehearsal, commit reviewed source changes in disposable or approved local repositories, then call `scripts/workspace.py resolve --local NAME=/absolute/repository` for every local source and choose a new output file. `checkout` requires a pinned manifest, every local source override explicitly repeated, and a nonexistent destination with an existing real parent directory. It rejects dirty sources and occupied destinations rather than overwriting user work. Ignored `.env`, private operational state, and build outputs are not source inputs. The README gives complete CLI examples.

For a public release, maintainers first publish authorized repositories, enter their actual HTTPS GitHub URLs, remove local-only flags/path metadata, and explicitly resolve the moving `main` references. Review real resolved commit IDs together for compatibility. Never invent publication evidence or substitute local source bytes for a remote commit. Keep selected source identity and separately pinned image digests with release evidence.

## Changes and tests

Preserve independent business owners, separate databases, least-privilege credentials, versioned HTTP/event contracts, and existing delivery conventions. Do not add arbitrary runtime templating, executable configuration, fallback authentication, fake provider success, or cross-owner business SQL. Owner-controlled public branding is plain JSON, not a script. Copy `config.example.json` to the frontend's public configuration deployment path only after setting the exact canonical HTTPS origin and supplying the referenced logo asset or omitting the optional logo URL.

Write behavioral regressions before implementation, including error and recovery outcomes. Real Git/filesystem fixtures should exercise checkout effects; source-text assertions do not establish checkout correctness. Run checks once the integrated owner changes are ready, not against another contributor's half-finished shared work:

```sh
uv run --no-project python -m unittest discover -s scripts/tests -p 'test_*.py'
```

Run application compilation, contract validation, Helm rendering, and runtime/browser acceptance through the existing documented integration workflow. A fixture checkout smoke is not application-feature proof. Record exact commands, results, selected commits, and remaining external acceptance gates; never claim unexecuted checks passed. Keep line endings LF and source files UTF-8. Update the relevant user documentation when behavior changes.

## Safety and review

Read `SECURITY.md` before handling diagnostics or credentials. Never copy whole developer directories, modify another operator's environment files or persistent data, publish raw reports containing secrets, or access production as part of a contribution. Use disposable local data for failure/recovery tests. Preserve dependency and asset notices. New original code uses `SPDX-License-Identifier: MIT`; third-party code must not be relicensed by adding this header.

Describe the behavioral change, compatibility impact, authored tests, exercised evidence, and any provider gates in your review request. Obtain independent review before merge readiness and explicit owner authorization before publication or deployment.
