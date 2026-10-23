# Security policy

## Reporting

Use the repository's private vulnerability reporting feature when its owner has enabled it. If it is unavailable, contact the repository owner privately through their published contact channel and request a secure reporting destination before sharing exploit details. Do not post credentials, customer data, provider evidence, full request bodies, or working exploits in public issues. No dedicated reporting address or response SLA is claimed by this development template.

Provide affected exact commits, reproduction steps using disposable data, impact, and redacted diagnostics. Never probe another operator's deployment or production resources without separate written authorization. Maintainers must reproduce reports in an isolated local environment and coordinate fixes and disclosure with the reporter.

## Source and release integrity

This checkout is development source, not a published, verified release. `workspace.sources.json` intentionally marks unpublished inputs local. Never replace missing remote revisions with invented hashes or silently clone a moving branch. `scripts/workspace.py resolve` is the explicit operation that reads remote `main` and emits a new pinned manifest. Review that manifest; `checkout` accepts exact commit IDs only. Neither operation runs source-supplied scripts, hooks, filters, submodules, builds, or migrations. Local overrides require explicit clean Git repository roots and use committed objects, not recursive workspace copies. Local path metadata is not permission to read that path on a later invocation.

Only reviewed, published HTTPS repository URLs and real lowercase 40-character commit IDs belong in a public release manifest. Remove local path metadata before publication. Pin built images by immutable digest separately. A successful source checkout is not evidence of compilation, runtime readiness, external provider acceptance, or security.

## Secrets and private operational data

Keep credentials in ignored owner `.env` files with restrictive permissions. Public `config.json` contains only name, logo/help links, supported locales, and canonical origin. Never place provider tokens, signing or encryption keys, session cookies, personal/payment evidence, backups, or raw acceptance diagnostics in Git, Docker contexts, browser configuration, CI logs, or uploaded artifacts. Purpose-separated generated credentials belong only to their runtime owner; restarting must not rotate them. Never share an infrastructure environment file with application owners.

The source checkout tool rejects tracked environment secrets, private-key filenames, symlinks, submodules, and common private/build directories; ignored and untracked files are never copied. These path checks are not a complete secret scanner. Arbitrarily named tracked files and Git history require human review and a redacted full-history secret scan before publication. Accidentally committed credentials must be revoked/rotated and handled as an incident; deleting a working-tree file does not remove it from history.

Use verified TLS, least-privilege service credentials, exact callback routes, fresh administrative MFA, and redacted logs. Do not bypass these checks to make local acceptance pass. External payment and messaging credentials are optional configuration gates, not permission to fabricate successful deliveries or payments. Exercise destructive recovery only on disposable state. Do not reset another operator's namespace, owner environment files, volumes, or retained backups.

Dependency and container vulnerability scanning remains subject to the operator's existing policy. This template neither silently enables disabled scanners nor claims that the absence of a scan means the absence of vulnerabilities.

## Licensing

The MIT license covers this repository's own code and explicitly authored template changes. Dependencies, vendored components, assets, and source obtained from other repositories retain their original licenses and notices. Review each source repository and third-party component before redistribution; this license does not relicense them or establish rights to unrelated source.
