# Security and privacy boundaries

## Keep operational data outside this repository

Never add environment files, credentials, tokens, public or private key material,
inventory, configuration containing destinations, reports, ciphertext snapshots,
notification ledgers, caches, logs, databases, backups or vault notes. Encrypted
operational data also does not belong here. The exact-file allowlist in
`.gitignore` is defense in depth, not a substitute for reviewing the publish set;
Git can force-add ignored files.

Runtime storage defaults to `~/.local/state/software-watcher`. The home-relative
`Documents/Vault` and `Projects` trees remain denied as runtime storage prefixes.
Directories must be owned by the current user and mode 0700; files mode 0600,
regular, and singly linked. Storage path symlinks, unsafe ownership/permissions,
special files and hardlinks fail closed. Do not relax these checks to make a
checkout work as a state directory. Other sensitive local storage prefixes should
be reviewed before deployment and added to the denied-prefix policy if needed.

Daily collection is gated by both an explicitly provisioned public recipient and
a matching `storage-policy.json` SHA-256 approval. Even an explicit constructor
recipient must satisfy that policy. GnuPG performs a real encryption probe before
collection. There is no plaintext fallback, secret-key generation, automatic key
retrieval or daily decryption. Production code does not install dependencies,
repair Hermes, load environment files, run network calls or spawn processes on
import. GnuPG and optional Hermes are executed only on explicit runtime paths.

New detailed daily evidence is encrypted in memory and staged only as ciphertext
before atomic replacement. Aggregate/hash checkpoints and notification intent are
plaintext in private storage: counts, hash equality, timing and delivery metadata
can still reveal information. Existing plaintext from older deployments is neither
encrypted nor deleted by this tool. Back it up and handle it under a separate
owner-reviewed migration; do not assume this rebuild protects historical files.

## Transport and trust

Daily public feeds use fixed HTTPS hosts/paths, no proxy credentials, size/time
budgets, constrained redirects and local applicability joins. Network peers can
still observe IP addresses, timing and public feed selection. Fedora data is
transport-authenticated with repomd SHA-256 consistency, not independently signed
verification. Feed contents are untrusted data. Parsing does not extract archive
paths or execute data. Missing, stale, unsupported and uncertain results are not a
security clearance. EPSS/NVD enrichment never establishes applicability.

The separate release-review queue can query configured public package/repository
identifiers. Do not use private component names with it. Its gocryptfs mount check
must be explicitly required when plaintext queue evidence needs encrypted storage.
Review roles are generic `owner`, `security`, and `audit`; none authorize updates.

Notifications default to dry-run and disabled destination placeholders. Live mode
requires explicit destination variables; actual transport also requires an
absolute existing interpreter path and an absolute reviewed Hermes profile path.
The optional Hermes CLI owns its own credential resolution and may access its
own private configuration only when that explicitly enabled transport runs.
Do not point it at an unreviewed profile or bootstrap/installer launcher.
Messages contain only bounded aggregate text. CLI diagnostics are suppressed.
Ambiguous sends require manual receipt reconciliation, not blind retries; neither
atomic exactly-once delivery nor external readback verification is claimed.
Review any old pending intents before changing destinations or enabling live mode.

## Reporting a vulnerability

Use GitHub's private reporting: open this repository's **Security** tab, then
**Report a vulnerability**. Do not open a public issue for sensitive security
details, and do not attach real inventory, credentials, operational output or key
material to a report. The repository owner must enable private reporting; if the
option is unavailable, do not substitute a public issue.
