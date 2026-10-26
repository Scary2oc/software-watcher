# Software Watcher

> Experimental, Fedora-focused project. Not independently security-audited.

A Linux, read-only software review tool. This repository is a **code-only rebuild
kit**, not a machine backup or an immediately deployable configuration.

## Feedback welcome

I'm learning as I build this, so constructive feedback is genuinely appreciated:
bugs, confusing documentation, risky assumptions, or better approaches.

Please do not include real inventories, credentials, keys, logs, or private
reports in an issue. For a suspected security vulnerability, use GitHub's private
reporting: open this repository's **Security** tab, then **Report a vulnerability**,
instead of opening a public issue. Private reporting must be enabled by the
repository owner; if the option is unavailable, do not post sensitive details
publicly.

## What it does

- Collects bounded installed metadata without importing inspected packages.
- Downloads fixed public bulk OSV, KEV, EPSS, NVD and Fedora updateinfo feeds.
  Daily applicability matching stays local: installed names, versions, paths and
  host identity are not submitted as feed queries.
- Encrypts new daily inventory snapshots and detailed reports with a separately
  provisioned GnuPG public recipient before writing them to disk.
- Retains aggregate/hash checkpoints and an aggregate notification ledger.
- Optionally sends sanitized aggregates using an explicitly configured, already
  installed Hermes runtime. Delivery defaults to dry-run with no destinations.
- Also provides a separate bounded release-review queue (`watcher.py`). That
  interface queries explicit public component identifiers and writes plaintext
  review evidence unless its gocryptfs mount gate is required. It is **not** the
  encrypted daily-report pipeline.

There are no installers, automatic updates, remediation commands, credentials,
keys, host inventories, runtime state, environment files or operational receipts
in this rebuild kit. Nothing is scheduled or enabled by copying it.

- See [SAMPLE_OUTPUT.md](SAMPLE_OUTPUT.md) for what a run looks like.

## Requirements

Linux and system Python 3.14 are the reference environment. This is not a
platform-independent deployment: `/usr/bin/gpg` and `/usr/bin/gpgconf` are needed
for encryption tests; system GnuPG and an existing private `~/.gnupg` directory
are needed for daily operation. System Python `rpm` bindings provide authoritative
Fedora EVR comparisons; the full current test suite requires them. Without those
bindings RPM rows remain unassessed, not guessed safe. System `packaging` improves
PyPI version comparisons; its absence permits only conservative numeric fallback.
Python's `compression.zstd` is needed for zstd Fedora metadata. The collector also
queries system RPM and Flatpak tools; unavailable tools are explicit errors.
Dependencies must be provisioned and reviewed separately; this code installs none.

## Offline verification

From this directory:

```sh
/usr/bin/python3 -B tests/run_offline.py
```

The runner uses a disposable home and disposable synthetic encryption keys outside
the checkout, clears watcher configuration variables, and blocks Python IPv4/IPv6
sockets and DNS. Tests never send real messages or collect real installed inventory.
The Hermes wrapper contract uses a synthetic upstream module, not installed Hermes
or its credential loader. Tests exercise actual GnuPG encryption/decryption.
The Python socket guard is not an OS-level sandbox for arbitrary child programs.

For CLI usage without collection or network:

```sh
/usr/bin/python3 -B -I -S daily_check.py --help
/usr/bin/python3 -B watcher.py --help
```

Follow [RESTORE.md](RESTORE.md) for owner-reviewed provisioning and
[SECURITY.md](SECURITY.md) for storage and data boundaries. Generic systemd user
unit templates are under `deploy/`; they are inert templates, not an installer.
`watchlist.example.json` is a disabled synthetic schema example, not real inventory.
