# Sample output (synthetic)

Generated with `/usr/bin/python3 -B tests/generate_sample.py --write`; verify with
`/usr/bin/python3 -B tests/generate_sample.py --check`. Do not edit output blocks.

The real daily-check pipeline uses only a synthetic collector and local fixture feeds.
No host inventory is collected and no messages are sent. HOME/TMPDIR are disposable, configuration is
cleared, Python network/DNS is blocked, and notifications explicitly use dry-run with
a forbidden sender. Disposable GPG keys exercise approved-policy encryption and real
decryption outside the repository; keys, fingerprints and private paths are omitted.
EPSS/NVD fixture publication dates are current for freshness checks, but are not displayed.

## Daily aggregate lines

Counts describe metadata entries, not unique CVEs or proof of exploitability.
Exit 0 means execution completed, not security clearance; unassessed means unknown.

### First run

```text
software-check changed: assessed=1 affected=1 kev_flagged=1 unassessed=1 needs_investigation=0 errors=0; notification_mode=dry-run notification_pending=0 notification_ambiguous=0; new sensitive evidence encrypted; legacy plaintext retained
```

Exit code: `0`.

### Identical replay

```text
software-check no-change: assessed=1 affected=1 kev_flagged=1 unassessed=1 needs_investigation=0 errors=0; notification_mode=dry-run notification_pending=0 notification_ambiguous=0; new sensitive evidence encrypted; legacy plaintext retained
```

Exit code: `0`.

### All six feeds unavailable

```text
software-check changed: assessed=0 affected=0 kev_flagged=0 unassessed=2 needs_investigation=0 errors=6; notification_mode=dry-run notification_pending=1 notification_ambiguous=0; new sensitive evidence encrypted; legacy plaintext retained
```

Exit code: `20`.

## What the counts mean

| Count | Meaning |
|---|---|
| `assessed` | Metadata entries with affected or not-affected advisory evidence |
| `affected` | Installed version matches a published affected range |
| `kev_flagged` | An affected match has a CVE in the KEV catalog |
| `unassessed` | No authoritative applicability judgment; unknown, not safe |
| `needs_investigation` | Evidence is stale, ambiguous or unsupported |
| `errors` | Operational failures, not a count of vulnerabilities |

The failure scenario makes PyPI OSV, KEV, EPSS, NVD, Fedora43 and Fedora44 unavailable;
feed failures return exit 20, never a clean result.

## Pending dry-run notification

This body is read from the actual notification ledger; nothing was sent.

```text
SANITIZED software-check urgent: assessed=0 affected=0 kev_flagged=0 unassessed=2 needs_investigation=0 errors=6; metadata-entry counts, not unique CVEs or proof of exploitability. Review private evidence locally.
```

## Decrypted report excerpts

Field-selected from the first encrypted report after real decryption.
Dynamic timestamps, local paths and fingerprints are excluded.

```json
{
  "ecosystem": "PyPI",
  "name": "example-pkg",
  "version": "1.5",
  "status": "affected",
  "reason": "Local OSV data only; not a security clearance or proof of absence",
  "matches": [
    {
      "id": "SYNTHETIC-ADVISORY-1",
      "aliases": [
        "CVE-2099-00001",
        "SYNTHETIC-ADVISORY-1"
      ],
      "kev": [
        "CVE-2099-00001"
      ],
      "evidence": {
        "ranges": [
          {
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "2.0"
              }
            ],
            "type": "ECOSYSTEM"
          }
        ]
      }
    }
  ]
}
```

```json
{
  "ecosystem": "RPM",
  "name": "example-rpm",
  "version": "1:1.0-1",
  "status": "unassessed",
  "reason": "No matching authoritative Fedora build evidence",
  "matches": []
}
```

## Private state

Reports and snapshots are GPG envelopes; the checkpoint contains handles and counts.
The ledger contains sanitized notification state. The approved public recipient and
its policy live in the state root; the disposable private key lives elsewhere and is
destroyed after generation. No state layout with dynamic filenames is published.
The log reminder `legacy plaintext retained` means older plaintext is never migrated or deleted.
