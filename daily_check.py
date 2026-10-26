#!/usr/bin/python3
"""Daily private inventory + LOCAL public-advisory comparison, no remediation.

Run with /usr/bin/python3 -B -I -S /absolute/path/daily_check.py. -S avoids
sitecustomize/.pth execution. Only trusted system packaging is optionally loaded.
"""
import sys
from pathlib import Path
if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    for lib in ('lib', 'lib64'):
        candidate = Path(sys.base_prefix) / lib / ('python%d.%d' % sys.version_info[:2]) / 'site-packages'
        if candidate.is_dir():
            sys.path.append(str(candidate))
import argparse
from collections import Counter
import datetime as dt
import fcntl
import hashlib
import json
import os
import time
import uuid
import zipfile
import inventory
import public_feeds
import vulnerabilities
import fedora_advisories
import enrichment
import notifications
from secure_store import EncryptedStore, EncryptionError
from watcher import DEFAULT_ROOT, LockedError, StorageError, dump, load, mkdir, storage_check


class PreflightEncryptionError(EncryptionError):
    """Recipient validation failed before the collector was invoked."""


def summary(report):
    c = report['counts']
    notice = report.get('notifications', {})
    return ('software-check ' + report['change'] + ': ' +
            ' '.join(k + '=' + str(c[k]) for k in ('assessed', 'affected', 'kev_flagged', 'unassessed', 'needs_investigation', 'errors')) +
            '; notification_mode=' + notice.get('mode', 'unknown') +
            ' notification_pending=' + str(notice.get('pending', 0)) +
            ' notification_ambiguous=' + str(notice.get('ambiguous', 0)) +
            '; new sensitive evidence encrypted; legacy plaintext retained')


def evaluate(snapshot, cache, fetcher=public_feeds.refresh):
    """Read-only local matching; only fixed public feed cache writes."""
    errors = list(snapshot['errors'])
    ecosystems = sorted({x['ecosystem'] for x in snapshot['entries']} & {'PyPI', 'npm'})
    feeds, indexes = {}, {}
    for eco in ecosystems + ['KEV', 'EPSS', 'NVD']:
        feed = fetcher(cache, eco)
        feeds[eco] = feed
        errors.extend(feed.get('errors', []))
    for eco in ecosystems:
        feed = feeds[eco]
        if not feed.get('usable'):
            continue
        try:
            names = {x['name'] for x in snapshot['entries'] if x['ecosystem'] == eco}
            indexes[eco], parse_errors, count = vulnerabilities.load_osv(Path(feed['path']), eco, names, inventory.normalize)
            feed['advisory_records'] = count
            feed['errors'].extend(parse_errors)
            errors.extend(parse_errors)
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
            feed['usable'] = False
            error = {'source': eco, 'error': type(exc).__name__}
            feed['errors'].append(error); errors.append(error)
    kev, kev_ok = set(), False
    if feeds['KEV'].get('usable'):
        try:
            data = json.loads(Path(feeds['KEV']['path']).read_bytes())
            rows = data['vulnerabilities']
            if not isinstance(rows, list) or not rows:
                raise ValueError('empty or invalid KEV catalog')
            kev = {x['cveID'] for x in rows}
            if not all(isinstance(x, str) and x.startswith('CVE-') for x in kev):
                raise ValueError('invalid KEV identity')
            feeds['KEV']['catalog_version'] = data.get('catalogVersion')
            feeds['KEV']['date_released'] = data.get('dateReleased')
            kev_ok = not (feeds['KEV'].get('stale') or feeds['KEV'].get('errors'))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            error = {'source': 'KEV', 'error': type(exc).__name__}
            feeds['KEV']['errors'].append(error); errors.append(error)
    findings = vulnerabilities.assess(snapshot['entries'], indexes, feeds, kev, kev_ok)
    fedora_rows, feeds['Fedora'] = fedora_advisories.refresh_public(cache, fetcher=fetcher)
    errors.extend(feeds['Fedora']['errors'])
    by_name = {}
    for advisory in fedora_rows:
        by_name.setdefault(advisory['name'], []).append(advisory)
    findings = [fedora_advisories.assess(row, by_name.get(row['name'], []), fresh=not feeds['Fedora']['stale'], kev=kev) if row['ecosystem']=='RPM' else row for row in findings]
    enrichment_counts = enrichment.enrich(findings, feeds)
    # Parsing can add errors after download; rebuild without losing local
    # collection errors or double-counting transport errors.
    errors = list(snapshot['errors']) + [e for feed in feeds.values() for e in feed.get('errors', [])]
    counts_by_status = Counter(x['status'] for x in findings)
    counts = {'assessed': sum(counts_by_status[s] for s in ('affected', 'not affected')),
              'affected': counts_by_status['affected'],
              'kev_flagged': sum(any(m['kev'] for m in x['matches']) for x in findings),
              'unassessed': counts_by_status['unassessed'],
              'needs_investigation': counts_by_status['needs investigation'], 'errors': len(errors)}
    return findings, feeds, counts, errors, enrichment_counts


def run(root=DEFAULT_ROOT, collector=inventory.collect, fetcher=public_feeds.refresh):
    started = time.monotonic()
    root = storage_check(root)
    mkdir(root)
    fd = os.open(root / '.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LockedError('lock held')
        try:
            store = EncryptedStore(root)
        except EncryptionError:
            raise PreflightEncryptionError('encryption preflight failed') from None
        snapshot = collector()
        previous = load(root / 'daily-checkpoint.json', {})
        handles = {hashlib.sha256(json.dumps(inventory.identity(x)).encode()).hexdigest():
                   hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest() for x in snapshot['entries']}
        old = previous.get('entry_handles', {})
        snapshot['diff'] = {'added_count': len(handles.keys() - old.keys()),
                            'removed_count': len(old.keys() - handles.keys()),
                            'changed_count': sum(old[k] != handles[k] for k in old.keys() & handles.keys()),
                            'removed_details': 'Previous sensitive envelopes require owner decryption; handles only in unattended checkpoint.'}
        snapshot['diff']['collection_complete'] = not bool(snapshot['errors'])
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ-') + uuid.uuid4().hex[:8]
        snapshot_path = root / 'snapshots' / (stamp + '.json.gpg')
        store.write(snapshot_path, snapshot)
        findings, feeds, counts, errors, enrichment_counts = evaluate(snapshot, root / 'advisory-cache', fetcher)
        # Fingerprint excludes clocks, HTTP byte counts and changing report paths.
        material = {'entries': snapshot['entries'], 'findings': findings, 'errors': errors,
                    'feeds': {k: {f: value.get(f) for f in ('usable', 'stale', 'errors')} for k, value in feeds.items()}}
        fingerprint = hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
        report = {'observed_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'snapshot': str(snapshot_path),
                  'inventory_entries': snapshot['entries'], 'findings': findings, 'counts': counts,
                  'errors': errors, 'feeds': feeds, 'fingerprint': fingerprint,
                  'change': 'no-change' if fingerprint == previous.get('fingerprint') else 'changed',
                  'coverage': snapshot['coverage'], 'enrichment': enrichment_counts,
                  'inventory_fingerprint': hashlib.sha256(json.dumps(handles, sort_keys=True).encode()).hexdigest(),
                  'elapsed_seconds': round(time.monotonic() - started, 3),
                  'privacy': 'LOCAL matching; public bulk URLs only; new sensitive evidence GnuPG encrypted; legacy plaintext retained',
                  'limits': 'No matching OSV advisory is not evidence of universal safety. KEV prioritizes matches, not applicability.'}
        store.write(root / 'reports' / (stamp + '.json.gpg'), report)
        store.write(root / 'daily-report-latest.json.gpg', report)
        report['notifications'] = notifications.process(root, report)
        dump(root / 'daily-checkpoint.json', {'entry_handles': handles, 'fingerprint': fingerprint, 'counts': counts})
        # Applicability uncertainty stays visible in counts, not an execution
        # failure. Transport/collection/parser errors always retain exit 20.
        notice = report['notifications']
        delivery_error = notice['mode'] == 'live' and (notice['pending'] or notice['ambiguous'])
        return report, 20 if errors or delivery_error else 0
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--check-storage', action='store_true', help='fail-closed encryption preflight, no collection or network')
    args = parser.parse_args(argv)
    try:
        if args.check_storage:
            EncryptedStore(storage_check(args.root))
            print('software-check encryption preflight passed; legacy plaintext retained')
            return 0
        report, code = run(args.root)
        print(summary(report))
        return code
    except LockedError:
        print('software-check blocked: lock held; errors=1; ENCRYPTION NOT COMPLETE')
        return 3
    except EncryptionError as exc:
        if not args.check_storage:
            notify_failure(args.root)
        if args.check_storage or isinstance(exc, PreflightEncryptionError):
            print('software-check blocked: approved encryption recipient/policy missing or unusable; errors=1; no collection performed')
            return 4
        print('software-check failed: encryption failed after collection may have started; errors=1; encrypted evidence may be incomplete')
        return 20
    except StorageError:
        print('software-check blocked: unsafe storage; errors=1; ENCRYPTION NOT COMPLETE')
        return 4
    except Exception as exc:
        # Never dump private objects in an unexpected runtime traceback.
        # KeyboardInterrupt/SystemExit still propagate.
        if not args.check_storage:
            notify_failure(args.root)
        print('software-check failed: ' + type(exc).__name__ + '; errors=1; ENCRYPTION NOT COMPLETE')
        return 20


def notify_failure(root):
    """Only fixed aggregates, under the same lock; never relax storage safety."""
    fd=None
    try:
        root=storage_check(root);mkdir(root)
        fd=os.open(root/'.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        notifications.process(root,{'counts':dict(assessed=0,affected=0,kev_flagged=0,unassessed=0,needs_investigation=0,errors=1)})
    except (StorageError,OSError,ValueError,KeyError,TypeError):
        pass # unsafe/unwritable/locked state: journal is the remaining channel
    finally:
        if fd is not None:os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
