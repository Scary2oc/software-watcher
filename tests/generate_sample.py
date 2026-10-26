"""Regenerate only synthetic documentation; subprocess diagnostics never escape."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent.parent


def generate():
    # A fresh interpreter avoids cached production configuration and test helpers.
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    base = os.environ.get('TMPDIR') or tempfile.gettempdir()
    with tempfile.TemporaryDirectory(prefix='SYNTHETIC-sample-', dir=base) as tmp:
        env.update(HOME=tmp, TMPDIR=tmp, SYNTHETIC_SAMPLE_WORKER_HOME=tmp)
        try:
            result = subprocess.run([sys.executable, '-I', '-B', '-S', str(Path(__file__).resolve()),
                                     '--worker'], env=env, capture_output=True, timeout=180)
        finally:
            # Also cover a worker timeout, when its own finally cannot execute.
            subprocess.run(['/usr/bin/gpgconf', '--homedir', str(Path(tmp)/'keys'),
                            '--kill', 'gpg-agent'], env=env, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('synthetic generation failed; diagnostics suppressed')
    return json.loads(result.stdout)


def worker():
    import datetime as dt
    import gzip
    import hashlib
    import socket
    import zipfile
    from unittest.mock import patch

    def offline(event, args):
        if event == 'socket.__new__' and args[1] in (socket.AF_INET, socket.AF_INET6):
            raise AssertionError('synthetic samples forbid network')
        if event in ('socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyaddr'):
            raise AssertionError('synthetic samples forbid DNS')
    sys.addaudithook(offline)
    home = Path(os.environ.get('HOME', ''))
    # Entry-point safety, not a sandbox: only the isolated launcher sets this.
    if (os.environ.get('SYNTHETIC_SAMPLE_WORKER_HOME') != str(home)
            or os.environ.get('TMPDIR') != str(home)
            or not home.name.startswith('SYNTHETIC-sample-')):
        raise RuntimeError('internal sample worker requires the isolated launcher')
    tempfile.tempdir = str(home)
    keyhome = home/'keys'
    keyhome.mkdir(mode=0o700)
    (home/'.gnupg').mkdir(mode=0o700)
    sys.path.insert(0, str(SOURCE))
    import daily_check as daily
    import inventory
    from watcher import dump

    def gpg(*args):
        result = subprocess.run(['/usr/bin/gpg', '--homedir', str(keyhome), '--batch',
                                 '--no-options', '--no-auto-key-retrieve', *args],
                                capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError('synthetic GPG operation failed')
        return result.stdout

    def forbidden_sender(*args, **kwargs):
        raise AssertionError('sample generation must never send')

    try:
        gpg('--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
            'SYNTHETIC documentation fixture', 'rsa2048', 'encr', '1d')
        root = home/'sample-state'
        root.mkdir(mode=0o700)
        public = gpg('--export')
        (root/'recipient.gpg').write_bytes(public)
        (root/'recipient.gpg').chmod(0o600)
        dump(root/'storage-policy.json', {'mode': 'gpg-public-recipient',
                                         'recipient_sha256': hashlib.sha256(public).hexdigest()})
        dump(root/'notification-policy.json', {'mode': 'dry-run'})
        fixtures = home/'fixtures'
        fixtures.mkdir(mode=0o700)
        archive = fixtures/'osv.zip'
        with zipfile.ZipFile(archive, 'w') as out:
            out.writestr('advisory.json', (SOURCE/'tests/fixtures/SYNTHETIC_osv.json').read_bytes())
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        kev = fixtures/'kev.json'
        kev.write_text(json.dumps({'vulnerabilities': [{'cveID': 'CVE-2099-00001'}]}))
        epss = fixtures/'epss.gz'
        epss.write_bytes(gzip.compress(('#score_date:'+today+'\ncve,epss,percentile\n'
                                        'CVE-2099-00001,0.9,0.99\n').encode(), mtime=0))
        nvd = fixtures/'nvd.gz'
        nvd.write_bytes(gzip.compress(json.dumps({'timestamp': today+'T00:00:00Z',
            'vulnerabilities': [{'cve': {'id': 'CVE-2099-00001'}}]}).encode(), mtime=0))
        update = fixtures/'updateinfo.gz'
        update.write_bytes(gzip.compress(b'<updates><update type="security"><id>FEDORA-SYNTHETIC</id>'
            b'<pkglist><collection><package name="SYNTHETIC-vendor-fixture" arch="x86_64" '
            b'epoch="0" version="2.0" release="1.fc44"/></collection></pkglist></update></updates>', mtime=0))
        digest = hashlib.sha256(update.read_bytes()).hexdigest()
        metadata = fixtures/'repomd.xml'
        metadata.write_text('<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="updateinfo">'
            '<checksum type="sha256">'+digest+'</checksum><location href="repodata/'+digest+
            '-updateinfo.xml.gz"/></data></repomd>')
        paths = {'PyPI': archive, 'KEV': kev, 'EPSS': epss, 'NVD': nvd,
                 'Fedora43': metadata, 'Fedora44': metadata}
        calls, unavailable = [], False

        def feed(cache, source, **kwargs):
            calls.append(source)
            if unavailable:
                return {'usable': False, 'stale': True,
                        'errors': [{'source': source, 'error': 'SYNTHETIC unavailable'}]}
            path = update if 'artifact' in kwargs else paths[source]
            return {'usable': True, 'stale': False, 'errors': [], 'path': str(path)}

        def collector():
            return {'entries': [inventory.entry('PyPI', 'example-pkg', '1.5', 'SYNTHETIC:env'),
                                inventory.entry('RPM', 'example-rpm', '1:1.0-1', 'SYNTHETIC:rpm')],
                    'errors': [], 'coverage': {'limitations': ['SYNTHETIC fixtures only']}}

        chunks = ['# Sample output (synthetic)\n\n'
            'Generated with `/usr/bin/python3 -B tests/generate_sample.py --write`; verify with\n'
            '`/usr/bin/python3 -B tests/generate_sample.py --check`. Do not edit output blocks.\n\n'
            'The real daily-check pipeline uses only a synthetic collector and local fixture feeds.\n'
            'No host inventory is collected and no messages are sent. HOME/TMPDIR are disposable, configuration is\n'
            'cleared, Python network/DNS is blocked, and notifications explicitly use dry-run with\n'
            'a forbidden sender. Disposable GPG keys exercise approved-policy encryption and real\n'
            'decryption outside the repository; keys, fingerprints and private paths are omitted.\n'
            'EPSS/NVD fixture publication dates are current for freshness checks, but are not displayed.\n\n'
            '## Daily aggregate lines\n\nCounts describe metadata entries, not unique CVEs or proof of exploitability.\n'
            'Exit 0 means execution completed, not security clearance; unassessed means unknown.\n']
        scenarios, first = [], {}
        process = daily.notifications.process
        with patch.object(daily.notifications, 'process',
                          side_effect=lambda r, report: process(r, report, sender=forbidden_sender, mode='dry-run')):
            for label in ('First run', 'Identical replay', 'All six feeds unavailable'):
                calls.clear()
                unavailable = label == 'All six feeds unavailable'
                report, code = daily.run(root, collector=collector, fetcher=feed)
                scenarios.append({'exit_code': code, 'calls': list(calls), 'errors': report['errors']})
                chunks.append('\n### '+label+'\n\n```text\n'+daily.summary(report)+'\n```\n\nExit code: `'+str(code)+'`.\n')
                decrypted = json.loads(gpg('--decrypt', str(root/'daily-report-latest.json.gpg')))
                if label == 'First run':
                    first = decrypted
        chunks.append('\n## What the counts mean\n\n'
            '| Count | Meaning |\n|---|---|\n'
            '| `assessed` | Metadata entries with affected or not-affected advisory evidence |\n'
            '| `affected` | Installed version matches a published affected range |\n'
            '| `kev_flagged` | An affected match has a CVE in the KEV catalog |\n'
            '| `unassessed` | No authoritative applicability judgment; unknown, not safe |\n'
            '| `needs_investigation` | Evidence is stale, ambiguous or unsupported |\n'
            '| `errors` | Operational failures, not a count of vulnerabilities |\n\n'
            'The failure scenario makes PyPI OSV, KEV, EPSS, NVD, Fedora43 and Fedora44 unavailable;\n'
            'feed failures return exit 20, never a clean result.\n')
        chunks.append('\n## Pending dry-run notification\n\nThis body is read from the actual notification ledger; nothing was sent.\n\n```text\n')
        ledger = json.loads((root/'notification-ledger.json').read_text())
        chunks.append('\n'.join(event['body'] for event in ledger['events'].values())+'\n```\n')
        chunks.append('\n## Decrypted report excerpts\n\nField-selected from the first encrypted report after real decryption.\n'
                      'Dynamic timestamps, local paths and fingerprints are excluded.\n')
        for row in first['findings']:
            excerpt = {key: row[key] for key in ('ecosystem', 'name', 'version', 'status', 'reason')}
            excerpt['matches'] = [{key: match[key] for key in ('id', 'aliases', 'kev', 'evidence')}
                                  for match in row['matches']]
            chunks.append('\n```json\n'+json.dumps(excerpt, indent=2)+'\n```\n')
        chunks.append('\n## Private state\n\nReports and snapshots are GPG envelopes; the checkpoint contains handles and counts.\n'
            'The ledger contains sanitized notification state. The approved public recipient and\n'
            'its policy live in the state root; the disposable private key lives elsewhere and is\n'
            'destroyed after generation. No state layout with dynamic filenames is published.\n'
            'The log reminder `legacy plaintext retained` means older plaintext is never migrated or deleted.\n')
        return {'document': ''.join(chunks), 'scenarios': scenarios}
    finally:
        subprocess.run(['/usr/bin/gpgconf', '--homedir', str(keyhome), '--kill', 'gpg-agent'],
                       capture_output=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    for flag in ('write', 'check', 'worker'):
        group.add_argument('--'+flag, action='store_true', help=argparse.SUPPRESS if flag == 'worker' else flag+' SAMPLE_OUTPUT.md')
    args = parser.parse_args()
    try:
        if args.worker:
            print(json.dumps(worker()))
            return 0
        result = generate()
    except (RuntimeError, subprocess.SubprocessError, OSError, ValueError):
        print('Synthetic generation failed; process diagnostics suppressed.', file=sys.stderr)
        return 1
    target = SOURCE/'SAMPLE_OUTPUT.md'
    if args.write:
        target.write_text(result['document'])
        print('SAMPLE_OUTPUT.md regenerated from synthetic scenarios.')
        return 0
    matches = target.read_text() == result['document']
    print('SAMPLE_OUTPUT.md matches synthetic generation.' if matches else 'SAMPLE_OUTPUT.md differs; run --write.')
    return 0 if matches else 1


if __name__ == '__main__':
    raise SystemExit(main())
