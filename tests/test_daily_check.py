"""End-to-end replay uses only synthetic inventory and local ZIP fixture feeds."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
import synthetic_encryption
import daily_check as d
import inventory

FIXTURE = Path(__file__).parent / 'fixtures/SYNTHETIC_osv.json'


def snapshot():
    return {'entries': [inventory.entry('PyPI', 'example-pkg', '1.5', '/SYNTHETIC/env'),
                        inventory.entry('RPM', 'example-rpm', '1:1.0-1', 'SYNTHETIC:rpm')],
            'errors': [], 'coverage': {'limitations': ['SYNTHETIC']}, 'observed_utc': '2026-01-01T00:00:00Z'}


class DailyTests(unittest.TestCase):
    def setUp(self):
        p=patch.object(d,'EncryptedStore',side_effect=synthetic_encryption.store)
        p.start();self.addCleanup(p.stop)
        p=patch.object(d.fedora_advisories,'refresh_public',return_value=([],{'usable':True,'stale':False,'errors':[]}))
        p.start();self.addCleanup(p.stop)

    def test_parallel_rpm_checkpoint_handles_and_upgrade_diff(self):
        rows = inventory.parse_rpm(''.join(
            'SYNTHETIC\t' + version + '\tx86_64\tFedora Project\n'
            for version in ('0:2.0-3.fc44', '0:2.0-4.fc44', '1:2.0-4.fc44')))
        current = rows[:2]
        def collector():
            return dict(snapshot(), entries=list(current))
        def feed(cache, eco):
            return {'usable': False, 'stale': False, 'errors': []}
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            store = synthetic_encryption.store(root)
            diffs = []
            write = store.write
            def capture(path, value):
                if path.parent.name == 'snapshots':
                    diffs.append(value['diff'])
                write(path, value)
            store.write = capture
            with patch.object(d, 'EncryptedStore', return_value=store), \
                 patch.object(d.notifications, 'process', return_value={
                     'mode': 'disabled', 'pending': 0, 'ambiguous': 0}):
                first, code = d.run(root, collector=collector, fetcher=feed)
                self.assertEqual(code, 0)
                checkpoint = json.loads((root / 'daily-checkpoint.json').read_text())
                handles = checkpoint['entry_handles']
                self.assertEqual(len(handles), 2)
                self.assertTrue(all(len(key) == 64 for key in handles))
                self.assertNotIn('SYNTHETIC', json.dumps(checkpoint))
                current.reverse()
                replay, code = d.run(root, collector=collector, fetcher=feed)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads((root / 'daily-checkpoint.json').read_text())['entry_handles'], handles)
                current[:] = rows[1:]
                upgraded, code = d.run(root, collector=collector, fetcher=feed)
                self.assertEqual(code, 0)
                upgraded_handles = json.loads((root / 'daily-checkpoint.json').read_text())['entry_handles']
                self.assertEqual(len(upgraded_handles), 2)
                self.assertEqual(len(handles.keys() & upgraded_handles.keys()), 1)
                self.assertNotEqual(first['inventory_fingerprint'], upgraded['inventory_fingerprint'])
                current[:] = rows[2:]
                _, code = d.run(root, collector=collector, fetcher=feed)
                self.assertEqual(code, 0)
                self.assertEqual(len(json.loads((root / 'daily-checkpoint.json').read_text())['entry_handles']), 1)
            self.assertEqual([(x['added_count'], x['removed_count'], x['changed_count']) for x in diffs],
                             [(2, 0, 0), (0, 0, 0), (1, 1, 0), (0, 1, 0)])

    def test_parallel_rpm_assessment_retains_each_build_without_rpm_runtime(self):
        rows = inventory.parse_rpm(''.join(
            'SYNTHETIC\t' + version + '\tx86_64\tFedora Project\n'
            for version in ('0:2.0-3.fc44', '0:2.0-4.fc44', '1:2.0-4.fc44')))
        advisories = d.fedora_advisories.parse_updateinfo(
            b'<updates><update type="security"><id>FEDORA-SYNTHETIC</id>'
            b'<references><reference type="cve" id="CVE-2099-00001"/></references>'
            b'<pkglist><collection><package name="SYNTHETIC" arch="x86_64" '
            b'epoch="0" version="2.0" release="4.fc44"/></collection></pkglist>'
            b'</update></updates>')
        # Fixed answers exercise pipeline preservation, NOT a substitute EVR algorithm.
        orderings = {(row['version'], '0:2.0-4.fc44'): order
                     for row, order in zip(rows, (-1, 0, 1))}
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            kev = root / 'SYNTHETIC-kev.json'
            kev.write_text('{"vulnerabilities":[{"cveID":"CVE-2099-00001"}]}')
            def feed(cache, eco):
                return {'usable': eco == 'KEV', 'stale': False, 'errors': [], 'path': str(kev)}
            with patch.object(d.fedora_advisories, 'refresh_public', return_value=(
                    advisories, {'usable': True, 'stale': False, 'errors': []})), \
                 patch.object(d.fedora_advisories, 'rpm', object()), \
                 patch.object(d.fedora_advisories, 'compare', side_effect=lambda a, b: orderings[a, b]) as compare:
                findings, _, counts, errors, _ = d.evaluate(dict(snapshot(), entries=rows), root, feed)
            self.assertEqual([row['version'] for row in findings], [row['version'] for row in rows])
            self.assertEqual([row['status'] for row in findings], ['affected', 'not affected', 'not affected'])
            self.assertEqual(compare.call_count, 3)
            self.assertEqual(findings[0]['matches'][0]['kev'], ['CVE-2099-00001'])
            self.assertEqual(findings[1]['fixed_evidence'][0]['evidence']['fixed_evr'], '0:2.0-4.fc44')
            self.assertEqual(counts, dict(assessed=3, affected=1, kev_flagged=1,
                                         unassessed=0, needs_investigation=0, errors=0))
            self.assertEqual(errors, [])
            with patch.object(d.fedora_advisories, 'rpm', None):
                findings, _, counts, _, _ = d.evaluate(dict(snapshot(), entries=rows), root, feed)
            self.assertEqual([row['version'] for row in findings], [row['version'] for row in rows])
            self.assertEqual([row['status'] for row in findings], ['unassessed'] * 3)
            self.assertEqual(counts['unassessed'], 3)

    def test_live_notification_failure_is_visible_and_nonzero(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp)
            counts=dict(assessed=0,affected=0,kev_flagged=0,unassessed=2,needs_investigation=0,errors=0)
            rows=[dict(x,status='unassessed',matches=[]) for x in snapshot()['entries']]
            with patch.object(d,'evaluate',return_value=(rows,{},counts,[],{})),patch.object(d.notifications,'process',return_value={'mode':'live','pending':1,'ambiguous':0,'delivered':0}):
                report,code=d.run(root,collector=snapshot)
            self.assertEqual(code,20)
            self.assertIn('notification_pending=1',d.summary(report))

    def test_lock_crash_recovery_and_no_plaintext_retained(self):
        import fcntl
        from watcher import LockedError
        marker='SYNTHETIC-private-never-plaintext'
        def collector():
            s=snapshot();s['entries'][0]['name']=marker;return s
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp)
            lock=os.open(root/'.lock',os.O_WRONLY|os.O_CREAT,0o600)
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(LockedError):d.run(root,collector=collector)
            os.close(lock)
            counts=dict(assessed=0,affected=0,kev_flagged=0,unassessed=2,needs_investigation=0,errors=0)
            findings=[dict(x,status='unassessed',matches=[]) for x in collector()['entries']]
            real=synthetic_encryption.store(root)
            original=real.write
            writes=[]
            def crash(path,value):
                writes.append(path)
                if len(writes)==2:raise OSError('SYNTHETIC crash')
                original(path,value)
            real.write=crash
            with patch.object(d,'evaluate',return_value=(findings,{},counts,[],{})):
                with patch.object(d,'EncryptedStore',return_value=real):
                    with self.assertRaises(OSError):d.run(root,collector=collector)
                self.assertFalse((root/'daily-checkpoint.json').exists())
                report,code=d.run(root,collector=collector)
                self.assertEqual(code,0)
                replay,code=d.run(root,collector=collector)
                self.assertEqual(replay['change'],'no-change')
            for p in root.rglob('*'):
                if p.is_file():self.assertNotIn(marker.encode(),p.read_bytes())

    def test_unknown_applicability_is_not_an_operational_failure(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            archive_path = root / 'synthetic.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                archive.writestr('advisory.json', FIXTURE.read_bytes())
            archive_path.chmod(0o600)
            kev_path = root / 'kev.json'
            kev_path.write_text('{"vulnerabilities":[{"cveID":"CVE-2099-00001"}]}')
            kev_path.chmod(0o600)
            def collector():
                s = snapshot()
                s['entries'][0]['version'] = 'unknown-local-version'
                return s
            def feed(cache, eco):
                extra=synthetic_encryption.extra(cache,eco)
                if extra:return extra
                return {'usable': True, 'stale': False, 'errors': [], 'sha256': 'SYNTHETIC',
                        'path': str(kev_path if eco == 'KEV' else archive_path)}
            d.run(root, collector=collector, fetcher=feed)
            replay, code = d.run(root, collector=collector, fetcher=feed)
            self.assertEqual(replay['change'], 'no-change')
            self.assertEqual(replay['counts']['needs_investigation'], 1)
            self.assertEqual(code, 0)

    def test_replay_nochange_private_reports_and_error(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            zip_path = root / 'synthetic.zip'
            with zipfile.ZipFile(zip_path, 'w') as archive:
                archive.writestr('advisory.json', FIXTURE.read_bytes())
            zip_path.chmod(0o600)
            kev_path = root / 'synthetic-kev.json'
            kev_path.write_text(json.dumps({'catalogVersion': 'SYNTHETIC', 'dateReleased': '2026-01-01',
                'vulnerabilities': [{'cveID': 'CVE-2099-00001'}]}))
            kev_path.chmod(0o600)
            generation = ['SYNTHETIC-first']
            def feed(cache, eco):
                extra=synthetic_encryption.extra(cache,eco)
                if extra:return extra
                return {'usable': True, 'errors': [], 'stale': False, 'sha256': generation[0],
                        'path': str(kev_path if eco == 'KEV' else zip_path), 'download_bytes': 0}
            first, code = d.run(root, collector=snapshot, fetcher=feed)
            self.assertEqual(code, 0)
            self.assertIn('EPSS', first['feeds'])
            self.assertIn('NVD', first['feeds'])
            self.assertIn('Fedora', first['feeds'])
            self.assertIn('enrichment', first)
            self.assertEqual(first['counts'], {'assessed': 1, 'affected': 1, 'kev_flagged': 1,
                'unassessed': 1, 'needs_investigation': 0, 'errors': 0})
            self.assertEqual(first['findings'][0]['matches'][0]['evidence']['ranges'][0]['type'], 'ECOSYSTEM')
            self.assertEqual(first['findings'][0]['matches'][0]['modified'], '2026-01-01T00:00:00Z')
            generation[0] = 'SYNTHETIC-new-dump-same-applicable-advisories'
            second, code = d.run(root, collector=snapshot, fetcher=feed)
            self.assertEqual(code, 0)
            self.assertEqual(second['change'], 'no-change')
            self.assertEqual(len(list((root/'snapshots').glob('*.json.gpg'))), 2)
            self.assertEqual(first['fingerprint'], second['fingerprint'])
            for path in root.rglob('*'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            self.assertNotIn('example-pkg', d.summary(second))
            def failing(cache, eco):
                return {'usable': False, 'errors': [{'source': eco, 'error': 'SYNTHETIC failure'}], 'stale': True}
            failed, code = d.run(root, collector=snapshot, fetcher=failing)
            self.assertEqual(code, 20)
            self.assertEqual(failed['counts']['assessed'], 0)
            self.assertGreater(failed['counts']['errors'], 0)
            self.assertNotIn('clean', d.summary(failed))


if __name__ == '__main__':
    unittest.main()
