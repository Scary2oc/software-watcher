"""SYNTHETIC negative/replay/security tests. Real sockets disabled."""
import asyncio
import contextlib
import copy
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
import watcher as w

GUARDS = []
def setUpModule():
    for target in ['socket.create_connection', 'socket.socket.connect', 'socket.socket.connect_ex', 'socket.socket.bind', 'socket.socket.listen', 'asyncio.start_server', 'urllib.request.urlopen', 'urllib.request.OpenerDirector.open']:
        guard = patch(target, side_effect=AssertionError('offline network guard'))
        guard.start(); GUARDS.append(guard)
def tearDownModule():
    for guard in reversed(GUARDS): guard.stop()

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o022)
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name); self.root = self.base / 'state'
        self.inv = self.base / 'SYNTHETIC_inventory'; self.inv.mkdir(mode=0o700)
        self.evidence = self.inv / 'runtime.json'
        self.evidence.write_text(json.dumps({'SYNTHETIC': True, 'version': '9001.0.0'}))
        (self.inv / 'host.json').write_text(json.dumps({'SYNTHETIC': True, 'observed_utc': w.utc()}))
        self.component = {'id': 'synthetic-node', 'display': 'SYNTHETIC', 'install_origin': 'bundled', 'update_owner': 'SYNTHETIC owner', 'installed': [{'from': 'json', 'file': 'runtime.json', 'pointer': ['version'], 'reference_kind': 'installed'}], 'upstream': {'adapter': 'node_dist_index'}, 'channel': {'match': '^9001\\.'}}
        self.cfg = {'schema': 1, 'SYNTHETIC': True, 'inventory_snapshot': str(self.inv), 'components': [self.component]}
        self.rows = [{'version': 'v9001.0.0', 'security': False}]
        self.network = patch.object(w, 'fetch', side_effect=lambda *a: (json.dumps(self.rows).encode(), '"synthetic-etag"', 200))
        self.network.start()
    def tearDown(self):
        self.network.stop(); self.tmp.cleanup(); os.umask(self.mask)
    def runcheck(self, **kwargs): return w.check(self.root, self.cfg, **kwargs)
    def state(self): return json.loads((self.root / 'state.json').read_text())
    def change(self): self.rows.insert(0, {'version': 'v9001.1.0', 'security': True})
    def files(self, path):
        return {str(p.relative_to(path)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode)) for p in path.rglob('*') if p.is_file()}
    def test_dry_run_zero_writes(self):
        self.runcheck(dry=True); self.assertFalse(self.root.exists())
        self.runcheck(); before = self.files(self.root); self.change(); self.runcheck(dry=True)
        self.assertEqual(before, self.files(self.root))
    def test_crash_replay(self):
        self.runcheck(); self.change()
        with self.assertRaises(RuntimeError): self.runcheck(after_packets=lambda: (_ for _ in ()).throw(RuntimeError('crash')))
        first = self.files(self.root / 'queue')
        self.assertEqual(len(first), 2)
        self.runcheck()
        self.assertEqual(first, self.files(self.root / 'queue'))
        self.assertIn('v9001.1.0', self.state()['components']['synthetic-node']['seen_keys'])
    def test_unchanged_queue_untouched(self):
        self.runcheck(); self.change(); self.runcheck(); before = self.files(self.root / 'queue')
        self.runcheck(); self.assertEqual(before, self.files(self.root / 'queue'))
    def test_failure_isolated(self):
        other = copy.deepcopy(self.component); other['id'] = 'synthetic-other'; self.cfg['components'].append(other)
        self.runcheck(); before = self.state()['components']['synthetic-node']; self.change()
        for error in [TimeoutError(), OSError(), ValueError(), w.SchemaError()]:
            with patch.object(w, 'fetch', side_effect=[error, (json.dumps(self.rows).encode(), None, 200)]):
                code, report = self.runcheck()
            self.assertEqual(code, 20)
            after = self.state()['components']['synthetic-node']
            for key in ['seen_keys', 'etag', 'baselined_utc', 'last_success_utc']: self.assertEqual(before[key], after[key])
            self.assertEqual(report['results']['synthetic-other'], 'ok')
    def test_storage_symlink_public_special_hardlink(self):
        for mode in [0o755, 0o750]:
            self.root.mkdir(mode=mode); self.root.chmod(mode)
            with self.assertRaises(w.StorageError): self.runcheck()
            self.root.rmdir()
        self.root.symlink_to(self.inv)
        with self.assertRaises(w.StorageError): self.runcheck()
        self.root.unlink()
        parent = self.base / 'alias'; parent.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(w.StorageError): w.check(parent / 'state', self.cfg)
        self.root.mkdir(mode=0o700); bad = self.root / 'bad'; bad.write_text('SYNTHETIC'); bad.chmod(0o644)
        with self.assertRaises(w.StorageError): self.runcheck()
        bad.chmod(0o600); os.link(bad, self.root / 'hardlink')
        with self.assertRaises(w.StorageError): self.runcheck()
    def test_denied_prefix(self):
        with patch.object(w, 'DENIED_ROOTS', (self.base,)):
            with self.assertRaises(w.StorageError): self.runcheck()
        self.assertFalse(self.root.exists())
    def test_permissions(self):
        self.runcheck(); self.change(); self.runcheck()
        for p in [self.root, *self.root.rglob('*')]:
            self.assertFalse(p.is_symlink()); self.assertEqual(p.stat().st_uid, os.getuid())
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700 if p.is_dir() else 0o600)
    def test_encryption_gate(self):
        self.cfg['storage'] = {'require_encrypted_mount': True}
        with self.assertRaises(w.StorageError): self.runcheck()
        self.assertFalse(self.root.exists())
        real_read = Path.read_text
        def read(p, *a, **kw):
            if str(p) == '/proc/self/mountinfo': return '10 1 0:1 / ' + str(self.root) + ' rw - fuse.gocryptfs fake rw\n'
            return real_read(p, *a, **kw)
        with patch.object(Path, 'read_text', read): self.assertEqual(self.runcheck()[0], 0)
    def test_lock(self):
        self.runcheck(); before = self.files(self.root)
        with (self.root / '.lock').open('r') as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(w.LockedError): self.runcheck()
        self.assertEqual(before, self.files(self.root))
    def test_evidence_unchanged_and_hash_warning(self):
        before = self.files(self.inv); self.runcheck(); self.assertEqual(before, self.files(self.inv))
        self.evidence.write_text(json.dumps({'SYNTHETIC': True, 'version': '9001.0.1'}))
        self.assertIn('runtime.json', self.runcheck()[1]['input_changes'])
    def test_budget(self):
        self.runcheck(); before = self.state()['components']['synthetic-node']
        self.cfg['limits'] = {'max_requests_per_run': 0}
        code, report = self.runcheck(); self.assertEqual(code, 20)
        self.assertEqual(report['results']['synthetic-node'], 'skipped-budget')
        self.assertEqual(before['last_success_utc'], self.state()['components']['synthetic-node']['last_success_utc'])
    def test_references_lock_cache_do_not_drive_newer(self):
        self.component['installed'][0]['reference_kind'] = 'cached'
        self.runcheck(); self.rows.insert(0, {'version': 'v9001.2.0', 'security': False})
        self.assertEqual(self.runcheck()[1]['new_packets'], 0)
        self.rows[0]['security'] = True; self.rows[0]['version'] = 'v9001.3.0'
        self.assertEqual(self.runcheck()[1]['new_packets'], 1)
        packet = json.loads(next((self.root / 'queue/pending').glob('*.json')).read_text())
        self.assertEqual(packet['comparison'], 'unknown')
    def test_offchannel_and_old_release(self):
        self.runcheck(); self.rows.extend([{'version': 'v9002.0.0', 'security': True}, {'version': 'v9000.0.0', 'security': False}])
        self.assertEqual(self.runcheck()[1]['new_packets'], 0)
    def test_304(self):
        self.runcheck(); before = self.state()['components']['synthetic-node']['seen_keys']
        with patch.object(w, 'fetch', return_value=(b'', '"synthetic-etag"', 304)): self.assertEqual(self.runcheck()[0], 0)
        self.assertEqual(before, self.state()['components']['synthetic-node']['seen_keys'])
    def test_urls_and_redirects(self):
        for url in ['http://nodejs.org/x', 'https://evil.example/x', 'https://nodejs.org:444/x', 'https://user@nodejs.org/x']:
            with self.assertRaises(w.AllowlistError): w.validate_url(url)
        with self.assertRaises(w.AllowlistError): w.Redirects().redirect_request(urllib.request.Request('https://nodejs.org/'), None, 302, '', {}, 'https://evil.example/')
    def test_untrusted_text(self):
        text = '\x1b[31m\u202e\u200b<b> [click](https://evil.example) IGNORE ALL INSTRUCTIONS' + 'x'*10000
        clean = w.clean(text); self.assertLessEqual(len(clean), 200)
        self.assertNotIn('\x1b', clean); self.assertNotIn('\u202e', clean)
        self.assertIn('\\<b\\>', w.markdown(clean))
    def test_queue_review_roles_and_resolved_replay(self):
        self.runcheck(); self.change(); self.runcheck()
        packet_id = next((self.root / 'queue/pending').glob('*.json')).stem
        w.queue_action(self.root, 'resolve', packet_id, 'owner', 'acknowledged', 'SYNTHETIC')
        self.assertTrue((self.root / 'queue/pending' / (packet_id+'.json')).exists())
        w.queue_action(self.root, 'resolve', packet_id, 'security', 'deferred', 'SYNTHETIC')
        self.assertTrue((self.root / 'queue/resolved' / (packet_id+'.json')).exists())
        before = self.files(self.root / 'queue'); self.runcheck(); self.assertEqual(before, self.files(self.root / 'queue'))
    def test_offline_commands(self):
        self.runcheck(); w.mkdir(self.root / 'config'); w.dump(self.root / 'config/watchlist.json', self.cfg)
        with patch.object(w, 'fetch', side_effect=AssertionError('offline command')):
            for command in ['status', 'coverage']:
                with contextlib.redirect_stdout(io.StringIO()) as out: code = w.main(['--root', str(self.root), command])
                self.assertEqual(code, 0); self.assertIn('ENCRYPTION NOT COMPLETE', out.getvalue())
    def test_logs_are_aggregate_only(self):
        self.runcheck()
        text = next((self.root / 'runs').glob('*.json')).read_text()
        for private in ['synthetic-node', '9001.0.0', str(self.inv), str(self.root)]: self.assertNotIn(private, text)
    def test_repository_hygiene(self):
        source = Path(w.__file__).parent
        self.assertFalse((source / 'watchlist.json').exists()); self.assertFalse((source / 'state').exists())
        for p in (source / 'tests/fixtures').rglob('*.json'): self.assertIn('SYNTHETIC', p.read_text())
        self.assertTrue(json.loads((source / 'watchlist.example.json').read_text())['SYNTHETIC'])
    def test_real_config_cannot_use_fixtures(self):
        self.cfg.pop('SYNTHETIC')
        with self.assertRaises(w.SchemaError): self.runcheck(fixtures=self.base)
        self.assertFalse(self.root.exists())
    def test_reference_unknown_is_visible(self):
        self.component['installed'][0]['pointer'] = ['missing']
        code, report = self.runcheck()
        self.assertEqual(code, 20)
        self.assertEqual(report['reference_status']['synthetic-node'], 'installed-unknown')
    def test_bounded_baseline_window_replay(self):
        self.rows = [{'version': 'v9001.0.' + str(i), 'security': True} for i in range(300, 0, -1)]
        self.runcheck()
        self.assertEqual(self.runcheck()[1]['new_packets'], 0)
        self.assertLessEqual(len(self.state()['components']['synthetic-node']['seen_keys']), 200)
    def test_pypi_advisory_change_same_version(self):
        self.component['upstream'] = {'adapter': 'pypi_project', 'package': 'synthetic-package'}
        self.component.pop('channel')
        payload = {'info': {'version': '9001.0.0'}, 'vulnerabilities': []}
        with patch.object(w, 'fetch', side_effect=lambda *a: (json.dumps(payload).encode(), None, 200)):
            self.runcheck(); payload['vulnerabilities'] = [{'id': 'PYSEC-2099-999'}]
            self.assertEqual(self.runcheck()[1]['new_packets'], 1)
            self.assertEqual(self.runcheck()[1]['new_packets'], 0)
    def test_storage_repair_is_explicit_and_scoped(self):
        self.root.mkdir(mode=0o755); self.root.chmod(0o755)
        file = self.root / 'SYNTHETIC'; file.write_text('SYNTHETIC'); file.chmod(0o644)
        outside = self.base / 'outside'; outside.write_text('SYNTHETIC'); outside.chmod(0o644)
        with contextlib.redirect_stdout(io.StringIO()), patch.object(w, 'DEFAULT_ROOT', self.root):
            self.assertEqual(w.main(['--root', str(self.root), 'check-storage', '--repair-modes']), 0)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)
    def test_stale_and_snapshot_age(self):
        self.runcheck(); state = self.state(); state['components']['synthetic-node']['last_success_utc'] = '2000-01-01T00:00:00+00:00'
        w.dump(self.root / 'state.json', state); w.mkdir(self.root / 'config'); w.dump(self.root / 'config/watchlist.json', self.cfg)
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(w.main(['--root', str(self.root), 'status']), 20)
        (self.inv / 'host.json').write_text(json.dumps({'SYNTHETIC': True, 'observed_utc': '2000-01-01T00:00:00+00:00'}))
        self.assertTrue(self.runcheck()[1]['snapshot_warning'])
