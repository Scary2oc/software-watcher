"""SYNTHETIC offline acceptance tests; no actual inventory is read."""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import watcher as w


class StorageTests(unittest.TestCase):
    def test_public_root_refused_without_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'private'
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            before = list(root.iterdir())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = w.main(['--root', str(root), 'check-storage'])
            self.assertEqual(code, 4)
            self.assertEqual(list(root.iterdir()), before)


class LifecycleTests(unittest.TestCase):
    def test_baseline_change_nochange_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inventory = base / 'SYNTHETIC_inventory'
            inventory.mkdir(mode=0o700)
            (inventory / 'host.json').write_text(json.dumps({'SYNTHETIC': True, 'observed_utc': w.utc()}))
            (inventory / 'runtime.json').write_text(json.dumps({'SYNTHETIC': True, 'version': '9001.0.0'}))
            component = {'id': 'synthetic-node', 'display': 'SYNTHETIC Node', 'install_origin': 'bundled', 'update_owner': 'SYNTHETIC owner', 'installed': [{'from': 'json', 'file': 'runtime.json', 'pointer': ['version'], 'reference_kind': 'installed'}], 'upstream': {'adapter': 'node_dist_index'}, 'channel': {'match': '^9001\\.'}, 'enabled': True}
            cfg = {'schema': 1, 'SYNTHETIC': True, 'inventory_snapshot': str(inventory), 'components': [component]}
            root = base / 'state'
            rows = [{'version': 'v9001.0.0', 'security': False, 'lts': False}]
            def fetch(url, cap, etag=None):
                return json.dumps(rows).encode(), None, 200
            with patch.object(w, 'fetch', side_effect=fetch):
                self.assertEqual(w.check(root, cfg)[0], 0)
                self.assertTrue(list((root / 'baseline').glob('*.md')))
                self.assertEqual(list((root / 'queue/pending').glob('*.json')), [])
                rows.insert(0, {'version': 'v9001.1.0', 'security': True, 'lts': False})
                self.assertEqual(w.check(root, cfg)[0], 10)
                packets = list((root / 'queue/pending').glob('*.json'))
                self.assertEqual(len(packets), 1)
                self.assertIn('security', json.loads(packets[0].read_text())['required_reviewers'])
                before = packets[0].read_bytes()
                self.assertEqual(w.check(root, cfg)[0], 0)
                self.assertEqual(packets[0].read_bytes(), before)
            checkpoint = json.loads((root / 'state.json').read_text())['components']['synthetic-node']
            with patch.object(w, 'fetch', side_effect=TimeoutError()):
                self.assertEqual(w.check(root, cfg)[0], 20)
            failed = json.loads((root / 'state.json').read_text())['components']['synthetic-node']
            for key in ['seen_keys', 'etag', 'baselined_utc', 'last_success_utc']:
                self.assertEqual(checkpoint.get(key), failed.get(key))
            self.assertEqual(packets[0].read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
