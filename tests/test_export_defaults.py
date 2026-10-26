"""Portable, fail-closed defaults; no operational configuration or transport."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import notifications as n
import secure_store
import watcher


class ExportDefaultsTests(unittest.TestCase):
    def test_sample_worker_rejects_direct_entry_without_writing_home(self):
        source = Path(__file__).with_name('generate_sample.py')
        with tempfile.TemporaryDirectory(prefix='SYNTHETIC-direct-worker-') as tmp:
            home = Path(tmp)
            result = subprocess.run([sys.executable, '-I', '-B', '-S', str(source), '--worker'],
                                    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                         'HOME': str(home), 'TMPDIR': str(home)},
                                    capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(home.iterdir()), [])
            self.assertNotIn(str(home), result.stdout + result.stderr)

    def test_sample_document_matches_real_offline_scenarios(self):
        import importlib.util
        source = Path(__file__).with_name('generate_sample.py')
        self.assertTrue(source.is_file(), 'reproducible sample generator is required')
        spec = importlib.util.spec_from_file_location('sample_generator', source)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.generate()
        self.assertEqual([row['exit_code'] for row in result['scenarios']], [0, 0, 20])
        failure = result['scenarios'][-1]
        self.assertEqual(failure['calls'], ['PyPI', 'KEV', 'EPSS', 'NVD', 'Fedora43', 'Fedora44'])
        self.assertEqual(failure['errors'], [{'source': source, 'error': 'SYNTHETIC unavailable'}
                                          for source in failure['calls']])
        self.assertTrue((source.parent.parent/'SAMPLE_OUTPUT.md').read_text() == result['document'],
                        'SAMPLE_OUTPUT.md must equal regenerated synthetic output')

    def test_unconfigured_live_notifications_fail_before_sender(self):
        counts = dict.fromkeys(n.FIELDS, 0)
        counts['errors'] = 1
        with tempfile.TemporaryDirectory() as tmp, patch.object(n, 'URGENT', 'disabled:urgent'), patch.object(n, 'ROUTINE', 'disabled:routine'):
            sent = []
            with self.assertRaises(ValueError):
                n.process(Path(tmp), {'counts': counts}, sender=lambda *a: sent.append(a), mode='live')
            self.assertEqual(sent, [])
            self.assertFalse((Path(tmp)/'notification-ledger.json').exists())

    def test_missing_runtime_never_invokes_subprocess(self):
        with patch.object(n, 'ROUTINE', 'slack:SYNTHETIC_ROUTINE'), patch.object(n, 'HERMES_PYTHON', None), patch.object(n.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                n.cli_sender(n.ROUTINE, n.text(dict.fromkeys(n.FIELDS, 0), 'report'))
            run.assert_not_called()

    def test_explicit_recipient_cannot_bypass_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recipient = root/'recipient.gpg'
            recipient.write_bytes(b'SYNTHETIC public recipient fixture')
            recipient.chmod(0o600)
            with patch.object(secure_store.EncryptedStore, 'encrypt', return_value=b'SYNTHETIC ciphertext') as encrypt:
                with self.assertRaises(secure_store.EncryptionError):
                    secure_store.EncryptedStore(root, recipient=recipient)
                encrypt.assert_not_called()

    def test_approved_policy_production_store_preflight_and_encrypted_run(self):
        import daily_check
        import synthetic_encryption
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            synthetic_encryption.store(root)
            preflight = subprocess.run([sys.executable, '-B', '-I', '-S',
                                        str(Path(daily_check.__file__)), '--root', tmp,
                                        '--check-storage'], capture_output=True)
            self.assertEqual(preflight.returncode, 0)
            self.assertFalse((root/'snapshots').exists())
            marker = 'SYNTHETIC-sensitive-inventory-marker'
            snapshot = {'entries': [], 'errors': [], 'coverage': {'marker': marker}}
            def unavailable(cache, source, **kwargs):
                return {'usable': False, 'stale': True,
                        'errors': [{'source': source, 'error': 'SYNTHETIC offline feed'}]}
            # Use the real store/policy path, not a store mock. No host inventory.
            report, code = daily_check.run(root, collector=lambda: snapshot, fetcher=unavailable)
            self.assertEqual(code, 20)
            self.assertEqual(report['notifications']['mode'], 'dry-run')
            self.assertTrue((root/'daily-report-latest.json.gpg').is_file())
            self.assertEqual(len(list((root/'snapshots').glob('*.gpg'))), 1)
            for path in root.rglob('*'):
                if path.is_file():
                    self.assertNotIn(marker.encode(), path.read_bytes())

    def test_storage_denies_generic_home_vault_and_projects(self):
        for root in (Path.home()/'Documents/Vault', Path.home()/'Projects'):
            with self.assertRaises(watcher.StorageError):
                watcher.storage_check(root/'SYNTHETIC-state')

    def test_production_imports_do_not_start_processes_or_network(self):
        root = Path(__file__).resolve().parent.parent
        script = '''
import sys
sys.path.insert(0, sys.argv[1])
def guard(event, args):
    if event in ('subprocess.Popen', 'os.system', 'socket.connect', 'socket.getaddrinfo'):
        raise AssertionError('import side effect')
sys.addaudithook(guard)
import watcher, inventory, public_feeds, vulnerabilities, enrichment
import fedora_advisories, secure_store, notifications, daily_check, hermes_send
'''
        with tempfile.TemporaryDirectory() as home:
            result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root)],
                                    capture_output=True, env={'PATH':'/usr/bin:/bin', 'HOME':home})
        self.assertEqual(result.returncode, 0, 'production imports must be offline and runtime-independent')
