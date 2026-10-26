"""Encryption boundary exercised with disposable SYNTHETIC keys only."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import daily_check
from watcher import StorageError


class SecureStoreTests(unittest.TestCase):
    def test_storage_preflight_never_processes_live_notifications(self):
        import contextlib
        import io
        from unittest.mock import patch
        from secure_store import EncryptionError
        import notifications

        real_process = notifications.process
        def forbidden_sender(*args):
            self.fail('storage preflight attempted notification delivery')
        def live_process(root, report):
            return real_process(root, report, mode='live', sender=forbidden_sender)

        cases = [(None, 0), (EncryptionError('SYNTHETIC encryption failure'), 4),
                 (RuntimeError('SYNTHETIC unexpected failure'), 20),
                 (StorageError('SYNTHETIC unsafe storage'), 4),
                 (daily_check.LockedError('SYNTHETIC lock'), 3)]
        for failure, expected in cases:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                with patch.object(daily_check, 'EncryptedStore', side_effect=failure), \
                     patch.object(notifications, 'URGENT', 'synthetic:urgent'), \
                     patch.object(notifications, 'ROUTINE', 'synthetic:routine'), \
                     patch.object(notifications, 'process', side_effect=live_process) as process, \
                     patch.object(daily_check, 'run', side_effect=AssertionError('preflight collected inventory')), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(daily_check.main(['--root', tmp, '--check-storage']), expected)
                    process.assert_not_called()
                self.assertFalse((Path(tmp)/'notification-ledger.json').exists())

    def test_post_collection_encryption_failure_is_not_reported_as_preflight(self):
        import contextlib
        import functools
        import io
        from unittest.mock import patch
        import synthetic_encryption
        from secure_store import EncryptionError

        real_run = daily_check.run
        for failed_write in (1, 2, 3):
            with self.subTest(failed_write=failed_write), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                calls = []
                def collector():
                    calls.append(True)
                    return {'entries': [], 'errors': [], 'coverage': {'SYNTHETIC': True}}
                def store_factory(state):
                    store = synthetic_encryption.store(state)
                    real_write = store.write
                    writes = []
                    def write(path, value):
                        writes.append(path)
                        if len(writes) == failed_write:
                            raise EncryptionError('SYNTHETIC_PRIVATE_FAILURE')
                        real_write(path, value)
                    store.write = write
                    return store
                counts = dict.fromkeys(daily_check.notifications.FIELDS, 0)
                output = io.StringIO()
                with patch.object(daily_check, 'EncryptedStore', side_effect=store_factory), \
                     patch.object(daily_check, 'evaluate', return_value=([], {}, counts, [], {})), \
                     patch.object(daily_check, 'run', side_effect=functools.partial(real_run, collector=collector)), \
                     contextlib.redirect_stdout(output):
                    self.assertEqual(daily_check.main(['--root', tmp]), 20)
                self.assertEqual(calls, [True])
                self.assertNotIn('no collection performed', output.getvalue())
                self.assertNotIn('SYNTHETIC_PRIVATE_FAILURE', output.getvalue())
                self.assertNotIn(tmp, output.getvalue())
                self.assertIn('evidence may be incomplete', output.getvalue())
                self.assertEqual(len(list((root/'snapshots').glob('*.gpg'))), int(failed_write > 1))
                ledger = json.loads((root/'notification-ledger.json').read_text())
                self.assertEqual(len(ledger['events']), 1)
                self.assertIn('errors=1', next(iter(ledger['events'].values()))['body'])

    def test_normal_daily_failures_still_deliver_sanitized_notifications(self):
        import contextlib
        import functools
        import io
        from unittest.mock import patch
        from secure_store import EncryptionError
        import notifications

        real_process = notifications.process
        def delivered(target, body):
            self.assertIn('errors=1', body)
            self.assertNotIn('SYNTHETIC_PRIVATE_FAILURE', body)
            return {'success': True}
        for failure, expected in [(EncryptionError('SYNTHETIC_PRIVATE_FAILURE'), 4),
                                  (RuntimeError('SYNTHETIC_PRIVATE_FAILURE'), 20)]:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                with patch.object(daily_check, 'EncryptedStore', side_effect=failure), \
                     patch.object(notifications, 'URGENT', 'synthetic:urgent'), \
                     patch.object(notifications, 'ROUTINE', 'synthetic:routine'), \
                     patch.object(notifications, 'process', side_effect=functools.partial(real_process, mode='live', sender=delivered)) as process, \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(daily_check.main(['--root', tmp]), expected)
                    process.assert_called_once()
                ledger = json.loads((Path(tmp)/'notification-ledger.json').read_text())
                self.assertEqual(next(iter(ledger['events'].values()))['state'], 'delivered')

    def test_missing_recipient_blocks_before_collection(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            called = []
            with self.assertRaises(StorageError):
                daily_check.run(Path(tmp), collector=lambda: called.append(True))
            self.assertEqual(called, [])
            self.assertFalse(list(Path(tmp).glob('snapshots/*')))

    def test_unexpected_scanner_error_is_sanitized(self):
        import contextlib,io
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            output=io.StringIO()
            with patch.object(daily_check,'run',side_effect=RuntimeError('SYNTHETIC_PRIVATE_IDENTITY')),contextlib.redirect_stdout(output):
                self.assertEqual(daily_check.main(['--root',tmp]),20)
            self.assertNotIn('SYNTHETIC_PRIVATE_IDENTITY',output.getvalue())
            self.assertIn('RuntimeError',output.getvalue())

    def test_secret_key_export_is_rejected_as_recipient(self):
        import secure_store,synthetic_encryption as synthetic
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp);recipient=root/'recipient.gpg'
            secret=subprocess.run(['/usr/bin/gpg','--homedir',str(synthetic.keyhome),'--batch','--export-secret-keys'],capture_output=True,check=True).stdout
            recipient.write_bytes(secret);recipient.chmod(0o600)
            synthetic.policy(root, secret)
            with self.assertRaises(secure_store.EncryptionError):
                secure_store.EncryptedStore(root,recipient=recipient)

    def test_gate_failure_stages_one_sanitized_urgent_event(self):
        import contextlib,io
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(daily_check.main(['--root',tmp]),4)
                self.assertEqual(daily_check.main(['--root',tmp]),4)
            ledger=json.loads((Path(tmp)/'notification-ledger.json').read_text())
            self.assertEqual(len(ledger['events']),1)
            event=next(iter(ledger['events'].values()))
            self.assertEqual(event['target'],'disabled:urgent')
            self.assertNotIn(tmp,event['body'])

    def test_storage_cli_has_explicit_fail_closed_preflight(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            result=subprocess.run(['/usr/bin/python3','-B','-I','-S',str(Path(daily_check.__file__)),'--root',tmp,'--check-storage'],capture_output=True,text=True)
            self.assertEqual(result.returncode,4)
            self.assertIn('encryption recipient',result.stdout)
            self.assertNotIn(tmp,result.stdout+result.stderr)

    def test_gpg_ciphertext_roundtrip_and_no_plaintext(self):
        import secure_store
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            home = root/'synthetic-keys'; home.mkdir(mode=0o700)
            subprocess.run(['/usr/bin/gpg','--homedir',str(home),'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','SYNTHETIC test','rsa2048','encr','1d'],check=True,capture_output=True)
            pub = subprocess.run(['/usr/bin/gpg','--homedir',str(home),'--batch','--export'],check=True,capture_output=True).stdout
            recipient = root/'recipient.gpg'; recipient.write_bytes(pub); recipient.chmod(0o600)
            from synthetic_encryption import policy
            policy(root, pub)
            store = secure_store.EncryptedStore(root, recipient=recipient)
            marker = 'SYNTHETIC-private-identity-version'
            store.write(root/'report.json.gpg', {'marker':marker})
            ciphertext = (root/'report.json.gpg').read_bytes()
            self.assertNotIn(marker.encode(),ciphertext)
            plain = subprocess.run(['/usr/bin/gpg','--homedir',str(home),'--batch','--decrypt',str(root/'report.json.gpg')],capture_output=True,check=True).stdout
            self.assertEqual(json.loads(plain),{'marker':marker})
            self.assertEqual((root/'report.json.gpg').stat().st_mode & 0o777,0o600)
            self.assertFalse(list(root.glob('.encrypt-*')))
            subprocess.run(['/usr/bin/gpgconf','--homedir',str(home),'--kill','gpg-agent'],capture_output=True)

if __name__ == '__main__': unittest.main()
