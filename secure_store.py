"""GnuPG public-recipient envelopes; no plaintext sensitive staging files.

The owner's approved public recipient must be provisioned separately. No secret
key is generated/stored by production code. No decryption/unlock is needed daily.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid
from watcher import StorageError, load, mkdir


class EncryptionError(StorageError):
    pass


class EncryptedStore:
    def __init__(self, root, recipient=None):
        self.root = Path(root)
        policy = load(self.root/'storage-policy.json', {})
        self.recipient = Path(recipient or self.root/'recipient.gpg')
        if self.recipient.parent != self.root or self.recipient.is_symlink() or not self.recipient.is_file():
            raise EncryptionError('approved public recipient missing')
        if self.recipient.stat().st_size > 1024**2 or self.recipient.stat().st_mode & 0o077:
            raise EncryptionError('unsafe public recipient')
        actual = hashlib.sha256(self.recipient.read_bytes()).hexdigest()
        if policy.get('mode') != 'gpg-public-recipient' or policy.get('recipient_sha256') != actual:
            raise EncryptionError('public recipient policy missing or changed')
        # A real encryption probe verifies availability/capability before collection.
        self.encrypt(b'SYNTHETIC software-check encryption preflight')

    def encrypt(self, payload):
        try:
            result = subprocess.run(['/usr/bin/gpg','--batch','--no-options','--no-autostart',
                '--no-auto-key-retrieve','--trust-model','always','--compress-algo','none',
                '--recipient-file',str(self.recipient),'--encrypt','--output','-'],
                input=payload,capture_output=True,timeout=45,
                env={'PATH':'/usr/bin:/bin','HOME':str(Path.home()),'LC_ALL':'C'})
            if result.returncode or not result.stdout:
                raise EncryptionError('public recipient encryption unavailable')
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            raise EncryptionError('public recipient encryption unavailable') from None

    def write(self, path, value):
        path = Path(path)
        if not path.name.endswith('.gpg') or self.root not in path.parents:
            raise StorageError('ciphertext target required')
        ciphertext = self.encrypt(json.dumps(value,sort_keys=True).encode())
        mkdir(path.parent)
        temp = path.parent/('.encrypt-'+uuid.uuid4().hex)
        try:
            fd = os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as out:
                out.write(ciphertext); out.flush(); os.fsync(out.fileno())
            os.replace(temp,path)
            fd = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            if temp.exists(): temp.unlink()
