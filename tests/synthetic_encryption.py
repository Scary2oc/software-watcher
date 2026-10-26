"""Disposable public encryption recipient for tests; never used operationally."""
import atexit
import os
from pathlib import Path
import subprocess
import tempfile
import gzip
import json
import datetime as dt
import hashlib
from watcher import dump
from secure_store import EncryptedStore

_home=tempfile.TemporaryDirectory(prefix='SYNTHETIC-gpg-',dir=os.environ.get('TMPDIR'))
keyhome=Path(_home.name)
subprocess.run(['/usr/bin/gpg','--homedir',str(keyhome),'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','SYNTHETIC daily fixture','rsa2048','encr','1d'],capture_output=True,check=True)
_public=subprocess.run(['/usr/bin/gpg','--homedir',str(keyhome),'--batch','--export'],capture_output=True,check=True).stdout

def policy(root, public):
    dump(Path(root)/'storage-policy.json', {'mode':'gpg-public-recipient',
                                          'recipient_sha256':hashlib.sha256(public).hexdigest()})


def store(root):
    recipient=Path(root)/'recipient.gpg'
    recipient.write_bytes(_public);recipient.chmod(0o600)
    policy(root, _public)
    return EncryptedStore(root,recipient=recipient)

def extra(root,source):
    if source not in ('EPSS','NVD'):return None
    root=Path(root);root.mkdir(mode=0o700,exist_ok=True)
    today=dt.datetime.now(dt.timezone.utc).date().isoformat()
    data=('#score_date:'+today+'\ncve,epss,percentile\nCVE-2099-00001,0.9,0.99\n').encode() if source=='EPSS' else json.dumps({'timestamp':today+'T00:00:00Z','vulnerabilities':[{'cve':{'id':'CVE-2099-00001'}}]}).encode()
    target=root/(source+'.gz');target.write_bytes(gzip.compress(data));target.chmod(0o600)
    return {'usable':True,'stale':False,'errors':[],'path':str(target),'download_bytes':0}

def cleanup():
    subprocess.run(['/usr/bin/gpgconf','--homedir',str(keyhome),'--kill','gpg-agent'],capture_output=True)
    _home.cleanup()
atexit.register(cleanup)
