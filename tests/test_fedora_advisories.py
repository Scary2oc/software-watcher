import os
from pathlib import Path
import tempfile
import unittest

class FedoraTests(unittest.TestCase):
    def test_public_bulk_metadata_and_checksum_no_inventory_request(self):
        import fedora_advisories as f
        import gzip,hashlib
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp)
            raw=b'<updates><update type="security"><id>FEDORA-SYNTHETIC</id><references><reference type="cve" id="CVE-2099-00001"/></references><pkglist><collection><package name="synthetic" arch="x86_64" epoch="1" version="2.0" release="3.fc44"/></collection></pkglist></update></updates>'
            body=gzip.compress(raw); sha=hashlib.sha256(body).hexdigest()
            artifact=root/'public.xml.gz';artifact.write_bytes(body)
            meta=root/'repomd.xml';meta.write_text('<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="updateinfo"><checksum type="sha256">'+sha+'</checksum><location href="repodata/'+sha+'-updateinfo.xml.gz"/></data></repomd>')
            requested=[]
            def fetch(cache,source,**kwargs):
                requested.append((source,kwargs))
                return {'usable':True,'stale':False,'errors':[],'path':str(artifact if kwargs.get('artifact') else meta)}
            rows,feed=f.refresh_public(root,fetcher=fetch)
            self.assertTrue(feed['usable'])
            self.assertEqual(len(rows),1) # deduplicated across fixed public releases
            self.assertTrue(all('synthetic' not in str(item) for item in requested))
            meta.write_text(meta.read_text().replace('.xml.gz','.xml.zst'))
            rows,feed=f.refresh_public(root,fetcher=fetch)
            self.assertFalse(feed['usable'])
            self.assertTrue(feed['errors'])
            meta.write_text(meta.read_text().replace('.xml.zst','.xml.gz'))
            artifact.write_bytes(b'corrupt')
            rows,feed=f.refresh_public(root,fetcher=fetch)
            self.assertFalse(feed['usable'])
            self.assertTrue(feed['errors'])

    def test_parallel_rpm_builds_use_system_evr_comparison(self):
        import fedora_advisories as f
        import inventory
        import vulnerabilities
        if f.rpm is None:
            self.skipTest('system RPM bindings required; exercised in Fedora CI')
        rows = inventory.parse_rpm(''.join(
            'SYNTHETIC\t' + version + '\tx86_64\tFedora Project\n'
            for version in ('0:2.0-3.fc44', '0:2.0-4.fc44', '1:2.0-4.fc44')))
        advisories = f.parse_updateinfo(
            b'<updates><update type="security"><id>FEDORA-SYNTHETIC</id>'
            b'<references><reference type="cve" id="CVE-2099-00001"/></references>'
            b'<pkglist><collection><package name="SYNTHETIC" arch="x86_64" '
            b'epoch="0" version="2.0" release="4.fc44"/></collection></pkglist>'
            b'</update></updates>')
        findings = [f.assess(row, advisories, fresh=True)
                    for row in vulnerabilities.assess(rows, {}, {}, set())]
        self.assertEqual([row['version'] for row in findings], [row['version'] for row in rows])
        self.assertEqual([row['status'] for row in findings], ['affected', 'not affected', 'not affected'])
        self.assertEqual(len({inventory.identity(row) for row in findings}), 3)

    def test_rpm_backports_epoch_and_unknown_are_not_upstream_guesses(self):
        import fedora_advisories as f
        entry={'ecosystem':'RPM','name':'synthetic','version':'1:2.0-4.fc44','source':'RPM:synthetic|x86_64','vendor':'Fedora Project'}
        advisory={'name':'synthetic','arch':'x86_64','fixed':'1:2.0-3.fc44','id':'FEDORA-SYNTHETIC','aliases':['CVE-2099-00001']}
        row=f.assess(entry,[advisory],fresh=True,kev={'CVE-2099-00001'})
        self.assertEqual(row['status'],'not affected')
        other_release=dict(advisory,fixed='1:2.0-9.fc43')
        self.assertEqual(f.assess(entry,[advisory,other_release],fresh=True)['status'],'not affected')
        entry['version']='0:9.0-9.fc44' # epoch dominates upstream version
        row=f.assess(entry,[advisory],fresh=True,kev={'CVE-2099-00001'})
        self.assertEqual(row['status'],'affected')
        self.assertTrue(row['matches'][0]['kev'])
        entry['vendor']='Unknown Vendor'
        self.assertEqual(f.assess(entry,[advisory],fresh=True)['status'],'unassessed')
        entry['vendor']='Fedora Project'
        self.assertEqual(f.assess(entry,[],fresh=True)['status'],'unassessed')
        self.assertEqual(f.assess(entry,[dict(advisory,fixed='bad')],fresh=True)['status'],'needs investigation')
        entry['version']='1:2.0-4.fc44'
        self.assertEqual(f.assess(entry,[advisory],fresh=False)['status'],'needs investigation')
        self.assertLess(f.compare('0:1.0~rc1-1.fc44','0:1.0-1.fc44'),0)
        self.assertGreater(f.compare('0:1.0^git1-1.fc44','0:1.0-1.fc44'),0)

if __name__=='__main__':unittest.main()
