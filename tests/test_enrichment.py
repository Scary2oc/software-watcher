import datetime as dt
import gzip
import json
import os
from pathlib import Path
import tempfile
import unittest

class EnrichmentTests(unittest.TestCase):
    def test_bulk_cve_join_never_changes_affectedness(self):
        import enrichment as e
        today=dt.date.today().isoformat()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp)
            ep=root/'epss.gz'; ep.write_bytes(gzip.compress(('#model_version:vTEST,score_date:'+today+'\ncve,epss,percentile\nCVE-2099-00001,0.9,0.99\n').encode()))
            nv=root/'nvd.gz'; nv.write_bytes(gzip.compress(json.dumps({'timestamp':today+'T00:00:00Z','vulnerabilities':[{'cve':{'id':'CVE-2099-00001','vulnStatus':'Analyzed','configurations':[{'nodes':[]}],'metrics':{}}}]}).encode()))
            findings=[{'status':'affected','matches':[{'aliases':['CVE-2099-00001']}]}]
            feeds={k:{'usable':True,'stale':False,'errors':[],'path':str(p)} for k,p in [('EPSS',ep),('NVD',nv)]}
            counts=e.enrich(findings,feeds)
            self.assertEqual(findings[0]['status'],'affected')
            match=findings[0]['matches'][0]
            self.assertEqual(match['epss'][0]['probability'],0.9)
            self.assertEqual(match['nvd'][0]['scope'],'supplemental CVE/product evidence only; not affectedness')
            self.assertEqual(counts['epss_joined_matches'],1)
            self.assertEqual(counts['nvd_joined_matches'],1)
            feeds['EPSS']['stale']=True
            e.enrich(findings,feeds)
            self.assertFalse(findings[0]['matches'][0]['epss'][0]['fresh'])
            ep.write_bytes(gzip.compress(b'#score_date:2001-01-01\ncve,epss,percentile\nCVE-2099-00001,NaN,1\n'))
            e.enrich(findings,feeds)
            self.assertTrue(feeds['EPSS']['errors'])
            self.assertEqual(findings[0]['status'],'affected')

if __name__=='__main__':unittest.main()
