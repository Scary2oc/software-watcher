import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class NotificationTests(unittest.TestCase):
    def setUp(self):
        import notifications as n
        for name, value in [('URGENT','telegram:SYNTHETIC_URGENT'),
                            ('ROUTINE','slack:SYNTHETIC_ROUTINE'),
                            ('HERMES_PYTHON',Path('/SYNTHETIC/venv/bin/python')),
                            ('HERMES_HOME',Path('/SYNTHETIC/hermes-profile'))]:
            p=patch.object(n,name,value);p.start();self.addCleanup(p.stop)

    def report(self, affected=1, kev=0, errors=0):
        return {'counts':{'assessed':2,'affected':affected,'kev_flagged':kev,'unassessed':3,'needs_investigation':1,'errors':errors},
                'findings':[{'name':'SYNTHETIC-PRIVATE','version':'SECRET-version','status':'affected','source':'/SYNTHETIC/private','matches':[{'id':'SYNTHETIC-ID','kev':['CVE-2099-00001'] if kev else []}]}],
                'fingerprint':str((affected,kev,errors)), 'coverage':{'limitations':['SYNTHETIC']}}

    def test_baseline_silent_changes_retry_dedupe_and_sanitized_transport(self):
        import notifications as n
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp);sent=[]
            def fail(target,text):sent.append((target,text));raise OSError('SYNTHETIC private token')
            self.assertEqual(n.process(root,self.report(),sender=fail,mode='live')['pending'],0)
            result=n.process(root,self.report(kev=1),sender=fail,mode='live')
            self.assertEqual(result['pending'],1)
            def success(target,text):sent.append((target,text));return {'success':True,'message_id':'SYNTHETIC-handle'}
            result=n.process(root,self.report(kev=1),sender=success,mode='live')
            self.assertEqual(result['pending'],0)
            self.assertEqual(result['delivered'],1)
            n.process(root,self.report(kev=1),sender=success,mode='live')
            self.assertEqual(len(sent),2)
            self.assertTrue(all(t=='telegram:SYNTHETIC_URGENT' for t,_ in sent))
            self.assertTrue(all('PRIVATE' not in text and 'SECRET' not in text and '/SYNTHETIC' not in text for _,text in sent))
            result=n.process(root,self.report(affected=2,kev=1),sender=success,mode='dry-run')
            self.assertEqual(result['pending'],1)
            self.assertEqual(len(sent),2)
            result=n.process(root,self.report(affected=2,kev=1),sender=success,mode='live')
            self.assertEqual(sent[-1][0],'slack:SYNTHETIC_ROUTINE')

    def test_missing_success_receipt_is_ambiguous_not_blind_retry(self):
        import notifications as n
        import subprocess
        with patch.object(n.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'not-json','')):
            with self.assertRaises(n.AmbiguousDelivery):n.cli_sender(n.ROUTINE,n.text(self.report()['counts'],'report'))

    def test_new_kev_mapping_alerts_even_when_aggregate_counts_are_equal(self):
        import notifications as n
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp);sent=[]
            send=lambda *args:(sent.append(args) or {'success':True})
            n.process(root,self.report(),sender=send,mode='live')
            n.process(root,self.report(kev=1),sender=send,mode='live')
            report=self.report(kev=1)
            report['findings'][0]['matches'][0]['kev']=['CVE-2099-00002']
            n.process(root,report,sender=send,mode='live')
            self.assertEqual(len(sent),2)

    def test_transport_uses_only_sanitized_stdin_and_keeps_no_diagnostics(self):
        import notifications as n
        import subprocess,json
        body=n.text(self.report()['counts'],'report')
        result=subprocess.CompletedProcess([],0,json.dumps({'success':True,'message_id':'12345','untrusted':'SECRET'}),'SECRET')
        with patch.object(n.subprocess,'run',return_value=result) as run:
            receipt=n.cli_sender(n.ROUTINE,body)
        self.assertEqual(receipt['message_id'],'12345')
        self.assertFalse(receipt['readback_verified'])
        self.assertNotIn('SECRET',json.dumps(receipt))
        args,kwargs=run.call_args
        self.assertNotIn(body,str(args))
        self.assertEqual(kwargs['input'],body)
        self.assertTrue(kwargs['capture_output'])
        self.assertNotIn('TOKEN',str(kwargs['env']))

    def test_transport_bypasses_mutating_installer_with_isolated_existing_runtime(self):
        import notifications as n
        import subprocess,json
        result=subprocess.CompletedProcess([],0,json.dumps({'success':True,'message_id':'12345'}),'')
        with patch.object(n.subprocess,'run',return_value=result) as run:
            n.cli_sender(n.ROUTINE,'SANITIZED software-check deployment test: SYNTHETIC, no real findings.')
        command=run.call_args.args[0]
        self.assertTrue(command[0].endswith('/venv/bin/python'))
        self.assertNotIn(str(Path.home()/'.local/bin/hermes'),command)
        self.assertEqual(command[1:3],['-I','-B'])
        self.assertEqual(Path(command[3]).name,'hermes_send.py')
        self.assertEqual(command[4:],['send','--to',n.ROUTINE,'--json','--file','-'])

    def test_missing_pinned_runtime_fails_without_installer_fallback(self):
        import notifications as n
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            with patch.object(n,'HERMES_PYTHON',Path(tmp)/'missing/venv/bin/python'):
                with self.assertRaises(FileNotFoundError):
                    n.cli_sender(n.ROUTINE,'SANITIZED software-check deployment test: SYNTHETIC, no real findings.')

    def test_thin_entrypoint_delegates_to_upstream_parser_and_handler(self):
        # A synthetic upstream module exercises the wrapper contract without any
        # Hermes installation, credential loader, or external transport.
        import argparse, runpy, sys, types
        package=types.ModuleType('hermes_cli')
        upstream=types.ModuleType('hermes_cli.send_cmd')
        calls=[]
        def register(subparsers):
            command=subparsers.add_parser('send')
            command.add_argument('--to')
            command.add_argument('--json',action='store_true')
            command.add_argument('--file')
            command.set_defaults(func=lambda args:calls.append((args.to,args.file,args.json)))
        upstream.register_send_subparser=register
        with patch.dict(sys.modules,{'hermes_cli':package,'hermes_cli.send_cmd':upstream}), patch.object(sys,'argv',['hermes_send.py','send','--to','slack:SYNTHETIC_ROUTINE','--json','--file','-']):
            runpy.run_path(str(Path(__file__).resolve().parent.parent/'hermes_send.py'),run_name='__main__')
        self.assertEqual(calls,[('slack:SYNTHETIC_ROUTINE','-',True)])

    def test_resolved_failure_is_not_replayed_on_first_real_baseline(self):
        import notifications as n
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp)
            n.process(root,{'counts':self.report(errors=1)['counts']},mode='dry-run')
            called=[]
            result=n.process(root,self.report(kev=1),mode='live',sender=lambda *args:(called.append(args) or {'success':True}))
            self.assertEqual(called,[])
            self.assertEqual(result['pending'],0)

    def test_pending_reports_coalesce_instead_of_replay_flood(self):
        import notifications as n
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp)
            n.process(root,self.report(),mode='dry-run')
            for count in (2,3,4):n.process(root,self.report(affected=count),mode='dry-run')
            sent=[]
            result=n.process(root,self.report(affected=4),mode='live',sender=lambda t,b:(sent.append(b) or {'success':True}))
            self.assertEqual(len(sent),1)
            self.assertIn('affected=4',sent[0])

    def test_first_error_alert_and_ambiguous_crash_not_replayed(self):
        import notifications as n
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp)
            def crash(target,text):raise KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):n.process(root,self.report(errors=1),sender=crash,mode='live')
            called=[]
            result=n.process(root,self.report(errors=1),sender=lambda *a:called.append(a),mode='live')
            self.assertEqual(called,[])
            self.assertEqual(result['ambiguous'],1)

if __name__=='__main__':unittest.main()
