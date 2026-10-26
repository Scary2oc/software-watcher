"""Deterministic sanitized notifications through existing `hermes send`, no LLM.

Daily mode defaults to dry-run until owner provisions notification-policy.json.
No tokens/config are read here. The established CLI resolves its own credentials.
Interrupted/timeout sends are ambiguous and require owner receipt reconciliation,
not blind resend. Explicit failures retry on the next invocation (at most once
per event per run). There is no claim of atomic exactly-once external delivery.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from watcher import dump,load

URGENT=os.environ.get('SOFTWARE_WATCHER_URGENT_TARGET', 'disabled:urgent')
ROUTINE=os.environ.get('SOFTWARE_WATCHER_ROUTINE_TARGET', 'disabled:routine')
FIELDS=('assessed','affected','kev_flagged','unassessed','needs_investigation','errors')
# Explicit existing runtime only; never discover, install or repair a runtime.
_runtime=os.environ.get('SOFTWARE_WATCHER_HERMES_PYTHON')
_profile=os.environ.get('SOFTWARE_WATCHER_HERMES_HOME')
HERMES_PYTHON=Path(_runtime) if _runtime else None
HERMES_HOME=Path(_profile) if _profile else None


class AmbiguousDelivery(Exception):
    pass


def digest(data):return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()


def text(counts,event):
    if event not in ('urgent','report'):raise ValueError('invalid event')
    values={k:counts.get(k,0) for k in FIELDS}
    if not all(type(v) is int and 0<=v<10000000 for v in values.values()):raise ValueError('invalid aggregate')
    return 'SANITIZED software-check '+event+': '+' '.join(k+'='+str(v) for k,v in values.items())+'; metadata-entry counts, not unique CVEs or proof of exploitability. Review private evidence locally.'


def cli_sender(target,body):
    if target not in (URGENT,ROUTINE) or target.startswith('disabled:') or not body.startswith('SANITIZED software-check '):raise ValueError('transport refused')
    if not HERMES_PYTHON or not HERMES_PYTHON.is_absolute() or not HERMES_HOME or not HERMES_HOME.is_absolute():
        raise ValueError('explicit existing Hermes interpreter and profile required')
    env={'PATH':'/usr/bin:/bin','HOME':str(Path.home()),'LC_ALL':'C',
         'HERMES_HOME':str(HERMES_HOME),'PYTHONDONTWRITEBYTECODE':'1'}
    # Owner explicitly provisions and reviews the isolated delivery route.
    # Suppress all raw CLI output: it may contain adapter diagnostics/credentials.
    result=subprocess.run([str(HERMES_PYTHON),'-I','-B',str(Path(__file__).with_name('hermes_send.py')),
                           'send','--to',target,'--json','--file','-'],
                          input=body,text=True,capture_output=True,timeout=60,env=env)
    try:payload=json.loads(result.stdout)
    except ValueError:raise AmbiguousDelivery('delivery receipt unavailable') from None
    if result.returncode or payload.get('error') or not payload.get('success') or payload.get('skipped'):
        raise OSError('delivery failed')
    handle=payload.get('message_id')
    # Never save arbitrary raw response objects or backend diagnostics.
    return {'success':True,'message_id':str(handle) if handle is not None and re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}',str(handle)) else None,
            'readback_verified':False}


def process(root,report,sender=cli_sender,mode=None):
    root=Path(root)
    mode=mode or load(root/'notification-policy.json',{}).get('mode','dry-run')
    if mode not in ('live','dry-run','disabled'):raise ValueError('invalid notification mode')
    if mode=='live' and any(not re.fullmatch(r'[a-z][a-z0-9_-]*:[A-Za-z0-9_.:-]{1,160}', target) or target.startswith('disabled:') for target in (URGENT,ROUTINE)):
        raise ValueError('explicit notification destinations required')
    path=root/'notification-ledger.json'
    ledger=load(path,{'initialized':False,'events':{},'kev_handles':[]})
    counts=report['counts'];safe=text(counts,'report')
    if not counts.get('errors'):
        for event in ledger['events'].values():
            if event['state']=='pending' and event.get('reason')=='scanner-failure':
                event['state']='superseded'
    kev=sorted({digest([row.get('source'),m.get('id'),m.get('kev')]) for row in report.get('findings',[]) for m in row.get('matches',[]) if m.get('kev')})
    # EPSS score drift and changing source clocks cannot generate daily chatter.
    key=digest({'counts':counts,'inventory':report.get('inventory_fingerprint'),
                'affected':sorted(digest([r.get('source'),m.get('id')]) for r in report.get('findings',[]) for m in r.get('matches',[]))})
    urgent=bool(counts.get('errors')) or ledger['initialized'] and bool(set(kev)-set(ledger['kev_handles']))
    meaningful=ledger['initialized'] and key!=ledger.get('last_key')
    if urgent or meaningful:
        target=URGENT if urgent else ROUTINE
        event_id=digest([target,key,kev if urgent else []])
        # Coalesce unsent historical reports per destination; never flood an
        # owner with every missed daily baseline when transport recovers.
        for old_id,event in ledger['events'].items():
            if old_id!=event_id and event['target']==target and event['state']=='pending':
                event['state']='superseded'
        ledger['events'].setdefault(event_id,{'target':target,'body':text(counts,'urgent' if urgent else 'report'),'state':'pending','attempts':0,
            'reason':'scanner-failure' if counts.get('errors') else 'new-kev' if urgent else 'meaningful-change'})
    ledger.update(initialized=ledger['initialized'] or 'findings' in report,kev_handles=kev,last_key=key)
    dump(path,ledger) # persist pending intent BEFORE transport
    delivered=0
    for event in ledger['events'].values():
        if event['state']!='pending' or mode!='live':continue
        event['state']='sending';event['attempts']+=1;dump(path,ledger)
        try:
            receipt=sender(event['target'],event['body'])
            if not receipt or not receipt.get('success'):raise OSError('delivery failed')
            event.update(state='delivered',receipt=receipt);delivered+=1
        except (subprocess.TimeoutExpired,AmbiguousDelivery):
            # The platform may have accepted it. Do not cause replay floods.
            event['state']='ambiguous'
        except (OSError,ValueError):
            event['state']='pending'
        dump(path,ledger)
    states=[x['state'] for x in ledger['events'].values()]
    return {'mode':mode,'pending':states.count('pending'),'ambiguous':states.count('sending')+states.count('ambiguous'),'delivered':delivered}
