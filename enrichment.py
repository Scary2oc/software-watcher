"""Local CVE-alias enrichment from bounded public bulk EPSS/NVD feeds.

EPSS estimates exploitation probability, not applicability. NVD product/CPE data
are supplemental evidence, never fuzzy confirmation. NVD modified is an eight-day
window, NOT a historical mirror; missing CVEs remain explicitly unknown.
"""
import csv
import datetime as dt
import gzip
import io
import json
import math
from pathlib import Path
import re

CVE=re.compile(r'CVE-\d{4}-\d{4,}')
CAP=256*1024**2


def expand(path,cap=CAP):
    with gzip.open(path,'rb') as stream: data=stream.read(cap+1)
    if len(data)>cap:raise ValueError('bulk decompression cap')
    return data


def epss(path, wanted):
    data=expand(path,128*1024**2).decode('utf-8')
    lines=data.splitlines()
    if not lines or not lines[0].startswith('#'):raise ValueError('EPSS metadata required')
    date=re.search(r'score_date:(\d{4}-\d{2}-\d{2})',lines[0])
    if not date:raise ValueError('EPSS date required')
    age=(dt.datetime.now(dt.timezone.utc).date()-dt.date.fromisoformat(date[1])).days
    index={}; total=0
    for row in csv.DictReader(lines[1:]):
        total+=1
        if total>1000000:raise ValueError('EPSS row cap')
        if not CVE.fullmatch(row['cve']):raise ValueError('EPSS identity')
        probability=float(row['epss']); percentile=float(row['percentile'])
        if not all(math.isfinite(x) and 0<=x<=1 for x in (probability,percentile)):raise ValueError('EPSS probability')
        if row['cve'] in wanted:index[row['cve']]={'cve':row['cve'],'probability':probability,'percentile':percentile,'score_date':date[1]}
    if not total:raise ValueError('empty EPSS')
    return index,total,0<=age<=2


def nvd(path,wanted):
    data=json.loads(expand(path))
    records=data['vulnerabilities']
    if not isinstance(records,list) or not records or len(records)>100000:raise ValueError('NVD row cap/empty')
    timestamp=dt.datetime.fromisoformat(data['timestamp'].replace('Z','+00:00'))
    if timestamp.tzinfo is None:timestamp=timestamp.replace(tzinfo=dt.timezone.utc)
    age=(dt.datetime.now(dt.timezone.utc)-timestamp).total_seconds()/86400
    index={}
    for record in records:
        cve=record['cve']; identity=cve['id']
        if not CVE.fullmatch(identity):raise ValueError('NVD identity')
        if identity in wanted:
            index[identity]={'cve':identity,'status':cve.get('vulnStatus','Unknown'),
                'configurations':cve.get('configurations',[]),'metrics':cve.get('metrics',{}),
                'last_modified':cve.get('lastModified'),
                'scope':'supplemental CVE/product evidence only; not affectedness'}
    return index,len(records),-1<=age<=2


def enrich(findings,feeds):
    wanted={alias for row in findings for match in row['matches'] for alias in match.get('aliases',[]) if CVE.fullmatch(alias)}
    indexes={}; counts={}
    for source,parser in [('EPSS',epss),('NVD',nvd)]:
        feed=feeds.get(source,{})
        indexes[source]={}
        if feed.get('usable'):
            try:
                index,total,fresh=parser(Path(feed['path']),wanted)
                feed['records']=total; indexes[source]=index
                if not fresh:
                    feed['stale']=True;feed['errors'].append({'source':source,'error':'dataset publication stale/unknown'})
            except (OSError,ValueError,KeyError,TypeError,OverflowError,EOFError,csv.Error):
                feed['usable']=False
                feed.setdefault('errors',[]).append({'source':source,'error':'invalid bounded bulk dataset'})
        joined=0; missing=0
        for row in findings:
            for match in row['matches']:
                aliases={x for x in match.get('aliases',[]) if CVE.fullmatch(x)}
                matches=[dict(indexes[source][x],fresh=not(feed.get('stale') or feed.get('errors'))) for x in sorted(aliases & indexes[source].keys())]
                match[source.lower()]=matches
                joined+=bool(matches);missing+=bool(aliases) and not matches
        counts[source.lower()+'_joined_matches']=joined
        counts[source.lower()+'_missing_matches']=missing
    counts['nvd_scope']='modified eight-day window only; no historical clearance'
    return counts
