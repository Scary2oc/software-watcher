"""Fedora vendor build evidence from bounded public feeds or local DNF cache.

Cache mtime is NOT proof of a successful repository refresh. This adapter reports
publication/revalidation freshness unknown and never clears packages with absent
advisories. Only Fedora Project RPMs and matching Fedora release/arch are joined.
"""
import hashlib
import io
from pathlib import Path
import re
import time
import xml.etree.ElementTree as ET
import public_feeds
try:
    from compression import zstd
    ZstdError = zstd.ZstdError
except ImportError:
    ZstdError = ValueError
try:
    import rpm
except ImportError:
    rpm = None

CAP = 256*1024**2


def parse_updateinfo(data):
    if len(data)>CAP or b'<!DOCTYPE' in data or b'<!ENTITY' in data:raise ValueError('XML expansion/DTD bound')
    document=ET.fromstring(data)
    if len(document)>100000:raise ValueError('advisory member bound')
    rows=[]
    for update in document:
        identity=update.findtext('id','')
        if not identity.startswith('FEDORA-') or update.get('type')!='security':continue
        aliases=[ref.get('id') for ref in update.findall('references/reference') if ref.get('type')=='cve' and re.fullmatch(r'CVE-\d{4}-\d{4,}',ref.get('id',''))]
        for package in update.findall('pkglist/collection/package'):
            a=package.attrib
            rows.append({'id':identity,'aliases':aliases,'name':a['name'],'arch':a['arch'],
                         'fixed':a.get('epoch','0')+':'+a['version']+'-'+a['release']})
    return rows


def refresh_public(cache,fetcher=public_feeds.refresh):
    # Constant public release feeds, NOT derived from installed inventory. All
    # clients fetch both; no package, installed EVR, or local path enters HTTP.
    rows=[];sources={};errors=[];seen=set()
    for release in ('43','44'):
        source='Fedora'+release
        metadata=fetcher(cache,source);sources[source+'-metadata']=metadata
        errors.extend(metadata['errors'])
        if not metadata['usable']:continue
        try:
            data=Path(metadata['path']).read_bytes()
            if len(data)>1024**2 or b'<!DOCTYPE' in data or b'<!ENTITY' in data:raise ValueError('repomd bound/DTD')
            root=ET.fromstring(data);ns={'r':'http://linux.duke.edu/metadata/repo'}
            node=next(n for n in root.findall('r:data',ns) if n.get('type')=='updateinfo')
            location=node.find('r:location',ns).get('href')
            check=node.find('r:checksum',ns)
            if check.get('type')!='sha256' or not re.fullmatch(r'repodata/[0-9a-f]{64}-updateinfo\.xml\.(gz|zst)',location):raise ValueError('artifact allowlist')
            feed=fetcher(cache,source,artifact=location);sources[source+'-updateinfo']=feed
            errors.extend(feed['errors'])
            if not feed['usable']:continue
            path=Path(feed['path'])
            if path.stat().st_size>32*1024**2 or public_feeds.digest(path)!=check.text:raise ValueError('vendor metadata checksum')
            if location.endswith('.gz'):
                import gzip
                stream=gzip.open(path,'rb')
            else:
                from compression import zstd
                stream=zstd.open(path,'rb')
            with stream:data=stream.read(CAP+1)
            for row in parse_updateinfo(data):
                key=json_key(row)
                if key not in seen:rows.append(row);seen.add(key)
        except (OSError,ValueError,KeyError,TypeError,AttributeError,StopIteration,ImportError,ET.ParseError,EOFError,ZstdError):
            errors.append({'source':source,'error':'invalid/unavailable authoritative updateinfo'})
    stale=bool(errors) or any(x.get('stale') for x in sources.values())
    return rows,{'source':'Fedora','usable':bool(rows),'stale':stale,'errors':errors,
                 'advisory_build_rows':len(rows),'sources':sources,
                 'scope':'fixed public Fedora 43/44 stable updates x86_64 repository metadata; no package queries; TLS plus repomd SHA256, not independent signature verification'}


def json_key(row):
    return row['id'],row['name'],row['fixed'],row['arch']


def evr(value):
    m = re.fullmatch(r'(\d+):([^:\s]+)-([^\s]+)',value)
    if not m: raise ValueError('invalid EVR')
    return m.groups()


def compare(a,b):
    if rpm is None: return None
    try: return rpm.labelCompare(evr(a),evr(b))
    except (ValueError,TypeError): return None


def assess(entry, advisories, fresh=False, kev=frozenset()):
    row=dict(entry,status='unassessed',matches=[],reason='No matching authoritative Fedora build evidence')
    if entry.get('vendor') != 'Fedora Project' or rpm is None: return row
    arch=entry['source'].rsplit('|',1)[-1]
    branch=re.search(r'\.fc(\d+)(?:\.|$)',entry['version'])
    if not branch:return row
    unknown=not fresh
    relevant=0
    fixed_evidence=[]
    for advisory in advisories:
        if advisory['name'] != entry['name'] or advisory['arch'] != arch:continue
        target=re.search(r'\.fc(\d+)(?:\.|$)',advisory['fixed'])
        if not target:
            unknown=True; continue
        if branch[1] != target[1]:
            continue # Other distro releases do not contaminate this build scope.
        ordering=compare(entry['version'],advisory['fixed'])
        if ordering is None: unknown=True;continue
        relevant+=1
        match={'id':advisory['id'],'aliases':sorted(advisory['aliases']),
               'kev':sorted(set(advisory['aliases'])&kev),'evidence':{'fixed_evr':advisory['fixed'],'arch':arch,'comparison':'system rpm.labelCompare'}}
        if ordering < 0: row['matches'].append(match)
        else:fixed_evidence.append(match)
    if row['matches']:row['status']='affected'
    elif relevant or unknown and advisories:row['status']='needs investigation' if unknown else 'not affected'
    row['fixed_evidence']=fixed_evidence
    row['data_incomplete']=unknown
    row['reason']='Local Fedora security updateinfo EVR evidence; cache refresh/publication freshness unknown' if not fresh else 'Fedora build advisory scope only, not universal clearance'
    return row


def load_local(roots=None):
    roots=roots or [Path('/var/cache/libdnf5'),Path.home()/'.cache/libdnf5']
    rows=[]; errors=[]; documents=0; ages=[]; seen=set()
    for root in roots:
        if not root.exists():continue
        for repomd in root.glob('*/repodata/repomd.xml'):
            # Restrict to standard Fedora stable repositories, not third parties.
            if not re.fullmatch(r'(fedora|updates)-[a-zA-Z0-9]+',repomd.parent.parent.name):continue
            try:
                if repomd.is_symlink() or repomd.stat().st_size>1024**2:raise ValueError('repomd bound')
                content=repomd.read_bytes()
                if b'<!DOCTYPE' in content or b'<!ENTITY' in content:raise ValueError('XML DTD refused')
                tree=ET.fromstring(content)
                ns={'r':'http://linux.duke.edu/metadata/repo'}
                for node in tree.findall('r:data',ns):
                    if node.get('type')!='updateinfo':continue
                    location=node.find('r:location',ns).get('href')
                    rel=Path(location)
                    if rel.is_absolute() or '..' in rel.parts:raise ValueError('metadata traversal')
                    file=repomd.parent.parent/rel
                    if not file.exists():continue
                    if file.is_symlink() or file.stat().st_size>CAP:raise ValueError('metadata bound')
                    raw=file.read_bytes()
                    check=node.find('r:checksum',ns)
                    if check is None or check.get('type')!='sha256' or hashlib.sha256(raw).hexdigest()!=check.text:raise ValueError('metadata digest')
                    if check.text in seen:continue
                    seen.add(check.text)
                    if file.suffix=='.zst':
                        from compression import zstd
                        stream=zstd.open(file,'rb')
                    elif file.suffix=='.gz':
                        import gzip
                        stream=gzip.open(file,'rb')
                    else:raise ValueError('unsupported metadata compression')
                    with stream: data=stream.read(CAP+1)
                    if len(data)>CAP or b'<!DOCTYPE' in data or b'<!ENTITY' in data:raise ValueError('XML expansion/DTD bound')
                    document=ET.fromstring(data)
                    if len(document)>100000:raise ValueError('advisory member bound')
                    documents+=1; ages.append(round((time.time()-repomd.stat().st_mtime)/86400,3))
                    for update in document:
                        identity=update.findtext('id','')
                        if not identity.startswith('FEDORA-') or update.get('type')!='security':continue
                        aliases=[ref.get('id') for ref in update.findall('references/reference') if ref.get('type')=='cve' and re.fullmatch(r'CVE-\d{4}-\d{4,}',ref.get('id',''))]
                        for package in update.findall('pkglist/collection/package'):
                            a=package.attrib
                            rows.append({'id':identity,'aliases':aliases,'name':a['name'],'arch':a['arch'],
                                'fixed':a.get('epoch','0')+':'+a['version']+'-'+a['release']})
            except (OSError,ValueError,TypeError,KeyError,AttributeError,ET.ParseError,ImportError,EOFError,ZstdError):
                errors.append({'source':'Fedora','error':'local metadata unavailable/invalid'})
    if not documents:errors.append({'source':'Fedora','error':'no usable cached official updateinfo'})
    return rows,{'source':'Fedora','usable':bool(documents),'stale':True,'errors':errors,
                 'documents':documents,'advisory_build_rows':len(rows),'cache_mtime_age_days':ages,
                 'freshness':'unknown publication/revalidation age; local cache mtime is not refresh proof'}
