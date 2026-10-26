"""Fixed public bulk feeds only. No package/version queries or proxy credentials."""
import datetime as dt
from email.utils import parsedate_to_datetime
import hashlib
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request
import uuid
from watcher import dump, load, mkdir

URLS = {'PyPI': 'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip',
        'npm': 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip',
        'KEV': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'EPSS': 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
        'NVD': 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz'}
for release in ('43','44'):
    URLS['Fedora'+release] = 'https://dl.fedoraproject.org/pub/fedora/linux/updates/'+release+'/Everything/x86_64/repodata/repomd.xml'
CAP = 256 * 1024**2


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # FIRST's documented stable URL has one relative dated-file redirect.
        # No other host/path/source may redirect; the dated target cannot hop.
        if req.full_url == URLS['EPSS'] and code in (301,302,307,308) and re.fullmatch(r'https://epss\.empiricalsecurity\.com/epss_scores-\d{4}-\d{2}-\d{2}\.csv\.gz',newurl):
            return urllib.request.Request(newurl,headers=dict(req.headers),method=req.get_method())
        raise ValueError('feed redirect refused')


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024**2), b''):
            h.update(chunk)
    return h.hexdigest()


def refresh(cache, ecosystem, cap=None, artifact=None):
    """Size-check before GET, atomically cache, revalidate once each daily run.

    Errors may retain old data but always mark it stale/incomplete immediately.
    Both conditional validators are sent when available. Age is revalidation age,
    not advisory publication age; OSV is not a real-time incident detector.
    """
    started = time.monotonic()
    url = URLS[ecosystem]
    if artifact is not None:
        if ecosystem not in ('Fedora43','Fedora44') or not re.fullmatch(r'repodata/[0-9a-f]{64}-updateinfo\.xml\.(gz|zst)',artifact):
            raise ValueError('Fedora public artifact refused')
        url = url.removesuffix('repodata/repomd.xml') + artifact
    cap = cap if cap is not None else ((32 if artifact else 1) if ecosystem.startswith('Fedora') else {'KEV':8,'EPSS':32,'NVD':64}.get(ecosystem,256))*1024**2
    mkdir(cache)
    suffix = {'KEV':'.json','EPSS':'.csv.gz','NVD':'.json.gz'}.get(ecosystem,'.zip')
    if ecosystem.startswith('Fedora'):
        suffix = '.xml.'+artifact.rsplit('.',1)[-1] if artifact else '.xml'
    target = Path(cache) / (ecosystem + suffix)
    meta_path = Path(cache) / (ecosystem + suffix + '.meta.json' if ecosystem.startswith('Fedora') else ecosystem + '.meta.json')
    meta = load(meta_path, {})
    result = {'source': ecosystem, 'usable': False, 'stale': True, 'errors': [],
              'download_bytes': 0, 'announced_bytes': None, 'checked_utc': utc(),
              'path': str(target), 'sha256': meta.get('sha256')}
    temp = Path(cache) / ('.download-' + uuid.uuid4().hex)
    try:
        headers = {'User-Agent': 'software-watcher-daily/1 (public bulk data)', 'Accept-Encoding': 'identity'}
        for key, field in [('If-None-Match', 'etag'), ('If-Modified-Since', 'last_modified')]:
            value = meta.get(field)
            if target.exists() and meta.get('url',url)==url and isinstance(value, str) and len(value) < 256 and not any(c in value for c in '\r\n'):
                headers[key] = value
        client = opener()
        try:
            with client.open(urllib.request.Request(url, method='HEAD', headers=headers), timeout=30) as response:
                if response.headers.get('Content-Encoding', 'identity') != 'identity':
                    raise ValueError('encoded feed refused')
                length = response.headers.get('Content-Length')
                length = int(length) if length is not None else None
                result['announced_bytes'] = length
                if length is None and ecosystem != 'KEV':
                    raise ValueError('OSV feed size unavailable')
                if length is not None and (length < 0 or length > cap):
                    raise ValueError('public feed exceeds download budget')
                # Some bulk hosts answer conditional HEAD with 200 plus the same
                # ETag. Revalidate integrity and size before skipping the body.
                tag = response.headers.get('ETag')
                if target.exists() and meta.get('url',url)==url and tag and tag == meta.get('etag') and length == meta.get('bytes'):
                    if digest(target) != meta.get('sha256'):
                        raise ValueError('cache digest mismatch')
                    meta['validated_utc'] = utc()
                    dump(meta_path, meta)
                    result.update(usable=True, stale=False, sha256=meta['sha256'], cache='head-validator')
                    return result
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code != 304 or not target.exists():
                raise
            if digest(target) != meta.get('sha256'):
                raise ValueError('cache digest mismatch')
            meta['validated_utc'] = utc()
            dump(meta_path, meta)
            result.update(usable=True, stale=False, sha256=meta['sha256'], cache='revalidated')
            return result
        # Strip HEAD validators for a new body: a conditional HEAD may return 200
        # with unchanged validators. The HEAD bounds the body, GET is capped too.
        headers = {k: value for k, value in headers.items() if not k.startswith('If-')}
        with client.open(urllib.request.Request(url, method='GET', headers=headers), timeout=30) as response:
            if response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise ValueError('encoded feed refused')
            length = response.headers.get('Content-Length')
            if length is not None and int(length) > cap:
                raise ValueError('public feed exceeds download budget')
            h = hashlib.sha256()
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as out:
                while True:
                    if time.monotonic() - started > 240:
                        raise TimeoutError('feed download deadline')
                    chunk = response.read(1024**2)
                    if not chunk:
                        break
                    result['download_bytes'] += len(chunk)
                    if result['download_bytes'] > cap:
                        raise ValueError('public feed exceeds download budget')
                    h.update(chunk); out.write(chunk)
                out.flush(); os.fsync(out.fileno())
            if length is not None and result['download_bytes'] != int(length):
                raise ValueError('truncated feed')
            meta = {'etag': response.headers.get('ETag'), 'last_modified': response.headers.get('Last-Modified'),
                    'validated_utc': utc(), 'sha256': h.hexdigest(), 'bytes': result['download_bytes'], 'url':url}
        os.replace(temp, target)
        directory = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        dump(meta_path, meta)
        result.update(usable=True, stale=False, sha256=meta['sha256'], cache='downloaded')
    except (OSError, ValueError, TimeoutError) as exc:
        result['errors'].append({'source': ecosystem, 'error': type(exc).__name__})
        result['usable'] = target.exists() and bool(meta.get('sha256')) and digest(target) == meta['sha256']
    finally:
        if temp.exists():
            temp.unlink()
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        result['last_validated_utc'] = meta.get('validated_utc')
        result['last_modified'] = meta.get('last_modified')
        result['publication_age_days'] = None
        if meta.get('last_modified'):
            try:
                published = parsedate_to_datetime(meta['last_modified'])
                age = (dt.datetime.now(dt.timezone.utc) - published).total_seconds() / 86400
                result['publication_age_days'] = round(age, 3)
                # Dumps should publish frequently; KEV may legitimately have no
                # additions for several days. These are freshness heuristics.
                if age > ({'KEV':14,'EPSS':2,'NVD':2}.get(ecosystem,3)) or age < -1:
                    result['stale'] = True
                    result['errors'].append({'source': ecosystem, 'error': 'publication freshness threshold exceeded'})
            except (ValueError, TypeError, OverflowError):
                result['stale'] = True
                result['errors'].append({'source': ecosystem, 'error': 'invalid publication date'})
    return result
