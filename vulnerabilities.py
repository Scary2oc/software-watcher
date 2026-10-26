"""Local OSV applicability. Unknown orderings are never inferred safe."""
import json
import re
import zipfile
try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    Version = None


def semver(value):
    match = re.fullmatch(r'v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?', value)
    if not match:
        raise ValueError('not semver')
    major, minor, patch, pre = match.groups()
    ids = pre.split('.') if pre else []
    if any(not x or (x.isdigit() and len(x) > 1 and x[0] == '0') for x in ids):
        raise ValueError('invalid prerelease')
    return (int(major), int(minor), int(patch), 1 if not pre else 0,
            tuple((0, int(x)) if x.isdigit() else (1, x) for x in ids))


def compare(eco, left, right):
    try:
        if eco == 'npm':
            a, b = semver(left), semver(right)
        elif eco == 'PyPI' and Version is not None:
            a, b = Version(left), Version(right)
        elif eco == 'PyPI':
            # Only plain numeric final releases have an unambiguous fallback.
            if not re.fullmatch(r'\d+(?:\.\d+)*', left) or not re.fullmatch(r'\d+(?:\.\d+)*', right):
                return None
            a, b = [int(x) for x in left.split('.')], [int(x) for x in right.split('.')]
            size = max(len(a), len(b))
            a += [0] * (size - len(a)); b += [0] * (size - len(b))
        else:
            return None
        return (a > b) - (a < b)
    except (ValueError, TypeError):
        return None


def range_match(eco, version, span):
    if span.get('type') not in ('ECOSYSTEM', 'SEMVER'):
        return None
    order_eco = 'npm' if span['type'] == 'SEMVER' else eco
    events = span.get('events')
    if not isinstance(events, list) or not events:
        return None
    start, intervals = None, []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        key, bound = next(iter(event.items()))
        if not isinstance(bound, str):
            return None
        if key == 'introduced':
            if start is not None:
                return None
            start = bound
        elif key in ('fixed', 'last_affected', 'limit') and start is not None:
            intervals.append((start, bound, key == 'last_affected'))
            start = None
        else:
            return None
    if start is not None:
        intervals.append((start, None, False))
    unknown = False
    for lower, upper, inclusive in intervals:
        if lower != '0' and upper is not None:
            ordering = compare(order_eco, lower, upper)
            if ordering is None or ordering > 0 or (ordering == 0 and not inclusive):
                return None
        low = 1 if lower == '0' else compare(order_eco, version, lower)
        high = -1 if upper is None else compare(order_eco, version, upper)
        if low is None or high is None:
            unknown = True
        elif low >= 0 and (high < 0 or (inclusive and high == 0)):
            return True
    return None if unknown else False


def is_affected(eco, version, affected):
    versions, ranges = affected.get('versions', []), affected.get('ranges', [])
    if not isinstance(versions, list) or not isinstance(ranges, list):
        return None
    if any(version == x or compare(eco, version, x) == 0 for x in versions if isinstance(x, str)):
        return True
    matches = [range_match(eco, version, span) if isinstance(span, dict) else None for span in ranges]
    if True in matches:
        return True
    if None in matches or (not versions and not ranges):
        return None
    if compare(eco, version, version) is None:
        return None
    return False


def load_osv(path, ecosystem, names, normalize, unpack_cap=2 * 1024**3):
    """Stream ZIP members, never extract paths or execute data; retain relevant rows."""
    index, errors, total = {}, [], 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > 250000 or sum(x.file_size for x in infos) > unpack_cap:
            raise ValueError('OSV expansion budget exceeded')
        for info in infos:
            if info.is_dir():
                continue
            if info.file_size > 8 * 1024**2:
                errors.append({'source': ecosystem, 'error': 'OSV member too large'})
                continue
            try:
                record = json.loads(archive.read(info))
                total += 1
                if not isinstance(record, dict) or not isinstance(record.get('id'), str) or not isinstance(record.get('affected'), list):
                    raise ValueError('invalid OSV record')
                aliases = record.get('aliases', [])
                if not isinstance(aliases, list) or not all(isinstance(x, str) for x in aliases):
                    raise ValueError('invalid OSV aliases')
                if record.get('withdrawn'):
                    continue
                for affected in record['affected']:
                    package = affected.get('package', {})
                    if package.get('ecosystem') != ecosystem:
                        continue
                    name = normalize(ecosystem, package['name'])
                    if name in names:
                        index.setdefault(name, []).append({'id': record['id'], 'aliases': record.get('aliases', []),
                                                          'affected': affected, 'modified': record.get('modified')})
            except (ValueError, TypeError, AttributeError, KeyError, zipfile.BadZipFile) as exc:
                errors.append({'source': ecosystem, 'error': type(exc).__name__})
    return index, errors, total


def assess(entries, indexes, feeds, kev, kev_ok=True):
    result = []
    for item in entries:
        eco = item['ecosystem']
        row = dict(item, status='unassessed', matches=[])
        if eco not in ('PyPI', 'npm'):
            row['reason'] = 'unassessed (distro backports)' if eco == 'RPM' else 'unsupported ecosystem/vendor evidence required'
            result.append(row)
            continue
        feed = feeds.get(eco, {})
        if not feed.get('usable'):
            row['reason'] = 'no usable public advisory feed'
            result.append(row)
            continue
        unknown = bool(feed.get('stale') or feed.get('errors') or not kev_ok)
        if compare(eco, item['version'], item['version']) is None:
            unknown = True
        for advisory in indexes.get(eco, {}).get(item['name'], []):
            match = is_affected(eco, item['version'], advisory['affected'])
            if match is None:
                unknown = True
            if match is True:
                ids = set(advisory.get('aliases', [])) | {advisory['id']}
                row['matches'].append({'id': advisory['id'], 'aliases': sorted(ids),
                                       'kev': sorted(ids & kev), 'modified': advisory.get('modified'),
                                       'evidence': {k: advisory['affected'][k] for k in ('versions', 'ranges') if k in advisory['affected']}})
        row['matches'] = list({x['id']: x for x in row['matches']}.values())
        row['status'] = 'affected' if row['matches'] else ('needs investigation' if unknown else 'not affected')
        row['data_incomplete'] = unknown
        row['reason'] = 'Local OSV data only; not a security clearance or proof of absence'
        result.append(row)
    return result
