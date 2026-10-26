"""Bounded, metadata-only installed inventory. Never import inspected packages."""
import datetime as dt
from email.parser import Parser
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SKIP = {'.git', '__pycache__', 'node_modules', 'target', '.cache', 'logs',
        'sessions', 'memories', 'credentials', 'auth', '.worktrees', 'backups'}


def normalize(ecosystem, name):
    if ecosystem == 'PyPI':
        return re.sub(r'[-_.]+', '-', name).lower()
    return name.lower() if ecosystem == 'npm' else name


def entry(eco, name, version, source, **extra):
    return dict(ecosystem=eco, name=normalize(eco, name), version=version,
                source=str(source), state='installed metadata', **extra)


def read_metadata(path, cap=2 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb', buffering=0) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('metadata must be a regular file')
        if info.st_size > cap:
            raise ValueError('metadata byte budget')
        data = stream.read(cap + 1)
        if len(data) > cap:
            raise ValueError('metadata byte budget')
        return data.decode('utf-8', errors='replace')


def collect_metadata(roots, npm_roots, budget=60000):
    entries, errors, visited = [], [], 0
    seen = set()
    for root in map(Path, roots):
        if not root.exists():
            continue
        def onerror(exc):
            errors.append({'source': str(exc.filename), 'error': type(exc).__name__})
        for current, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            path = Path(current)
            if path in seen:
                dirs[:] = []
                continue
            seen.add(path)
            visited += 1
            if visited > budget:
                errors.append({'source': str(root), 'error': 'directory budget exhausted'})
                break
            depth = len(path.relative_to(root).parts)
            # Once an environment metadata directory is found, package code is
            # not discovery scope. Do not traverse implementations or their data.
            if path.name in ('site-packages', 'dist-packages'):
                dirs[:] = [d for d in dirs if d.endswith(('.dist-info', '.egg-info'))]
            if depth >= 13 and dirs:
                errors.append({'source': str(path), 'error': 'depth budget exhausted'})
            dirs[:] = [d for d in dirs if d not in SKIP and depth < 13 and not (path/d).is_symlink()]
            if path.name.endswith(('.dist-info', '.egg-info')):
                dirs[:] = []
                meta = path / ('METADATA' if 'METADATA' in files else 'PKG-INFO')
                try:
                    msg = Parser().parsestr(read_metadata(meta), headersonly=True)
                    name, version = msg.get('Name'), msg.get('Version')
                    if not name or not version:
                        raise ValueError('missing distribution identity')
                    eco = 'Python direct/unknown' if 'direct_url.json' in files else 'PyPI'
                    entries.append(entry(eco, name, version, meta,
                                         origin='direct reference; identity unverified' if eco != 'PyPI' else 'distribution metadata; registry identity not authenticated'))
                except (OSError, ValueError) as exc:
                    errors.append({'source': str(meta), 'error': type(exc).__name__})
        if visited > budget:
            break
    # Global npm installed payloads, including nested installed dependency tiers.
    # No npm execution, lifecycle hooks, lockfiles, or project declarations.
    seen_node = set()
    def node_modules(root, depth=0):
        nonlocal visited
        if not root.exists():
            return
        if depth > 16 or visited >= budget:
            errors.append({'source': str(root), 'error': 'npm traversal budget exhausted'})
            return
        try:
            packages = []
            for p in root.iterdir():
                if p.name.startswith('@') and p.is_dir():
                    packages.extend(p.iterdir())
                elif not p.name.startswith('.'):
                    packages.append(p)
            for p in packages:
                if p.is_symlink() or not p.is_dir():
                    if p.is_symlink():
                        errors.append({'source': str(p), 'error': 'linked npm payload not followed'})
                    continue
                if p in seen_node:
                    continue
                seen_node.add(p)
                visited += 1
                if visited > budget:
                    errors.append({'source': str(p), 'error': 'npm traversal budget exhausted'})
                    return
                meta = p / 'package.json'
                try:
                    data = json.loads(read_metadata(meta))
                    if not isinstance(data.get('name'), str) or not isinstance(data.get('version'), str):
                        raise ValueError('missing npm identity')
                    entries.append(entry('npm', data['name'], data['version'], meta))
                except (OSError, ValueError, AttributeError) as exc:
                    errors.append({'source': str(meta), 'error': type(exc).__name__})
                node_modules(p / 'node_modules', depth + 1)
        except OSError as exc:
            errors.append({'source': str(root), 'error': type(exc).__name__})
    for root in map(Path, npm_roots):
        node_modules(root)
    return {'entries': sorted(entries, key=identity), 'errors': errors,
            'coverage': {'metadata_roots': list(map(str, roots)), 'npm_roots': list(map(str, npm_roots)),
                         'directories_visited': visited, 'directory_budget': budget}}


def identity(item):
    key = item['ecosystem'], item['name'], item['source']
    # RPM permits parallel builds of the same name/arch. Include the full EVR
    # in collection/checkpoint identity; upgrades are removed + added, not changed.
    return key + (item['version'],) if item['ecosystem'] == 'RPM' else key


def diff_entries(previous, current):
    old = {identity(x): x for x in previous}
    new = {identity(x): x for x in current}
    return {'added': [new[k] for k in sorted(new.keys() - old.keys())],
            'removed': [old[k] for k in sorted(old.keys() - new.keys())],
            'changed': [{'before': old[k], 'after': new[k]} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]]}


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90,
                            env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'LC_ALL': 'C'},
                            cwd=Path.home(), check=True)
    return result.stdout


def parse_rpm(raw):
    rows=[]
    for line in raw.splitlines():
        fields=line.split('\t')
        if len(fields)!=4:raise ValueError('unexpected RPM field count')
        name,version,arch,vendor=fields
        rows.append(entry('RPM',name,version,'RPM:'+name+'|'+arch,arch=arch,vendor=vendor))
    return rows


def collect():
    home = Path.home()
    roots = [home/p for p in ('.local/lib', '.local/opt', '.local/share/uv/tools',
             '.local/share/pipx', '.local/pipx', 'Projects', 'src', 'Tools', 'Applications')]
    roots += [Path('/usr/local/lib'), Path('/opt')]
    npm_roots = [home/'.npm-global/lib/node_modules', home/'.local/lib/node_modules',
                 Path('/usr/local/lib/node_modules'), Path('/usr/lib/node_modules')]
    npm_roots += list((home/'.nvm/versions/node').glob('*/lib/node_modules'))
    npm_roots += list((home/'.local/share/fnm/node-versions').glob('*/installation/lib/node_modules'))
    result = collect_metadata(roots, npm_roots)
    for eco, args in [('RPM', ['/usr/bin/rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n']),
                      ('Flatpak', ['/usr/bin/flatpak', 'list', '--columns=application,version,branch,arch,origin,installation'])]:
        try:
            raw = command(args)
            if eco=='RPM':
                result['entries'].extend(parse_rpm(raw))
                continue
            for line in raw.splitlines():
                fields = line.split('\t')
                required = 3 if eco == 'RPM' else 6
                if len(fields) != required:
                    result['errors'].append({'source': eco, 'error': 'unexpected field count'})
                    continue
                name, version, *rest = fields
                result['entries'].append(entry(eco, name, version, eco + ':' + '|'.join([name, *rest])))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            result['errors'].append({'source': eco, 'error': type(exc).__name__})
    # Cargo's installation ledger is metadata, not a Cargo.lock dependency claim.
    cargo = home/'.cargo/.crates2.json'
    if cargo.exists():
        try:
            for key in json.loads(read_metadata(cargo)).get('installs', {}):
                name, version, origin = key.split(' ', 2)
                result['entries'].append(entry('crates.io' if 'registry+' in origin else 'Cargo unknown', name, version, str(cargo) + ':' + name))
        except (OSError, ValueError, AttributeError) as exc:
            result['errors'].append({'source': str(cargo), 'error': type(exc).__name__})
    result['entries'] = sorted({identity(x): x for x in result['entries']}.values(), key=identity)
    result['observed_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
    result['hostname'] = os.uname().nodename
    result['coverage']['limitations'] = [
        'Bounded known-root discovery; absent roots are skipped, arbitrary environments are not exhaustive.',
        'RPM, Flatpak, bundled runtimes and Cargo need vendor/ecosystem assessment; no upstream backport guesses.',
        'Cached, lockfile-only and running-process references are not collected or treated as installed.',
        'Only global npm layouts are scanned; project node_modules and linked payloads are outside coverage.',
        'Active execution, installation purpose, containers and other hosts are not established.']
    return result
