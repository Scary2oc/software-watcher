"""Offline collector tests; all package metadata is synthetic."""
from unittest import mock
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import inventory


class CollectorTests(unittest.TestCase):
    def test_collect_preserves_parallel_rpm_builds(self):
        versions = ['0:2.0-3.fc44', '0:2.0-4.fc44', '1:2.0-4.fc44']
        raw = ''.join('SYNTHETIC\t' + version + '\tx86_64\tFedora Project\n'
                      for version in versions)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            with patch.object(inventory.Path, 'home', return_value=Path(tmp)), \
                 patch.object(inventory.Path, 'glob', return_value=[]), \
                 patch.object(inventory, 'collect_metadata', return_value={
                     'entries': [], 'errors': [], 'coverage': {}}) as metadata, \
                 patch.object(inventory, 'command', side_effect=[raw + raw, '']) as command, \
                 patch.object(inventory.os, 'uname', return_value=SimpleNamespace(nodename='SYNTHETIC')):
                result = inventory.collect()
        metadata.assert_called_once()
        self.assertEqual(command.call_count, 2)
        self.assertIn('%{EPOCHNUM}:%{VERSION}-%{RELEASE}', command.call_args_list[0].args[0][-1])
        self.assertEqual(result['errors'], [])
        self.assertEqual([row['version'] for row in result['entries']], versions)
        self.assertEqual(len({inventory.identity(row) for row in result['entries']}), 3)

    def test_rpm_identity_uses_epoch_version_release_and_arch(self):
        rows = inventory.parse_rpm(
            'SYNTHETIC\t0:2.0-3.fc44\tx86_64\tFedora Project\n'
            'SYNTHETIC\t1:2.0-3.fc44\tx86_64\tFedora Project\n'
            'SYNTHETIC\t0:3.0-3.fc44\tx86_64\tFedora Project\n'
            'SYNTHETIC\t0:2.0-4.fc44\tx86_64\tFedora Project\n'
            'SYNTHETIC\t0:2.0-3.fc44\taarch64\tFedora Project\n')
        self.assertEqual(len({inventory.identity(row) for row in rows}), 5)
        for row in rows:
            self.assertIn(row['version'], inventory.identity(row))

    def test_rpm_upgrade_diff_is_removed_plus_added(self):
        old, retained, new = inventory.parse_rpm(''.join(
            'SYNTHETIC\t' + version + '\tx86_64\tFedora Project\n'
            for version in ('0:2.0-3.fc44', '0:2.0-4.fc44', '1:2.0-4.fc44')))
        self.assertEqual(inventory.diff_entries([old, retained], [retained, new]),
                         {'added': [new], 'removed': [old], 'changed': []})
        self.assertEqual(inventory.diff_entries([old, retained], [retained, old]),
                         {'added': [], 'removed': [], 'changed': []})
        vendor_change = dict(retained, vendor='SYNTHETIC Other Vendor')
        self.assertEqual(inventory.diff_entries([retained], [vendor_change]),
                         {'added': [], 'removed': [],
                          'changed': [{'before': retained, 'after': vendor_change}]})

    def test_rpm_vendor_metadata_preserves_build_and_arch(self):
        rows=inventory.parse_rpm('SYNTHETIC\t1:2.0-3.fc44\tx86_64\tFedora Project\n')
        self.assertEqual(rows[0]['vendor'],'Fedora Project')
        self.assertEqual(rows[0]['version'],'1:2.0-3.fc44')
        self.assertEqual(rows[0]['arch'],'x86_64')
        self.assertEqual(rows[0]['name'],'SYNTHETIC')
        with self.assertRaises(ValueError):inventory.parse_rpm('incomplete')

    def test_direct_url_distribution_is_not_assumed_pypi(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            meta = root / 'example-1.0.dist-info'
            meta.mkdir()
            (meta / 'METADATA').write_text('Name: example\nVersion: 1.0\n')
            # Never read or retain URLs: they can include credentials.
            (meta / 'direct_url.json').write_text('{"url":"SYNTHETIC-PRIVATE"}')
            result = inventory.collect_metadata([root], [])
            self.assertEqual(result['entries'][0]['ecosystem'], 'Python direct/unknown')
            self.assertNotIn('SYNTHETIC-PRIVATE', json.dumps(result))

    def test_npm_payloads_error_and_cache_exclusion(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            npm = root / 'node_modules'
            pkg = npm / '@scope/pkg'
            pkg.mkdir(parents=True)
            (pkg / 'package.json').write_text(json.dumps({'name': '@scope/pkg', 'version': '1.2.3'}))
            bad = npm / 'broken'
            bad.mkdir()
            (bad / 'package.json').write_text('{')
            cached = root / '.cache/env/example-1.0.dist-info'
            cached.mkdir(parents=True)
            (cached / 'METADATA').write_text('Name: cached\nVersion: 1.0\n')
            result = inventory.collect_metadata([root], [npm])
            self.assertEqual([x['name'] for x in result['entries']], ['@scope/pkg'])
            self.assertEqual(len(result['errors']), 1)

    def test_package_implementation_is_not_discovery_scope(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            site = root / 'env/lib/python3.14/site-packages'
            (site / 'package' / ('nested/' * 20)).mkdir(parents=True)
            meta = site / 'example-1.0.dist-info'
            meta.mkdir()
            (meta / 'METADATA').write_text('Name: example\nVersion: 1.0\n')
            result = inventory.collect_metadata([root], [])
            self.assertEqual(result['errors'], [])
            self.assertEqual(len(result['entries']), 1)

    def test_metadata_only_and_snapshot_diff(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp)
            site = root / 'project/.venv/lib/python3.14/site-packages'
            meta = site / 'example_pkg-1.0.dist-info'
            meta.mkdir(parents=True)
            (meta / 'METADATA').write_text('Name: Example_Pkg\nVersion: 1.0\n')
            (site / 'sitecustomize.py').write_text('raise AssertionError("must not execute")')
            result = inventory.collect_metadata([root], [])
            self.assertEqual(len(result['entries']), 1)
            item = result['entries'][0]
            self.assertEqual((item['ecosystem'], item['name'], item['version']), ('PyPI', 'example-pkg', '1.0'))
            self.assertEqual(item['state'], 'installed metadata')
            self.assertEqual(inventory.diff_entries(result['entries'], result['entries']), {'added': [], 'removed': [], 'changed': []})
            changed = dict(item, version='2.0')
            self.assertEqual(len(inventory.diff_entries([item], [changed])['changed']), 1)


class MetadataReadTests(unittest.TestCase):
    def test_metadata_symlinks_surface_collector_errors(self):
        for ecosystem in ('python', 'npm'):
            with self.subTest(ecosystem=ecosystem), tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
                root = Path(tmp)
                package = root / ('example.dist-info' if ecosystem == 'python' else 'example')
                package.mkdir()
                meta = package / ('METADATA' if ecosystem == 'python' else 'package.json')
                target = root / 'synthetic-target'
                target.write_text('Name: example\nVersion: 1.0\n' if ecosystem == 'python'
                                  else '{"name":"example","version":"1.0"}')
                meta.symlink_to(target)
                result = inventory.collect_metadata([package], []) if ecosystem == 'python' else inventory.collect_metadata([], [root])
                self.assertEqual(result['entries'], [])
                self.assertEqual(result['errors'], [{'source': str(meta), 'error': 'OSError'}])

    def test_fifo_metadata_is_rejected_without_blocking(self):
        import io
        real_open = os.open
        real_stream_open = io.open

        def guarded_stream_open(file, *args, **kwargs):
            # Permit fdopen's already-open descriptor, never a path to the FIFO.
            if not isinstance(file, int):
                self.fail('FIFO high-level open forbidden')
            return real_stream_open(file, *args, **kwargs)

        def guarded_open(path, flags):
            # Assert before touching any FIFO, including on the RED run.
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_NOFOLLOW)
            return real_open(path, flags)

        for ecosystem in ('python', 'npm'):
            with self.subTest(ecosystem=ecosystem), tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
                root = Path(tmp)
                package = root / ('example.dist-info' if ecosystem == 'python' else 'example')
                package.mkdir()
                meta = package / ('METADATA' if ecosystem == 'python' else 'package.json')
                os.mkfifo(meta)
                # Cover each high-level path API as well as low-level flags.
                # Descriptor-only io.open remains available to real os.fdopen.
                with mock.patch.object(inventory.os, 'open', side_effect=guarded_open), \
                     mock.patch.object(Path, 'open', side_effect=AssertionError('FIFO high-level open forbidden')), \
                     mock.patch('builtins.open', side_effect=guarded_stream_open), \
                     mock.patch.object(io, 'open', side_effect=guarded_stream_open):
                    with self.assertRaises(ValueError):
                        inventory.read_metadata(meta)
                    result = inventory.collect_metadata([package], []) if ecosystem == 'python' else inventory.collect_metadata([], [root])
                self.assertEqual(result['entries'], [])
                self.assertEqual(result['errors'], [{'source': str(meta), 'error': 'ValueError'}])

    def test_metadata_growth_is_bounded_by_bytes(self):
        cap = 8
        real_fstat = os.fstat
        real_fdopen = os.fdopen
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            meta = Path(tmp) / 'METADATA'
            meta.write_bytes(b'a' * cap)

            def grow_after_stat(fd):
                info = real_fstat(fd)
                with meta.open('ab') as stream:
                    stream.write(b'b' * 64)
                return info

            def bounded_stream(fd, *args, **kwargs):
                stream = real_fdopen(fd, *args, **kwargs)
                original_read = stream.read

                def checked_read(size=-1):
                    self.assertGreaterEqual(size, 0, 'metadata reads must be bounded')
                    self.assertLessEqual(size, cap + 1)
                    self.assertIn('b', stream.mode, 'cap must count bytes, not characters')
                    return original_read(size)

                stream.read = checked_read
                return stream

            with mock.patch.object(inventory.os, 'fstat', side_effect=grow_after_stat), mock.patch.object(inventory.os, 'fdopen', side_effect=bounded_stream):
                with self.assertRaisesRegex(ValueError, 'metadata byte budget'):
                    inventory.read_metadata(meta, cap=cap)

    def test_metadata_exact_byte_cap_and_replacement_decoding(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            meta = Path(tmp) / 'METADATA'
            for data in (b'', b'normal', 'éééé'.encode('utf-8'), b'invalid\xff'):
                with self.subTest(data=data):
                    meta.write_bytes(data)
                    self.assertEqual(inventory.read_metadata(meta, cap=len(data)),
                                     data.decode('utf-8', errors='replace'))
                    if data:
                        with self.assertRaisesRegex(ValueError, 'metadata byte budget'):
                            inventory.read_metadata(meta, cap=len(data) - 1)

    def test_oversized_metadata_surfaces_collector_errors(self):
        for ecosystem in ('python', 'npm'):
            with self.subTest(ecosystem=ecosystem), tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
                root = Path(tmp)
                package = root / ('example.dist-info' if ecosystem == 'python' else 'example')
                package.mkdir()
                meta = package / ('METADATA' if ecosystem == 'python' else 'package.json')
                meta.write_bytes(b'x' * (2 * 1024 * 1024 + 1))
                result = inventory.collect_metadata([package], []) if ecosystem == 'python' else inventory.collect_metadata([], [root])
                self.assertEqual(result['entries'], [])
                self.assertEqual(result['errors'], [{'source': str(meta), 'error': 'ValueError'}])


if __name__ == '__main__':
    unittest.main()
