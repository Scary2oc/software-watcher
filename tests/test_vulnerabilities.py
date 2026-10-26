"""Synthetic OSV fixture replay; no network."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import inventory
import vulnerabilities as v


class RangeTests(unittest.TestCase):
    def test_ecosystem_range_and_explicit_list(self):
        affected = {'versions': ['0.5'], 'ranges': [{'type': 'ECOSYSTEM', 'events': [
            {'introduced': '1.0'}, {'fixed': '2.0'}, {'introduced': '3.0'}, {'last_affected': '3.1'}]}]}
        for version, expected in [('0.5', True), ('0.9', False), ('1.5', True), ('2.0', False), ('3.1', True), ('3.2', False)]:
            with self.subTest(version=version):
                self.assertIs(v.is_affected('PyPI', version, affected), expected)
        self.assertIsNone(v.is_affected('PyPI', '1.0', {'ranges': [{'type': 'GIT', 'events': []}]}))

    def test_malformed_aliases_are_feed_errors(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            path = Path(tmp) / 'fixture.zip'
            data = json.loads((Path(__file__).parent / 'fixtures/SYNTHETIC_osv.json').read_bytes())
            data['aliases'] = [None]
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('fixture.json', json.dumps(data))
            index, errors, count = v.load_osv(path, 'PyPI', {'example-pkg'}, inventory.normalize)
            self.assertTrue(errors)
            self.assertFalse(index)

    def test_numeric_fallback_and_stale_status(self):
        with patch.object(v, 'Version', None):
            self.assertEqual(v.compare('PyPI', '1.0', '1.0.0'), 0)
            self.assertIsNone(v.compare('PyPI', '1.0rc1', '1.0'))
        item = inventory.entry('PyPI', 'example-pkg', '1.0', 'SYNTHETIC')
        result = v.assess([item], {'PyPI': {}}, {'PyPI': {'usable': True, 'stale': True}}, set())
        self.assertEqual(result[0]['status'], 'needs investigation')
        result = v.assess([item], {'PyPI': {}}, {'PyPI': {'usable': True, 'stale': False}}, set())
        self.assertEqual(result[0]['status'], 'not affected')
        rpm = inventory.entry('RPM', 'example', '1:1.0-1', 'SYNTHETIC')
        self.assertEqual(v.assess([rpm], {}, {}, set())[0]['reason'], 'unassessed (distro backports)')

    def test_bad_intervals_are_not_reported_unaffected(self):
        malformed = {'ranges': [{'type': 'ECOSYSTEM', 'events': [
            {'introduced': '2.0'}, {'fixed': '1.0'}]}]}
        self.assertIsNone(v.is_affected('PyPI', '1.5', malformed))

    def test_semver_prerelease_limit_and_build(self):
        affected = {'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'limit': '2.0.0'}]}]}
        self.assertTrue(v.is_affected('npm', '2.0.0-rc.1', affected))
        self.assertFalse(v.is_affected('npm', '2.0.0+build.1', affected))
        self.assertEqual(v.compare('npm', '1.0.0-alpha.2', '1.0.0-alpha.10'), -1)
        self.assertIsNone(v.is_affected('npm', 'workspace:*', affected))
        self.assertIsNone(v.is_affected('npm', '1.0.0', {'ranges': [{'type': 'SEMVER', 'events': [{'fixed': '2.0.0'}]}]}))


if __name__ == '__main__':
    unittest.main()
