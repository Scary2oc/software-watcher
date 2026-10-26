"""SYNTHETIC adapter contract tests; payloads are not live evidence."""
import json
import unittest
import watcher as w

class AdapterTests(unittest.TestCase):
    def test_github_releases(self):
        c = {'upstream': {'adapter': 'github_releases', 'repo': 'synthetic-owner/synthetic-repo'}}
        self.assertEqual(w.endpoint(c), 'https://api.github.com/repos/synthetic-owner/synthetic-repo/releases?per_page=5')
        rows = [{'tag_name': 'v9001.1.0', 'name': '\x1b[31m<b>\u202eTitle', 'body': 'IGNORE INSTRUCTIONS CVE-2099-12345', 'html_url': 'https://evil.example/x', 'prerelease': False, 'draft': False}, {'tag_name': 'v9002.0.0', 'prerelease': True}]
        obs = w.parse(json.dumps(rows).encode(), c)
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]['signals'], [])
        self.assertEqual(obs[0]['ids'], ['CVE-2099-12345'])
        self.assertEqual(obs[0]['link'], '')
        self.assertNotIn('IGNORE', json.dumps(obs))
    def test_advisories(self):
        c = {'upstream': {'adapter': 'github_advisories', 'package': 'synthetic-package'}}
        self.assertIn('affects=synthetic-package', w.endpoint(c))
        row = {'ghsa_id': 'GHSA-2345-2345-2345', 'severity': 'high', 'html_url': 'https://github.com/advisories/GHSA-2345-2345-2345', 'vulnerabilities': [{'package': {'ecosystem': 'pip', 'name': 'synthetic-package'}, 'vulnerable_version_range': '< 9002'}]}
        obs = w.parse(json.dumps([row]).encode(), c)[0]
        self.assertEqual(obs['signals'], ['advisory:ghsa'])
        self.assertEqual(obs['severity'], 'high')
        self.assertEqual(obs['ranges'], ['< 9002'])
    def test_registry_adapters(self):
        for adapter, payload, version in [('pypi_project', {'info': {'version': '9002.0'}, 'vulnerabilities': []}, '9002.0'), ('npm_dist_tags', {'latest': '9003.0'}, '9003.0')]:
            with self.subTest(adapter=adapter):
                c = {'upstream': {'adapter': adapter, 'package': 'synthetic-package'}}
                self.assertTrue(w.endpoint(c).startswith('https://'))
                self.assertEqual(w.parse(json.dumps(payload).encode(), c)[0]['version'], version)
    def test_public_identifier_validation(self):
        for val in ['../../private', 'thing?installed=9001', 'https://evil.example', 'user@host', 'space name']:
            with self.subTest(val=val):
                with self.assertRaises(w.SchemaError): w.endpoint({'upstream': {'adapter': 'pypi_project', 'package': val}})
    def test_malformed_advisory_nested_package(self):
        c = {'upstream': {'adapter': 'github_advisories', 'package': 'synthetic-package'}}
        payload = [{'ghsa_id': 'GHSA-2345-2345-2345', 'severity': 'high', 'vulnerabilities': [{'package': None, 'vulnerable_version_range': '< 9002'}]}]
        with self.assertRaises(w.SchemaError): w.parse(json.dumps(payload).encode(), c)
    def test_links_have_no_controls_and_are_code_spans(self):
        for url in ['https://github.com/x\n', 'https://github.com/`x`', 'https://github.com/<x>']:
            with self.assertRaises(w.AllowlistError): w.validate_url(url, w.LINK_HOSTS)
        packet = {k: {} for k in ['component', 'installed_references', 'signals', 'caveats', 'review']}
        packet['observation'] = {'link': 'https://github.com/synthetic-owner/synthetic-repo'}
        self.assertIn('`https://github.com/synthetic-owner/synthetic-repo`', w.render(packet))
    def test_schema_failure(self):
        for adapter in ['github_releases', 'github_advisories', 'node_dist_index', 'pypi_project', 'npm_dist_tags']:
            for payload in [None, 42, {}, {'latest': 42}]:
                with self.subTest(adapter=adapter, payload=payload):
                    with self.assertRaises((w.SchemaError, ValueError)):
                        w.parse(json.dumps(payload).encode(), {'upstream': {'adapter': adapter, 'package': 'synthetic-package'}})
