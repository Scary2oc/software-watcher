"""Public-feed transport tests; synthetic responses, no network."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch
import public_feeds as f


class Response(io.BytesIO):
    def __init__(self, data=b'', headers=None, status=200):
        super().__init__(data)
        self.headers = headers or {}
        self.status = status


class Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []
    def open(self, request, timeout):
        self.requests.append(request)
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result


class FeedTests(unittest.TestCase):
    def test_enrichment_fixed_public_urls_and_rate_limit_gap(self):
        for source in ('EPSS', 'NVD'):
            self.assertIn(source, f.URLS)
            with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
                op=Opener([urllib.error.HTTPError(f.URLS[source],429,'rate limit',{'Retry-After':'60'},None)])
                with patch.object(f,'opener',return_value=op):
                    result=f.refresh(Path(tmp),source)
                self.assertFalse(result['usable'])
                self.assertTrue(result['stale'])
                self.assertTrue(result['errors'])
                self.assertEqual(len(op.requests),1)
                self.assertNotIn('?',op.requests[0].full_url)

    def test_epss_only_same_host_dated_redirect(self):
        handler=f.NoRedirect()
        request=__import__('urllib.request',fromlist=['Request']).Request('https://epss.empiricalsecurity.com/epss_scores-current.csv.gz')
        accepted=handler.redirect_request(request,None,302,'',{},'https://epss.empiricalsecurity.com/epss_scores-2026-10-25.csv.gz')
        self.assertTrue(accepted.full_url.endswith('.csv.gz'))
        with self.assertRaises(ValueError):
            handler.redirect_request(request,None,302,'',{},'https://evil.example/file')

    def test_head_same_validator_avoids_body_even_without_304(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            cache=Path(tmp)
            op=Opener([Response(headers={'Content-Length':'3'}),Response(b'abc',{'ETag':'"fixed"'}),Response(headers={'Content-Length':'3','ETag':'"fixed"'})])
            with patch.object(f,'opener',return_value=op):
                f.refresh(cache,'npm',cap=10)
                second=f.refresh(cache,'npm',cap=10)
            self.assertEqual(second['download_bytes'],0)
            self.assertEqual(len(op.requests),3)
            self.assertTrue(second['usable'])

    def test_old_publication_is_visible_even_when_revalidated(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            cache = Path(tmp)
            op = Opener([Response(headers={'Content-Length': '3'}),
                         Response(b'abc', {'ETag': '"fixture"', 'Last-Modified': 'Mon, 01 Jan 2001 00:00:00 GMT'})])
            with patch.object(f, 'opener', return_value=op):
                result = f.refresh(cache, 'PyPI', cap=10)
            self.assertTrue(result['usable'])
            self.assertTrue(result['stale'])
            self.assertTrue(result['errors'])

    def test_failed_refresh_preserves_cache_but_is_stale(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            cache = Path(tmp)
            op = Opener([Response(headers={'Content-Length': '3'}), Response(b'abc', {'ETag': '"fixture"'})])
            with patch.object(f, 'opener', return_value=op):
                f.refresh(cache, 'PyPI', cap=10)
            with patch.object(f, 'opener', return_value=Opener([OSError('synthetic outage')])):
                failed = f.refresh(cache, 'PyPI', cap=10)
            self.assertTrue(failed['usable'])
            self.assertTrue(failed['stale'])
            self.assertEqual(len(failed['errors']), 1)
            self.assertEqual((cache / 'PyPI.zip').read_bytes(), b'abc')

    def test_cache_conditional_and_oversize(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            cache = Path(tmp)
            opener = Opener([Response(headers={'Content-Length': '3'}), Response(b'abc', {'ETag': '"fixture"'}),
                             urllib.error.HTTPError(f.URLS['PyPI'], 304, '', {}, None)])
            with patch.object(f, 'opener', return_value=opener):
                first = f.refresh(cache, 'PyPI', cap=10)
                again = f.refresh(cache, 'PyPI', cap=10)
            self.assertTrue(first['usable'])
            self.assertEqual(first['download_bytes'], 3)
            self.assertEqual(again['download_bytes'], 0)
            self.assertEqual(opener.requests[-1].get_header('If-none-match'), '"fixture"')
            self.assertTrue(all(r.get_method() in ('HEAD', 'GET') and r.data is None for r in opener.requests))
            with patch.object(f, 'opener', return_value=Opener([Response(headers={'Content-Length': '99'})])):
                too_big = f.refresh(cache, 'npm', cap=10)
            self.assertFalse(too_big['usable'])
            self.assertTrue(too_big['errors'])


if __name__ == '__main__':
    unittest.main()
