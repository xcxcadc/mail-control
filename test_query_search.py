"""MIME and HTTP acceptance for global subject/body keyword search."""
import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('mail_control_query_search', Path(__file__).parent / 'src' / 'mail_control.py')
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)


class QuerySearchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.box = 'support@example.com'
        self.other = 'other@elsewhere.example'
        self.root_patch = patch.object(app.CONFIG, 'mail_root', self.root)
        self.box_patch = patch.object(app, 'global_mailboxes', return_value=[self.box, self.other])
        self.root_patch.start()
        self.box_patch.start()
        for mailbox in (self.box, self.other):
            (self.root / mailbox / 'new').mkdir(parents=True)
            (self.root / mailbox / '.Archive' / 'cur').mkdir(parents=True)
        app._message_headers.cache_clear()
        app._message_body_matches.cache_clear()

    def tearDown(self):
        self.box_patch.stop()
        self.root_patch.stop()
        app._message_headers.cache_clear()
        app._message_body_matches.cache_clear()
        self.directory.cleanup()

    def message(self, subject='普通主题', body='普通正文', charset='utf-8', cte=None):
        message = EmailMessage()
        message['Subject'] = subject
        message['From'] = '发件人 <sender@example.net>'
        message['To'] = self.box
        message['Cc'] = 'copy@example.net'
        message.set_content(body, charset=charset, **({'cte': cte} if cte else {}))
        return message

    def write(self, message, name='fixture', mailbox=None, folder='new'):
        path = self.root / (mailbox or self.box) / folder / name
        path.write_bytes(message.as_bytes())
        return path

    def search(self, query, field='all', **filters):
        return app.list_global_messages(query=query, search_field=field, **filters)

    def test_default_search_finds_body_and_preserves_metadata(self):
        self.write(self.message(body='唯一正文订单 Alpha-452'))
        result = self.search('alpha-452')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['search_field'], 'all')
        self.assertEqual(result['messages'][0]['subject'], '普通主题')
        self.assertNotIn('text', result['messages'][0])
        self.assertEqual(self.search('唯一正文', 'subject')['total'], 0)

    def test_field_selection_and_header_shortcut_do_not_scan_bodies(self):
        self.write(self.message(subject='Ticket 号码 AbC-99'))
        with patch.object(app, '_message_body_matches', side_effect=AssertionError('body scan')):
            self.assertEqual(self.search('abc-99', 'subject')['total'], 1)
            self.assertEqual(self.search('发件人', 'from')['total'], 1)
            self.assertEqual(self.search('copy@example.net', 'to')['total'], 1)
            self.assertEqual(self.search('support@example.com')['total'], 1)
            self.assertEqual(self.search('abc-99')['total'], 1)
            self.assertEqual(self.search('absent', 'from')['total'], 0)

    def test_utf8_base64_and_gb18030_quoted_printable(self):
        self.write(self.message(body='中文订单：甲乙丙丁', cte='base64'), 'utf8')
        self.write(self.message(body='中文订单：收货地址测试', charset='gb18030', cte='quoted-printable'), 'gb')
        self.assertEqual(self.search('甲乙丙丁', 'body')['total'], 1)
        self.assertEqual(self.search('收货地址测试', 'body')['total'], 1)

    def test_invalid_or_binary_charset_falls_back_to_utf8(self):
        for charset in ('not-a-real-charset', 'base64_codec'):
            with self.subTest(charset=charset):
                path = self.root / self.box / 'new' / 'bad-charset'
                path.write_bytes(('Subject: Charset\nContent-Type: text/plain; charset=' + charset + '\n\nCharsetNeedle中文').encode())
                self.assertEqual(self.search('CharsetNeedle中文', 'body')['total'], 1)

    def test_html_visible_words_entities_inline_tags_and_hidden_content(self):
        message = self.message()
        message.set_content('<html><head><title>SecretTitle</title><style>SecretStyle</style></head><body><script>SecretScript</script><p>订单 &amp; <b>ABC</b>123</p><div hidden>SecretHidden</div><p>第二段</p></body></html>', subtype='html', cte='base64')
        self.write(message)
        self.assertEqual(self.search('订单 & ABC123 第二段', 'body')['total'], 1)
        for word in ('SecretTitle', 'SecretStyle', 'SecretScript', 'SecretHidden', '<b>'):
            with self.subTest(word=word):
                self.assertEqual(self.search(word, 'body')['total'], 0)

    def test_nested_alternative_plain_and_html_are_searchable(self):
        message = self.message(body='PlainNeedle')
        message.add_alternative('<p>HTMLNeedle</p>', subtype='html', charset='utf-8', cte='quoted-printable')
        message.add_attachment(b'unrelated', maintype='application', subtype='octet-stream', filename='report.bin')
        self.write(message)
        self.assertEqual(self.search('PlainNeedle', 'body')['total'], 1)
        self.assertEqual(self.search('HTMLNeedle', 'body')['total'], 1)

    def test_attachment_content_filename_and_forwarded_message_are_not_body(self):
        message = self.message()
        message.add_attachment('AttachmentOnlyNeedle', filename='FilenameNeedle.txt')
        forwarded = self.message(subject='ForwardedNeedle', body='ForwardedBodyNeedle')
        message.add_attachment(forwarded, filename='forward.eml')
        self.write(message)
        for word in ('AttachmentOnlyNeedle', 'FilenameNeedle', 'ForwardedNeedle', 'ForwardedBodyNeedle'):
            with self.subTest(word=word):
                self.assertEqual(self.search(word, 'body')['total'], 0)
                self.assertEqual(self.search(word)['total'], 0)

    def test_large_attachment_is_not_decoded_or_read_into_memory(self):
        message = self.message(body='BodyOnly')
        message.add_attachment(b'z' * (3 * 1024 * 1024), maintype='application', subtype='octet-stream', filename='large.bin')
        path = self.write(message)
        original = Path.open
        sizes = []

        class BoundedReader:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def readline(self, size=-1):
                sizes.append(size)
                if not 0 < size <= 64 * 1024:
                    raise AssertionError('unbounded message read')
                return self.stream.readline(size)

        def opened(item, *args, **kwargs):
            stream = original(item, *args, **kwargs)
            return BoundedReader(stream) if item == path else stream

        signature = tuple(getattr(path.stat(), name) for name in ('st_dev', 'st_ino', 'st_mtime_ns', 'st_ctime_ns', 'st_size'))
        with patch.object(Path, 'open', opened), patch.object(app.base64, 'b64decode', side_effect=AssertionError('attachment decoded')):
            self.assertFalse(app._message_body_matches(path, signature, 'missingneedle'))
        self.assertGreater(len(sizes), 10)

    def test_repeated_query_uses_boolean_cache_and_edits_invalidate_it(self):
        path = self.write(self.message(body='CachedNeedle'))
        self.assertEqual(self.search('CachedNeedle', 'body')['total'], 1)
        self.assertEqual(self.search('CachedNeedle', 'body')['total'], 1)
        self.assertGreater(app._message_body_matches.cache_info().hits, 0)
        self.assertEqual(app._message_body_matches.cache_info().maxsize, 512)
        path.write_bytes(self.message(body='Changed body').as_bytes())
        self.assertEqual(self.search('CachedNeedle', 'body')['total'], 0)
        path.unlink()
        self.assertEqual(self.search('Changed body', 'body')['total'], 0)
        self.write(self.message(body='NewArrivalNeedle'), 'arrival')
        self.assertEqual(self.search('NewArrivalNeedle', 'body')['total'], 1)

    def test_concurrent_cold_body_scans_are_serialized(self):
        paths = [self.write(self.message(body='ThreadNeedle'), str(index)) for index in range(3)]
        state = {'active': 0, 'maximum': 0}
        lock = threading.Lock()
        original = app._StreamingBodySearch.feed

        def feed(part, *args, **kwargs):
            with lock:
                state['active'] += 1
                state['maximum'] = max(state['maximum'], state['active'])
            try:
                time.sleep(0.01)
                return original(part, *args, **kwargs)
            finally:
                with lock:
                    state['active'] -= 1

        results = []
        def search(path):
            signature = tuple(getattr(path.stat(), name) for name in ('st_dev', 'st_ino', 'st_mtime_ns', 'st_ctime_ns', 'st_size'))
            results.append(app._message_body_matches(path, signature, 'threadneedle'))

        with patch.object(app._StreamingBodySearch, 'feed', feed):
            threads = [threading.Thread(target=search, args=(path,)) for path in paths]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
        self.assertEqual(results, [True] * 3)
        self.assertEqual(state['maximum'], 1)

    def test_empty_keyword_only_reads_page_headers_and_never_body(self):
        for index in range(4):
            self.write(self.message(subject=str(index)), str(index))
        with patch.object(app, '_message_body_matches', side_effect=AssertionError('body scan')), patch.object(app, '_message_headers', wraps=app._message_headers) as headers:
            result = self.search('', 'body', limit=1)
            self.assertEqual(result['total'], 4)
            self.assertEqual(len(result['messages']), 1)
            self.assertEqual(headers.call_count, 1)

    def test_casefold_and_phrase_whitespace_across_chunks(self):
        body = 'a' * (64 * 1024 - 3) + '中文关键字\n订单\t  Straße'
        self.write(self.message(body=body, cte='8bit'))
        self.assertEqual(self.search('中文关键字 订单 strasse', 'body')['total'], 1)

    def test_base64_and_quoted_printable_decoder_chunk_boundaries(self):
        for cte in ('base64', 'quoted-printable'):
            with self.subTest(cte=cte):
                path = self.write(self.message(body='甲' * 30000 + 'TheLastNeedle中文尾部', cte=cte), cte)
                self.assertEqual(self.search('TheLastNeedle中文尾部', 'body')['total'], 1)
                path.unlink()

    def test_html_keyword_at_end_of_large_body(self):
        message = self.message()
        message.set_content('<p>' + 'x' * 200000 + '</p><div>最后的关键字</div>', subtype='html', charset='utf-8', cte='quoted-printable')
        self.write(message)
        self.assertEqual(self.search('最后的关键字', 'body')['total'], 1)

    def test_exact_mailbox_domain_folder_and_pagination_remain_applied(self):
        for index in range(5):
            path = self.write(self.message(body='FilteredNeedle'), str(index))
            os.utime(path, (100 + index, 100 + index))
        self.write(self.message(body='FilteredNeedle'), 'other', mailbox=self.other)
        self.write(self.message(body='FilteredNeedle'), 'archive', folder='.Archive/cur')
        result = self.search('FilteredNeedle', 'body', prefix='support', domain='example.com', folder='INBOX', offset=2, limit=2)
        self.assertEqual(result['total'], 5)
        self.assertEqual([item['id'] for item in result['messages']], ['2', '1'])
        self.assertTrue(all(item['mailbox'] == self.box for item in result['messages']))
        self.assertIn('.Archive', result['folders'])

    def test_invalid_field_and_excessive_keyword_are_rejected(self):
        for filters in ({'search_field': 'attachment'}, {'search_field': 'all', 'query': 'x' * 1001}):
            with self.subTest(filters=filters), self.assertRaises(ValueError):
                app.list_global_messages(**filters)

    def test_http_routes_search_parameter_alias_validation_and_authentication(self):
        self.write(self.message(body='APIBodyNeedle'))
        server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}/api/global/messages?'
        try:
            with patch.object(app.Handler, 'authorized', return_value=True):
                for key in ('q', 'query'):
                    url = base + urllib.parse.urlencode({key: 'APIBodyNeedle', 'search_field': 'body'})
                    with urllib.request.urlopen(url, timeout=5) as response:
                        result = json.load(response)
                        self.assertEqual(result['total'], 1)
                        self.assertEqual(result['search_field'], 'body')
                        self.assertEqual(response.headers['Cache-Control'], 'no-store')
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(base + 'search_field=attachment', timeout=5)
                self.assertEqual(error.exception.code, 400)
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(base + 'q=APIBodyNeedle&search_field=body', timeout=5)
            self.assertEqual(error.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
