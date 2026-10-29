"""Integration checks for local uploads, Chinese plans and HTTP boundaries.

The cryptographic engine is mocked. Real candidate generation and real hc22000
target parsing are used. HTTP requests go through the actual handler with an
in-memory socket, so these tests neither bind a port nor access a network.
"""
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode

APP = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(APP / 'vendor'), str(APP)]

import app
from engine import JobManager
from platform_tools import read_targets


def hash_record(ssid='山海实验室', ap='020000000011'):
    # Structurally valid synthetic PMKID record. No live capture is involved.
    return f'WPA*01*{"11" * 16}*{ap}*020000000012*{ssid.encode("utf-8").hex()}***\n'.encode('ascii')


class MemorySocket:
    def __init__(self, request):
        self.request = io.BytesIO(request)
        self.response = io.BytesIO()

    def makefile(self, *_args, **_kwargs):
        return self.request

    def sendall(self, data):
        self.response.write(data)


def request(application, method, path, body=b'', headers=None, token=True):
    actual = {'Host': '127.0.0.1:8873', 'Content-Length': str(len(body))}
    if token:
        actual['X-Local-Token'] = application.token
    actual.update(headers or {})
    head = f'{method} {path} HTTP/1.1\r\n'
    head += ''.join(f'{key}: {value}\r\n' for key, value in actual.items()) + '\r\n'
    connection = MemorySocket(head.encode('latin-1') + body)
    server = SimpleNamespace(server_port=8873, application=application)
    app.Handler(connection, ('127.0.0.1', 12345), server)
    head_bytes, response = connection.response.getvalue().split(b'\r\n\r\n', 1)
    status = int(head_bytes.split(b' ', 2)[1])
    response_headers = {line.split(b':', 1)[0].lower(): line.split(b':', 1)[1].strip()
                        for line in head_bytes.split(b'\r\n')[1:]}
    if response_headers.get(b'content-type', b'').startswith(b'application/json'):
        response = json.loads(response)
    return status, response_headers, response


class ApplicationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hashcat = self.root / 'tools' / 'hashcat.exe'
        self.hashcat.parent.mkdir()
        self.hashcat.touch()
        (self.hashcat.parent / 'rules').mkdir()
        (self.hashcat.parent / 'rules' / 'best66.rule').write_text(':\n', encoding='ascii')
        self.tools = {'hashcat': str(self.hashcat), 'hcxpcapngtool': None,
                      'converter_backend': 'mock', 'platform': 'Windows', 'errors': []}
        self.manager = MagicMock()
        self.manager.list_jobs.return_value = []
        self.manager.create_job.return_value = 'b' * 32
        self.manager.get.return_value = {'id': 'b' * 32, 'status': 'paused'}
        self.patches = [patch.object(app, 'discover_tools', return_value=self.tools),
                        patch.object(app, 'JobManager', return_value=self.manager),
                        patch.object(app, 'convert_capture', side_effect=self.convert)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.application = app.Application(self.root / 'data')

    @staticmethod
    def convert(source, destination, *_):
        shutil.copyfile(source, destination)
        read_targets(destination)
        return {'path': str(destination), 'backend': 'mock', 'log': 'synthetic test'}

    def import_capture(self, name='家里.pcap', content=None):
        content = hash_record() if content is None else content
        return self.application.import_file(io.BytesIO(content), len(content), name, 'capture')

    def base_plan(self, capture=None, **options):
        capture = capture or self.import_capture()
        result = {'capture_id': capture['id'], 'target_id': capture['targets'][0]['id'],
                  'seconds': 30, 'seeds': [], 'masks': []}
        result.update(options)
        return result

    def test_chinese_ssid_target_and_candidate_preview(self):
        capture = self.import_capture(content=hash_record() + hash_record('另一个网络', '020000000021'))
        self.assertEqual(capture['targets'][0]['ssid'], '山海实验室')
        plan = self.application.preview(self.base_plan(capture, seeds=['春风'], suffixes=['2026!'],
                                                      separators=[''], include_literal=True))
        self.assertEqual(plan['target']['ssid'], '山海实验室')
        self.assertEqual(read_targets(plan['target_path'])[0]['ssid'], '山海实验室')
        self.assertEqual(len(read_targets(plan['target_path'])), 1)
        candidates = plan['candidates']
        self.assertIn('春风2026!', candidates['preview'])
        self.assertIn('chunfeng2026!', candidates['preview'])
        self.assertEqual(plan['stages'][0]['mode'], 0)
        self.assertEqual(plan['stages'][0]['args'], [candidates['path']])
        self.assertEqual(plan['max_seconds'], 30)

    def test_bom_dictionary_is_frozen_and_only_ascii_gets_rules(self):
        original = b'\xef\xbb\xbf' + '春风2026!\r\nHome2026\r\nshort\r\n'.encode('utf-8')
        wordlist = self.application.import_file(io.BytesIO(original), len(original), '字典.txt', 'words')
        plan = self.application.preview(self.base_plan(wordlist_id=wordlist['id'], rules=True))
        self.assertEqual(len(plan['stages']), 2)
        dictionary = Path(plan['stages'][0]['args'][0])
        ascii_only = Path(plan['stages'][1]['args'][0])
        self.assertEqual(dictionary.read_bytes(), '春风2026!\nHome2026\nshort\n'.encode('utf-8'))
        self.assertEqual(ascii_only.read_bytes(), b'Home2026\nshort\n')
        self.assertIn('-S', plan['stages'][1]['args'])
        self.assertNotIn('-r', plan['stages'][0]['args'])
        self.assertEqual(Path(wordlist['path']).read_bytes(), original)
        Path(wordlist['path']).write_text('changed\n', encoding='utf-8')
        self.assertIn('春风2026!', dictionary.read_text(encoding='utf-8'))

    def test_import_rejects_invalid_utf8_and_incomplete_upload_without_records(self):
        for content, length in ((b'\xff\xfea\x00', 4), (b'abc', 10), (b'abc\x00def', 7)):
            with self.subTest(content=content), self.assertRaises((ValueError, UnicodeError)):
                self.application.import_file(io.BytesIO(content), length, 'bad.txt', 'words')
        self.assertEqual(list((self.application.data / 'imports').iterdir()), [])

    def test_preview_rejects_empty_invalid_mask_and_unknown_target(self):
        capture = self.import_capture()
        for changes in ({}, {'masks': ['?d?d']}, {'masks': ['?x' * 8]},
                        {'seeds': '春风'}, {'target_id': 'not-a-target', 'pcfg': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.application.preview(self.base_plan(capture, **changes))

    def test_failed_preview_removes_its_incomplete_plan(self):
        options = self.base_plan(seeds=['春风'], suffixes=['2026'], masks=['?x'])
        before = set((self.application.data / 'plans').iterdir())
        with self.assertRaises(ValueError):
            self.application.preview(options)
        self.assertEqual(set((self.application.data / 'plans').iterdir()), before)

    def test_json_option_types_do_not_silently_change_semantics(self):
        capture = self.import_capture()
        for changes in ({'include_literal': 'false'}, {'include_prefix': 'false'},
                        {'rules': 'false'}, {'pcfg': 1}, {'max_candidates': True},
                        {'max_candidates': 0}, {'max_candidates': 200001}, {'seconds': None},
                        {'seconds': True}, {'seconds': 5.5}, {'year_start': '2025', 'year_end': 2026},
                        {'year_start': 2025, 'year_end': True}, {'year_start': 2025},
                        {'year_start': 2026, 'year_end': 2025}, {'year_start': 2100, 'year_end': 2101}):
            options = self.base_plan(capture, seeds=['春风'], suffixes=['2026'], **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.application.preview(options)

    def test_run_uses_saved_plan_not_raw_paths_from_request(self):
        plan = self.application.preview(self.base_plan(masks=['Home?d?d?d?d'], pcfg=True))
        self.assertEqual([stage['mode'] for stage in plan['stages']], [4, 3])
        result = self.application.run_plan(plan['id'])
        self.assertEqual(result['id'], 'b' * 32)
        self.manager.start.assert_called_once_with('b' * 32)
        args, kwargs = self.manager.create_job.call_args
        self.assertEqual(args[0], plan['target_path'])
        self.assertEqual(kwargs['metadata']['plan_id'], plan['id'])
        for bad in ('../outside', '/tmp/plan', 'a' * 31, None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.application.run_plan(bad)

    def test_http_token_host_origin_boundaries(self):
        for headers, token in (({}, False), ({'X-Local-Token': 'wrong'}, True),
                               ({'Host': 'evil.example:8873'}, True),
                               ({'Host': 'localhost:8873'}, True),
                               ({'Origin': 'https://evil.example'}, True),
                               ({'Origin': 'null'}, True)):
            with self.subTest(headers=headers, token=token):
                status, _, body = request(self.application, 'GET', '/api/state', headers=headers, token=token)
                self.assertEqual(status, 403)
                self.assertIn('error', body)
        status, headers, body = request(self.application, 'GET', '/api/state',
                                        headers={'Origin': 'http://127.0.0.1:8873'})
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(headers[b'x-content-type-options'], b'nosniff')
        self.assertEqual(body['jobs'], [])

    def test_http_non_ascii_token_is_denied_without_handler_exception(self):
        status, _, body = request(self.application, 'GET', '/api/state', headers={'X-Local-Token': 'ÿ'})
        self.assertEqual(status, 403)
        self.assertIn('error', body)

    def test_http_raw_upload_can_only_write_managed_import(self):
        content = 'password2026\n'.encode('utf-8')
        query = urlencode({'name': '../../../../outside/秘密.txt', 'kind': 'words',
                           'path': str(self.root / 'outside.txt')})
        status, _, item = request(self.application, 'POST', '/api/upload?' + query, body=content)
        self.assertEqual(status, 200)
        self.assertEqual(item['name'], '秘密.txt')
        managed = self.application.data / 'imports' / item['id']
        self.assertEqual(Path(item['path']).parent, managed)
        self.assertEqual(Path(item['path']).name, 'source.txt')
        self.assertEqual(Path(item['path']).read_bytes(), content)
        self.assertFalse((self.root / 'outside.txt').exists())

    def test_http_errors_are_json_and_do_not_dispatch_invalid_upload(self):
        calls_before = self.manager.create_job.call_count
        for path, body in (('/api/preview', b'{'), ('/api/preview', b'[]'),
                           ('/api/run', b'{"plan_id":"../../bad"}'),
                           ('/api/upload?kind=unknown&name=a.txt', b'abc')):
            with self.subTest(path=path, body=body):
                status, _, value = request(self.application, 'POST', path, body=body)
                self.assertEqual(status, 400)
                self.assertIn('error', value)
        self.assertEqual(self.manager.create_job.call_count, calls_before)

    def test_http_null_seconds_returns_json_error(self):
        options = self.base_plan(pcfg=True, seconds=None)
        status, _, body = request(self.application, 'POST', '/api/preview',
                                  body=json.dumps(options).encode('utf-8'))
        self.assertEqual(status, 400)
        self.assertIn('error', body)

    def test_result_api_decodes_hex_deduplicates_and_only_reads_managed_job(self):
        ident = 'b' * 32
        folder = self.application.data / 'jobs' / ident
        folder.mkdir()
        found = folder / 'found.txt'
        chinese = '春风2026!'.encode('utf-8')
        found.write_bytes(b'$HEX[' + chinese.hex().encode('ascii') + b']\n'
                          + b'Home2026\nHome2026\n' + chinese + b'\n')
        outside = self.root / 'outside-result.txt'
        outside.write_text('must not read this', encoding='utf-8')
        self.manager.get.return_value = {'id': ident, 'status': 'cracked', 'results_path': str(outside)}
        read_bytes = Path.read_bytes

        def managed_read(path):
            self.assertEqual(path, found)
            return read_bytes(path)

        with patch.object(Path, 'read_bytes', autospec=True, side_effect=managed_read) as reader:
            status, _, body = request(self.application, 'POST', '/api/result',
                                      body=json.dumps({'id': ident}).encode('utf-8'))
            self.assertEqual(status, 200)
            self.assertEqual(body['passwords'], ['春风2026!', 'Home2026'])
            self.assertEqual(body['path'], str(found))
            self.assertEqual(body['status'], 'cracked')
            self.assertEqual(reader.call_count, 1)
            for bad in ('../outside-result.txt', str(outside), 'b' * 31, None):
                with self.subTest(bad=bad):
                    status, _, body = request(self.application, 'POST', '/api/result',
                                              body=json.dumps({'id': bad}).encode('utf-8'))
                    self.assertEqual(status, 400)
                    self.assertIn('error', body)
                    self.assertEqual(reader.call_count, 1)


class FirstLaunchTest(unittest.TestCase):
    def test_ui_and_settings_remain_available_without_installed_hashcat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'static').mkdir()
            (root / 'static' / 'index.html').write_text('<html>__LOCAL_TOKEN__</html>', encoding='utf-8')
            tools = {'hashcat': None, 'hcxpcapngtool': None, 'converter_backend': None, 'errors': []}
            with patch.object(app, 'ROOT', root), patch.object(app, 'discover_tools', return_value=tools), \
                    patch.object(app, 'JobManager', JobManager):
                application = app.Application(root / 'data')
                try:
                    status, _, html = request(application, 'GET', '/', token=False)
                    self.assertEqual(status, 200)
                    self.assertIn(application.token.encode('ascii'), html)
                    status, _, state = request(application, 'GET', '/api/state')
                    self.assertEqual(status, 200)
                    self.assertIsNone(state['tools']['hashcat'])
                    status, _, state = request(application, 'POST', '/api/settings', body=b'{}')
                    self.assertEqual(status, 200)
                    self.assertEqual(state['jobs'], [])
                finally:
                    application.manager.close()


if __name__ == '__main__':
    unittest.main()
