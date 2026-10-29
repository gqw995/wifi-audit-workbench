from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import platform_tools as pt


def pmkid(ssid='测试网络', ap='020000000001'):
    return f'WPA*01*{"12" * 16}*{ap}*020000000002*{ssid.encode("utf-8").hex()}***'


class PlatformToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / '中文 握手.hc22000'
        self.source.write_text(pmkid() + '\n', encoding='ascii')

    def tearDown(self):
        self.temp.cleanup()

    def test_groups_exact_ssid_bytes_and_deduplicates(self):
        self.source.write_text(pmkid() + '\n' + pmkid() + '\n' + pmkid('另一个') + '\n')
        targets = pt.read_targets(self.source)
        self.assertEqual([x['count'] for x in targets], [1, 1])
        self.assertEqual(targets[0]['ssid'], '测试网络')
        self.assertEqual(targets[0]['ssid_hex'], '测试网络'.encode().hex())
        self.assertNotEqual(targets[0]['id'], targets[1]['id'])

    def test_structurally_invalid_hash_is_rejected_not_silently_skipped(self):
        cases = [pmkid().replace('12' * 16, '12' * 15), pmkid().replace('020000000001', 'zz0000000001'),
                 pmkid('x' * 33), 'WPA*03*bad', pmkid() + '\nbroken']
        for data in cases:
            with self.subTest(data=data):
                self.source.write_text(data)
                with self.assertRaises(ValueError):
                    pt.read_targets(self.source)

    def test_eapol_length_and_nonce_validation(self):
        eapol = bytes([2, 3, 0, 95]) + bytes(95)
        fields = ['WPA', '02', '12' * 16, '020000000001', '020000000002', '74657374', '34' * 32, eapol.hex(), '80']
        self.source.write_text('*'.join(fields))
        self.assertEqual(pt.read_targets(self.source)[0]['count'], 1)
        for index, bad in [(6, '34' * 31), (7, eapol[:-1].hex()), (8, 'ff')]:
            modified = fields.copy()
            modified[index] = bad
            self.source.write_text('*'.join(modified))
            with self.assertRaises(ValueError):
                pt.read_targets(self.source)

    def test_copy_and_selection_preserve_source_and_do_not_append(self):
        copied = self.root / 'copy.hc22000'
        original = self.source.read_bytes()
        result = pt.convert_capture(self.source, copied)
        self.assertEqual(result['backend'], 'hc22000')
        self.assertEqual(copied.read_bytes(), original)
        with self.assertRaises(ValueError):
            pt.convert_capture(self.source, copied)
        selected = self.root / 'selected.hc22000'
        pt.write_selected(copied, result['targets'][0]['id'], selected)
        self.assertEqual(pt.read_targets(selected)[0]['count'], 1)
        with self.assertRaises(ValueError):
            pt.write_selected(copied, 'missing', self.root / 'missing.hc22000')
        self.assertFalse((self.root / 'missing.hc22000').exists())
        self.assertEqual(self.source.read_bytes(), original)

    def test_native_converter_receives_unsplit_unicode_paths(self):
        capture = self.root / '家里 $(echo nope).pcap'
        capture.write_bytes(b'synthetic')
        output = self.root / 'converted.hc22000'
        calls = []
        def run(argv, timeout=120):
            calls.append(argv)
            Path(argv[2]).write_text(pmkid())
            return '', 'converted'
        with patch.object(pt, '_find_tool', return_value='/safe/hcxpcapngtool'), patch.object(pt, '_run', side_effect=run):
            result = pt.convert_capture(capture, output)
        self.assertEqual(result['backend'], 'native')
        self.assertEqual(calls[0][-1], str(capture.resolve()))
        self.assertEqual(len(calls[0]), 4)

    def test_failed_conversion_does_not_publish_partial_output(self):
        capture = self.root / 'sample.pcap'
        capture.write_bytes(b'synthetic')
        output = self.root / 'converted.hc22000'
        def run(argv, timeout=120):
            Path(argv[2]).write_text('bad hash')
            return '', 'partial'
        with patch.object(pt, '_find_tool', return_value='/safe/hcxpcapngtool'), patch.object(pt, '_run', side_effect=run):
            with self.assertRaises(ValueError):
                pt.convert_capture(capture, output)
        self.assertFalse(output.exists())

    def test_wsl_uses_explicit_argv_and_wslpath(self):
        capture = self.root / '中文 capture.pcap'
        capture.write_bytes(b'synthetic')
        output = self.root / 'converted.hc22000'
        calls = []
        translated = {}
        def run(argv, timeout=120):
            calls.append(argv)
            if '/usr/bin/which' in argv:
                return '/usr/bin/hcxpcapngtool', ''
            if 'wslpath' in argv:
                linux = '/mnt/test/' + str(len(translated))
                translated[linux] = Path(argv[-1])
                return linux, ''
            translated[argv[-2]].write_text(pmkid())
            return '', 'WSL conversion'
        with patch.object(pt.platform, 'system', return_value='Windows'), patch.object(pt, '_find_tool', return_value=None), \
             patch.object(pt.shutil, 'which', return_value='C:/Windows/wsl.exe'), patch.object(pt, '_run', side_effect=run):
            result = pt.convert_capture(capture, output, wsl_distro='Ubuntu-24.04')
        self.assertEqual(result['backend'], 'wsl')
        self.assertTrue(all(x[:4] == ['C:/Windows/wsl.exe', '--distribution', 'Ubuntu-24.04', '--exec'] for x in calls))
        self.assertEqual(sum('wslpath' in x for x in calls), 2)
        self.assertTrue(all('sh' not in x and '-c' not in x for x in calls))

    def test_run_never_enables_shell_and_reports_failure(self):
        with patch.object(pt.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'ok', b'')) as run:
            self.assertEqual(pt._run(['tool', 'space name']), ('ok', 'ok'))
            self.assertNotIn('shell', run.call_args.kwargs)
        with patch.object(pt.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7, b'', b'bad')):
            with self.assertRaisesRegex(ValueError, '7'):
                pt._run(['tool'])

    def test_discovery_does_not_install_anything(self):
        with patch.object(pt.platform, 'system', return_value='Windows'), patch.object(pt, '_find_tool', return_value=None), \
             patch.object(pt.shutil, 'which', return_value='wsl.exe'), patch.object(pt, '_run', return_value=('/usr/bin/hcxpcapngtool', '')) as run:
            state = pt.discover_tools({'wsl_distro': 'Ubuntu'})
        self.assertEqual(state['converter_backend'], 'wsl')
        self.assertEqual(run.call_args.args[0], ['wsl.exe', '--distribution', 'Ubuntu', '--exec', '/usr/bin/which', 'hcxpcapngtool'])


if __name__ == '__main__':
    unittest.main()
