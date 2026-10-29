import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))
sys.path.insert(0, str(APP / 'vendor'))

from cn_candidates import generate_candidates


class ChineseCandidatesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def generate(self, seeds, **options):
        result = generate_candidates(seeds, self.temp.name, **options)
        content = Path(result['path']).read_bytes()
        self.assertFalse(content.startswith(b'\xef\xbb\xbf'))
        self.assertEqual(hashlib.sha256(content).hexdigest(), result['sha256'])
        self.assertEqual(result['count'], len(content.splitlines()))
        return result, content.decode('utf-8').splitlines()

    def test_phrase_reading_and_first_letters_not_initials(self):
        result, words = self.generate(['重庆', '雨我圆'], suffixes=['2026'], separators=[''])
        for expected in ('chongqing', 'ChongQing', 'chongqing2026', 'yuwoyuan', 'ywy2026'):
            # Three initials + four digits is correctly too short for WPA2.
            if expected == 'ywy2026':
                self.assertNotIn(expected, words)
            else:
                self.assertIn(expected, words)
        _, words = self.generate(['雨我圆'], suffixes=['20260'], separators=[''])
        self.assertIn('ywy20260', words)
        self.assertNotIn('20260', words)
        self.assertFalse(result['truncated'])

    def test_literal_utf8_bounds_are_bytes_and_no_normalization(self):
        _, words = self.generate(['中中', '中中12', '中' * 21, '中' * 22, 'e\u0301abcdef'],
                                 suffixes=[], separators=[], include_literal=True)
        self.assertNotIn('中中', words)            # 6 bytes
        self.assertIn('中中12', words)             # 8 bytes
        self.assertIn('中' * 21, words)             # 63 bytes
        self.assertNotIn('中' * 22, words)           # 66 bytes
        self.assertIn('e\u0301abcdef', words)
        self.assertNotIn('éabcdef', words)
        self.assertTrue(all(8 <= len(word.encode('utf-8')) <= 63 for word in words))

    def test_literal_is_opt_in_and_latin_manual_reading_is_retained(self):
        _, words = self.generate(['山海2026', 'chongqing2026'], suffixes=[], separators=[])
        self.assertNotIn('山海2026', words)
        self.assertIn('shanhai2026', words)
        self.assertIn('chongqing2026', words)

    def test_dedup_controls_and_exact_ascii_literals(self):
        result, words = self.generate(['Lab2026!', 'Lab2026!', 'bad\nseed', 'bad\tseed', '',
                                       '$HEX[3132333435363738]', ' abcdef '],
                                      suffixes=['', ''], separators=['', ''])
        self.assertEqual(len(words), len(set(words)))
        self.assertIn('$HEX[3132333435363738]', words)
        self.assertIn(' abcdef ', words)
        self.assertEqual(result['skipped']['invalid_seed'], 2)
        self.assertEqual(result['skipped']['empty_seed'], 1)
        self.assertGreater(result['skipped']['duplicate'], 0)

    def test_cap_and_output_order_are_deterministic_without_overwriting(self):
        options = {'suffixes': ['0000', '0001', '0002'], 'separators': ['', '_'], 'max_candidates': 5}
        first, words1 = self.generate(['root', 'next'], **options)
        second, words2 = self.generate(['root', 'next'], **options)
        self.assertEqual(words1, words2)
        self.assertEqual(words1[:2], ['root0000', 'next0000'])
        self.assertEqual(first['count'], 5)
        self.assertTrue(first['truncated'])
        self.assertNotEqual(first['path'], second['path'])
        self.assertEqual(first['sha256'], second['sha256'])
        saved = json.loads(Path(first['manifest']).read_text(encoding='utf-8'))
        self.assertEqual(saved['config']['seeds'], ['root', 'next'])

    def test_exact_cap_is_not_reported_as_truncated(self):
        result, words = self.generate(['12345678'], suffixes=[], separators=[], max_candidates=1)
        self.assertEqual(words, ['12345678'])
        self.assertFalse(result['truncated'])

    def test_explicit_years_and_prefixes(self):
        _, words = self.generate(['root'], suffixes=[], separators=['-'], year_start=2025,
                                 year_end=2026, include_prefix=True)
        for expected in ('root-2025', 'root-2026', '2025-root', '2026-root'):
            self.assertIn(expected, words)
        self.assertNotIn('root-2024', words)

    def test_invalid_bounds_and_lists_fail_before_writing(self):
        for kwargs in ({'max_candidates': 0}, {'max_candidates': 200001}, {'max_candidates': True},
                       {'year_start': 2026}, {'year_start': 2101, 'year_end': 2102},
                       {'year_start': 2026, 'year_end': 2025}, {'suffixes': '2026'},
                       {'separators': ['\n']}, {'suffixes': ['年']}, {'include_literal': 'false'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.generate(['root'], **kwargs)
        with self.assertRaises(ValueError):
            self.generate(['root'] * 201)
        with self.assertRaises(ValueError):
            self.generate('root')
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
