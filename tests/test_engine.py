import io
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import EngineError, JobManager, normalize_returncode, parse_status


class QueueStream:
    def __init__(self):
        self.queue = queue.Queue()

    def __iter__(self):
        return self

    def __next__(self):
        value = self.queue.get()
        if value is None:
            raise StopIteration
        return value

    def close(self):
        self.queue.put(None)


class FakeProcess:
    def __init__(self, factory, argv, scenario):
        self.factory, self.argv = factory, argv
        self.returncode = None
        self.stdout = QueueStream()
        self.finished = threading.Event()
        self.factory.active += 1
        self.factory.maximum = max(self.factory.maximum, self.factory.active)
        status = {'status': 3, 'progress': [5, 100], 'recovered_hashes': [0, 1],
                  'time_start': int(time.time()), 'estimated_stop': int(time.time()) + 10,
                  'devices': [{'device_name': 'Synthetic GPU', 'speed': 50000, 'temp': 50, 'util': 100}]}
        self.stdout.queue.put(json.dumps(status) + '\n')
        checkpoint = Path(argv[argv.index('--restore-file-path') + 1])
        checkpoint.write_bytes(b'synthetic-checkpoint; never executed')
        if scenario != 'block':
            self.finish(scenario)

    def finish(self, code):
        if self.finished.is_set():
            return
        if code == 0:
            Path(self.argv[self.argv.index('--outfile') + 1]).write_text('Lab2026!42\n')
        self.returncode = code
        self.factory.active -= 1
        self.finished.set()
        self.stdout.queue.put(None)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if not self.finished.wait(timeout):
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode

    def send_signal(self, value):
        self.finish(-2)

    def terminate(self):
        self.finish(-15)

    def kill(self):
        self.finish(-9)


class FakeBackend:
    def __init__(self, scenarios):
        self.scenarios = iter(scenarios)
        self.calls = []
        self.active, self.maximum = 0, 0

    def popen(self, argv, **kwargs):
        assert kwargs['shell'] is False
        assert kwargs['stdin'] is subprocess.DEVNULL
        process = FakeProcess(self, argv, next(self.scenarios))
        self.calls.append((argv, kwargs, process))
        return process


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / '人工握手.hc22000'
        self.target.write_text('WPA*02*synthetic\n')
        self.words = self.root / '中文 words & $(literal).txt'
        self.words.write_text('Lab2026!42\n', encoding='utf-8')
        self.manager = None
        self.patches = []

    def tearDown(self):
        if self.manager:
            self.manager.close()
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp.cleanup()

    def backend(self, scenarios, version='v8.0.0\n'):
        fake = FakeBackend(scenarios)
        for patcher in [patch('engine.subprocess.Popen', side_effect=fake.popen),
                        patch('engine.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=version))]:
            patcher.start()
            self.patches.append(patcher)
        self.manager = JobManager(self.root / 'jobs', self.root / 'Hashcat 中文/hashcat.exe')
        return fake

    def create(self, stages=None):
        return self.manager.create_job(self.target, stages or [{'name': '中文候选', 'mode': 0,
                                                               'args': [str(self.words)], 'runtime': 30}])

    def wait_status(self, job_id, statuses):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            job = self.manager.get(job_id)
            if job['status'] in statuses:
                return job
            time.sleep(0.01)
        self.fail('Timed out waiting: ' + str(self.manager.get(job_id)))

    def test_frozen_unicode_inputs_and_sequential_stages(self):
        fake = self.backend([1, 0])
        job_id = self.create([{'name': '字典', 'mode': 0, 'args': [str(self.words)], 'runtime': 30},
                              {'name': '格式', 'mode': 3, 'args': ['Lab2026!?d?d'], 'runtime': 30}])
        self.words.write_text('changed-original\n')
        self.manager.start(job_id)
        result = self.wait_status(job_id, {'cracked', 'error'})
        self.assertEqual(result['status'], 'cracked')
        self.assertEqual(result['foundCount'], 1)
        self.assertNotIn('Lab2026!42', json.dumps(result))
        self.assertEqual([stage['status'] for stage in result['stages']], ['exhausted', 'cracked'])
        self.assertEqual(fake.maximum, 1)
        command = fake.calls[0][0]
        self.assertIn('--wordlist-autohex-disable', command)
        self.assertEqual(Path(command[6]).read_text(), 'Lab2026!42\n')
        self.assertNotIn('--potfile-disable', command)
        self.assertNotIn('--restore-disable', command)

    def test_pause_resume_uses_checkpoint_and_own_argv(self):
        fake = self.backend(['block', 0])
        job_id = self.create()
        self.manager.start(job_id)
        self.wait_status(job_id, {'running'})
        while not fake.calls:
            time.sleep(0.01)
        self.manager.pause(job_id)
        paused = self.wait_status(job_id, {'paused'})
        self.assertTrue(paused['stages'][0]['checkpoint_available'])
        self.manager.resume(job_id)
        done = self.wait_status(job_id, {'cracked', 'error'})
        self.assertEqual(done['status'], 'cracked')
        self.assertEqual(done['stages'][0]['attempts'], 2)
        self.assertIn('--restore-position', fake.calls[1][0])
        self.assertNotIn('--restore', fake.calls[1][0])
        resumed_command = fake.calls[1][0]
        self.assertLess(int(resumed_command[resumed_command.index('--runtime') + 1]), 30)
        self.assertEqual(fake.maximum, 1)

    def test_budgets_and_pending_stages_survive_restart(self):
        self.backend([4, 'block', 1])
        job_id = self.create([{'mode': 0, 'args': [str(self.words)], 'runtime': 7},
                              {'mode': 3, 'args': ['?d' * 8], 'runtime': 30}])
        self.manager.start(job_id)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            result = self.manager.get(job_id)
            if result['stages'][1]['status'] == 'running':
                break
            time.sleep(0.01)
        self.manager.close()
        self.manager = JobManager(self.root / 'jobs', self.root / 'Hashcat 中文/hashcat.exe')
        state = self.manager.get(job_id)
        self.assertEqual(state['status'], 'interrupted')
        self.assertEqual(state['stages'][0]['used_seconds'], 7)
        self.assertEqual(state['stages'][0]['attempts'], 1)
        self.manager.resume(job_id)
        result = self.wait_status(job_id, {'timed_out', 'error'})
        self.assertEqual(result['status'], 'timed_out')
        self.assertEqual(result['stages'][0]['attempts'], 1)
        self.assertEqual(result['stages'][1]['attempts'], 2)

    def test_concurrent_start_does_not_duplicate_work(self):
        fake = self.backend(['block', 1])
        first, second = self.create(), self.create()
        threads = [threading.Thread(target=self.manager.start, args=(first,)) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.manager.start(second)
        self.wait_status(first, {'running'})
        self.manager.pause(first)
        self.wait_status(second, {'exhausted', 'error'})
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(fake.maximum, 1)

    def test_modified_frozen_input_is_not_resumed(self):
        self.backend(['block'])
        job_id = self.create()
        self.manager.start(job_id)
        self.wait_status(job_id, {'running'})
        self.manager.pause(job_id)
        paused = self.wait_status(job_id, {'paused'})
        (self.root / 'jobs' / job_id / paused['assets'][0]['path']).write_text('tampered')
        self.manager.resume(job_id)
        result = self.wait_status(job_id, {'error'})
        self.assertIn('已被修改', result['message'])

    def test_bad_version_and_native_errors_are_errors(self):
        self.backend([], version='v7.1.2\n')
        job_id = self.create()
        self.manager.start(job_id)
        self.assertIn('8.x', self.wait_status(job_id, {'error'})['message'])

    def test_native_failure_does_not_advance_or_claim_exhausted(self):
        fake = self.backend([244])
        job_id = self.create([{'mode': 0, 'args': [str(self.words)], 'runtime': 30},
                              {'mode': 3, 'args': ['?d' * 8], 'runtime': 30}])
        self.manager.start(job_id)
        result = self.wait_status(job_id, {'error'})
        self.assertEqual(result['stages'][0]['returncode'], -12)
        self.assertEqual(result['stages'][1]['status'], 'pending')
        self.assertEqual(len(fake.calls), 1)

    def test_pause_queued_job_does_not_start_it(self):
        fake = self.backend(['block'])
        first, second = self.create(), self.create()
        self.manager.start(first)
        self.wait_status(first, {'running'})
        self.manager.start(second)
        self.manager.pause(second)
        self.assertEqual(self.manager.get(second)['status'], 'paused')
        self.manager.pause(first)
        self.wait_status(first, {'paused'})
        self.assertEqual(len(fake.calls), 1)

    def test_corrupt_state_is_preserved_and_listed(self):
        self.backend([])
        job_id = self.create()
        path = self.root / 'jobs' / job_id / 'job.json'
        path.write_text('{bad')
        with self.assertRaises(EngineError):
            self.manager.get(job_id)
        self.assertEqual(self.manager.list_jobs()[0]['status'], 'error')
        self.assertEqual(path.read_text(), '{bad')

    def test_valid_json_with_invalid_schema_is_preserved(self):
        self.backend([])
        job_id = self.create()
        path = self.root / 'jobs' / job_id / 'job.json'
        path.write_text(json.dumps({'schema': 1, 'id': job_id, 'stages': []}))
        self.assertEqual(self.manager.list_jobs()[0]['status'], 'error')

    def test_disallowed_arguments_and_path_traversal(self):
        self.backend([])
        with self.assertRaises(EngineError):
            self.create([{'mode': 3, 'args': ['?d' * 8, '--force'], 'runtime': 5}])
        with self.assertRaises(EngineError):
            self.manager.get('../outside')

    def test_json_status_and_cross_platform_exit_codes(self):
        self.assertIsNone(parse_status('initializing...'))
        self.assertIsNone(parse_status('{"status":3}'))
        self.assertEqual(parse_status('\x1b[0m{"status":3,"progress":[1,8]}')['progress'], [1, 8])
        self.assertEqual(normalize_returncode(244), -12)
        self.assertEqual(normalize_returncode(4294967285), -11)
        self.assertEqual(normalize_returncode(4), 4)


if __name__ == '__main__':
    unittest.main()
