"""Single-worker, local Hashcat 8 jobs with frozen inputs and native checkpoints."""
from __future__ import annotations

from collections import deque
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid


class EngineError(ValueError):
    pass


_ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_ID = re.compile(r'^[a-f0-9]{32}$')
_TERMINAL = {'cracked', 'exhausted', 'timed_out'}
_ERRORS = {
    -13: '计算插件错误', -12: '输入文件内容不可用', -11: '算法自检失败',
    -10: 'GPU 自动调优失败', -9: '混合计算后端错误', -8: 'GPU 缓冲区错误',
    -6: '计算内核创建失败', -5: '计算内核编译失败', -4: '显存不足',
    -3: '计算设备不支持此算法', -2: '命令参数或文件路径错误', -1: '计算引擎错误',
}


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path, value):
    fd, name = tempfile.mkstemp(prefix='.state-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def normalize_returncode(code):
    """C negative exits become unsigned bytes on POSIX / DWORDs on Windows."""
    if code is not None and 243 <= code <= 255:
        return code - 256
    if code is not None and 0xFFFFFFF3 <= code <= 0xFFFFFFFF:
        return code - 0x100000000
    return code


def parse_status(line):
    clean = _ANSI.sub('', line).strip()
    if not clean.startswith('{'):
        return None
    try:
        value = json.loads(clean)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get('status'), int):
        return None
    progress = value.get('progress')
    if not isinstance(progress, list) or len(progress) != 2:
        return None
    return value


class JobManager:
    """One Hashcat process at a time. No shell or remote service is involved.

    Stages: {name, mode: 0|3|4|6, args: list[str], runtime: seconds}.
    mode 0: wordlist, optionally -r RULE and -S; mode 3: mask or .hcmask;
    mode 4: no args, bundled model name, or one .tar.xz model file;
    mode 6: wordlist, mask, optionally -S. runtime=0 means unlimited.
    """

    def __init__(self, data_dir, hashcat_path):
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.hashcat_path = str(Path(hashcat_path).expanduser().resolve())
        self._lock = threading.RLock()
        self._queue = queue.Queue()
        self._requests = {}
        self._closing = False
        self._active = None
        self._version = None
        for folder in self.data_dir.iterdir():
            if not folder.is_dir() or not _ID.fullmatch(folder.name):
                continue
            try:
                job = self._load(folder.name)
            except EngineError:
                continue  # Preserve a damaged record for inspection.
            if job['status'] in ('running', 'queued', 'pausing'):
                job['status'] = 'interrupted'
                job['message'] = '上次程序未正常结束；可从已有检查点恢复。'
                for stage in job['stages']:
                    if stage['status'] == 'running':
                        stage['status'] = 'interrupted'
                self._save(job)
        self._worker = threading.Thread(target=self._work, name='wifi-audit-worker', daemon=True)
        self._worker.start()

    def _folder(self, job_id):
        if not isinstance(job_id, str) or not _ID.fullmatch(job_id):
            raise EngineError('无效的任务编号。')
        return self.data_dir / job_id

    def _load(self, job_id):
        try:
            value = json.loads((self._folder(job_id) / 'job.json').read_text(encoding='utf-8'))
            if (value.get('id') != job_id or value.get('schema') != 1
                    or not isinstance(value.get('stages'), list)
                    or not isinstance(value.get('status'), str)
                    or not isinstance(value.get('created_at'), (int, float))
                    or not isinstance(value.get('assets'), list)
                    or not isinstance(value.get('logtail'), list)
                    or not all(isinstance(stage, dict) and 'id' in stage and 'status' in stage
                               and 'elapsed_seconds' in stage and 'used_seconds' in stage
                               for stage in value['stages'])):
                raise ValueError('wrong schema')
            return value
        except (OSError, ValueError, AttributeError) as exc:
            raise EngineError('任务记录不存在或损坏：' + job_id) from exc

    def _save(self, job):
        job['updated_at'] = time.time()
        _atomic_json(self._folder(job['id']) / 'job.json', job)

    def create_job(self, target_path, stages, title='', metadata=None):
        with self._lock:
            if self._closing:
                raise EngineError('程序正在关闭。')
            if not stages:
                raise EngineError('至少需要一个测试阶段。')
            job_id = uuid.uuid4().hex
            folder = self._folder(job_id)
            folder.mkdir(mode=0o700)
            (folder / 'assets').mkdir(mode=0o700)
            assets, copied = [], {}

            def freeze(value):
                source = Path(value).expanduser().resolve()
                if not source.is_file():
                    raise EngineError('找不到输入文件：' + str(source))
                if str(source) not in copied:
                    relative = 'assets/' + str(len(assets)) + '-' + source.name
                    destination = folder / relative
                    shutil.copyfile(source, destination)
                    assets.append({'path': relative, 'sha256': _sha256(destination), 'size': destination.stat().st_size})
                    copied[str(source)] = relative
                return {'file': copied[str(source)]}

            try:
                target = freeze(target_path)
                prepared = []
                for index, spec in enumerate(stages):
                    mode = spec.get('mode')
                    args = list(spec.get('args', []))
                    runtime = spec.get('runtime', 300)
                    if (not isinstance(mode, int) or isinstance(mode, bool) or mode not in (0, 3, 4, 6)
                            or isinstance(runtime, bool) or not isinstance(runtime, int) or not 0 <= runtime <= 2147483647):
                        raise EngineError('无效的测试模式或时间预算。')
                    if not all(isinstance(arg, str) and '\0' not in arg for arg in args):
                        raise EngineError('阶段参数必须为文本。')
                    frozen = []
                    if mode in (0, 6):
                        if not args:
                            raise EngineError('字典模式需要候选文件。')
                        frozen.append(freeze(args.pop(0)))
                    if mode in (3, 6):
                        if not args or args[0].startswith('-'):
                            raise EngineError('需要有效的格式表达式。')
                        mask = args.pop(0)
                        frozen.append(freeze(mask) if Path(mask).is_file() else mask)
                    if mode == 4:
                        if len(args) > 1 or (args and args[0].startswith('-')):
                            raise EngineError('概率模式只接受一个模型文件或内置模型名。')
                        if args:
                            model = args.pop(0)
                            frozen.append(model if model in ('default-passwords', 'hints') else freeze(model))
                    while args:
                        option = args.pop(0)
                        if option == '-S' and mode in (0, 6):
                            frozen.append(option)
                        elif option == '-r' and mode == 0 and args:
                            frozen.extend([option, freeze(args.pop(0))])
                        else:
                            raise EngineError('不支持的阶段参数：' + option)
                    prepared.append({'id': f'stage-{index + 1:03}', 'name': str(spec.get('name', f'阶段 {index + 1}')),
                                     'mode': mode, 'args': frozen, 'runtime': runtime, 'used_seconds': 0.0,
                                     'elapsed_seconds': 0.0, 'status': 'pending', 'attempts': 0, 'progress': None,
                                     'speed': 0, 'eta_seconds': None, 'returncode': None})
                job = {'schema': 1, 'id': job_id, 'title': str(title), 'metadata': metadata or {},
                       'created_at': time.time(), 'status': 'created', 'message': '', 'target': target,
                       'assets': assets, 'stages': prepared, 'current_stage': None, 'logtail': [],
                       'hashcat_version': None}
                self._save(job)
            except Exception:
                shutil.rmtree(folder)
                raise
            return job_id

    def get(self, job_id):
        with self._lock:
            job = self._load(job_id)
            folder = self._folder(job_id)
            result = folder / 'found.txt'
            job['results_path'] = str(result)
            job['foundCount'] = 0
            if result.is_file():
                with result.open('rb') as stream:
                    job['foundCount'] = sum(1 for line in stream if line.strip())
            job['elapsed_seconds'] = sum(stage['elapsed_seconds'] for stage in job['stages'])
            job['used_seconds'] = sum(stage['used_seconds'] for stage in job['stages'])
            for stage in job['stages']:
                stage['checkpoint_available'] = (folder / (stage['id'] + '.restore')).is_file()
            current = job['current_stage']
            stage = next((s for s in job['stages'] if s['id'] == current), None)
            job['progress'] = stage['progress'] if stage else None
            job['speed'] = stage['speed'] if stage else 0
            job['eta_seconds'] = stage['eta_seconds'] if stage else None
            return deepcopy(job)

    def list_jobs(self):
        jobs = []
        with self._lock:
            for folder in self.data_dir.iterdir():
                if not folder.is_dir() or not _ID.fullmatch(folder.name):
                    continue
                try:
                    jobs.append(self.get(folder.name))
                except EngineError as exc:
                    jobs.append({'id': folder.name, 'title': '损坏的任务记录', 'status': 'error',
                                 'message': str(exc), 'created_at': 0, 'stages': [], 'foundCount': 0})
        return sorted(jobs, key=lambda job: job['created_at'], reverse=True)

    def start(self, job_id):
        with self._lock:
            if self._closing:
                raise EngineError('程序正在关闭。')
            job = self._load(job_id)
            if job['status'] in ('queued', 'running', 'pausing'):
                return
            if job['status'] in _TERMINAL:
                raise EngineError('任务已经结束；更改预算或范围后请创建新任务。')
            self._requests.pop(job_id, None)
            job['status'] = 'queued'
            job['message'] = '等待计算设备。'
            self._save(job)
            self._queue.put(job_id)

    def resume(self, job_id):
        self.start(job_id)

    def pause(self, job_id):
        with self._lock:
            job = self._load(job_id)
            if job['status'] == 'running':
                self._requests[job_id] = 'paused'
                job['status'] = 'pausing'
                job['message'] = '正在停止计算并保留最近的检查点。'
            elif job['status'] in ('queued', 'created'):
                job['status'] = 'paused'
                job['message'] = '任务已暂停。'
            else:
                return
            self._save(job)

    def close(self):
        with self._lock:
            if self._closing:
                return
            self._closing = True
            if self._active:
                self._requests[self._active] = 'interrupted'
            self._queue.put(None)
        self._worker.join(timeout=10)

    def _verify_version(self):
        if self._version:
            return self._version
        result = subprocess.run([self.hashcat_path, '--version'], capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=30, shell=False)
        match = re.search(r'\bv?(8\.\d+\.\d+)\b', result.stdout)
        if result.returncode != 0 or not match:
            raise EngineError('需要 Hashcat 8.x；请在设置中选择已解压的 hashcat.exe。')
        self._version = match.group(1)
        return self._version

    def _work(self):
        while True:
            job_id = self._queue.get()
            if job_id is None:
                return
            with self._lock:
                if self._closing:
                    continue
                try:
                    job = self._load(job_id)
                except EngineError:
                    continue
                if job['status'] != 'queued':
                    continue
                self._active = job_id
            try:
                self._run_job(job_id)
            except Exception as exc:
                with self._lock:
                    try:
                        job = self._load(job_id)
                    except EngineError:
                        continue  # Do not overwrite a corrupted record or kill the queue worker.
                    job['status'], job['message'] = 'error', str(exc)
                    for stage in job['stages']:
                        if stage['status'] == 'running':
                            stage['status'] = 'error'
                    self._save(job)
            finally:
                with self._lock:
                    self._active = None

    def _run_job(self, job_id):
        version = self._verify_version()
        folder = self._folder(job_id)
        with self._lock:
            job = self._load(job_id)
            if job['hashcat_version'] and job['hashcat_version'] != version and any(folder.glob('*.restore')):
                raise EngineError('Hashcat 版本发生变化；请使用原版本恢复，或创建新任务。')
            for asset in job['assets']:
                if _sha256(folder / asset['path']) != asset['sha256']:
                    raise EngineError('任务输入已被修改；为避免错误续算，请创建新任务。')
            job['hashcat_version'] = version
            self._save(job)
        for index in range(len(job['stages'])):
            with self._lock:
                job = self._load(job_id)
                request = self._requests.get(job_id)
                if request or job['status'] == 'paused':
                    job['status'] = request or 'paused'
                    self._save(job)
                    return
                if job['stages'][index]['status'] in _TERMINAL:
                    continue
            if not self._run_stage(job_id, index):
                return
        with self._lock:
            job = self._load(job_id)
            job['status'] = 'timed_out' if any(s['status'] == 'timed_out' for s in job['stages']) else 'exhausted'
            job['message'] = '测试计划结束，部分阶段达到时间预算。' if job['status'] == 'timed_out' else '本次候选范围已全部测试完毕。'
            self._save(job)

    def _command(self, job, stage):
        folder = self._folder(job['id'])
        checkpoint = folder / (stage['id'] + '.restore')
        render = lambda arg: str(folder / arg['file']) if isinstance(arg, dict) else arg
        args = [self.hashcat_path, '-m', '22000', '-a', str(stage['mode']), render(job['target'])]
        args.extend(render(arg) for arg in stage['args'])
        if stage['mode'] in (0, 6):
            args.append('--wordlist-autohex-disable')
        args.extend(['--session', job['id'] + '-' + stage['id'], '--restore-file-path', str(checkpoint),
                     '--potfile-path', str(folder / 'known.potfile'), '--outfile', str(folder / 'found.txt'),
                     '--outfile-format', '2', '--status', '--status-json', '--status-timer', '1', '--logfile-disable'])
        if stage['runtime']:
            remaining = max(1, int(stage['runtime'] - stage['used_seconds']))
            args.extend(['--runtime', str(remaining)])
        if checkpoint.is_file():
            args.append('--restore-position')
        return args

    @staticmethod
    def _stop_process(process):
        if process.poll() is not None:
            return
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGINT)
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)

    def _run_stage(self, job_id, index):
        folder = self._folder(job_id)
        with self._lock:
            job = self._load(job_id)
            stage = job['stages'][index]
            if stage['runtime'] and stage['used_seconds'] >= stage['runtime']:
                stage['status'] = 'timed_out'
                self._save(job)
                return True
            command = self._command(job, stage)
            base_used = stage['used_seconds']
            base_elapsed = stage['elapsed_seconds']
            budget = stage['runtime']
            stage['status'], stage['attempts'] = 'running', stage['attempts'] + 1
            stage['last_argv'] = command
            job['status'], job['current_stage'] = 'running', stage['id']
            job['message'] = '计算中。'
            self._save(job)
        options = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
        started = time.monotonic()
        epoch_started = time.time()
        active_start = None
        output = queue.Queue()
        process = subprocess.Popen(command, cwd=folder, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace',
                                   bufsize=1, shell=False, **options)

        def read_output():
            try:
                for line in process.stdout:
                    output.put(line)
            finally:
                output.put(None)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        tail = deque(job['logtail'], maxlen=60)
        requested = None
        try:
            with (folder / 'hashcat.log').open('a', encoding='utf-8') as log:
                ended = False
                while not ended or process.poll() is None:
                    with self._lock:
                        requested = self._requests.get(job_id)
                    if requested and process.poll() is None:
                        self._stop_process(process)
                    try:
                        line = output.get(timeout=0.2)
                    except queue.Empty:
                        continue
                    if line is None:
                        ended = True
                        continue
                    log.write(line)
                    log.flush()
                    clean = _ANSI.sub('', line).strip()
                    parsed = parse_status(clean)
                    if parsed:
                        ts = parsed.get('time_start')
                        if isinstance(ts, (int, float)) and epoch_started - 2 <= ts <= time.time():
                            active_start = max(epoch_started, ts)
                        with self._lock:
                            job = self._load(job_id)
                            stage = job['stages'][index]
                            compute = max(0, time.time() - active_start) if active_start is not None else 0
                            stage['used_seconds'] = min(budget, base_used + compute) if budget else base_used + compute
                            stage['elapsed_seconds'] = base_elapsed + time.monotonic() - started
                            stage['progress'] = parsed['progress']
                            stage['restore_point'] = parsed.get('restore_point', 0)
                            stage['speed'] = sum(d.get('speed', 0) for d in parsed.get('devices', []) if isinstance(d, dict))
                            eta = parsed.get('estimated_stop')
                            stage['eta_seconds'] = max(0, int(eta - time.time())) if isinstance(eta, (int, float)) and eta > 1 else None
                            stage['devices'] = [{k: d.get(k) for k in ('device_name', 'speed', 'temp', 'util')}
                                                for d in parsed.get('devices', []) if isinstance(d, dict)]
                            self._save(job)
                    elif clean:
                        # Hashcat writes recovered plaintext to outfile; never mirror hash/plain lines into the UI.
                        if not clean.startswith(('WPA*', '$HEX[')):
                            tail.append(clean[:1000])
                process.wait()
        finally:
            if process.poll() is None:
                self._stop_process(process)
            if process.stdout:
                process.stdout.close()
            reader.join(timeout=1)
        code = normalize_returncode(process.returncode)
        elapsed = time.monotonic() - started
        compute = max(0, time.time() - active_start) if active_start is not None else 0
        with self._lock:
            job = self._load(job_id)
            stage = job['stages'][index]
            remaining = max(0, budget - base_used) if budget else None
            if code == 4 and remaining is not None:
                compute = remaining
            stage['used_seconds'] = base_used + (min(compute, remaining) if remaining is not None else compute)
            stage['elapsed_seconds'] = base_elapsed + elapsed
            stage['returncode'] = code
            job['logtail'] = list(tail)
            if code == 0:
                stage['status'], job['status'], job['message'] = 'cracked', 'cracked', '已找到匹配口令，点击查看结果。'
            elif code == 1:
                stage['status'] = 'exhausted'
            elif requested:
                stage['status'], job['status'] = requested, requested
                checkpoint = folder / (stage['id'] + '.restore')
                job['message'] = ('已暂停；将从原生检查点恢复，可能重算尚未保存的批次。' if checkpoint.is_file()
                                  else '已停止；尚未形成检查点，恢复时将从当前阶段开头计算。')
            elif code == 4:
                stage['status'] = 'timed_out'
            elif code in (2, 3, 5):
                stage['status'], job['status'] = 'interrupted', 'interrupted'
                job['message'] = '计算被中断，可从已有检查点恢复。'
            else:
                stage['status'], job['status'] = 'error', 'error'
                job['message'] = _ERRORS.get(code, '计算进程异常结束') + f'（退出码 {code}），请查看日志。'
            self._save(job)
            return stage['status'] in ('exhausted', 'timed_out')
