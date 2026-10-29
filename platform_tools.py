"""Discover native tools and delegate capture decoding to hcxtools.

No wireless packet parsing, installation, network access, or shell evaluation
is performed here. Hash-record checks validate structure, not password truth.
"""
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_HASH_BYTES = 16 * 1024 * 1024
_HEX = re.compile(r"^[0-9a-fA-F]*$")


def _find_tool(name, configured=None):
    if configured:
        supplied = str(configured).strip()
        resolved = shutil.which(supplied)
        if resolved:
            return str(Path(resolved).resolve())
        path = Path(supplied).expanduser()
        return str(path.resolve()) if path.is_file() else None
    suffix = '.exe' if platform.system() == 'Windows' else ''
    filename = name + suffix
    folder = 'hashcat' if name == 'hashcat' else 'hcxtools'
    candidates = [ROOT / 'tools' / folder / filename, ROOT / folder / filename]
    if platform.system() == 'Darwin':
        candidates.extend([Path('/opt/homebrew/bin') / name, Path('/usr/local/bin') / name])
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    found = shutil.which(filename)
    return str(Path(found).resolve()) if found else None


def _run(argv, timeout=120):
    # Encoding affects diagnostic text only. Paths are Unicode argv, never shell text.
    kwargs = {'capture_output': True, 'timeout': timeout, 'check': False}
    if platform.system() == 'Windows':
        kwargs['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    result = subprocess.run(argv, **kwargs)
    log = (result.stdout + result.stderr).decode('utf-8', errors='replace')
    if result.returncode:
        raise ValueError(f'工具执行失败（退出码 {result.returncode}）：{log[-4000:]}')
    return result.stdout.decode('utf-8', errors='replace').strip(), log


def _wsl_prefix(executable, distro):
    args = [executable]
    if distro:
        args.extend(['--distribution', str(distro)])
    return args + ['--exec']


def discover_tools(config=None):
    config = config or {}
    errors = []
    hashcat = _find_tool('hashcat', config.get('hashcat_path'))
    hcx = _find_tool('hcxpcapngtool', config.get('hcx_path'))
    for key, found in [('hashcat_path', hashcat), ('hcx_path', hcx)]:
        if config.get(key) and not found:
            errors.append(f'配置的工具不存在：{key}')
    wsl = shutil.which('wsl.exe') if platform.system() == 'Windows' else None
    wsl_hcx = False
    distro = config.get('wsl_distro') or None
    if not hcx and wsl:
        try:
            stdout, _ = _run(_wsl_prefix(wsl, distro) + ['/usr/bin/which', 'hcxpcapngtool'], timeout=10)
            wsl_hcx = stdout.startswith('/') and '\n' not in stdout
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            errors.append('WSL 中未找到可用的 hcxtools：' + str(exc))
    return {'platform': platform.system(), 'hashcat': hashcat, 'hcxpcapngtool': hcx,
            'wsl': wsl, 'wsl_distro': distro, 'wsl_hcxtools': wsl_hcx,
            'converter_backend': 'native' if hcx else ('wsl' if wsl_hcx else None),
            'errors': errors}


def _source(path, limit):
    path = Path(path).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError('请选择一个普通文件。')
    size = path.stat().st_size
    if not 0 < size <= limit:
        raise ValueError(f'文件为空或超过大小上限（{limit // 1024 // 1024} MiB）。')
    return path


def _output(path, source=None):
    path = Path(path).expanduser().absolute()
    if source is not None and path.resolve() == source.resolve():
        raise ValueError('输出文件不能覆盖原始输入。')
    if path.exists() or path.is_symlink():
        raise ValueError('输出文件已存在，请选择新的文件名。')
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _hex(value, size=None, maximum=None):
    if len(value) % 2 or not _HEX.fullmatch(value):
        raise ValueError('十六进制字段无效')
    raw = bytes.fromhex(value)
    if size is not None and len(raw) != size:
        raise ValueError(f'字段长度应为 {size} 字节')
    if maximum is not None and len(raw) > maximum:
        raise ValueError(f'字段超过 {maximum} 字节')
    return raw


def read_targets(hashfile):
    """Validate WPA*01/02 records and group by AP plus exact SSID bytes."""
    source = _source(hashfile, MAX_HASH_BYTES)
    try:
        text = source.read_text(encoding='ascii')
    except UnicodeError as exc:
        raise ValueError('hc22000 应为 ASCII 文本；中文 SSID 必须以十六进制保存。') from exc
    groups = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.strip().split('*')
        try:
            if len(fields) != 9 or fields[0] != 'WPA' or fields[1] not in ('01', '02'):
                raise ValueError('仅支持 WPA*01（PMKID）和 WPA*02（EAPOL）记录')
            _hex(fields[2], size=16)
            ap = _hex(fields[3], size=6)
            _hex(fields[4], size=6)
            ssid = _hex(fields[5], maximum=32)
            if fields[1] == '01':
                if fields[6] or fields[7]:
                    raise ValueError('PMKID 记录不应包含 ANonce／EAPOL')
                if fields[8]:
                    _hex(fields[8], size=1)
            else:
                _hex(fields[6], size=32)
                eapol = _hex(fields[7], maximum=512)
                pair = _hex(fields[8], size=1)
                if len(eapol) < 99 or eapol[1] != 3:
                    raise ValueError('EAPOL-Key 数据过短或类型不正确')
                if int.from_bytes(eapol[2:4], 'big') + 4 != len(eapol):
                    raise ValueError('EAPOL 声明长度与实际数据不一致')
                if (pair[0] & 7) > 5:
                    raise ValueError('EAPOL message-pair 类型不支持')
        except ValueError as exc:
            raise ValueError(f'hc22000 第 {number} 行无效：{exc}') from exc
        target_id = ap.hex() + ':' + ssid.hex()
        if target_id not in groups:
            groups[target_id] = {'id': target_id, 'ssid': ssid.decode('utf-8', errors='backslashreplace'),
                                 'ssid_hex': ssid.hex(), 'bssid': ap.hex(':'), 'count': 0, 'lines': []}
        normalized = '*'.join([fields[0], *[value.lower() for value in fields[1:]]])
        if normalized not in groups[target_id]['lines']:
            groups[target_id]['lines'].append(normalized)
            groups[target_id]['count'] += 1
    if not groups:
        raise ValueError('文件中没有可测试的 WPA2 校验记录。')
    return list(groups.values())


def _copy_new(source, output):
    created = False
    try:
        with output.open('xb') as destination:
            created = True
            with source.open('rb') as original:
                shutil.copyfileobj(original, destination)
        try:
            output.chmod(0o600)
        except OSError:
            pass
    except Exception:
        if created:
            output.unlink(missing_ok=True)
        raise


def convert_capture(source, output, hcx_path=None, wsl_distro=None):
    """Return {path, backend, log, targets}; never overwrite or append to output."""
    source = _source(source, MAX_CAPTURE_BYTES)
    output = _output(output, source)
    if source.suffix.lower() == '.hc22000':
        targets = read_targets(source)
        _copy_new(source, output)
        return {'path': str(output), 'backend': 'hc22000', 'log': '已验证并复制 hc22000 文件。', 'targets': targets}
    if source.suffix.lower() not in ('.cap', '.pcap', '.pcapng'):
        raise ValueError('支持 .pcap、.pcapng、.cap 和 .hc22000 文件。')
    native = _find_tool('hcxpcapngtool', hcx_path)
    if hcx_path and not native:
        raise ValueError('配置的 hcxpcapngtool 不存在，请修正工具路径。')
    wsl = shutil.which('wsl.exe') if platform.system() == 'Windows' else None
    if not native and not wsl:
        raise ValueError('未找到 hcxtools。请配置 hcxpcapngtool，或在 Windows 的 WSL 中安装 hcxtools。')
    # hcxpcapngtool appends its output. Always convert into a fresh temporary path.
    with tempfile.TemporaryDirectory(prefix='convert-', dir=output.parent) as temp_dir:
        temporary = Path(temp_dir) / 'capture.hc22000'
        if native:
            argv = [native, '-o', str(temporary), str(source)]
            backend = 'native'
        else:
            prefix = _wsl_prefix(wsl, wsl_distro)
            _run(prefix + ['/usr/bin/which', 'hcxpcapngtool'], timeout=10)
            input_linux, _ = _run(prefix + ['wslpath', '-a', '-u', str(source)], timeout=10)
            output_linux, _ = _run(prefix + ['wslpath', '-a', '-u', str(temporary)], timeout=10)
            if not input_linux.startswith('/') or not output_linux.startswith('/') or '\n' in input_linux + output_linux:
                raise ValueError('WSL 文件路径转换失败。')
            argv = prefix + ['hcxpcapngtool', '-o', output_linux, input_linux]
            backend = 'wsl'
        _, log = _run(argv)
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise ValueError('未提取到可测试的握手，请重新采集。\n' + log[-3000:])
        targets = read_targets(temporary)
        _copy_new(temporary, output)
    return {'path': str(output), 'backend': backend, 'log': log, 'targets': targets}


def write_selected(hashfile, target_id, output):
    """Write one selected AP/SSID to a new file; return {path, target}."""
    source = _source(hashfile, MAX_HASH_BYTES)
    output = _output(output, source)
    target = next((item for item in read_targets(source) if item['id'] == target_id), None)
    if target is None:
        raise ValueError('选择的网络不存在，请重新导入文件。')
    with output.open('x', encoding='ascii', newline='\n') as stream:
        stream.write('\n'.join(target['lines']) + '\n')
    try:
        output.chmod(0o600)
    except OSError:
        pass
    return {'path': str(output), 'target': {key: value for key, value in target.items() if key != 'lines'}}
