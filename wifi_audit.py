#!/usr/bin/env python3
"""Local WPA2 audit launcher. Cryptographic work is performed by Hashcat."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
DEFAULT_RULE = Path('/opt/homebrew/opt/hashcat/share/hashcat/rules/best66.rule')


def local_file(value):
    value = value.strip()
    path = Path(value).expanduser()
    if not path.is_file():
        parts = shlex.split(value)
        if len(parts) != 1:
            raise ValueError('请一次输入一个文件路径。')
        path = Path(parts[0]).expanduser()
    if not path.is_file():
        raise ValueError('找不到文件：' + str(path))
    return path.resolve()


def binary(name):
    found = shutil.which(name)
    if not found:
        path = Path('/opt/homebrew/bin') / name
        found = str(path) if path.is_file() else None
    if not found:
        raise ValueError('未找到 ' + name + '，请先安装 hashcat 和 hcxtools。')
    return found


def mask_info(mask):
    sizes = {'d': 10, 'l': 26, 'u': 26, 's': 33, 'a': 95, '?': 1}
    count, length, i = 1, 0, 0
    if not mask or not mask.isascii() or not mask.isprintable():
        raise ValueError('格式请使用可打印的英文字符；?d 数字，?l 小写，?u 大写，?a 全部可打印字符，?? 表示问号。')
    while i < len(mask):
        if mask[i] == '?':
            i += 1
            if i >= len(mask) or mask[i] not in sizes:
                raise ValueError('不支持的格式占位符；支持 ?d ?l ?u ?s ?a 和 ??。')
            count *= sizes[mask[i]]
        length += 1
        i += 1
    return length, count


def select_target(path, run_dir):
    groups = {}
    for line in path.read_text(encoding='ascii').splitlines():
        fields = line.strip().split('*')
        if len(fields) < 9 or fields[0] != 'WPA' or fields[1] not in ('01', '02'):
            continue
        try:
            ap = bytes.fromhex(fields[3])
            ssid = bytes.fromhex(fields[5])
        except ValueError:
            continue
        if len(ap) != 6:
            continue
        groups.setdefault((ap, ssid), []).append(line)
    if not groups:
        raise ValueError('没有可用的 WPA-PBKDF2 校验记录。请重新采集完整的 WPA2-Personal 握手。')
    items = list(groups.items())
    for index, ((ap, ssid), _) in enumerate(items, 1):
        label = ssid.decode('utf-8', errors='backslashreplace')
        print(f'{index}. SSID={label!r}  BSSID={ap.hex(":")}')
    pick = 1 if len(items) == 1 else int(input('选择你家路由器的编号：'))
    if not 1 <= pick <= len(items):
        raise ValueError('编号超出范围。')
    selected = run_dir / 'selected.hc22000'
    selected.write_text('\n'.join(dict.fromkeys(items[pick - 1][1])) + '\n', encoding='ascii')
    return selected


def main():
    parser = argparse.ArgumentParser(description='StickS3 采集，Mac 本地计算；适用于 WPA2-Personal。')
    parser.add_argument('--capture', help='.pcap/.pcapng/.cap 或 .hc22000 文件')
    parser.add_argument('--mode', choices=('dict', 'rules', 'mask', 'hybrid'))
    parser.add_argument('--words', help='每行一个候选词的 UTF-8 文件')
    parser.add_argument('--rule', help='Hashcat 规则文件；默认 best66.rule')
    parser.add_argument('--mask', help='例如 Home?d?d?d?d；混合模式仅填写后缀格式')
    parser.add_argument('--seconds', type=int, help='计算时限秒数，0 表示不限时；默认 300')
    args = parser.parse_args()
    os.umask(0o077)
    hashcat = binary('hashcat')
    capture = local_file(args.capture or input('把握手文件拖入终端，然后回车：'))
    mode = args.mode
    if not mode:
        print('1 字典   2 字典＋变形规则   3 指定格式枚举   4 词根＋格式后缀')
        mode = {'1': 'dict', '2': 'rules', '3': 'mask', '4': 'hybrid'}.get(input('选择 [3]：').strip() or '3')
        if mode is None:
            raise ValueError('无效的模式编号。')
    words = None
    if mode in ('dict', 'rules', 'hybrid'):
        words = local_file(args.words or input('把字典／词根文件拖入终端，然后回车：'))
    mask = None
    if mode in ('mask', 'hybrid'):
        hint = '完整格式，例如 Home?d?d?d?d：' if mode == 'mask' else '后缀格式，例如 ?d?d?d?d：'
        mask = args.mask if args.mask is not None else input(hint).strip()
        length, count = mask_info(mask)
        if mode == 'mask' and not 8 <= length <= 63:
            raise ValueError('WPA2 口令长度应为 8–63 字节。')
        if mode == 'hybrid' and length > 63:
            raise ValueError('后缀过长。')
        print(f'格式产生 {count:,} 个组合' + ('／每个词根。' if mode == 'hybrid' else '。'))
    rule = local_file(args.rule or str(DEFAULT_RULE)) if mode == 'rules' else None
    seconds = args.seconds
    if seconds is None:
        seconds = int(input('计算时限，单位秒 [300]，0 为不限时：').strip() or '300')
    if seconds < 0:
        raise ValueError('时限不能为负数。')
    results = ROOT / 'results'
    results.mkdir(exist_ok=True, mode=0o700)
    run_dir = Path(tempfile.mkdtemp(prefix='run-', dir=results))
    print('本次结果目录：', run_dir, flush=True)
    if capture.suffix.lower() == '.hc22000':
        converted = capture
    else:
        converted = run_dir / 'converted.hc22000'
        subprocess.run([binary('hcxpcapngtool'), '-o', str(converted), str(capture)], check=True)
        if not converted.is_file() or not converted.stat().st_size:
            raise ValueError('采集文件没有转换出可测试的握手。请重新采集。')
    target = select_target(converted, run_dir)
    command = [hashcat, '-m', '22000', '-a', {'dict': '0', 'rules': '0', 'mask': '3', 'hybrid': '6'}[mode], str(target)]
    if words:
        command.append(str(words))
    if mask:
        command.append(mask)
    if rule:
        command.extend(['-r', str(rule)])
    if mode in ('rules', 'hybrid'):
        # Expand short roots before WPA2's minimum-length check.
        command.append('-S')
    command.extend(['--session', run_dir.name, '--potfile-disable', '--restore-disable', '--logfile-disable',
                    '--outfile', str(run_dir / 'found.txt'), '--outfile-format', '2', '--status', '--status-timer', '10'])
    if seconds:
        command.extend(['--runtime', str(seconds)])
    (run_dir / 'command.txt').write_text(shlex.join(command) + '\n', encoding='utf-8')
    print('开始本地计算。终端内可按 s 查看状态、p 暂停、q 结束。此入口重新运行会从头计算。', flush=True)
    completed = subprocess.run(command, cwd=run_dir)
    found = run_dir / 'found.txt'
    if found.is_file() and found.stat().st_size:
        print('\n已找回至少一个口令，保存在：', found)
    else:
        print('\n本次未找回口令；仅说明本次范围／时间内未找到，不能据此证明密码安全。')
    print('Hashcat 退出码：', completed.returncode, '；详细状态见上方输出。')
    return 0 if completed.returncode in (0, 1, 2, 3, 4) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError, EOFError) as exc:
        print('无法继续：', exc, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\n已中止。')
        sys.exit(130)
