"""Bounded, offline Chinese/pinyin candidates for an existing WPA2 audit.

This module only creates candidate text. Hashcat performs all cryptography.
Inputs and outputs are exact Unicode strings encoded as UTF-8, without implicit
normalization. Literal non-ASCII passwords are opt-in because router support
varies. Do not apply byte-position Hashcat rules to those literal candidates.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import tempfile

try:
    from pypinyin import Style, lazy_pinyin
except ImportError:
    Style = lazy_pinyin = None


DEFAULT_SUFFIXES = ("123", "1234", "123456", "520", "1314", "666", "888")
DEFAULT_SEPARATORS = ("", "_", "@", "!")
MAX_CANDIDATES = 200_000


def _strings(values, name, limit):
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{name}应为字符串列表，不能是单个字符串。")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"{name}只能包含字符串。")
        result.append(value)
        if len(result) > limit:
            raise ValueError(f"{name}最多允许 {limit} 项。")
    return result


def _root_forms(seeds, include_literal, skipped):
    """Keep exact roots first, followed by a few explicit ASCII case variants."""
    roots, cases = {}, {}
    for seed in seeds:
        if not seed:
            skipped["empty_seed"] += 1
            continue
        if not seed.isprintable():
            skipped["invalid_seed"] += 1
            continue
        if len(seed.encode("utf-8")) > 256:
            skipped["overlong_seed"] += 1
            continue
        if seed.isascii():
            forms = [seed]
        else:
            if lazy_pinyin is None:
                raise RuntimeError("缺少离线拼音库 pypinyin；请运行安装程序或安装 pypinyin 0.55.0。")
            syllables = lazy_pinyin(seed, style=Style.NORMAL, v_to_u=False)
            full = "".join(syllables)
            initials = "".join(lazy_pinyin(seed, style=Style.FIRST_LETTER, v_to_u=False))
            # Unknown characters remain unchanged in pypinyin. Do not silently
            # discard them and accidentally test a different word.
            forms = [word for word in (full, initials) if word.isascii() and word.isprintable()]
            if full.isascii():
                cases.setdefault("".join(part[:1].upper() + part[1:] for part in syllables), None)
            if include_literal:
                forms.insert(0, seed)
        for root in forms:
            if not root:
                continue
            roots.setdefault(root, None)
            if root.isascii():
                for variant in (root.lower(), root[:1].upper() + root[1:].lower(), root.upper()):
                    cases.setdefault(variant, None)
    for root in cases:
        roots.setdefault(root, None)
    return list(roots)


def generate_candidates(seeds, output_dir, *, suffixes=None, separators=None,
                        year_start=None, year_end=None, include_literal=False,
                        max_candidates=MAX_CANDIDATES, include_prefix=False):
    """Write a deterministic, deduplicated UTF-8 candidate file and manifest.

    Each seed is used exactly as supplied. Manual pinyin is just another Latin
    seed; phrase-aware pypinyin uses one reading, never a polyphone cross-product.
    Default suffixes are finite test presets, not an empirical popularity rank.
    A year range must be explicitly supplied. The hard limits bound work/memory.

    ``roots`` is the number of distinct root forms. ``skipped`` counts only the
    candidates visited before stopping, not an estimate of the remaining space.
    ``truncated`` means another valid unique candidate existed beyond the cap.
    Returned ``path`` is unique, so generating again cannot overwrite a running
    or resumable job's input. Call Hashcat with --wordlist-autohex-disable to
    preserve literal strings such as $HEX[...].
    """
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= MAX_CANDIDATES:
        raise ValueError(f"候选上限应为 1–{MAX_CANDIDATES:,} 的整数。")
    if not isinstance(include_literal, bool) or not isinstance(include_prefix, bool):
        raise ValueError("原文和前缀选项必须是布尔值。")
    seeds = _strings(seeds, "输入词", 200)
    suffixes = _strings(DEFAULT_SUFFIXES if suffixes is None else suffixes, "后缀", 100)
    separators = _strings(DEFAULT_SEPARATORS if separators is None else separators, "连接符", 8)
    for name, items in (("后缀", suffixes), ("连接符", separators)):
        if any(value and (not value.isprintable() or len(value.encode("utf-8")) > 63) for value in items):
            raise ValueError(f"{name}不能含控制字符或超过 63 个 UTF-8 字节。")
        if not include_literal and any(not value.isascii() for value in items):
            raise ValueError(f"{name}含非 ASCII 字符，请先启用字面原文测试。")
    if (year_start is None) != (year_end is None):
        raise ValueError("请同时填写年份起点和终点。")
    if year_start is not None:
        if (isinstance(year_start, bool) or isinstance(year_end, bool)
                or not isinstance(year_start, int) or not isinstance(year_end, int)
                or not 1900 <= year_start <= year_end <= 2100):
            raise ValueError("年份范围应在 1900–2100 之间，且起点不大于终点。")
        suffixes += [str(year) for year in range(year_start, year_end + 1)]
    suffixes = list(dict.fromkeys(suffixes))
    separators = list(dict.fromkeys(separators))
    skipped = Counter()
    roots = _root_forms(seeds, include_literal, skipped)

    def combinations():
        yield from roots
        # Traverse the suffix first so every root gets a turn before moving to
        # the next suffix, instead of spending the entire budget on one seed.
        for suffix in suffixes:
            for separator in separators:
                for root in roots:
                    yield root + separator + suffix
                    if include_prefix:
                        yield suffix + separator + root

    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, filename = tempfile.mkstemp(prefix="cn-candidates-", suffix=".txt", dir=output_dir)
    path = Path(filename)
    manifest_path = path.with_suffix(".json")
    seen, preview = set(), []
    digest = hashlib.sha256()
    truncated = False
    try:
        with os.fdopen(fd, "wb") as stream:
            for candidate in combinations():
                encoded = candidate.encode("utf-8")
                if len(encoded) < 8:
                    skipped["too_short"] += 1
                    continue
                if len(encoded) > 63:
                    skipped["too_long"] += 1
                    continue
                if encoded in seen:
                    skipped["duplicate"] += 1
                    continue
                if len(seen) == max_candidates:
                    truncated = True
                    break
                seen.add(encoded)
                record = encoded + b"\n"
                stream.write(record)
                digest.update(record)
                if len(preview) < 12:
                    preview.append(candidate)
        result = {"path": str(path), "manifest": str(manifest_path), "count": len(seen),
                  "roots": len(roots), "truncated": truncated, "skipped": dict(skipped),
                  "preview": preview, "encoding": "utf-8", "sha256": digest.hexdigest()}
        manifest = {"generator": "cn_candidates/1", "config": {
            "seeds": seeds, "suffixes": suffixes, "separators": separators,
            "year_start": year_start, "year_end": year_end, "include_literal": include_literal,
            "include_prefix": include_prefix, "max_candidates": max_candidates}, "result": result}
        with manifest_path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(manifest_path, 0o600)
        return result
    except BaseException:
        path.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        raise
