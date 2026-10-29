#!/usr/bin/env python3
"""Local Chinese interface for mature Hashcat/hcxtools engines."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse
import uuid
import webbrowser

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))
from cn_candidates import generate_candidates
from engine import JobManager
from platform_tools import convert_capture, discover_tools, read_targets, write_selected
from wifi_audit import mask_info


def save_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def load_json(path, default=None):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def checked_id(value):
    if not isinstance(value, str) or len(value) != 32 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("无效的记录编号。")
    return value


class Application:
    def __init__(self, data_dir):
        self.data = Path(data_dir).resolve()
        self.data.mkdir(parents=True, exist_ok=True)
        for folder in ("imports", "plans", "jobs"):
            (self.data / folder).mkdir(exist_ok=True)
        self.config = load_json(self.data / "config.json", {})
        if os.name == "nt" and not self.config.get("hashcat_path"):
            bundled = ROOT / "tools" / "hashcat" / "hashcat.exe"
            if bundled.is_file():
                self.config["hashcat_path"] = str(bundled)
        self.tools = discover_tools(self.config)
        self.manager = JobManager(self.data / "jobs", self.tools.get("hashcat") or "")
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.diagnostic = {"state": "idle", "output": "", "kind": ""}

    def _record(self, collection, item):
        return self.data / collection / checked_id(item)

    def state(self):
        imports = []
        for file in sorted((self.data / "imports").glob("*/meta.json"), reverse=True):
            item = load_json(file)
            imports.append(item)
        return {"tools": self.tools, "config": self.config, "imports": imports,
                "jobs": self.manager.list_jobs(), "diagnostic": self.diagnostic,
                "platform": sys.platform, "data_dir": str(self.data)}

    def settings(self, settings):
        with self.lock:
            jobs = self.manager.list_jobs()
            if any(j.get("status") in ("running", "queued", "pausing") for j in jobs):
                raise ValueError("请先暂停计算任务，再更改工具路径。")
            config = {}
            for field in ("hashcat_path", "hcx_path", "wsl_distro"):
                value = str(settings.get(field, "")).strip()
                if "\0" in value:
                    raise ValueError("路径包含无效字符。")
                config[field] = value
            tools = discover_tools(config)
            if config["hashcat_path"] and not tools.get("hashcat"):
                raise ValueError("找不到指定的 Hashcat。请选择解压目录中的 hashcat.exe。")
            self.manager.close()
            self.config, self.tools = config, tools
            self.manager = JobManager(self.data / "jobs", tools.get("hashcat") or "")
            save_json(self.data / "config.json", config)
            return self.state()

    def import_file(self, input_stream, length, name, kind):
        if kind not in ("capture", "words"):
            raise ValueError("不支持的文件类别。")
        maximum = 64 * 1024 * 1024 if kind == "capture" else 256 * 1024 * 1024
        if not 0 < length <= maximum:
            raise ValueError("文件为空或超过限制：握手 64 MB，字典 256 MB。")
        name = name.replace("\\", "/").split("/")[-1]
        suffix = Path(name).suffix.lower()
        if kind == "capture" and suffix not in (".pcap", ".pcapng", ".cap", ".hc22000", ".22000"):
            raise ValueError("请选择 pcap、pcapng、cap 或 hc22000 文件。")
        ident = uuid.uuid4().hex
        folder = self.data / "imports" / ident
        folder.mkdir()
        source = folder / ("source" + (suffix if kind == "capture" else ".txt"))
        remaining = length
        try:
            with source.open("wb") as output:
                while remaining:
                    chunk = input_stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("文件传输未完成。")
                    output.write(chunk)
                    remaining -= len(chunk)
            item = {"id": ident, "name": name, "kind": kind, "size": length,
                    "created": time.time(), "path": str(source)}
            if kind == "capture":
                converted = folder / "capture.hc22000"
                if suffix == ".22000":
                    source.rename(source.with_suffix(".hc22000"))
                    source = source.with_suffix(".hc22000")
                    item["path"] = str(source)
                result = convert_capture(source, converted, self.config.get("hcx_path") or None,
                                         self.config.get("wsl_distro") or None)
                item.update({"hash_path": str(converted), "backend": result["backend"],
                             "targets": [{k: v for k, v in t.items() if k != "lines"}
                                         for t in read_targets(converted)]})
                (folder / "conversion.log").write_text(result.get("log", ""), encoding="utf-8")
            else:
                count = 0
                with source.open(encoding="utf-8-sig", errors="strict") as words:
                    for line in words:
                        if "\0" in line:
                            raise ValueError("字典含 NUL 字符；请使用每行一个候选的 UTF-8 文本。")
                        count += 1
                item["lines"] = count
            save_json(folder / "meta.json", item)
            return item
        except Exception:
            shutil.rmtree(folder)
            raise

    def demo(self):
        source = ROOT / "examples" / "synthetic.hc22000"
        with source.open("rb") as stream:
            return self.import_file(stream, source.stat().st_size, "人工演示.hc22000", "capture")

    def preview(self, options):
        if not isinstance(options, dict):
            raise ValueError("计划配置应为对象。")
        capture = load_json(self._record("imports", options.get("capture_id")) / "meta.json")
        if not capture or capture["kind"] != "capture":
            raise ValueError("请先导入握手文件。")
        seconds = options.get("seconds", 300)
        if type(seconds) is not int or not 5 <= seconds <= 86400:
            raise ValueError("每阶段时限应为 5–86400 的整数秒。")
        maximum = options.get("max_candidates", 200000)
        if type(maximum) is not int or not 1 <= maximum <= 200000:
            raise ValueError("候选上限应为 1–200000 的整数。")
        for field in ("include_literal", "include_prefix", "rules", "pcfg"):
            if type(options.get(field, False)) is not bool:
                raise ValueError("测试开关必须使用布尔值：" + field)
        start, end = options.get("year_start"), options.get("year_end")
        if (start is None) != (end is None):
            raise ValueError("请同时填写年份起点和终点。")
        if start is not None and (type(start) is not int or type(end) is not int
                                  or not 1900 <= start <= end <= 2100):
            raise ValueError("年份应为 1900–2100 的整数，且起点不大于终点。")
        ident = uuid.uuid4().hex
        folder = self.data / "plans" / ident
        folder.mkdir()
        try:
            return self._build_preview(options, capture, seconds, ident, folder)
        except Exception:
            shutil.rmtree(folder)
            raise

    def _build_preview(self, options, capture, seconds, ident, folder):
        selected = write_selected(Path(capture["hash_path"]), str(options.get("target_id", "")),
                                  folder / "target.hc22000")
        stages, descriptions = [], []
        cn = None
        seeds = options.get("seeds", [])
        if not isinstance(seeds, list):
            raise ValueError("中文词组格式不正确。")
        if any(str(seed).strip() for seed in seeds):
            cn = generate_candidates(seeds, folder, suffixes=options.get("suffixes", []),
                                     separators=options.get("separators", [""]),
                                     year_start=options.get("year_start"),
                                     year_end=options.get("year_end"),
                                     include_literal=options.get("include_literal", False),
                                     include_prefix=options.get("include_prefix", False),
                                     max_candidates=options.get("max_candidates", 200000))
            if cn["count"]:
                stages.append({"name": "中文词组与拼音组合", "mode": 0,
                               "args": [str(cn["path"])], "runtime": seconds})
                descriptions.append({"name": stages[-1]["name"], "count": cn["count"],
                                     "note": "精确字节候选，不应用会切断汉字的变形规则"})
        word_id = options.get("wordlist_id")
        if word_id:
            words = load_json(self._record("imports", word_id) / "meta.json")
            if not words or words["kind"] != "words":
                raise ValueError("请选择已导入的 UTF-8 字典。")
            # Freeze and remove BOM without changing any candidate's other bytes.
            clean = folder / "dictionary.txt"
            ascii_only = folder / "ascii.txt"
            ascii_count = 0
            with Path(words["path"]).open(encoding="utf-8-sig") as src, \
                    clean.open("w", encoding="utf-8", newline="\n") as dst, \
                    ascii_only.open("w", encoding="ascii", newline="\n") as asc:
                for line in src:
                    word = line.rstrip("\r\n")
                    dst.write(word + "\n")
                    if word.isascii() and word.isprintable() and 1 <= len(word) <= 63:
                        asc.write(word + "\n")
                        ascii_count += 1
            stages.append({"name": "本地字典", "mode": 0, "args": [str(clean)], "runtime": seconds})
            descriptions.append({"name": "本地字典", "count": words["lines"], "note": words["name"]})
            if options.get("rules") and ascii_count:
                candidates = [Path(self.tools.get("hashcat") or ".").parent / "rules" / "best66.rule",
                              Path("/opt/homebrew/opt/hashcat/share/hashcat/rules/best66.rule")]
                rule = next((p for p in candidates if p.is_file()), None)
                if rule is None:
                    raise ValueError("未找到 best66.rule。请保留完整的 Hashcat 8 解压目录。")
                stages.append({"name": "ASCII 字典变形", "mode": 0,
                               "args": [str(ascii_only), "-r", str(rule), "-S"], "runtime": seconds})
                descriptions.append({"name": "ASCII 字典变形", "count": None,
                                     "note": f"仅变形 {ascii_count:,} 个 ASCII 词根；汉字原文保留在上一阶段"})
        if options.get("pcfg"):
            stages.append({"name": "通用概率生成", "mode": 4, "args": [], "runtime": seconds})
            descriptions.append({"name": "通用概率生成", "count": None,
                                 "note": "Hashcat 自带 PCFG 模型；非中文专用，按本阶段时间预算停止"})
        masks = options.get("masks", [])
        if not isinstance(masks, list) or len(masks) > 20 or any(not isinstance(mask, str) for mask in masks):
            raise ValueError("最多配置 20 个文本格式。")
        for mask in masks:
            mask = mask.strip()
            if not mask:
                continue
            length, count = mask_info(mask)
            if not 8 <= length <= 63:
                raise ValueError("格式生成的密码应为 8–63 字节。")
            stages.append({"name": "格式枚举：" + mask, "mode": 3, "args": [mask], "runtime": seconds})
            descriptions.append({"name": stages[-1]["name"], "count": count, "note": "在指定范围内枚举"})
        if not stages:
            raise ValueError("请至少配置中文词组、字典、概率生成或一种格式枚举。")
        target = selected["target"]
        plan = {"id": ident, "target_path": selected["path"], "target": target,
                "title": str(options.get("title") or target["ssid"])[:100],
                "stages": stages, "descriptions": descriptions,
                "max_seconds": seconds * len(stages), "candidates": cn,
                "created": time.time(), "capture_name": capture["name"]}
        save_json(folder / "plan.json", plan)
        return plan

    def run_plan(self, ident):
        if self.diagnostic["state"] == "running":
            raise ValueError("设备检查／基准测试正在运行，请等待结束。")
        if not self.tools.get("hashcat"):
            raise ValueError("请先在工具设置中指定 Hashcat 8 的可执行文件。")
        plan = load_json(self._record("plans", ident) / "plan.json")
        if not plan:
            raise ValueError("计划不存在，请重新预览。")
        job_id = self.manager.create_job(plan["target_path"], plan["stages"], title=plan["title"],
                                        metadata={"target": plan["target"], "plan_id": ident,
                                                  "capture_name": plan["capture_name"]})
        self.manager.start(job_id)
        return {"id": job_id}

    def diagnose(self, benchmark=False):
        with self.lock:
            if self.diagnostic["state"] == "running":
                raise ValueError("设备检查正在进行。")
            if any(j.get("status") in ("running", "queued", "pausing") for j in self.manager.list_jobs()):
                raise ValueError("请先暂停计算任务，再运行设备检查。")
            executable = self.tools.get("hashcat")
            if not executable:
                raise ValueError("尚未找到 Hashcat。请设置工具路径。")
            self.diagnostic = {"state": "running", "output": "", "kind": "benchmark" if benchmark else "devices"}
            def work():
                try:
                    command = [executable, "-m", "22000", "-b" if benchmark else "-I"]
                    result = subprocess.run(command, cwd=str(Path(executable).parent),
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            encoding="utf-8", errors="replace", timeout=180)
                    self.diagnostic = {"state": "done" if result.returncode == 0 else "error",
                                       "output": result.stdout[-24000:], "kind": "benchmark" if benchmark else "devices"}
                except Exception as exc:
                    self.diagnostic = {"state": "error", "output": str(exc), "kind": "devices"}
            threading.Thread(target=work, daemon=True).start()
            return self.diagnostic

    def results(self, ident):
        job = self.manager.get(ident)
        path = self.data / "jobs" / checked_id(ident) / "found.txt"
        values = []
        if path.is_file():
            # Hashcat uses $HEX[...] to preserve bytes in non-ASCII output.
            for raw in path.read_bytes()[:1024 * 1024].splitlines():
                if raw.startswith(b"$HEX[") and raw.endswith(b"]"):
                    try:
                        raw = bytes.fromhex(raw[5:-1].decode("ascii"))
                    except ValueError:
                        pass
                values.append(raw.decode("utf-8", errors="backslashreplace"))
        return {"passwords": list(dict.fromkeys(values)), "path": str(path),
                "status": job["status"]}


class Handler(BaseHTTPRequestHandler):
    server_version = "WiFiAuditLocal/2"

    def log_message(self, *_):
        pass

    def reply(self, value, status=200, content_type="application/json; charset=utf-8"):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _allowed(self, api=True):
        expected = f"127.0.0.1:{self.server.server_port}"
        if self.headers.get("Host") != expected:
            self.reply({"error": "只允许本机访问。"}, 403)
            return False
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + expected:
            self.reply({"error": "不允许跨站请求。"}, 403)
            return False
        token = self.headers.get("X-Local-Token", "")
        if api and (not token.isascii() or not secrets.compare_digest(token, self.server.application.token)):
            self.reply({"error": "会话已失效，请刷新页面。"}, 403)
            return False
        return True

    def do_GET(self):
        route = urlparse(self.path).path
        if not self._allowed(api=route != "/"):
            return
        app = self.server.application
        try:
            if route == "/":
                html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
                self.reply(html.replace("__LOCAL_TOKEN__", app.token).encode(), content_type="text/html; charset=utf-8")
            elif route == "/api/state":
                self.reply(app.state())
            elif route.startswith("/api/jobs/"):
                self.reply(app.manager.get(route.rsplit("/", 1)[-1]))
            else:
                self.reply({"error": "页面不存在。"}, 404)
        except (ValueError, TypeError, KeyError, FileNotFoundError) as exc:
            self.reply({"error": str(exc)}, 400)

    def do_POST(self):
        if not self._allowed():
            return
        app = self.server.application
        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if parsed.path == "/api/upload":
                query = parse_qs(parsed.query)
                self.reply(app.import_file(self.rfile, length, query.get("name", ["input"])[0],
                                           query.get("kind", ["capture"])[0]))
                return
            if not 0 <= length <= 128 * 1024:
                raise ValueError("请求内容过大。")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("请求格式错误。")
            if parsed.path == "/api/settings":
                result = app.settings(body)
            elif parsed.path == "/api/demo":
                result = app.demo()
            elif parsed.path == "/api/preview":
                result = app.preview(body)
            elif parsed.path == "/api/run":
                result = app.run_plan(body.get("plan_id"))
            elif parsed.path == "/api/pause":
                app.manager.pause(body["id"])
                result = {"ok": True}
            elif parsed.path == "/api/resume":
                app.manager.resume(body["id"])
                result = {"ok": True}
            elif parsed.path == "/api/diagnose":
                result = app.diagnose(bool(body.get("benchmark")))
            elif parsed.path == "/api/result":
                result = app.results(body["id"])
            else:
                self.reply({"error": "接口不存在。"}, 404)
                return
            self.reply(result)
        except (ValueError, TypeError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
            self.reply({"error": str(exc)}, 400)


def main():
    parser = argparse.ArgumentParser(description="Wi-Fi 本地密码审计工作台")
    parser.add_argument("--port", type=int, default=8873)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "local-data")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    app = Application(args.data_dir)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.application = app
    url = f"http://127.0.0.1:{server.server_port}"
    print("本地工作台：" + url, flush=True)
    print("计算期间请保留此窗口。任务数据：" + str(app.data), flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在保存任务状态……", flush=True)
    finally:
        server.server_close()
        app.manager.close()


if __name__ == "__main__":
    main()
