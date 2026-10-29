# Wi-Fi 本地审计工作台

在本机中文界面中导入 StickS3 采集的 Wi-Fi 握手，配置候选与计算预算，再交给 Hashcat 测试自有或获授权网络的口令。StickS3 负责采集，电脑负责离线计算；运行工作台不要求电脑连接被测试的 Wi-Fi。

## 功能

- 导入 `.pcap`、`.pcapng`、`.cap`、`.hc22000` 或 `.22000`，按 SSID 与 BSSID 选择目标网络。
- 生成中文原文、拼音、首字母、大小写、年份和自定义数字／符号组合，预览候选后再运行。
- 使用本地 UTF-8 字典、ASCII 规则、Hashcat 通用 PCFG 概率生成或格式枚举。
- 按阶段设置时间预算，管理任务队列、暂停、检查点恢复与本地结果。
- 提供设备检查、WPA2 基准测试和人工演示样本。

界面默认仅监听 `http://127.0.0.1:8873`。导入的握手、候选和任务结果保存在本地 `local-data`，工作台不上传这些数据。

## Windows 便携版

前往 [Releases](https://github.com/gqw995/wifi-audit-workbench/releases)，下载 `WiFiAudit-Windows-RTX5080.zip` 并完整解压到本地可写目录，双击 `启动工作台.cmd`。便携包包含 Windows Python、完整 Hashcat 8.0.0 和拼音依赖，无需另外安装 Python。

RTX 5080 需要兼容的 NVIDIA 驱动及 CUDA Toolkit 12.8 或更新版本。直接导入 `.hc22000` 无需 WSL；在 Windows 转换 PCAP 时，可使用 WSL Ubuntu 中的 hcxtools，或配置已验证的本地转换器。

安装、驱动、WSL 和首次演示的具体步骤见 [Windows 使用说明](Windows使用说明.md)。源码下载包不包含便携版运行库，不能直接用便携版 CMD 启动。

## 从源码运行

需要 Python 3.11 或更新版本，以及独立安装的完整 Hashcat 8.0.0。转换抓包文件还需要 hcxtools 的 `hcxpcapngtool`；已经转换的 `.hc22000` 可直接使用。

在仓库根目录创建并激活 Python 虚拟环境：

```bash
python -m venv .venv
```

Windows PowerShell：

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS／Linux：

```bash
source .venv/bin/activate
```

安装依赖并启动：

```bash
python -m pip install -r requirements.txt
python app.py
```

`requirements.txt` 固定使用 `pypinyin==0.55.0`。在只有 `python3` 命令的系统上，创建虚拟环境时使用 `python3 -m venv .venv`。

浏览器打开后，在“工具与设备”配置 Hashcat 完整路径；转换 PCAP 时再配置 hcxpcapngtool 或 Windows WSL 发行版。程序不会自动安装显卡驱动、Hashcat 或 WSL。Hashcat 必须保留官方分发包的模型、规则、模块等配套文件，不能只复制可执行文件。

可使用 `python app.py --no-browser` 禁止自动打开浏览器，或用 `--port` 指定其他本机端口。运行期间保留终端；退出前暂停任务并等待状态保存。

## 人工演示与验证范围

界面中的人工演示使用 `Codex-WiFi-Lab`，预设口令为 `Lab2026!42`。选择格式 `Lab2026!?d?d` 即可进行小范围控制测试。`examples` 还包含人工构造的中文 SSID、汉字口令和拼音口令样本；这些数据均不来自真实用户网络。

已在 macOS 上验证实际 Hashcat／hcxtools、中文候选、检查点恢复和界面流程。Windows／WSL 参数有模拟测试，**尚未在 Windows 和 RTX 5080 实机上完成验证**，没有该显卡的实测速率。首次使用应先检查设备、运行人工样本，再做本机基准测试。详细记录见 [新版验证记录](新版验证记录.txt) 和 [verification-v2](verification-v2)。

在仓库根目录运行自动化测试：

```bash
python -m unittest discover -s tests -v
```

未找回口令只表示本次候选与时间范围没有命中。中文原文按 UTF-8 字节处理，与拼音候选不同；通用 PCFG 不是专门面向中文口令训练的模型。恢复可能重算尚未保存的整个批次，界面刷新频率不代表检查点保存频率。Potfile 记录已找回的结果，不是所有试过的候选清单。

## 项目文件

| 路径 | 内容 |
| --- | --- |
| `app.py`、`static/` | 本机服务与中文界面 |
| `engine.py` | Hashcat 阶段、队列、预算与恢复 |
| `cn_candidates.py` | 中文／拼音候选生成 |
| `platform_tools.py` | 工具发现、抓包转换与目标选择 |
| `examples/`、`tests/` | 人工样本与自动化测试 |
| `verification-v2/` | 人工样本验证摘要 |

源码仓库排除本地任务、结果、缓存以及 `runtime`、`tools`、`vendor` 等便携包依赖目录。发布包中的依赖清单与全文件校验清单单独随 Release 分发。

成熟方案比较见 [方案调研](方案调研.md)，第三方软件来源与授权信息见 [工具来源与许可](工具来源与许可.md)。[旧版使用说明](使用说明.md) 保留为早期命令行入口参考；当前中文工作台入口是 `app.py`。
