#!/bin/zsh
cd -- "${0:A:h}" || exit 1
if [[ -x /opt/homebrew/bin/python3.11 ]]; then
  wifi_python=/opt/homebrew/bin/python3.11
else
  wifi_python=$(command -v python3)
fi
if [[ -z "$wifi_python" ]]; then
  print '未找到 Python 3。此入口需要现有 Python 环境。'
  read -r '?按回车关闭窗口。'
  exit 1
fi
print '正在启动本地工作台：http://127.0.0.1:8873'
print '计算期间请保留此窗口。结束前请先在界面暂停任务。'
"$wifi_python" -X utf8 app.py
wifi_exit=$?
print ''
if [[ $wifi_exit -ne 0 ]]; then
  print "程序已退出，退出码：$wifi_exit。请查看上方错误信息。"
fi
read -r '?按回车关闭窗口。'
exit "$wifi_exit"
