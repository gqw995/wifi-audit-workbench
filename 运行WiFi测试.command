#!/bin/zsh
cd -- "${0:A:h}" || exit 1
export PATH="/opt/homebrew/bin:$PATH"
if [[ -x /opt/homebrew/bin/python3.11 ]]; then
  /opt/homebrew/bin/python3.11 wifi_audit.py
else
  /usr/bin/python3 wifi_audit.py
fi
printf '\n按回车关闭窗口。'
read -r
