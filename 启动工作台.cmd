@echo off
chcp 65001 >nul
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
if errorlevel 1 goto directory_error
if not exist "runtime\python.exe" goto missing_runtime
echo 正在启动 Wi-Fi 本地审计工作台……
echo 浏览器地址：http://127.0.0.1:8873
echo 计算期间请保留此窗口。结束前请先在界面暂停任务。
"runtime\python.exe" -X utf8 "app.py"
set "wifi_exit=%ERRORLEVEL%"
echo.
if not "%wifi_exit%"=="0" echo 程序已退出，退出码：%wifi_exit%。请查看上方错误信息。
echo 按任意键关闭此窗口。
pause >nul
exit /b %wifi_exit%

:missing_runtime
echo 未找到 runtime\python.exe。请先完整解压发布包，再运行本文件。
echo 不要在压缩包预览窗口内直接双击启动器。
pause
exit /b 1

:directory_error
echo 无法进入程序目录。请将整个文件夹解压到本地可写目录。
pause
exit /b 1
