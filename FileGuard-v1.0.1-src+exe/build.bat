@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ============================================================
echo   FileGuard 打包脚本  (生成单文件 dist\FileGuard.exe)
echo ============================================================
echo.

if "%PYTHON%"=="" set PYTHON=python

echo [1/4] 检查 Python 环境...
"%PYTHON%" --version || goto :fail

echo.
echo [2/4] 安装依赖 (Flask / watchdog / pywin32 / PyYAML / pyinstaller)...
"%PYTHON%" -m pip install -r requirements.txt pyinstaller || goto :fail

echo.
echo [3/4] 生成图标...
"%PYTHON%" tools\make_icon.py

echo.
echo [4/4] 清理旧构建并打包（首次约需 1-3 分钟）...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
"%PYTHON%" -m PyInstaller --noconfirm --clean FileGuard.spec || goto :fail

echo.
echo ============================================================
echo   打包完成 ^>^>  dist\FileGuard.exe
echo   说明：exe 已内置 UAC 管理员清单，双击会请求提权
echo   首次运行会在 exe 同目录生成 config.yaml / 日志 / 回收站
echo ============================================================
echo.
dir /b dist
pause
exit /b 0

:fail
echo.
echo *** 构建失败，请查看上方错误信息 ***
pause
exit /b 1
