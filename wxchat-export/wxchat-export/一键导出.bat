@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ================================================================
echo   微信聊天记录一键导出
echo ================================================================
echo.
set "PY=python"
where python >nul 2>nul && goto run
set "PY=py -3"
where py >nul 2>nul && goto run
echo [!] 没有找到 Python，请先安装 Python 3.10 以上版本。
echo     下载: https://www.python.org/downloads/windows/
echo     安装时请勾选 Add Python to PATH。
echo.
pause
exit /b 1
:run
%PY% main.py %*
echo.
echo 完成，按任意键关闭窗口。
pause >nul
