@echo off
setlocal

cd /d "%~dp0"
call "%~dp0ai-web-auditor.cmd" gui

echo.
echo AI Web Auditor se ha cerrado.
pause
