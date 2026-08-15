@echo off
setlocal

set "PROJECT_ROOT=%~dp0"
set "PYTHONPATH=%PROJECT_ROOT%src;%PYTHONPATH%"

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py -3 -m ai_web_auditor %*
    exit /b %ERRORLEVEL%
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python -m ai_web_auditor %*
    exit /b %ERRORLEVEL%
)

where python3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python3 -m ai_web_auditor %*
    exit /b %ERRORLEVEL%
)

set "CODEX_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%CODEX_PYTHON%" (
    "%CODEX_PYTHON%" -m ai_web_auditor %*
    exit /b %ERRORLEVEL%
)

echo Python no esta disponible en PATH.
echo Instala Python 3.10+ desde https://www.python.org/downloads/ y marca "Add python.exe to PATH".
exit /b 1
