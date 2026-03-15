@echo off
REM Wrapper script for repomap CLI
REM Uses uv to run repomap from the tool's own virtualenv

set "VIRTUAL_ENV="
set "SCRIPT_DIR=%~dp0"
REM Remove trailing backslash to avoid escaping issues with \"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
uv run --project "%SCRIPT_DIR%" repomap %*
