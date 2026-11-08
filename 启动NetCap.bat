@echo off
rem NetCap 启动器（优先用 exe，找不到再退回 python 脚本）
cd /d "%~dp0"
if exist "%~dp0NetCap.exe" (
    start "" "%~dp0NetCap.exe"
    exit /b
)
start "" pythonw.exe "%~dp0netcap.py"
