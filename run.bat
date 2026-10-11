@echo off
REM Manual foreground run (for testing only). The installed task runs silently.
cd /d %~dp0
py -m uvicorn app:app --host 127.0.0.1 --port 8443
pause
