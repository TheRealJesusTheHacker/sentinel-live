@echo off
REM Build SentinelLive.exe locally on Windows (requires Python 3.11+).
REM The GitHub Actions workflow does this automatically on every release.
cd /d %~dp0
py -m pip install --quiet -r requirements.txt pyinstaller
py -m PyInstaller --noconfirm --onefile --noconsole --name SentinelLive ^
  --add-data "templates;templates" ^
  --add-data "static;static" ^
  --hidden-import aiosqlite ^
  app.py
echo.
echo Built: %~dp0dist\SentinelLive.exe
pause
