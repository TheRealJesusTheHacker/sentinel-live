@echo off
REM Build SentinelLive.exe locally on Windows (requires Python 3.11+).
REM The GitHub Actions workflow does this automatically on every release.
cd /d %~dp0
py -m pip install --quiet --require-hashes -r requirements-build.lock.txt
py -m PyInstaller --noconfirm --onefile --noconsole --name SentinelLive ^
  --add-data "templates;templates" ^
  --add-data "static;static" ^
  --add-data "insights;insights" ^
  --hidden-import aiosqlite ^
  app.py
echo.
echo Built: %~dp0dist\SentinelLive.exe
pause
