@echo off
cd /d "%~dp0"

REM Starts the server detached and console-less, then exits -- see
REM apps/launcher.py. This window can be closed at any time; the server
REM keeps running, and closing the page in the browser is what stops it.
REM
REM Only cmd built-ins are used below. timeout/where/ping are separate
REM programs that another entry on PATH can shadow, and a launcher that
REM dies on one of those is indistinguishable from one that did nothing.

python -m apps.launcher

if errorlevel 1 (
    echo.
    echo Hawkeye could not start.
    echo If the line above says python was not recognised, install Python 3
    echo and tick "Add python.exe to PATH" during setup.
    echo More detail: data\launcher.log and data\server.log
)

echo.
pause
