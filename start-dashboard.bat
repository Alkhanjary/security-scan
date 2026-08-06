@echo off
REM Starts the security-scan web dashboard and opens it in your browser.
setlocal

cd /d "%~dp0"

if "%PORT%"=="" set PORT=5057

echo Starting security-scan dashboard on http://127.0.0.1:%PORT% ...
echo Press Ctrl+C in this window to stop it.
echo.

REM Give the server a moment to bind before the browser opens, otherwise the
REM first request can land before Flask is listening and show a refused page.
start "" /b cmd /c "timeout /t 2 /nobreak >nul && start "" http://127.0.0.1:%PORT%"

py web\app.py
if errorlevel 1 (
  echo.
  echo The dashboard failed to start.
  echo If it's a missing package, run:  py -m pip install -r requirements.txt
  echo.
  pause
)

endlocal
