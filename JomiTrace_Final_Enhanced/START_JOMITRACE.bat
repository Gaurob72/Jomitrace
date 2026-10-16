@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo          JomiTrace - Local Demo
echo ==========================================
echo.
if not exist ".venv\Scripts\python.exe" (
  echo Creating a local Python environment...
  py -m venv .venv
  if errorlevel 1 (
    python -m venv .venv
    if errorlevel 1 (
      echo Could not create Python environment. Install Python 3 and try again.
      pause
      exit /b 1
    )
  )
)
echo Installing/updating dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Check your internet connection and Python installation.
  pause
  exit /b 1
)
echo.
echo Starting JomiTrace at http://127.0.0.1:8001
echo Keep this window open while using the website.
start "" "http://127.0.0.1:8001"
".venv\Scripts\python.exe" -m uvicorn main:app --reload --port 8001
pause
