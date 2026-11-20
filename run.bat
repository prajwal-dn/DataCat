@echo off
set "PYTHON_PATH=%LOCALAPPDATA%\Python\bin\python.exe"
if not exist "%PYTHON_PATH%" (
    set "PYTHON_PATH=python"
)
"%PYTHON_PATH%" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
