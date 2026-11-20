$pythonPath = "$env:LOCALAPPDATA\Python\bin\python.exe"
if (-not (Test-Path $pythonPath)) {
    $pythonPath = "python"
}
& $pythonPath -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
