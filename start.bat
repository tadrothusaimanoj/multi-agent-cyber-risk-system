@echo off
echo Installing Python dependencies...
pip install --disable-pip-version-check -q fastapi uvicorn sqlalchemy pydantic pydantic-settings pulp scikit-learn numpy joblib

echo Installing Node dependencies...
call npm install --no-audit --no-fund --loglevel=error

echo Starting Backend in the background...
start /B python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

echo Waiting for Backend to be healthy...
:wait_loop
curl -s http://localhost:8000/api/health | findstr "healthy" >nul
if errorlevel 1 (
  echo Backend not ready, waiting...
  ping 127.0.0.1 -n 3 >nul
  goto wait_loop
)

echo Backend is healthy! Starting Frontend...
call npm run dev
