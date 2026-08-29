@echo off
echo Starting AgentShield 3-Member Architecture...
echo.

echo [1/3] Starting Member 2: Security Gateway (Port 8000)...
cd gateway
start cmd /k "py -m uvicorn app.main:app --port 8000"
cd ..
timeout /t 3 > nul

echo [2/3] Starting Member 3: Dashboard Backend (Port 8501)...
cd dashboard
start cmd /k "py -m uvicorn backend.main:app --port 8501"
cd ..
timeout /t 3 > nul

echo [3/3] Running Member 1: AI Agent Scenarios...
cd agent
start cmd /k "py scenarios.py"
cd ..

echo.
echo All services launched!
echo Gateway Docs: http://localhost:8000/docs
echo Dashboard API: http://localhost:8501/api/dashboard/stats
pause
