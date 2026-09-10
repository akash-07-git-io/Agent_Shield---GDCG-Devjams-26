@echo off
echo ==============================================================================
echo                      AGENTSHIELD - 3-MEMBER ARCHITECTURE
echo ==============================================================================
echo.

echo [1/3] Starting Member 2: Security Gateway (Port 8000)...
cd gateway
start "AgentShield Security Gateway (Port 8000)" cmd /k "py -m uvicorn app.main:app --port 8000"
cd ..
timeout /t 3 > nul

echo [2/3] Starting Member 3: Security Dashboard (Port 8501)...
cd dashboard
start "AgentShield Security Dashboard (Port 8501)" cmd /k "py -m uvicorn backend.main:app --port 8501"
cd ..
timeout /t 3 > nul

echo [3/3] Running Member 1: AI Agent Scenarios...
cd agent
start "AgentShield Agent Scenarios" cmd /k "py scenarios.py"
cd ..

echo.
echo ==============================================================================
echo [SUCCESS] All AgentShield services are running!
echo.
echo   * Security Dashboard UI:  http://localhost:8501
echo   * Security Gateway Docs:  http://localhost:8000/docs
echo   * Dashboard Telemetry:    http://localhost:8501/api/dashboard/stats
echo ==============================================================================
pause
