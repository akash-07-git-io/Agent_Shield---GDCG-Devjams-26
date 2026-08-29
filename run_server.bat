@echo off
echo Starting AgentShield Security Engine Gateway on http://127.0.0.1:8000 ...
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
pause
