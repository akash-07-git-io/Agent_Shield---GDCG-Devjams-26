
#!/usr/bin/env bash
# ==============================================================================
#                      AGENTSHIELD - 3-MEMBER ARCHITECTURE
#                  Linux / macOS Cross-Platform Launch Script
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "=============================================================================="
echo "                   AGENTSHIELD — ZERO-TRUST RUNTIME GATEWAY"
echo "                     DevJams'26 | 3-Member Architecture"
echo "=============================================================================="
echo ""

# Cleanup background processes on exit
cleanup() {
    echo ""
    echo "[AgentShield] Shutting down background services..."
    kill $(jobs -p) 2>/dev/null || true
    echo "[AgentShield] Services stopped."
}
trap cleanup EXIT INT TERM

# 1. Start Security Gateway (Port 8000)
echo "[1/3] Starting Member 2: Security Gateway (Port 8000)..."
(cd gateway && python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000) &
GATEWAY_PID=$!
sleep 2

# 2. Start Security Dashboard (Port 8501)
echo "[2/3] Starting Member 3: Security SOC Dashboard (Port 8501)..."
(cd dashboard && python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8501) &
DASHBOARD_PID=$!
sleep 2

echo ""
echo "=============================================================================="
echo "[SUCCESS] AgentShield Core Services Are Operational!"
echo ""
echo "  * Security Dashboard UI:   http://localhost:8501"
echo "  * Security Gateway Docs:   http://localhost:8000/docs"
echo "  * Telemetry API Endpoint:  http://localhost:8501/api/dashboard/stats"
echo "=============================================================================="
echo ""
echo "Press [Ctrl+C] to stop all services."
echo ""

wait
