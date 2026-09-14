# Run from the backend/ directory:
#   pip install -r requirements.txt
#   uvicorn app.main:app --reload --port 8000
#
# The frontend (repo root) then points at it with:
#   VITE_MAILSENTINEL_API_BASE=http://localhost:8000
# in a local .env file (git-ignored; see .env.example at repo root).
#
# Without provider keys the API still works: deterministic checks +
# graceful UNKNOWN intel + heuristic verdict (mode LIVE, confidence lower).
# Add keys to backend/.env (git-ignored) to enable OpenAI / VirusTotal /
# AbuseIPDB / Google Safe Browsing. Never put keys in VITE_* variables.
