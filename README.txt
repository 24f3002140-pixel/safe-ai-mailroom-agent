SAFE AI MAILROOM AGENT - BATCHED FIX

WHY THIS VERSION
----------------
The previous version sent one Gemini request per dossier. The grader sends
64 stable dossiers + 3 fresh dossiers in one evaluation, so the free-tier
15 requests/minute quota was exceeded.

This version batches up to 8 uncached dossiers into ONE Gemini request.
Typical first evaluation: 67 dossiers -> 9 Gemini requests.
Typical second evaluation: 64 cached + 3 new -> 1 Gemini request.

RENDER SETTINGS
---------------
Build Command:
pip install -r requirements.txt

Start Command:
gunicorn -k uvicorn.workers.UvicornWorker -w 1 --timeout 120 --graceful-timeout 120 -b 0.0.0.0:$PORT app:app

Environment:
GEMINI_API_KEY = your valid Google AI Studio Gemini key
GEMINI_MODEL = gemini-3.1-flash-lite
MODEL_BATCH_SIZE = 8
PYTHON_VERSION = 3.11.11

IITM ENDPOINT
-------------
https://safe-ai-mailroom-agent-aqwt.onrender.com/v1/mailroom/actions
