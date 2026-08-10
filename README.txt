SAFE AI MAILROOM AGENT - FIXED PROJECT

FILES
-----
app.py
requirements.txt

RENDER SETTINGS
---------------
Build Command:
pip install -r requirements.txt

Start Command:
gunicorn -k uvicorn.workers.UvicornWorker -w 1 --timeout 120 --graceful-timeout 120 -b 0.0.0.0:$PORT app:app

Required Environment Variables:
GEMINI_API_KEY = your Gemini API key
GEMINI_MODEL = gemini-3.1-flash-lite
PYTHON_VERSION = 3.11.11

Optional:
DB_PATH = /tmp/mailroom.db
MODEL_TIMEOUT_SECONDS = 45
MAX_BODY_BYTES = 524288

IITM ENDPOINT
-------------
https://safe-ai-mailroom-agent-aqwt.onrender.com/v1/mailroom/actions

IMPORTANT
---------
This version sends the Gemini key using the x-goog-api-key HTTP header instead
of putting ?key=... in the URL. It also prints GEMINI ERROR details in Render
logs if Google rejects the request.
