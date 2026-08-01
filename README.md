Build: pip install -r requirements.txt
Start: gunicorn -k uvicorn.workers.UvicornWorker -w 1 --timeout 120 --graceful-timeout 120 -b 0.0.0.0:$PORT app:app
Env: PYTHON_VERSION=3.11.11, GEMINI_API_KEY, GEMINI_MODEL=gemini-3.1-flash-lite, MODEL_TIMEOUT_SECONDS=48, DB_PATH=/tmp/mailroom.db
Submit: https://YOUR-SERVICE.onrender.com/v1/mailroom/actions
