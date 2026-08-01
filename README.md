# Safe AI Mailroom Agent

## Endpoint
`POST /v1/mailroom/actions`

## Local test
1. Install Python 3.11+
2. Run:
   ```
   pip install -r requirements.txt
   set GEMINI_API_KEY=YOUR_KEY
   uvicorn app:app --reload
   ```
3. Open `http://127.0.0.1:8000/`

## Deploy on Render
1. Create a GitHub repository.
2. Upload all files from this folder.
3. In Render choose **New + > Blueprint**.
4. Connect the repository.
5. Add the secret environment variable `GEMINI_API_KEY`.
6. Deploy.
7. Submit:
   `https://YOUR-RENDER-NAME.onrender.com/v1/mailroom/actions`

## Important
The exact grader schema text must be checked. This project supports common field names,
but if the exam page's collapsed “Exact propose request/response” section shows different
field names or a different receipt-signature formula, update those exact parts before Save.
