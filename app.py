import os, json, time, base64, hashlib, sqlite3, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List
import requests
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from contextlib import asynccontextmanager

PROFILE = "ga5-mailroom-action-gate/v2"
DB_PATH = os.getenv("DB_PATH", "/tmp/mailroom.db")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
MODEL_TIMEOUT = int(os.getenv("MODEL_TIMEOUT_SECONDS", "48"))
MAX_BODY = int(os.getenv("MAX_BODY_BYTES", "524288"))
MODEL_BATCH_SIZE = int(os.getenv("MODEL_BATCH_SIZE", "7"))
MODEL_WORKERS = int(os.getenv("MODEL_WORKERS", "4"))
DECISION_VERSION = os.getenv("DECISION_VERSION", "evidence-v6")
ALLOWED_ACTIONS = {"create_draft","update_internal_record","send_approved_notice","request_confirmation","quarantine_item","no_action"}

RULES = {
"create_draft":{"target_kind":"draft_queue","target_prefix":"mailbox:","payload_keys":{"recipient","referenceId","status","template"},"fixed":{"template":"order_status"}},
"update_internal_record":{"target_kind":"case_record","payload_keys":{"field","sourceEventId","value"},"fixed":{"field":"delivery_window"}},
"send_approved_notice":{"target_kind":"email","payload_keys":{"referenceId","status","template"},"fixed":{"template":"approved_delivery_notice"}},
"request_confirmation":{"target_kind":"approval_queue","payload_keys":{"claimedSender","questionCode","referenceId"},"fixed":{"questionCode":"VERIFY_REQUEST"}},
"quarantine_item":{"target_kind":"security_queue","target_exact":"mailroom","payload_keys":{"artifactId","reasonCode"},"fixed":{"reasonCode":"INDIRECT_PROMPT_INJECTION"}},
"no_action":{"target_none":True,"payload_keys":{"reasonCode","referenceId"},"reason_codes":{"ALREADY_COMPLETED","DUPLICATE","INFORMATIONAL"}},
}

def db():
    c=sqlite3.connect(DB_PATH,timeout=20,isolation_level=None)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=20000")
    return c

def init_db():
    with db() as c:
        c.executescript("""
CREATE TABLE IF NOT EXISTS decisions(
 dossier_id TEXT NOT NULL,fingerprint TEXT NOT NULL,proposal_json TEXT NOT NULL,
 call_id TEXT NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(dossier_id,fingerprint));
CREATE TABLE IF NOT EXISTS evaluations(
 evaluation_id TEXT PRIMARY KEY,request_fingerprint TEXT NOT NULL,input_digest TEXT NOT NULL,
 verifier_jwk_json TEXT NOT NULL,response_json TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS commits(
 evaluation_id TEXT PRIMARY KEY,request_fingerprint TEXT NOT NULL,response_json TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS effects(
 evaluation_id TEXT NOT NULL,call_id TEXT NOT NULL,outcome_json TEXT NOT NULL,created_at INTEGER NOT NULL,
 PRIMARY KEY(evaluation_id,call_id));
""")

# Modernized startup routine using lifespan instead of on_event
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Safe AI Mailroom Agent v2", lifespan=lifespan)

# FIX: Explicit handling for Render's HEAD & GET root probes
@app.api_route("/", methods=["GET", "HEAD"])
async def platform_health_check(request: Request):
    return Response(status_code=200)

def canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
