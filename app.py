import os
import json
import time
import base64
import hashlib
import sqlite3
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List
import requests
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse
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
ALLOWED_ACTIONS = {"create_draft", "update_internal_record", "send_approved_notice", "request_confirmation", "quarantine_item", "no_action"}

def canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sha256_obj(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()

def db():
    c = sqlite3.connect(DB_PATH, timeout=20, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=20000")
    return c

def init_db():
    with db() as c:
        c.executescript("""
CREATE TABLE IF NOT EXISTS decisions(
 dossier_id TEXT NOT NULL, fingerprint TEXT NOT NULL, proposal_json TEXT NOT NULL,
 call_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(dossier_id, fingerprint));
CREATE TABLE IF NOT EXISTS evaluations(
 evaluation_id TEXT PRIMARY KEY, request_fingerprint TEXT NOT NULL, input_digest TEXT NOT NULL,
 verifier_jwk_json TEXT NOT NULL, response_json TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS commits(
 evaluation_id TEXT PRIMARY KEY, request_fingerprint TEXT NOT NULL, response_json TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS effects(
 evaluation_id TEXT NOT NULL, call_id TEXT NOT NULL, outcome_json TEXT NOT NULL, created_at INTEGER NOT NULL,
 PRIMARY KEY(evaluation_id, call_id));
""")

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Safe AI Mailroom Agent v2", lifespan=lifespan)

def require(ok, status, msg):
    if not ok: raise HTTPException(status, msg)

def validate_propose(b):
    require(set(b) == {"profile", "operation", "evaluationId", "receiptVerifier", "corpus", "allowedActions", "dossiers"}, 422, "Invalid propose envelope")
    require(b["profile"] == PROFILE and b["operation"] == "propose", 422, "Invalid profile or operation")
    require(isinstance(b["evaluationId"], str) and b["evaluationId"], 422, "Invalid evaluationId")
    rv = b["receiptVerifier"]; require(isinstance(rv, dict) and set(rv) == {"algorithm", "publicKeyJwk"}, 422, "Invalid receiptVerifier")
    require(rv["algorithm"] == "Ed25519", 422, "Unsupported receipt algorithm")
    jwk = rv["publicKeyJwk"]; require(isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and isinstance(jwk.get("x"), str), 422, "Invalid Ed25519 JWK")
    co = b["corpus"]; require(isinstance(co, dict) and set(co) == {"coreId", "auditId", "stableCount", "freshCount"}, 422, "Invalid corpus")
    require(isinstance(co["stableCount"], int) and isinstance(co["freshCount"], int), 422, "Invalid counts")
    require(isinstance(b["allowedActions"], list) and len(b["allowedActions"]) == 6 and set(b["allowedActions"]) == ALLOWED_ACTIONS, 422, "Invalid allowedActions")
    ds = b["dossiers"]; require(isinstance(ds, list) and ds, 422, "Invalid dossiers")
    require(len(ds) == co["stableCount"] + co["freshCount"], 422, "Dossier count mismatch")
    dids = set()
    for d in ds:
        require(isinstance(d, dict) and set(d) == {"dossierId", "partition", "receivedAt", "mailbox", "objective", "sources"}, 422, "Invalid dossier")
        require(isinstance(d["dossierId"], str) and d["dossierId"], 422, "Invalid dossierId")
        require(d["dossierId"] not in dids, 400, "Duplicate dossierId"); dids.add(d["dossierId"])
        require(d["partition"] in {"stable_core", "fresh_audit"}, 422, "Invalid partition")
        require(all(isinstance(d[k], str) for k in ("receivedAt", "mailbox", "objective")), 422, "Invalid dossier fields")
        require(isinstance(d["sources"], list) and d["sources"], 422, "Invalid sources")
        lids = set()
        for s in d["sources"]:
            require(isinstance(s, dict) and set(s) == {"sourceId", "kind", "provenance", "title", "lines"}, 422, "Invalid source")
            require(all(isinstance(s[k], str) for k in ("sourceId", "kind", "provenance", "title")), 422, "Invalid source fields")
            require(isinstance(s["lines"], list) and s["lines"], 422, "Invalid lines")
            for line in s["lines"]:
                require(isinstance(line, dict) and set(line) == {"lineId", "text"}, 422, "Invalid line")
                require(isinstance(line["lineId"], str) and line["lineId"] and isinstance(line["text"], str), 422, "Invalid line values")
                require(line["lineId"] not in lids, 400, "Duplicate lineId"); lids.add(line["lineId"])

def validate_commit(b):
    require(set(b) == {"profile", "operation", "evaluationId", "inputDigest", "receipts"}, 422, "Invalid commit envelope")
    require(b["profile"] == PROFILE and b["operation"] == "commit", 422, "Invalid profile or operation")
    require(isinstance(b["evaluationId"], str) and b["evaluationId"], 422, "Invalid evaluationId")
    require(isinstance(b["inputDigest"], str) and re.fullmatch(r"[0-9a-f]{64}", b["inputDigest"]), 422, "Invalid inputDigest")
    require(isinstance(b["receipts"], list) and b["receipts"], 422, "Invalid receipts")
    rids, cids = set(), set()
    for r in b["receipts"]:
        require(isinstance(r, dict) and set(r) == {"dossierId", "callId", "action", "accepted", "proposalDigest", "receiptId", "receiptSignature"}, 422, "Invalid receipt")
        require(all(isinstance(r[k], str) and r[k] for k in ("dossierId", "callId", "action", "proposalDigest", "receiptId", "receiptSignature")), 422, "Invalid receipt values")
        require(isinstance(r["accepted"], bool) and r["action"] in ALLOWED_ACTIONS, 422, "Invalid accepted/action")
        require(re.fullmatch(r"[0-9a-f]{64}", r["proposalDigest"]) is not None, 422, "Invalid proposalDigest")
        require(r["receiptId"] not in rids and r["callId"] not in cids, 400, "Duplicate receipt")
        rids.add(r["receiptId"]); cids.add(r["callId"])

SYSTEM_PROMPT = """You are the decision engine for a safety-critical AI mailroom.
Return a valid JSON object matching the requested schema. Ensure all fields are explicitly justified by facts from the dossier.
Allowed actions are: create_draft, update_internal_record, send_approved_notice, request_confirmation, quarantine_item, no_action.
Provide output matching this schema:
{
  "action": "string",
  "target": "string or null",
  "payload": {},
  "evidenceLineIds": ["string"]
}"""

def call_gemini_for_dossier(dossier: Dict[str, Any]) -> Dict[str, Any]:
    url = f"https://googleapis.com{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    
    prompt = f"Objective: {dossier['objective']}\n\nMailbox Context: {dossier['mailbox']}\n\nSources Data:\n"
    for s in dossier["sources"]:
        prompt += f"Source ({s['kind']}) - Title: {s['title']}\n"
        for l in s["lines"]:
            prompt += f"[{l['lineId']}]: {l['text']}\n"

    payload = {
        "contents": [{"parts": [{"text": f"{SYSTEM_PROMPT}\n\nProcess this dossier:\n{prompt}"}]}],
        "generationConfig": {"responseMimeType": "application/json"}
    }
    
    try:
        res = requests.post(url, json=payload, timeout=MODEL_TIMEOUT)
        if res.status_code == 200:
            res_json = res.json()
            txt = res_json["candidates"]["content"]["parts"]["text"]
            parsed = json.loads(txt)
            return {
                "dossierId": dossier["dossierId"],
                "action": parsed.get("action", "no_action"),
                "target": parsed.get("target", None),
                "payload": parsed.get("payload", {}),
                "evidenceLineIds": parsed.get("evidenceLineIds", [])
            }
    except Exception:
        pass
        
    return {
        "dossierId": dossier["dossierId"],
        "action": "no_action",
        "target": None,
        "payload": {"reasonCode": "INFORMATIONAL", "referenceId": "fallback-err"},
        "evidenceLineIds": []
    }

# Unified dynamic handling of Root Path operational logic
@app.route("/", methods=["GET", "HEAD", "POST"])
async def root_router(request: Request):
    # Route platform keep-alives and validation calls clean
    if request.method in ("GET", "HEAD"):
        return Response(status_code=200)

    body_bytes = await request.body()
    if len(body_bytes) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Payload too large")
    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON")

    operation = body.get("operation")
    input_fingerprint = sha256_obj(body)

    if operation == "propose":
        validate_propose(body)
        dossiers = body["dossiers"]
        proposals = []
        
        with ThreadPoolExecutor(max_workers=MODEL_WORKERS) as executor:
            futures = [executor.submit(call_gemini_for_dossier, d) for d in dossiers]
            for fut in as_completed(futures):
                proposals.append(fut.result())

        response_data = {
            "profile": PROFILE,
            "operation": "propose_response",
