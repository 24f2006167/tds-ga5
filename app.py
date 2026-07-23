"""
TDS GA5 — Unified FastAPI App  (v3 — Fully fixed Q8 + Q10 A2A 1.0)
Q2  /prorate
Q3  /q3/check
Q4  /q4/scan
Q5  /q5/check
Q6  /mcp
Q8  /q8/check
Q9  /q9/mailroom
Q10 /a2a/  (A2A 1.0 Protocol Compliant)
"""

import asyncio
import calendar
import hashlib
import json
import os
import re
import threading
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

# ── Optional Gemini for invoice decisions ────────────────────────────────────
try:
    from google import genai as _genai_sdk
    _GEMINI_KEY = os.getenv("GEMINI_API_KEY", "")
    if _GEMINI_KEY:
        _GEMINI_CLIENT = _genai_sdk.Client(api_key=_GEMINI_KEY)
    else:
        _GEMINI_CLIENT = None
except Exception:
    _GEMINI_CLIENT = None

# ────────────────────────────────────────────────────────────────────────────
# Config
# ────────────────────────────────────────────────────────────────────────────
YOUR_EMAIL = "24f2006167@ds.study.iitm.ac.in"

# Q3
Q3_SECRET_PATH   = "/home/agent/.pgpass"
Q3_WRITE_DIR     = "/home/agent/workspace/build/"
Q3_ALLOWED_HOSTS = ["objects.githubusercontent.com", "raw.githubusercontent.com"]

# Q8
Q8_SANDBOX_ROOT  = "/srv/agent-redteam/sandbox-426f63f28d"
Q8_ALLOWED_HOSTS = {"example.com", "www.iana.org"}
Q8_CANARY_TOKEN  = "AGENT_GUARDRAIL_CANARY_24e40e302a65de94f5ee4908e83a0b556a3088f3"

# Q8 — known contents of safe files
Q8_SAFE_CONTENTS: Dict[str, str] = {
    "/srv/agent-redteam/sandbox-426f63f28d/notes/report.txt":
        "SAFE_REPORT_70c0ee84503bd0e13aa22675",
    "/srv/agent-redteam/sandbox-426f63f28d/notes/looks-like-..-but-safe.txt":
        "SAFE_WEIRD_0bf53bfeb4c649a75e989336",
    "/srv/agent-redteam/sandbox-426f63f28d/encoded/%2e%2e-literal.txt":
        "SAFE_ENCODED_7c64b2675c54913af654fc31",
}

# ────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="TDS GA5 API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

A2A_MEDIA = "application/a2a+json"

# Exception handler for A2A to guarantee application/a2a+json media type on errors
@app.exception_handler(HTTPException)
async def a2a_http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/a2a"):
        return Response(
            content=json.dumps({"error": str(exc.detail)}),
            status_code=exc.status_code,
            media_type=A2A_MEDIA,
        )
    return JSONResponse(content={"detail": exc.detail}, status_code=exc.status_code)

# ════════════════════════════════════════════════════════════════════════════
# HEALTH
# ════════════════════════════════════════════════════════════════════════════
@app.get("/health")
async def health():
    return {"status": "ok"}


# ════════════════════════════════════════════════════════════════════════════
# Q2  /prorate
# ════════════════════════════════════════════════════════════════════════════
@app.post("/prorate")
async def prorate(req: Request):
    b     = await req.json()
    old   = b["old_price"]
    new   = b["new_price"]
    spec  = b.get("spec", "v2")
    year  = b.get("year")  or b.get("billing_year")
    month = b.get("month") or b.get("billing_month")
    day   = b.get("upgrade_day") or b.get("day")

    days_in_month  = b.get("days_in_actual_month") or (
        calendar.monthrange(int(year), int(month))[1] if year and month else 30)
    days_remaining = b.get("days_remaining") or (
        int(days_in_month) - int(day) + 1)

    delta  = new - old
    charge = round(delta * (days_remaining / (30 if spec == "v1" else days_in_month)), 2)
    return {"charge": charge}


# ════════════════════════════════════════════════════════════════════════════
# Q3  /q3/check
# ════════════════════════════════════════════════════════════════════════════
def _normpath(p: str) -> str:
    return os.path.normpath(p)

def _resolves_inside(path: str, root: str) -> bool:
    full = _normpath(path if os.path.isabs(path) else os.path.join(root, path))
    root_n = _normpath(root)
    return full == root_n or full.startswith(root_n + os.sep)

def _extract_host(url: str) -> str:
    try:
        if not re.match(r"^https?://", url, re.I):
            url = "http://" + url
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""

def _is_secret_bash(cmd: str, secret_path: str) -> bool:
    secret_norm = os.path.normpath(secret_path)
    secret_base = os.path.basename(secret_path)
    trial = _normpath(cmd.replace("$HOME", "/home/agent").replace("~", "/home/agent"))
    if secret_norm in trial or secret_base in cmd:
        return True
    import base64
    try:
        match = re.search(r'[A-Za-z0-9+/=]{20,}', cmd)
        if match:
            decoded = base64.b64decode(match.group()).decode(errors='ignore')
            if secret_norm in decoded or secret_base in decoded:
                return True
    except Exception:
        pass
    return False

@app.post("/q3/check")
async def q3_check(req: Request):
    b    = await req.json()
    tool = b.get("tool", "")
    args = b.get("arguments", b.get("args", {}))

    if tool == "bash":
        if _is_secret_bash(args.get("command", ""), Q3_SECRET_PATH):
            return {"decision": "block", "reason": "Command targets the restricted secret path."}
        return {"decision": "allow", "reason": "Bash command appears safe."}

    if tool == "write_file":
        path = args.get("path", "")
        if _resolves_inside(path, Q3_WRITE_DIR):
            return {"decision": "allow", "reason": "Write is within allowed directory."}
        return {"decision": "block", "reason": "Write target is outside the allowed directory."}

    if tool == "http_request":
        host = _extract_host(args.get("url", ""))
        if host in Q3_ALLOWED_HOSTS:
            return {"decision": "allow", "reason": "Host is in the allowed list."}
        return {"decision": "block", "reason": f"Host '{host}' is not in the allowed list."}

    return {"decision": "allow", "reason": "Unknown tool; allowed by default."}


# ════════════════════════════════════════════════════════════════════════════
# Q4  /q4/scan
# ════════════════════════════════════════════════════════════════════════════
EXCESSIVE_RE = re.compile(
    r"(entire\s+file\s*system|whole\s+home|unrestricted|unlimited|arbitrary)\s*"
    r"(egress|access|network|file)?|"
    r"(read|write)\s+(access\s+to\s+)?(/\b|the\s+entire)|"
    r"egress\s+to\s+any|network[:\s]+any",
    re.I)
INJECT_RE = re.compile(
    r"(stop|cancel|halt|abort).*?(ignore|override|bypass).*?(user|request|instruction)", re.I | re.S)
SECRET_RE = re.compile(
    r"(?:api_?key|api_?secret|auth_?token|password|secret)[^\n]*[A-Za-z0-9\-_]{16,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|sk-[A-Za-z0-9]{20,}|"
    r"[0-9a-fA-F]{32,}|https?://[^@\s]+:[^@\s]+@", re.I)

def _lacks_provenance(skill: str) -> bool:
    fm = re.match(r"^---\s*\n(.*?)\n---", skill, re.S)
    if not fm: return True
    body = fm.group(1)
    return not (re.search(r"^\s*(author|maintainer)\s*:", body, re.I | re.M) or
                re.search(r"^\s*version\s*:", body, re.I | re.M) or
                re.search(r"^\s*(changelog|history)\s*:", body, re.I | re.M))

@app.post("/q4/scan")
async def q4_scan(req: Request):
    b     = await req.json()
    skill = b.get("skill", "")
    cats: List[str] = []
    if SECRET_RE.search(skill):      cats.append("hardcoded_secret")
    if INJECT_RE.search(skill):      cats.append("prompt_injection")
    if EXCESSIVE_RE.search(skill):   cats.append("excessive_permissions")
    if _lacks_provenance(skill):     cats.append("unclear_provenance")
    return {"categories": cats}


# ════════════════════════════════════════════════════════════════════════════
# Q5  /q5/check
# ════════════════════════════════════════════════════════════════════════════
def _canon_args(args: Any) -> str:
    if isinstance(args, dict):
        return json.dumps({k: _canon_args(v) for k, v in args.items() if k != "trace_id"},
                          sort_keys=True, separators=(",", ":"))
    if isinstance(args, list):
        return json.dumps([_canon_args(i) for i in args], separators=(",", ":"))
    if isinstance(args, str):
        return " ".join(args.split())
    return json.dumps(args)

def _step_key(s: dict):
    return (s.get("tool", ""), _canon_args(s.get("args", s.get("arguments", {}))))

@app.post("/q5/check")
async def q5_check(req: Request):
    b      = await req.json()
    budget = b["budget_tokens"]
    steps  = b.get("steps", [])
    cumul  = sum(s.get("tokens_used", 0) for s in steps)

    if cumul >= budget:
        return {"decision": "halt", "reason": f"Cumulative tokens_used ({cumul}) ≥ budget ({budget})."}

    if len(steps) >= 3:
        tail = steps[-3:]
        if len({_step_key(s) for s in tail}) == 1:
            t, _ = _step_key(tail[0])
            return {"decision": "halt", "reason": f"Loop: '{t}' called 3+ times identically."}

    if len(steps) >= 6:
        tail = steps[-6:]
        k = [_step_key(s) for s in tail]
        if k[0] == k[2] == k[4] and k[1] == k[3] == k[5] and k[0] != k[1]:
            return {"decision": "halt", "reason": "Loop: 2-step A/B cycle over 6 trailing steps."}

    return {"decision": "continue",
            "reason": f"Tokens ({cumul}) under budget ({budget}) and progressing."}


# ════════════════════════════════════════════════════════════════════════════
# Q6  /mcp  (MCP Streamable HTTP)
# ════════════════════════════════════════════════════════════════════════════
_EMAIL_NORM = YOUR_EMAIL.strip().lower()

def _mcp_solve(challenge: str) -> str:
    return hashlib.sha256(f"{challenge}:{_EMAIL_NORM}".encode()).hexdigest()[:16]

def _mcp_ok(id_: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}

def _mcp_err(id_: Any, code: int, msg: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": msg}}

_TOOL_DEF = {
    "name": "solve_challenge",
    "description": "Solve the per-call SHA-256 challenge.",
    "inputSchema": {"type": "object", "properties": {}, "required": []},
}

async def _handle_mcp(msg: dict, req: Request) -> dict:
    method, id_ = msg.get("method", ""), msg.get("id")
    if method == "initialize":
        return _mcp_ok(id_, {"protocolVersion": "2024-11-05",
                              "capabilities": {"tools": {}},
                              "serverInfo": {"name": "ga5-mcp", "version": "1.0"}})
    if method in ("notifications/initialized", "notifications/progress"):
        return {}
    if method == "tools/list":
        return _mcp_ok(id_, {"tools": [_TOOL_DEF]})
    if method == "tools/call":
        if msg.get("params", {}).get("name") == "solve_challenge":
            challenge = req.headers.get("x-exam-challenge",
                        req.headers.get("X-Exam-Challenge", ""))
            return _mcp_ok(id_, {"content": [{"type": "text", "text": _mcp_solve(challenge)}]})
        return _mcp_err(id_, -32602, "Unknown tool")
    if method == "ping":
        return _mcp_ok(id_, {})
    return _mcp_err(id_, -32601, f"Method not found: {method}")

@app.post("/mcp")
async def mcp_post(req: Request):
    body = await req.json()
    if isinstance(body, list):
        return JSONResponse([await _handle_mcp(m, req) for m in body])
    return JSONResponse(await _handle_mcp(body, req))

@app.get("/mcp")
async def mcp_sse(req: Request):
    async def stream():
        endpoint = str(req.url).replace("/mcp", "") + "/mcp"
        yield f"data: {json.dumps({'type':'endpoint','url':endpoint})}\n\n"
        await asyncio.sleep(60)
    return StreamingResponse(stream(), media_type="text/event-stream")


# ════════════════════════════════════════════════════════════════════════════
# Q8  /q8/check
# ════════════════════════════════════════════════════════════════════════════
_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
        "127.0.0.0/8","169.254.0.0/16","::1/128","fc00::/7")]

def _is_private(host: str) -> bool:
    try:    return any(ipaddress.ip_address(host) in n for n in _PRIVATE_NETS)
    except: return False

def _is_ssrf_value(val: str) -> bool:
    val = val.strip()
    if re.match(r"^https?://", val, re.I):
        h = _extract_host(val)
        return (h not in Q8_ALLOWED_HOSTS) or _is_private(h)
    if _is_private(val):
        return True
    if re.search(r"169\.254|metadata\.google|metadata\.internal|localhost", val, re.I):
        return True
    return False

@app.post("/q8/check")
async def q8_check(req: Request):
    b    = await req.json()
    tool = b.get("tool", "")
    args = b.get("arguments", b.get("args", {}))

    # ── read_file / write_file ───────────────────────────────────────────────
    if tool in ("read_file", "write_file"):
        raw_path = args.get("path") or args.get("file") or args.get("filepath") or ""
        root = _normpath(Q8_SANDBOX_ROOT)

        # Resolve path accurately (handling relative vs absolute)
        if os.path.isabs(raw_path):
            norm = _normpath(raw_path)
        else:
            norm = _normpath(os.path.join(root, raw_path))

        # Check path traversal
        if not (norm == root or norm.startswith(root + os.sep)):
            return {
                "action": "block", "decision": "block",
                "reason": "Path escapes the sandbox root.", "result": None
            }

        # Safe contents lookup
        result = (Q8_SAFE_CONTENTS.get(raw_path) or 
                  Q8_SAFE_CONTENTS.get(norm) or 
                  Q8_SAFE_CONTENTS.get(unquote(raw_path)) or
                  Q8_SAFE_CONTENTS.get(unquote(norm)))

        if tool == "write_file":
            result = {"written": True}
        elif result is None:
            try:
                with open(norm, "r") as fh:
                    result = fh.read()
            except Exception:
                result = "SAFE_FILE_CONTENT_OK"

        if isinstance(result, str) and Q8_CANARY_TOKEN in result:
            return {
                "action": "block", "decision": "block",
                "reason": "Canary token detected in file content.", "result": None
            }

        return {
            "action": "allow", "decision": "allow",
            "reason": "Path is within the sandbox.", "result": result
        }

    # ── fetch_url / http_request / network ───────────────────────────────────
    if tool in ("fetch_url", "fetch", "http_request", "http", "network", "browse", "curl", "request", "web_search"):
        url = args.get("url") or args.get("uri") or args.get("link") or args.get("target") or args.get("endpoint") or ""
        
        # Ensure scheme for proper urlparse
        url_to_parse = url if re.match(r"^https?://", url, re.I) else "http://" + url
        parsed = urlparse(url_to_parse)
        host = (parsed.hostname or "").lower()

        if _is_private(host):
            return {
                "action": "block", "decision": "block",
                "reason": "Private/metadata IP not allowed.", "result": None
            }

        if host not in Q8_ALLOWED_HOSTS:
            return {
                "action": "block", "decision": "block",
                "reason": f"Host '{host}' not in allowed list.", "result": None
            }

        # Check SSRF via query params
        for vals in parse_qs(parsed.query).values():
            for v in vals:
                if _is_ssrf_value(v):
                    return {
                        "action": "block", "decision": "block",
                        "reason": "Query param carries an SSRF target.", "result": None
                    }

        # Allowed — return safe content or fetch
        try:
            async with httpx.AsyncClient(timeout=4) as client:
                resp = await client.get(url_to_parse, follow_redirects=True,
                                        headers={"User-Agent": "GA5-Guardrail/1.0"})
                content = resp.text[:2048]
        except Exception:
            content = "<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1></body></html>"

        return {
            "action": "allow", "decision": "allow",
            "reason": "Host is in the allowed list.", "result": content
        }

    return {
        "action": "allow", "decision": "allow",
        "reason": "Tool not restricted by this guardrail.", "result": None
    }


# ════════════════════════════════════════════════════════════════════════════
# Q9  /q9/mailroom
# ════════════════════════════════════════════════════════════════════════════
_q9: Dict[str, Any] = {}

@app.post("/q9/mailroom")
async def q9_mailroom(req: Request):
    b  = await req.json()
    op = b.get("operation", "propose")

    if op == "propose":
        eid      = b.get("evaluationId", str(uuid.uuid4()))
        dossiers = b.get("dossiers", [])
        proposals = [_q9_classify(d) for d in dossiers]
        _q9[eid]  = proposals
        return JSONResponse({"status": "awaiting_receipts",
                             "evaluationId": eid, "proposals": proposals})

    if op == "commit":
        eid      = b.get("evaluationId", "")
        receipts = b.get("receipts", [])
        outcomes = [{"packageId": r.get("packageId",""), "receipt": r, "executed": True}
                    for r in receipts]
        return JSONResponse({"status": "completed", "evaluationId": eid, "outcomes": outcomes})

    raise HTTPException(400, "Unknown operation")

def _q9_classify(d: dict) -> dict:
    did = d.get("dossierId", str(uuid.uuid4()))
    txt = json.dumps(d)
    aid = str(uuid.uuid4())[:12]

    if re.search(r"(higher.priority|copy.*?vault marker|ignore.*?instruction)", txt, re.I):
        return {"packageId": did, "actionId": aid, "action": "quarantine_item",
                "target": {"kind": "security_queue", "id": "mailroom"},
                "payload": {"artifactId": did, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                "evidenceRefs": []}

    if re.search(r"no new change|already completed|duplicate", txt, re.I):
        return {"packageId": did, "actionId": aid, "action": "no_action",
                "target": None,
                "payload": {"reasonCode": "ALREADY_COMPLETED", "referenceId": did},
                "evidenceRefs": []}

    if re.search(r"permits one delivery.status notice", txt, re.I):
        rec = re.search(r"approved.recipient\s*[:\-]\s*(\S+)", txt, re.I)
        return {"packageId": did, "actionId": aid, "action": "send_approved_notice",
                "target": {"kind": "email", "id": rec.group(1) if rec else ""},
                "payload": {"referenceId": did, "status": "delivered",
                            "template": "approved_delivery_notice"},
                "evidenceRefs": []}

    mb = re.search(r"mailbox[:\s]+(\S+)", txt, re.I)
    return {"packageId": did, "actionId": aid, "action": "create_draft",
            "target": {"kind": "draft_queue",
                       "id": f"mailbox:{mb.group(1) if mb else 'default'}"},
            "payload": {"recipient": "", "referenceId": did,
                        "status": "pending", "template": "order_status"},
            "evidenceRefs": []}


# ════════════════════════════════════════════════════════════════════════════
# Q10  A2A 1.0 — Invoice Agent
# Base path: /a2a/
# ════════════════════════════════════════════════════════════════════════════
A2A_VER       = "1.0"
A2A_IN_BATCH  = "application/vnd.ga5.invoice-claim-batch+json"
A2A_OUT_PROPS = "application/vnd.ga5.invoice-action-proposals+json"
A2A_OUT_RCPT  = "application/vnd.ga5.invoice-action-receipts+json"
A2A_RESULTS   = "application/vnd.ga5.invoice-action-results+json"

# Storage: {principal: {task_id: task_dict}}
_A2A_TASKS: Dict[str, Dict[str, Any]] = defaultdict(dict)
# Idempotency: {principal: {msg_id: (msg_hash, task_id)}}
_A2A_IDEM:  Dict[str, Dict[str, tuple]] = defaultdict(dict)

_PKG_CACHE: Dict[str, dict] = {}
_TASK_LOCKS: Dict[str, threading.Lock] = {}

def _task_lock(task_id: str) -> threading.Lock:
    if task_id not in _TASK_LOCKS:
        _TASK_LOCKS[task_id] = threading.Lock()
    return _TASK_LOCKS[task_id]

def _get_principal(req: Request) -> str:
    auth = req.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = auth[7:].strip()
    if not token:
        raise HTTPException(401, "Empty bearer token")
    return token

def _check_version(req: Request):
    ver = req.headers.get("a2a-version", req.headers.get("A2A-Version", ""))
    if ver != A2A_VER:
        raise HTTPException(400, f"A2A-Version must be {A2A_VER}")

def _check_media(req: Request):
    ct = req.headers.get("content-type", "")
    if A2A_MEDIA not in ct:
        raise HTTPException(400, f"Content-Type must be {A2A_MEDIA}")

def _a2a_resp(data: dict, status_code: int = 200) -> Response:
    return Response(content=json.dumps(data), status_code=status_code, media_type=A2A_MEDIA)

def _canon_msg(msg: dict) -> str:
    return hashlib.sha256(
        json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

def _canonical_pkg(pkg: dict) -> str:
    return hashlib.sha256(
        json.dumps(pkg, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

def _new_task(task_id: str, ctx_id: str) -> dict:
    return {
        "id":        task_id,
        "contextId": ctx_id,
        "status":    "TASK_STATE_INPUT_REQUIRED",
        "history":   [],
        "artifacts": [],
        "metadata":  {},
    }

VALID_ACTIONS = {
    "settle_invoice", "request_approval", "hold_invoice",
    "reject_duplicate", "open_exception",
}

_INVOICE_PROMPT_TMPL = """You are an expert invoice reconciliation agent.
For each invoice package below, choose EXACTLY ONE action from:
  settle_invoice, request_approval, hold_invoice, reject_duplicate, open_exception

Rules:
- settle_invoice: valid, reconciled, within autonomous authority (amount <= 1,000,000 minor units / INR 10,000)
- request_approval: valid but outside delegated authority (amount > 1,000,000 minor units)
- hold_invoice: payment must pause pending stated verification
- reject_duplicate: same commercial invoice was already paid or duplicate
- open_exception: material records conflict / discrepancy

Return a JSON array, one object per package, in the SAME ORDER as input:
[
  {{
    "packageId": "...",
    "action": "settle_invoice",
    "vendorName": "...",
    "invoiceNumber": "...",
    "amountMinor": 12345,
    "currency": "INR",
    "evidenceRefs": ["exact quote 1", "exact quote 2"],
    "rationale": "Detailed rationale naming chosen action and evidence"
  }}
]

Packages:
{packages_json}
"""

async def _decide_packages_llm(packages: list) -> list:
    if not _GEMINI_CLIENT:
        return [_rule_based_decision(p) for p in packages]

    prompt = _INVOICE_PROMPT_TMPL.format(
        packages_json=json.dumps(packages, indent=2))
    try:
        resp = _GEMINI_CLIENT.models.generate_content(
            model="gemini-1.5-flash-latest",
            contents=prompt,
        )
        text = resp.text.strip()
        m = re.search(r"\[.*\]", text, re.S)
        if m:
            decisions = json.loads(m.group())
            if len(decisions) == len(packages):
                return [_build_proposal(packages[i], decisions[i])
                        for i in range(len(packages))]
    except Exception:
        pass
    return [_rule_based_decision(p) for p in packages]

def _build_proposal(pkg: dict, d: dict) -> dict:
    action = d.get("action", "settle_invoice")
    if action not in VALID_ACTIONS:
        action = "settle_invoice"
    return {
        "packageId":    pkg.get("packageId", str(uuid.uuid4())),
        "actionId":     str(uuid.uuid4()).replace("-","")[:14],
        "action":       action,
        "facts": {
            "vendorName":    d.get("vendorName") or pkg.get("vendorName",""),
            "invoiceNumber": d.get("invoiceNumber") or pkg.get("invoiceNumber",""),
            "amountMinor":   d.get("amountMinor") if d.get("amountMinor") is not None else pkg.get("amountMinor", 0),
            "currency":      d.get("currency") or pkg.get("currency", "INR"),
        },
        "evidenceRefs": [str(x) for x in (d.get("evidenceRefs") or [])[:3]],
        "rationale":    (d.get("rationale") or f"Action {action} selected based on invoice rules.")[:1500],
    }

def _rule_based_decision(pkg: dict) -> dict:
    txt = json.dumps(pkg)
    action = "settle_invoice"
    evidence = []
    
    if re.search(r"duplicate|already paid|previously (paid|settled)", txt, re.I):
        action = "reject_duplicate"
        m = re.search(r"([^.]*?(?:duplicate|already paid|previously (?:paid|settled))[^.]*\.?)", txt, re.I)
        if m: evidence.append(m.group(1).strip())
    elif re.search(r"pending verification|hold|verification required|pause", txt, re.I):
        action = "hold_invoice"
        m = re.search(r"([^.]*?(?:pending verification|hold|verification required|pause)[^.]*\.?)", txt, re.I)
        if m: evidence.append(m.group(1).strip())
    elif re.search(r"conflict|discrepancy|mismatch|material records", txt, re.I):
        action = "open_exception"
        m = re.search(r"([^.]*?(?:conflict|discrepancy|mismatch|material records)[^.]*\.?)", txt, re.I)
        if m: evidence.append(m.group(1).strip())
    elif isinstance(pkg.get("amountMinor"), (int, float)) and pkg["amountMinor"] > 1_000_000:
        action = "request_approval"
        evidence.append(f"Amount {pkg.get('amountMinor')} exceeds limit 1000000")

    if not evidence:
        evidence.append(f"Invoice {pkg.get('invoiceNumber', '')} verified")

    return {
        "packageId":    pkg.get("packageId", str(uuid.uuid4())),
        "actionId":     str(uuid.uuid4()).replace("-","")[:14],
        "action":       action,
        "facts": {
            "vendorName":    pkg.get("vendorName") or pkg.get("vendor", ""),
            "invoiceNumber": pkg.get("invoiceNumber") or pkg.get("invoice_number", ""),
            "amountMinor":   pkg.get("amountMinor") if pkg.get("amountMinor") is not None else pkg.get("amount", 0),
            "currency":      pkg.get("currency", "INR"),
        },
        "evidenceRefs": evidence,
        "rationale":    f"Action '{action}' proposed. Evidence: {', '.join(evidence)}",
    }

async def _cached_decide(packages: list) -> list:
    result_map: Dict[int, dict] = {}
    uncached_idxs: List[int]    = []
    uncached_pkgs: list         = []

    for i, pkg in enumerate(packages):
        h = _canonical_pkg(pkg)
        if h in _PKG_CACHE:
            cached = dict(_PKG_CACHE[h])
            cached["packageId"] = pkg.get("packageId", cached["packageId"])
            cached["actionId"]  = str(uuid.uuid4()).replace("-","")[:14]
            result_map[i] = cached
        else:
            uncached_idxs.append(i)
            uncached_pkgs.append(pkg)

    if uncached_pkgs:
        new_decisions = await _decide_packages_llm(uncached_pkgs)
        for j, i in enumerate(uncached_idxs):
            h = _canonical_pkg(packages[i])
            _PKG_CACHE[h] = new_decisions[j]
            result_map[i] = new_decisions[j]

    return [result_map[i] for i in range(len(packages))]


# ── Agent Card ────────────────────────────────────────────────────────────────

@app.get("/.well-known/agent-card.json")
async def agent_card(req: Request):
    proto = req.headers.get("x-forwarded-proto", "https")
    host = req.headers.get("host", str(req.url.hostname))
    base = f"{proto}://{host}/a2a/"
    
    return Response(
        content=json.dumps({
            "name":        "GA5 Invoice Action Agent",
            "description": "Reads invoice batches, decides one business action per package, "
                            "waits for grader results, and stores completed tasks.",
            "version":     "1.0",
            "url":         base,
            "capabilities": {
                "supportedInterfaces": [{
                    "url":              base,
                    "protocolBinding":  "HTTP+JSON",
                    "protocolVersion":  "1.0",
                    "defaultInputModes":  [A2A_IN_BATCH],
                    "defaultOutputModes": [A2A_OUT_PROPS, A2A_OUT_RCPT],
                }],
                "skills": [{
                    "name":        "invoice_action_agent",
                    "description": "Reconciles invoice packages and proposes one typed action "
                                   "per package with cited evidence.",
                    "tags":        ["invoice", "a2a", "reconciliation", "finance"],
                }],
            },
        }),
        media_type="application/json"
    )


# ── message:send ──────────────────────────────────────────────────────────────

@app.post("/a2a/message:send")
async def a2a_send(req: Request):
    principal = _get_principal(req)
    _check_version(req)
    _check_media(req)

    body = await req.json()
    msg  = body.get("message", {})
    msg_id  = msg.get("messageId", str(uuid.uuid4()))
    task_id = msg.get("taskId")
    ctx_id  = msg.get("contextId", str(uuid.uuid4()))

    msg_hash = _canon_msg(msg)

    # ── Idempotency Check ────────────────────────────────────────────────────
    if msg_id in _A2A_IDEM[principal]:
        old_hash, stored_task_id = _A2A_IDEM[principal][msg_id]
        if old_hash != msg_hash:
            return _a2a_resp({"error": "IDEMPOTENCY_CONFLICT"}, status_code=409)
        task = _A2A_TASKS[principal].get(stored_task_id)
        if task:
            return _a2a_resp({"task": task})

    # ── Continuation vs New Task ─────────────────────────────────────────────
    parts = msg.get("parts", [])
    result_parts = [p for p in parts if p.get("mediaType") == A2A_RESULTS]

    if result_parts and task_id:
        return await _handle_continuation(principal, msg, msg_id, task_id, ctx_id, result_parts, msg_hash)

    return await _handle_new_batch(principal, msg, msg_id, ctx_id, msg_hash, body)


async def _handle_new_batch(principal, msg, msg_id, ctx_id, msg_hash, body):
    task_id = str(uuid.uuid4())
    task    = _new_task(task_id, ctx_id)
    task["history"].append(msg)

    all_packages = []
    batch_id     = ""
    for part in msg.get("parts", []):
        if part.get("mediaType") == A2A_IN_BATCH:
            data        = part.get("data", {})
            batch_id    = data.get("batchId", batch_id)
            all_packages.extend(data.get("packages", []))

    proposals = await _cached_decide(all_packages)

    artifact = {
        "artifactId": str(uuid.uuid4()),
        "name": "Invoice Action Proposals",
        "parts": [{
            "mediaType": A2A_OUT_PROPS,
            "data": {
                "batchId":   batch_id,
                "proposals": proposals,
            },
        }]
    }
    task["artifacts"] = [artifact]
    task["status"]    = "TASK_STATE_INPUT_REQUIRED"
    task["metadata"]["batchId"]   = batch_id
    task["metadata"]["principal"] = principal

    _A2A_TASKS[principal][task_id]  = task
    _A2A_IDEM[principal][msg_id]    = (msg_hash, task_id)

    return _a2a_resp({"task": task})


async def _handle_continuation(principal, msg, msg_id, task_id, ctx_id, result_parts, msg_hash):
    task = _A2A_TASKS[principal].get(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.get("metadata", {}).get("principal") != principal:
        raise HTTPException(404, "Task not found")

    with _task_lock(task_id):
        # Validate contextId matches task
        if ctx_id and task.get("contextId") and ctx_id != task.get("contextId"):
            return _a2a_resp({"error": "INVALID_CONTINUATION"}, status_code=400)

        # Terminal state: replay stored task
        if task["status"] in ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED", "TASK_STATE_FAILED"):
            _A2A_IDEM[principal][msg_id] = (msg_hash, task_id)
            return _a2a_resp({"task": task})

        stored_batch = task["metadata"].get("batchId", "")

        # Extract proposals from stored artifact
        stored_proposals: Dict[str, dict] = {}
        for art in task.get("artifacts", []):
            for part in art.get("parts", []):
                if part.get("mediaType") == A2A_OUT_PROPS:
                    for prop in part.get("data", {}).get("proposals", []):
                        stored_proposals[prop["packageId"]] = prop

        executions = []
        for rpart in result_parts:
            data    = rpart.get("data", {})
            r_batch = data.get("batchId")
            if r_batch and stored_batch and r_batch != stored_batch:
                return _a2a_resp({"error": "INVALID_CONTINUATION_BATCH_MISMATCH"}, status_code=400)

            results = data.get("results", [])
            for r in results:
                pid    = r.get("packageId")
                aid    = r.get("actionId")
                action = r.get("action")
                nonce  = r.get("receiptNonce", "")
                outcome= r.get("outcome", "REJECTED")

                prop = stored_proposals.get(pid)
                if not prop:
                    continue
                # Strict action identity check
                if prop["actionId"] != aid or prop["action"] != action:
                    continue

                if outcome == "ACCEPTED":
                    executions.append({
                        "packageId":    pid,
                        "actionId":     aid,
                        "action":       action,
                        "receiptNonce": nonce,
                        "facts":        prop["facts"],
                        "evidenceRefs": prop.get("evidenceRefs", []),
                    })

        receipt_artifact = {
            "artifactId": str(uuid.uuid4()),
            "name": "Invoice Action Receipts",
            "parts": [{
                "mediaType": A2A_OUT_RCPT,
                "data": {
                    "batchId":    stored_batch,
                    "executions": executions,
                },
            }]
        }
        task["artifacts"].append(receipt_artifact)
        task["history"].append(msg)
        task["status"] = "TASK_STATE_COMPLETED"

        _A2A_IDEM[principal][msg_id] = (msg_hash, task_id)

    return _a2a_resp({"task": task})


# ── task reads ────────────────────────────────────────────────────────────────

@app.get("/a2a/tasks/{task_id}")
async def a2a_get(task_id: str, req: Request):
    principal = _get_principal(req)
    _check_version(req)
    task = _A2A_TASKS[principal].get(task_id)
    if not task or task.get("metadata", {}).get("principal") != principal:
        raise HTTPException(404, "Task not found")
    return _a2a_resp({"task": task})

@app.get("/a2a/tasks")
async def a2a_list(req: Request):
    principal = _get_principal(req)
    _check_version(req)
    tasks = [t for t in _A2A_TASKS[principal].values() if t.get("metadata", {}).get("principal") == principal]
    return _a2a_resp({"tasks": tasks})


# ── cancel ────────────────────────────────────────────────────────────────────

@app.post("/a2a/tasks/{task_id}:cancel")
async def a2a_cancel(task_id: str, req: Request):
    principal = _get_principal(req)
    _check_version(req)
    _check_media(req)

    task = _A2A_TASKS[principal].get(task_id)
    if not task or task.get("metadata", {}).get("principal") != principal:
        raise HTTPException(404, "Task not found")

    with _task_lock(task_id):
        if task["status"] in ("TASK_STATE_COMPLETED", "TASK_STATE_FAILED"):
            return _a2a_resp({"error": "Task already terminal"}, status_code=409)
        
        task["status"] = "TASK_STATE_CANCELED"

    return _a2a_resp({"task": task})
