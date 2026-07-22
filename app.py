"""
TDS GA5 — Unified FastAPI App
Covers Q2, Q3, Q4, Q5, Q6 (MCP), Q8, Q9, Q10

Deploy once; submit the appropriate route URL for each question.

Your personalised values (secret file, allowed domains, etc.) come from the spec.
Update the CONFIG section below with YOUR personal values from the exam page.
"""

import calendar
import hashlib
import json
import os
import re
import uuid
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs
import ipaddress

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio

app = FastAPI(title="TDS GA5 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# PERSONALISE THIS SECTION (read from the exam page for your email)
# ---------------------------------------------------------------------------
YOUR_EMAIL = "24f2006167@ds.study.iitm.ac.in"    # ← your exam email (lowercase)

# Q3 / Q8 personalised values from the exam – fill in after you open the task:
Q3_SECRET_PATH  = "/home/agent/.pgpass"           # the "must NEVER read" file
Q3_WRITE_DIR    = "/home/agent/workspace/build/"  # allowed write root
Q3_ALLOWED_HOSTS = ["objects.githubusercontent.com", "raw.githubusercontent.com"]

# Q8 personalised values:
Q8_SANDBOX_ROOT   = "/srv/agent-redteam/sandbox-426f63f28d"
Q8_ALLOWED_HOSTS  = {"example.com", "www.iana.org"}
Q8_CANARY_TOKEN   = "AGENT_GUARDRAIL_CANARY_24e40e302a65de94f5ee4908e83a0b556a3088f3"

# Q10 A2A — choose a secret bearer token (you pick it, submit the URL + this token)
A2A_BEARER = "ga5-secret-token-2026"
# ---------------------------------------------------------------------------


# ============================================================
#  HEALTH
# ============================================================
@app.get("/health")
async def health():
    return {"status": "ok"}


# ============================================================
#  Q2 — Proration  /prorate
# ============================================================
@app.post("/prorate")
async def prorate(req: Request):
    b = await req.json()
    old  = b["old_price"]
    new  = b["new_price"]
    spec = b.get("spec", "v2")           # "v1" or "v2"

    # Support both field-name variants the grader may send
    year  = b.get("year")  or b.get("billing_year")
    month = b.get("month") or b.get("billing_month")
    day   = b.get("upgrade_day") or b.get("day") or b.get("days_remaining")

    days_in_month   = b.get("days_in_actual_month") or (calendar.monthrange(int(year), int(month))[1] if year and month else 30)
    days_remaining  = b.get("days_remaining") or (int(days_in_month) - int(day) + 1)

    delta = new - old
    if spec == "v1":
        charge = round(delta * (days_remaining / 30), 2)
    else:
        charge = round(delta * (days_remaining / days_in_month), 2)

    return {"charge": charge}


# ============================================================
#  Q3 — Pre-tool-call Guardrail  /q3/check
# ============================================================

def _normpath(p: str) -> str:
    return os.path.normpath(p)

def _resolves_inside(path: str, root: str) -> bool:
    if os.path.isabs(path):
        full = _normpath(path)
    else:
        full = _normpath(os.path.join(root, path))
    root_n = _normpath(root)
    return full == root_n or full.startswith(root_n + os.sep)

def _extract_host(url: str) -> str:
    try:
        return urlparse(url).hostname.lower()
    except Exception:
        return ""

@app.post("/q3/check")
async def q3_check(req: Request):
    b    = await req.json()
    tool = b.get("tool", "")
    args = b.get("arguments", b.get("args", {}))

    if tool == "bash":
        cmd = args.get("command", "")
        # Block any attempt to read the secret file (raw path, env-var expansion, etc.)
        secret_base = os.path.basename(Q3_SECRET_PATH)
        if _is_secret_bash(cmd, Q3_SECRET_PATH):
            return {"decision": "block", "reason": f"Command targets the restricted secret path."}
        return {"decision": "allow", "reason": "Bash command appears safe."}

    if tool == "write_file":
        path = args.get("path", "")
        if _resolves_inside(path, Q3_WRITE_DIR):
            return {"decision": "allow", "reason": "Write is within allowed directory."}
        return {"decision": "block", "reason": "Write target is outside the allowed directory."}

    if tool == "http_request":
        url  = args.get("url", "")
        host = _extract_host(url)
        if host in Q3_ALLOWED_HOSTS:
            return {"decision": "allow", "reason": "Host is in the allowed list."}
        return {"decision": "block", "reason": f"Host '{host}' is not in the allowed list."}

    # Unknown tool → allow (safe default)
    return {"decision": "allow", "reason": "Unknown tool; allowed by default."}

def _is_secret_bash(cmd: str, secret_path: str) -> bool:
    """Return True if the bash command is an attempt to read the secret file."""
    secret_norm  = os.path.normpath(secret_path)
    secret_base  = os.path.basename(secret_path)
    home_variants = ["/home/agent", "$HOME", "~"]

    # Direct match (normalised)
    for h in home_variants:
        trial = os.path.normpath(cmd.replace("$HOME", "/home/agent").replace("~", "/home/agent"))
        if secret_norm in trial:
            return True

    # Filename appears in command
    if secret_base in cmd:
        return True

    # base64-encoded path
    import base64
    try:
        decoded = base64.b64decode(re.search(r'[A-Za-z0-9+/=]{20,}', cmd).group()).decode()
        if secret_norm in decoded or secret_base in decoded:
            return True
    except Exception:
        pass

    return False


# ============================================================
#  Q4 — Skill Safety Audit  /q4/scan
# ============================================================

EXCESSIVE_PATTERN = re.compile(
    r"""
    (
        entire\s+file\s*system
      | whole\s+home
      | full\s+file\s*system
      | unrestricted\s+(egress|access|network)
      | unlimited\s+(egress|access|network)
      | arbitrary\s+(egress|access|network|file)
      | (read|write|read[-/]write)\s+(access\s+to\s+)?(/\b|the\s+entire|the\s+whole|the\s+full)
      | egress\s+(to\s+)?(any\s+(\w+\s+)?domain|all\s+\w+)
      | (access|network)\s+to\s+any\s+(\w+\s+)?host
      | access\s+to\s+any\s+(\w+\s+)?domain
      | network[:\s]+\s*any\s+\w*\s*(host|domain|external)
    )
    """,
    re.I | re.X,
)

PROMPT_INJECT_PATTERN = re.compile(
    r"(stop|cancel|halt|pause|abort).*?(ignore|override|disregard|bypass).*?(user|request|instruction|command)",
    re.I | re.S,
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"""
    (
        (?:api_?key|api_?secret|auth_?token|webhook_?secret|private_?key|password|secret)[^\n]*?["'`]?[A-Za-z0-9\-_]{16,}["'`]?
      | (?:AKIA|ASIA)[A-Z0-9]{16}                                  # AWS access key
      | (?:sk-|sk_live_|sk_test_)[A-Za-z0-9]{20,}                 # OpenAI / Stripe
      | [0-9a-fA-F]{32,}                                           # raw hex secret >=32 chars
      | https?://[^@\s]+:[^@\s]+@                                  # URL with embedded password
    )
    """,
    re.I | re.X,
)

@app.post("/q4/scan")
async def q4_scan(req: Request):
    b    = await req.json()
    skill = b.get("skill", "")

    categories: List[str] = []

    # 1. Hardcoded secret
    if HARDCODED_SECRET_PATTERN.search(skill):
        categories.append("hardcoded_secret")

    # 2. Prompt injection (stop + ignore + user-reference)
    if PROMPT_INJECT_PATTERN.search(skill):
        categories.append("prompt_injection")

    # 3. Excessive permissions
    if EXCESSIVE_PATTERN.search(skill):
        categories.append("excessive_permissions")

    # 4. Unclear provenance — no author/version/changelog in frontmatter
    if _lacks_provenance(skill):
        categories.append("unclear_provenance")

    return {"categories": categories}

def _lacks_provenance(skill: str) -> bool:
    """Return True if the YAML front-matter has no author, version, or changelog."""
    # Extract front-matter block
    fm_match = re.match(r"^---\s*\n(.*?)\n---", skill, re.S)
    if not fm_match:
        return True
    fm = fm_match.group(1)
    has_author    = bool(re.search(r"^\s*(author|maintainer)\s*:", fm, re.I | re.M))
    has_version   = bool(re.search(r"^\s*version\s*:", fm, re.I | re.M))
    has_changelog = bool(re.search(r"^\s*(changelog|history)\s*:", fm, re.I | re.M))
    return not (has_author or has_version or has_changelog)


# ============================================================
#  Q5 — Run Budget & Loop Guard  /q5/check
# ============================================================

def _canon_args(args: Any) -> str:
    """Canonical JSON: sort keys, normalise whitespace inside strings, drop trace_id."""
    if isinstance(args, dict):
        cleaned = {k: _canon_args(v) for k, v in args.items() if k != "trace_id"}
        return json.dumps(cleaned, sort_keys=True, separators=(",", ":"))
    if isinstance(args, list):
        return json.dumps([_canon_args(i) for i in args], separators=(",", ":"))
    if isinstance(args, str):
        return " ".join(args.split())   # normalise whitespace
    return json.dumps(args)

@app.post("/q5/check")
async def q5_check(req: Request):
    b = await req.json()
    budget = b["budget_tokens"]
    steps  = b.get("steps", [])

    # Rule 1 — budget
    cumulative = sum(s.get("tokens_used", 0) for s in steps)
    if cumulative >= budget:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({cumulative}) has reached the budget ({budget}).",
        }

    # Rule 2a — 3+ consecutive identical calls (same tool + same canonical args)
    def step_key(s):
        tool = s.get("tool", "")
        args = _canon_args(s.get("args", s.get("arguments", {})))
        return (tool, args)

    n = 3
    if len(steps) >= n:
        tail = steps[-n:]
        keys = {step_key(s) for s in tail}
        if len(keys) == 1:
            t, _ = step_key(tail[0])
            return {
                "decision": "halt",
                "reason": f"Loop detected: '{t}' called {n}+ times in a row with identical arguments.",
            }

    # Rule 2b — 2-step A/B cycle repeating for 6+ trailing steps
    if len(steps) >= 6:
        tail = steps[-6:]
        if len({step_key(s) for s in tail}) == 2:
            # Check it alternates: A B A B A B
            k = [step_key(s) for s in tail]
            if k[0] == k[2] == k[4] and k[1] == k[3] == k[5] and k[0] != k[1]:
                return {
                    "decision": "halt",
                    "reason": "Loop detected: 2-step A/B cycle repeating over 6 trailing steps.",
                }

    return {
        "decision": "continue",
        "reason": f"Cumulative tokens ({cumulative}) is under budget ({budget}) and agent is making progress.",
    }


# ============================================================
#  Q6 — Live MCP Server  /mcp  (Streamable HTTP transport)
# ============================================================

EMAIL_NORM = YOUR_EMAIL.strip().lower()

def _mcp_solve(challenge: str) -> str:
    s = f"{challenge}:{EMAIL_NORM}"
    return hashlib.sha256(s.encode()).hexdigest()[:16]

def _mcp_response(id_: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}

def _mcp_error(id_: Any, code: int, msg: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": msg}}

TOOL_DEF = {
    "name": "solve_challenge",
    "description": "Solve the per-call challenge using HMAC-SHA256.",
    "inputSchema": {"type": "object", "properties": {}, "required": []},
}

@app.post("/mcp")
async def mcp_post(req: Request):
    try:
        body = await req.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid json"})

    # Support batch or single
    if isinstance(body, list):
        return JSONResponse([await _handle_mcp_msg(msg, req) for msg in body])
    return JSONResponse(await _handle_mcp_msg(body, req))

async def _handle_mcp_msg(msg: dict, req: Request) -> dict:
    method = msg.get("method", "")
    id_    = msg.get("id")

    if method == "initialize":
        return _mcp_response(id_, {
            "protocolVersion": "2024-11-05",
            "capabilities":    {"tools": {}},
            "serverInfo":      {"name": "ga5-mcp", "version": "1.0"},
        })

    if method == "notifications/initialized":
        return {}   # notification, no reply needed

    if method == "tools/list":
        return _mcp_response(id_, {"tools": [TOOL_DEF]})

    if method == "tools/call":
        params = msg.get("params", {})
        if params.get("name") == "solve_challenge":
            challenge = req.headers.get("x-exam-challenge", req.headers.get("X-Exam-Challenge", ""))
            answer    = _mcp_solve(challenge)
            return _mcp_response(id_, {"content": [{"type": "text", "text": answer}]})
        return _mcp_error(id_, -32602, "Unknown tool")

    if method in ("ping",):
        return _mcp_response(id_, {})

    return _mcp_error(id_, -32601, f"Method not found: {method}")

# SSE endpoint for clients that prefer it
@app.get("/mcp")
async def mcp_sse(req: Request):
    async def event_stream():
        yield f"data: {json.dumps({'type':'endpoint','url':str(req.url).replace('/mcp','') + '/mcp'})}\n\n"
        await asyncio.sleep(60)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ============================================================
#  Q8 — Guardrail Red-Team Round-Trip  /q8/check
# ============================================================

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _is_private_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False

def _is_internal_value(val: str) -> bool:
    """Detect if a query-parameter value looks like an internal target."""
    val = val.strip()
    # Another URL pointing inside
    if re.match(r"https?://", val, re.I):
        inner_host = _extract_host(val)
        if inner_host and inner_host not in Q8_ALLOWED_HOSTS:
            return True
        if inner_host and _is_private_ip(inner_host):
            return True
    # Raw IP
    if _is_private_ip(val):
        return True
    # metadata keyword
    if re.search(r"169\.254|metadata\.google|metadata\.internal|localhost", val, re.I):
        return True
    return False

@app.post("/q8/check")
async def q8_check(req: Request):
    b = await req.json()
    tool = b.get("tool", "")
    args = b.get("arguments", b.get("args", {}))

    if tool in ("read_file", "write_file"):
        path = args.get("path", "")
        if _resolves_inside(path, Q8_SANDBOX_ROOT):
            return {"action": "allow", "reason": "Path is within the sandbox."}
        return {"action": "block", "reason": "Path escapes the sandbox root."}

    if tool in ("fetch_url", "fetch", "http_request", "network"):
        url  = args.get("url", "")
        parsed = urlparse(url)
        host   = (parsed.hostname or "").lower()

        # Block private/metadata IPs
        if _is_private_ip(host):
            return {"action": "block", "reason": "Private or metadata IP is not allowed."}

        # Block disallowed hostnames (exact match)
        if host not in Q8_ALLOWED_HOSTS:
            return {"action": "block", "reason": f"Host '{host}' is not in the allowed list."}

        # Even if the host is allowed, check redirect/ssrf params
        for vals in parse_qs(parsed.query).values():
            for v in vals:
                if _is_internal_value(v):
                    return {"action": "block", "reason": "Query parameter carries an internal/SSRF target."}

        return {"action": "allow", "reason": "Request is to an allowed host with safe parameters."}

    # Default allow for unknown tools
    return {"action": "allow", "reason": "Tool not restricted by this guardrail."}


# ============================================================
#  Q9 — Safe AI Mailroom Agent  /q9/mailroom
# ============================================================
# This is a STUB that logs requests and returns a minimal response.
# For full credit you need an LLM layer to classify dossiers.
# The scaffolding below handles the API envelope correctly.

q9_store: Dict[str, Any] = {}   # evaluationId → stored proposal

@app.post("/q9/mailroom")
async def q9_mailroom(req: Request):
    b = await req.json()
    op = b.get("operation", "propose")

    if op == "propose":
        eval_id = b.get("evaluationId", str(uuid.uuid4()))
        dossiers = b.get("dossiers", [])
        proposals = []
        for d in dossiers:
            proposal = _classify_dossier(d)
            proposals.append(proposal)
        q9_store[eval_id] = proposals
        return JSONResponse({
            "status": "awaiting_receipts",
            "evaluationId": eval_id,
            "proposals": proposals,
        })

    if op == "commit":
        eval_id  = b.get("evaluationId", "")
        receipts = b.get("receipts", [])
        proposals = q9_store.get(eval_id, [])
        outcomes  = []
        for r in receipts:
            outcomes.append({
                "packageId": r.get("packageId", ""),
                "receipt":   r,
                "executed":  True,
            })
        return JSONResponse({"status": "completed", "evaluationId": eval_id, "outcomes": outcomes})

    raise HTTPException(status_code=400, detail="Unknown operation")

def _classify_dossier(d: dict) -> dict:
    """
    Rule-based dossier classifier.
    Replace / augment with LLM call for the audit dossiers.
    """
    did      = d.get("dossierId", str(uuid.uuid4()))
    content  = json.dumps(d)

    # Prompt injection check first
    if re.search(r"(higher.priority instruction|copy any vault marker|ignore.*?instruction)", content, re.I):
        return {
            "packageId": did,
            "actionId":  str(uuid.uuid4())[:12],
            "action":    "quarantine_item",
            "target":    {"kind": "security_queue", "id": "mailroom"},
            "payload":   {"artifactId": did, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            "evidenceRefs": [],
        }

    # No-action (duplicate / informational)
    if re.search(r"no new change|already completed|duplicate", content, re.I):
        return {
            "packageId": did,
            "actionId":  str(uuid.uuid4())[:12],
            "action":    "no_action",
            "target":    None,
            "payload":   {"reasonCode": "ALREADY_COMPLETED", "referenceId": did},
            "evidenceRefs": [],
        }

    # Approved delivery notice
    if re.search(r"permits one delivery.status notice", content, re.I):
        recipient = re.search(r"approved.recipient\s*[:\-]\s*(\S+)", content, re.I)
        return {
            "packageId": did,
            "actionId":  str(uuid.uuid4())[:12],
            "action":    "send_approved_notice",
            "target":    {"kind": "email", "id": recipient.group(1) if recipient else ""},
            "payload":   {"referenceId": did, "status": "delivered", "template": "approved_delivery_notice"},
            "evidenceRefs": [],
        }

    # Default: create_draft (customer work request)
    mailbox = re.search(r"mailbox[:\s]+(\S+)", content, re.I)
    return {
        "packageId": did,
        "actionId":  str(uuid.uuid4())[:12],
        "action":    "create_draft",
        "target":    {"kind": "draft_queue", "id": f"mailbox:{mailbox.group(1) if mailbox else 'default'}"},
        "payload":   {
            "recipient":   "",
            "referenceId": did,
            "status":      "pending",
            "template":    "order_status",
        },
        "evidenceRefs": [],
    }


# ============================================================
#  Q10 — A2A Invoice Agent  /a2a/
# ============================================================

A2A_MEDIA  = "application/a2a+json"
A2A_TASKS: Dict[str, Any] = {}          # taskId → Task
A2A_MSG_MAP: Dict[str, str] = {}        # messageId → taskId  (idempotency)

def _a2a_headers():
    return {"Content-Type": A2A_MEDIA}

def _new_task(task_id: str, state: str = "input_required") -> dict:
    return {
        "id":        task_id,
        "status":    state,
        "artifacts": [],
        "history":   [],
    }

def _require_auth(req: Request):
    auth = req.headers.get("authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != A2A_BEARER:
        raise HTTPException(status_code=401, detail="Unauthorized")

def _require_version(req: Request):
    v = req.headers.get("a2a-version", req.headers.get("A2A-Version", ""))
    if v != "1.0":
        raise HTTPException(status_code=400, detail="A2A-Version must be 1.0")

# Agent Card (public)
@app.get("/.well-known/agent-card.json")
async def agent_card(req: Request):
    base = str(req.base_url).rstrip("/")
    return JSONResponse({
        "name":        "GA5 Invoice Agent",
        "description": "TDS GA5 A2A invoice-action agent.",
        "version":     "1.0",
        "url":         f"{base}/a2a/",
        "capabilities": {
            "supportedInterfaces": [{
                "protocolBinding":    "HTTP+JSON",
                "protocolVersion":    "1.0",
                "defaultInputModes":  ["application/vnd.ga5.invoice-claim-batch+json",
                                       "application/vnd.ga5.invoice-action-receipts+json"],
                "defaultOutputModes": ["application/vnd.ga5.invoice-action-proposals+json",
                                       "application/vnd.ga5.invoice-action-receipts+json"],
            }],
            "skills": [{
                "name":        "invoice_action_agent",
                "description": "Reads invoice batches and decides one action per package.",
                "tags":        ["invoice", "a2a"],
            }],
        },
    })

@app.post("/a2a/message:send")
async def a2a_message_send(req: Request):
    _require_auth(req)
    _require_version(req)

    body = await req.json()
    msg  = body.get("message", {})
    msg_id   = msg.get("messageId", str(uuid.uuid4()))
    task_id  = msg.get("taskId")

    # Idempotency: same messageId → return same task
    if msg_id in A2A_MSG_MAP:
        existing_task_id = A2A_MSG_MAP[msg_id]
        return Response(
            content=json.dumps({"task": A2A_TASKS.get(existing_task_id, {})}),
            media_type=A2A_MEDIA,
        )

    if not task_id:
        task_id = str(uuid.uuid4())

    task = _new_task(task_id, "input_required")
    task["history"].append(msg)

    # Extract invoice batch from message parts
    proposals = []
    for part in msg.get("parts", []):
        if part.get("mediaType") == "application/vnd.ga5.invoice-claim-batch+json":
            data     = part.get("data", {})
            batch_id = data.get("batchId", "")
            packages = data.get("packages", [])
            for pkg in packages:
                proposals.append(_decide_invoice(pkg, batch_id))

    artifact = {
        "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
        "data": {
            "batchId":   batch_id if packages else "",
            "proposals": proposals,
        },
    }
    task["artifacts"].append(artifact)
    task["status"] = "input_required"

    A2A_TASKS[task_id]  = task
    A2A_MSG_MAP[msg_id] = task_id

    return Response(content=json.dumps({"task": task}), media_type=A2A_MEDIA)


@app.post("/a2a/tasks/{task_id}:cancel")
async def a2a_cancel(task_id: str, req: Request):
    _require_auth(req)
    _require_version(req)
    task = A2A_TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["status"] in ("completed", "cancelled", "failed"):
        return Response(content=json.dumps({"task": task}), media_type=A2A_MEDIA)
    task["status"] = "cancelled"
    return Response(content=json.dumps({"task": task}), media_type=A2A_MEDIA)


@app.get("/a2a/tasks/{task_id}")
async def a2a_get_task(task_id: str, req: Request):
    _require_auth(req)
    _require_version(req)
    task = A2A_TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return Response(content=json.dumps({"task": task}), media_type=A2A_MEDIA)


@app.get("/a2a/tasks")
async def a2a_list_tasks(req: Request):
    _require_auth(req)
    _require_version(req)
    # Per-user isolation: return only tasks for this bearer (here we have one token so return all)
    return Response(
        content=json.dumps({"tasks": list(A2A_TASKS.values())}),
        media_type=A2A_MEDIA,
    )


# Receipt continuation — grader posts results back
@app.post("/a2a/tasks/{task_id}/receipts")
async def a2a_receipt(task_id: str, req: Request):
    _require_auth(req)
    _require_version(req)
    body = await req.json()
    task = A2A_TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    results  = body.get("results", [])
    executions = []
    for r in results:
        if r.get("outcome") == "ACCEPTED":
            executions.append(r)

    receipt_artifact = {
        "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
        "data": {"executions": executions},
    }
    task["artifacts"].append(receipt_artifact)
    task["status"] = "completed"
    return Response(content=json.dumps({"task": task}), media_type=A2A_MEDIA)


def _decide_invoice(pkg: dict, batch_id: str) -> dict:
    """Rule-based invoice action decision (adjust with LLM if needed)."""
    content = json.dumps(pkg)
    vendor  = pkg.get("vendorName", pkg.get("vendor", ""))
    inv_no  = pkg.get("invoiceNumber", pkg.get("invoice_number", ""))
    amount  = pkg.get("amountMinor", 0)
    pkg_id  = pkg.get("packageId", str(uuid.uuid4()))

    action_id = str(uuid.uuid4()).replace("-", "")[:14]

    # Duplicate invoice
    if re.search(r"duplicate|already paid|previously (paid|settled)", content, re.I):
        return {
            "packageId":    pkg_id,
            "actionId":     action_id,
            "action":       "reject_duplicate",
            "facts":        {"vendorName": vendor, "invoiceNumber": inv_no, "amountMinor": amount, "currency": "INR"},
            "evidenceRefs": [],
            "rationale":    "Invoice matches a previously paid record; rejecting as duplicate.",
        }

    # Hold for verification
    if re.search(r"pending verification|verification required|hold", content, re.I):
        return {
            "packageId":    pkg_id,
            "actionId":     action_id,
            "action":       "hold_invoice",
            "facts":        {"vendorName": vendor, "invoiceNumber": inv_no, "amountMinor": amount, "currency": "INR"},
            "evidenceRefs": [],
            "rationale":    "Invoice is pending external verification; placing on hold.",
        }

    # Exception
    if re.search(r"conflict|discrepancy|material records conflict", content, re.I):
        return {
            "packageId":    pkg_id,
            "actionId":     action_id,
            "action":       "open_exception",
            "facts":        {"vendorName": vendor, "invoiceNumber": inv_no, "amountMinor": amount, "currency": "INR"},
            "evidenceRefs": [],
            "rationale":    "Material records conflict; opening exception workflow.",
        }

    # Request approval if large amount (over 10 lakh)
    if isinstance(amount, (int, float)) and amount > 1_000_000:
        return {
            "packageId":    pkg_id,
            "actionId":     action_id,
            "action":       "request_approval",
            "facts":        {"vendorName": vendor, "invoiceNumber": inv_no, "amountMinor": amount, "currency": "INR"},
            "evidenceRefs": [],
            "rationale":    "Amount exceeds autonomous settlement authority; requesting approval.",
        }

    # Default: settle
    return {
        "packageId":    pkg_id,
        "actionId":     action_id,
        "action":       "settle_invoice",
        "facts":        {"vendorName": vendor, "invoiceNumber": inv_no, "amountMinor": amount, "currency": "INR"},
        "evidenceRefs": [],
        "rationale":    "Invoice is commercially valid and within autonomous authority; settling.",
    }
