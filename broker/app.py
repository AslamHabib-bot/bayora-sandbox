"""Policy broker: the ONLY path between red team, blue team and the client LLM.

Every request (allowed or denied) is written to the signed audit log.
Payloads are never written in clear; only their SHA-256 commitment is logged.
"""
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from audit import AuditLog
from verify_audit import verify

AUDIT_DIR = os.environ.get("AUDIT_DIR", "/data")
LLM_URL = os.environ.get("LLM_URL", "http://llm:8000")
PORT = int(os.environ.get("PORT", "8080"))
MAX_BODY = 64 * 1024

TOKENS = {
    os.environ["RED_TOKEN"]: "red",
    os.environ["BLUE_TOKEN"]: "blue",
    os.environ["AUDITOR_TOKEN"]: "auditor",
}

# Capability table: what each role may do. Everything else is denied + logged.
POLICY = {
    "red": {("POST", "/v1/attack")},
    "blue": {("GET", "/v1/observations"), ("POST", "/v1/defense")},
    "auditor": {("GET", "/v1/audit/verify")},
}

audit = AuditLog(AUDIT_DIR)
state_lock = threading.Lock()
defense_rules = []   # blue-private: never returned to red
observations = []    # what blue may see: model output + verdict, NOT the attack payload


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def authenticate(header: str):
    if not header.startswith("Bearer "):
        return None
    presented = header[7:]
    role = None
    for token, r in TOKENS.items():  # constant-time compare, no early exit
        if hmac.compare_digest(token, presented):
            role = r
    return role


def call_llm(session_id: str, prompt: str) -> str:
    req = urllib.request.Request(
        LLM_URL + "/generate",
        data=json.dumps({"session_id": session_id, "prompt": prompt}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["response"]


class Handler(BaseHTTPRequestHandler):
    server_version = "bayora-broker"

    def log_message(self, *a):  # keep container logs free of payload-bearing URLs
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("body too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def _handle(self, method):
        path = self.path.split("?")[0]
        role = authenticate(self.headers.get("Authorization", ""))
        if role is None:
            audit.append("anonymous", f"{method} {path}", "denied", {"reason": "no/invalid token"})
            return self._send(401, {"error": "unauthenticated"})
        if (method, path) not in POLICY[role]:
            audit.append(role, f"{method} {path}", "denied", {"reason": "not permitted for role"})
            return self._send(403, {"error": "forbidden by policy"})
        try:
            body = self._body() if method == "POST" else {}
            if (method, path) == ("POST", "/v1/attack"):
                return self._attack(role, body)
            if (method, path) == ("POST", "/v1/defense"):
                return self._defense(role, body)
            if (method, path) == ("GET", "/v1/observations"):
                return self._observations(role)
            if (method, path) == ("GET", "/v1/audit/verify"):
                ok, msg, head, n = verify(audit.log_path, audit.pub_path)
                return self._send(200, {"ok": ok, "message": msg, "entries": n, "head": head})
        except (ValueError, KeyError) as e:
            audit.append(role, f"{method} {path}", "error", {"reason": type(e).__name__})
            return self._send(400, {"error": "bad request"})
        except Exception as e:  # LLM unreachable etc.
            audit.append(role, f"{method} {path}", "error", {"reason": type(e).__name__})
            return self._send(502, {"error": "upstream failure"})
        self._send(404, {"error": "not found"})

    def _attack(self, role, body):
        prompt = str(body["prompt"])
        session_id = uuid.uuid4().hex  # fresh LLM session per attack: no cross-session context
        with state_lock:
            rules = list(defense_rules)
        blocked, response = False, ""
        if any(r in prompt.lower() for r in rules):
            blocked, response = True, "[blocked by policy]"
        else:
            response = call_llm(session_id, prompt)
            if any(r in response.lower() for r in rules):
                blocked, response = True, "[blocked by policy]"
        with state_lock:
            observations.append({
                "obs_id": len(observations) + 1,
                "ts": time.time(),
                "response": response,
                "blocked": blocked,
            })
        audit.append(role, "attack", "allowed", {
            "session_id": session_id,
            "payload_sha256": sha256(prompt),  # commitment only, payload never logged
            "blocked": blocked,
        })
        self._send(200, {"session_id": session_id, "response": response, "blocked": blocked})

    def _defense(self, role, body):
        new = [str(x).lower() for x in body["block_substrings"]]
        with state_lock:
            defense_rules.extend(new)
        audit.append(role, "defense_update", "allowed", {"rules_sha256": sha256(json.dumps(new))})
        self._send(200, {"rules_active": len(new)})

    def _observations(self, role):
        with state_lock:
            snap = list(observations)
        audit.append(role, "read_observations", "allowed", {"count": len(snap)})
        self._send(200, {"observations": snap})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
