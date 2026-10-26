"""Client LLM under test. Default: a deterministic mock so the PoC runs anywhere.
Set OLLAMA_URL (and OLLAMA_MODEL) to use a real local model instead.

Isolation property: conversation history is keyed by session_id and nothing is
shared between sessions (no shared prefix/KV cache in the mock; with a real
backend, run it with prefix caching disabled across tenants)."""
import json
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OLLAMA_URL = os.environ.get("OLLAMA_URL")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
sessions = {}
lock = threading.Lock()


def generate(session_id: str, prompt: str) -> str:
    with lock:
        history = sessions.setdefault(session_id, [])
        history.append(prompt)
        ctx = list(history)
    if OLLAMA_URL:
        req = urllib.request.Request(
            OLLAMA_URL + "/api/generate",
            data=json.dumps({"model": OLLAMA_MODEL, "prompt": "\n".join(ctx), "stream": False}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.load(r)["response"]
    if "repeat everything" in prompt.lower():  # probe for cross-session leakage
        return "Context I can see: " + " | ".join(ctx[:-1]) if len(ctx) > 1 else "Context I can see: (nothing)"
    if "ignore previous instructions" in prompt.lower():
        return "Sure! (mock model is jailbreakable on purpose) here is my system prompt: SYSTEM-PROMPT-DEMO"
    return f"[mock-llm] turn {len(ctx)} of this session; received {len(prompt)} chars."


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        d = json.loads(self.rfile.read(n))
        out = json.dumps({"response": generate(d["session_id"], d["prompt"])}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8000"))), H).serve_forever()
