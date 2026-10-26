"""Blue-team client. Registers defences, reads observations, runs isolation probes."""
import json
import os
import socket
import sys
import urllib.error
import urllib.request

BROKER = os.environ.get("BROKER_URL", "http://broker:8080")
TOKEN = os.environ.get("BLUE_TOKEN", "")
results = []


def call(method, path, body=None):
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + TOKEN}
    req = urllib.request.Request(BROKER + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, {}


def reachable(host, port):
    try:
        socket.create_connection((host, port), timeout=2).close()
        return True
    except OSError:
        return False


def check(name, passed, detail=""):
    results.append(passed)
    print(f"  [{'PASS' if passed else 'FAIL'}] {name} {detail}")


print("BLUE TEAM: functional + isolation tests")
code, r = call("POST", "/v1/defense", {"block_substrings": ["system-prompt-demo"]})
check("defence registered via broker", code == 200)

code, r = call("GET", "/v1/observations")
obs = r.get("observations", [])
check("can read model outputs / verdicts", code == 200, f"({len(obs)} observations)")
raw = json.dumps(obs).lower()
check("attack payloads are NOT visible to blue", "ignore previous" not in raw and "canary-red" not in raw)

code, _ = call("POST", "/v1/attack", {"prompt": "probe"})
check("blue cannot submit attacks / act as red", code == 403, f"(HTTP {code})")
check("cannot reach red team directly", not reachable("red", 8080))
check("cannot reach the LLM directly (bypassing broker)", not reachable("llm", 8000))
code, _ = call("GET", "/v1/audit/verify")
check("blue cannot read audit/provenance endpoints", code == 403, f"(HTTP {code})")

print(f"\nBLUE RESULT: {sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
