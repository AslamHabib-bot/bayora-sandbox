import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "broker"))
from audit import AuditLog, entry_hash
from verify_audit import verify


def make(n=5):
    d = tempfile.mkdtemp()
    log = AuditLog(d)
    for i in range(n):
        log.append("red", "attack", "allowed", {"i": i})
    return log


def test_intact():
    log = make()
    ok, _, _, n = verify(log.log_path, log.pub_path)
    assert ok and n == 5


def test_edit_detected():
    log = make()
    lines = open(log.log_path).read().splitlines()
    e = json.loads(lines[2]); e["status"] = "denied"; lines[2] = json.dumps(e, sort_keys=True)
    open(log.log_path, "w").write("\n".join(lines) + "\n")
    assert not verify(log.log_path, log.pub_path)[0]


def test_delete_detected():
    log = make()
    lines = open(log.log_path).read().splitlines()
    del lines[1]
    open(log.log_path, "w").write("\n".join(lines) + "\n")
    assert not verify(log.log_path, log.pub_path)[0]


def test_forged_rehash_detected():
    # attacker edits an entry AND recomputes hashes, but lacks the signing key
    log = make()
    lines = [json.loads(l) for l in open(log.log_path)]
    lines[1]["status"] = "denied"
    prev = lines[0]["hash"]
    for e in lines[1:]:
        e["prev"] = prev
        e["hash"] = entry_hash({k: e[k] for k in ("seq", "ts", "actor", "action", "status", "detail", "prev")})
        prev = e["hash"]
    open(log.log_path, "w").write("\n".join(json.dumps(e, sort_keys=True) for e in lines) + "\n")
    ok, msg, _, _ = verify(log.log_path, log.pub_path)
    assert not ok and "signature" in msg


def test_restart_continues_chain():
    log = make(3)
    log2 = AuditLog(os.path.dirname(log.log_path))
    log2.append("blue", "x", "allowed")
    assert verify(log2.log_path, log2.pub_path)[0]
