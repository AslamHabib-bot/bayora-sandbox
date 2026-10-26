#!/usr/bin/env python3
"""Standalone audit verifier. Usage: verify_audit.py <audit.jsonl> <audit_pub.pem>

Recomputes the hash chain and checks every Ed25519 signature.
Exit code 0 = intact, 1 = tampering detected.
"""
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def verify(log_path: str, pub_path: str):
    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    prev, expected_seq, count = GENESIS, 1, 0
    with open(log_path) as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
                body = {k: e[k] for k in ("seq", "ts", "actor", "action", "status", "detail", "prev")}
            except (ValueError, KeyError):
                return False, f"line {lineno}: malformed entry", prev, count
            if e["seq"] != expected_seq:
                return False, f"line {lineno}: sequence gap (expected {expected_seq}, got {e['seq']})", prev, count
            if e["prev"] != prev:
                return False, f"line {lineno}: chain broken (prev hash mismatch)", prev, count
            h = hashlib.sha256(canonical(body)).hexdigest()
            if h != e.get("hash"):
                return False, f"line {lineno}: entry content altered (hash mismatch)", prev, count
            try:
                pub.verify(bytes.fromhex(e["sig"]), bytes.fromhex(h))
            except (InvalidSignature, ValueError):
                return False, f"line {lineno}: invalid signature", prev, count
            prev, expected_seq, count = h, expected_seq + 1, count + 1
    return True, "chain intact, all signatures valid", prev, count


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    ok, msg, head, n = verify(sys.argv[1], sys.argv[2])
    print(("VERIFIED" if ok else "TAMPERING DETECTED") + f": {msg} | entries={n} head={head[:16]}...")
    sys.exit(0 if ok else 1)
