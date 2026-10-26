"""Tamper-evident audit log: SHA-256 hash chain + Ed25519 signature on every entry."""
import datetime
import hashlib
import json
import os
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def entry_hash(body: dict) -> str:
    return hashlib.sha256(canonical(body)).hexdigest()


class AuditLog:
    def __init__(self, directory: str):
        os.makedirs(directory, exist_ok=True)
        self.log_path = os.path.join(directory, "audit.jsonl")
        self.key_path = os.path.join(directory, "audit_key.pem")
        self.pub_path = os.path.join(directory, "audit_pub.pem")
        self._lock = threading.Lock()
        self._key = self._load_or_create_key()
        self._seq, self._prev = self._recover_head()

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            key = Ed25519PrivateKey.generate()
            with open(self.key_path, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
            os.chmod(self.key_path, 0o600)
        with open(self.pub_path, "wb") as f:
            f.write(key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
        return key

    def _recover_head(self):
        seq, prev = 0, GENESIS
        if os.path.exists(self.log_path):
            with open(self.log_path) as f:
                for line in f:
                    if line.strip():
                        e = json.loads(line)
                        seq, prev = e["seq"], e["hash"]
        return seq, prev

    def append(self, actor: str, action: str, status: str, detail: dict | None = None) -> dict:
        with self._lock:
            self._seq += 1
            body = {
                "seq": self._seq,
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "actor": actor,
                "action": action,
                "status": status,
                "detail": detail or {},
                "prev": self._prev,
            }
            h = entry_hash(body)
            entry = {**body, "hash": h, "sig": self._key.sign(bytes.fromhex(h)).hex()}
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev = h
            return entry
