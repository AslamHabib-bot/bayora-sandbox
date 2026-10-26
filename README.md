# Bayora sandbox: isolated red team / blue team / LLM testing (Hack in Hills '26, Problem 4)

Team Ogadri. A proof of concept for running adversarial AI safety tests where the attacker, the defender and the model under
test share infrastructure **without exposing each other's state**, with a tamper-evident record of everything that happened.

```
 red_net (internal)        llm_net (internal)        blue_net (internal)
 +---------+                +---------+                +----------+
 |  RED    |--+          +--|   LLM   |            +---|   BLUE   |
 +---------+  |          |  +---------+            |   +----------+
              v          v                         v
            +--------------------------------------------+
            |   POLICY BROKER  (only multi-homed service) |
            |   auth -> capability check -> forward/filter|
            |   every event -> hash-chained, signed log   |
            +--------------------------------------------+
                               |
                       audit_data volume (broker-only)
```

## Quick start (needs Docker with Compose v2)
```bash
./demo.sh          # builds, runs red/blue attack tests, verifies and tamper-tests the audit log
docker compose down -v
```
Without Docker you can still run the logic tests: `pip install cryptography pytest && pytest tests`.

## What the demo proves
| Step | Shows |
|---|---|
| Red attack + probes | Attack reaches the LLM only through the broker; red cannot reach blue/LLM, call blue endpoints, read the audit log, or use a forged token |
| Blue defence + probes | Blue sees model outputs and verdicts but **never attack payloads**; cannot act as red or reach red/LLM |
| Red again | Blue's hidden rule now blocks the attack; red sees only the verdict |
| Audit verify | Hash chain and Ed25519 signatures valid |
| Tamper | Editing one entry is detected (`TAMPERING DETECTED`) |

## Mapping to the evaluation objectives
1. **Isolate without breaking function**: internal networks + brokered API; the full flow runs in seconds.
2. **Prevent leakage**: payloads never returned or logged in clear; blue rules broker-private; per-session LLM contexts; audit log restricted to the auditor role.
3. **Audit integrity**: SHA-256 chain + Ed25519 signatures, independent verifier (`broker/verify_audit.py`).
4. **Deployability**: plain Docker Compose, no special hardware.
5. **LLM-native threats**: per-session context, cross-session canary test, notes on KV/prefix cache (see threat model).
6. **Residual risk**: [`docs/threat-model.md`](docs/threat-model.md).

## Layout
```
broker/   policy broker, audit log, standalone verifier
llm/      client LLM (mock by default; Ollama optional via OLLAMA_URL)
red/      red-team client + isolation probes
blue/     blue-team client + isolation probes
tests/    unit tests for the audit chain (incl. forged re-hash attack)
docs/     threat model
demo.sh   one-command demo
```

## Hardening applied to every container
Non-root user, read-only root filesystem, all capabilities dropped, `no-new-privileges`, pids/memory/CPU limits, noexec tmpfs, no published ports, internal-only networks.

## Honest limitations
The broker is a single trusted component, containers share a kernel, and the default LLM is a mock. See the threat model for the full list and future work (gVisor/Firecracker, KMS-held signing key, per-tenant GPUs, external log anchoring).

## TODO for the team
- [x] Run `./demo.sh` on a machine with Docker and fix anything environment-specific
- [ ] Swap in a real local model (Ollama) and test prefix-cache behaviour
- [ ] Load real payloads from JailbreakBench / HarmBench into `red/`
- [ ] Add a timing-leak experiment and report the result honestly
- [x] Record a backup demo video
