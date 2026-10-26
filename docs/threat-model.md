# Threat model and residual risk

## Assets
| Asset | Owner | Must not be observable by |
|---|---|---|
| Attack payloads | Red | Blue, LLM operator tooling, audit readers |
| Defence rules / logic | Blue | Red |
| Client LLM state (session context, caches) | Model under test | Other sessions, Red, Blue |
| Audit log + signing key | Broker / auditor | Anyone able to alter history |

## Trust boundaries
Red, Blue and LLM are each **untrusted** by the others. The **broker is the single trusted component**
(it sees every payload and holds every rule and the signing key). The host kernel and Docker daemon are also trusted.

## What the PoC protects against
| Threat | Control | Demonstrated by |
|---|---|---|
| Red reaches Blue or the LLM directly | Separate `internal` Docker networks; only the broker is multi-homed | `attack.py` reachability probes |
| Blue reads red's payloads | Broker never returns payloads; observations contain only model output + verdict | `defend.py` payload-visibility check |
| Red learns/changes blue's rules | Rules stored broker-side; role capability table denies the endpoints | `attack.py` 403 checks |
| Token forgery / role confusion | Per-team random bearer tokens, constant-time compare, default deny | forged-token test |
| Cross-session LLM contamination | New session id per attack; history keyed per session; no shared cache in the mock | canary + "repeat everything" probe |
| Rewriting or deleting history | SHA-256 hash chain + Ed25519 signature per entry; payloads logged only as hashes | `verify_audit.py`, `tests/test_audit.py` |
| Container breakout primitives / DoS | Rootless user, read-only rootfs, all caps dropped, no-new-privileges, pids/mem/cpu limits | `docker-compose.yml` |
| Monitoring becoming a leak channel | Audit log readable only by the auditor role; entries carry hashes, not content | role policy table |

## What it does NOT protect against (residual risk)
1. **Compromised broker.** It sees everything and holds the signing key. An attacker there can read all payloads/rules and forge a valid log.
   *Future:* split the broker into per-tenant proxies, keep the signing key in a KMS/HSM or TPM, remote-attest the broker.
2. **Shared kernel.** Containers share the host kernel; a kernel exploit breaks isolation.
   *Future:* gVisor or Firecracker microVMs per tenant; confidential computing.
3. **Timing and resource side channels.** cgroup limits reduce but do not eliminate noisy-neighbour effects. Response time and the `blocked` flag are visible to red and can leak a little about blue's rules.
   *Future:* constant-time padding of responses, per-tenant CPU pinning / GPUs, measured leakage bounds.
4. **Real inference servers.** The default model is a mock. With a real backend, shared KV/prefix caches can leak across tenants unless disabled or partitioned per tenant; this must be configured and tested.
5. **Log tail truncation.** A hash chain cannot show that *recent* entries were removed. *Future:* periodically publish the head hash to an external anchor (second host, transparency log, timestamping service).
6. **Static tokens.** Tokens are long-lived random secrets in environment variables. *Future:* short-lived tokens or mTLS identities issued by Vault/SPIFFE.
7. **Blue never sees payloads.** Stricter than the spec requires, which limits defence development. *Future:* controlled reveal after a test run is concluded.

## Conditions under which guarantees fail
Host or Docker-daemon compromise; broker compromise; kernel escape; misconfigured compose file (e.g. attaching red to `blue_net`, running privileged); leaking `.env` tokens.
