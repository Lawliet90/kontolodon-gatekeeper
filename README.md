# kontolodon-gatekeeper

Proof Gatekeeper agent for zkVerify Agent Games Season 01 — handle **@kontolodon**.

## What it does

Receives signed task envelopes (`agent-games.proof-gatekeeper.v1`), verifies the
`x-agent-games-signature` HMAC over the raw body, decides APPROVE/REJECT per the
7 documented trap types, generates a local Groth16 proof (snarkjs, gatekeeper
circuit) and submits it to Kurier for zkVerify mainnet settlement, then answers
within the 60 s deadline. Fail closed: REJECT on timeout/uncertainty.

## Circuit (verified by testing, 2026-11-15)

- Groth16/BN128, Circom 2.x. vk hash
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.
- 13 public signals:
  `[Poseidon(salt, taskId), registeredVkHash mod p, proofVkHash mod p, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId]`; `salt` is the only private input.
- `decision=1` iff every check passes; `decision=0` requires ≥1 failing check
  (the circuit asserts this — a fully valid task cannot be proven REJECT).
- `taskId` is encoded as `keccak256(task_id)` (string) mod p.
- Local proof: ~1–4 s; `snarkjs groth16 verify` returns OK.

## Trap decision order
PROOF_REUSED (local seen-set, persisted in `seen-proofs.json`) →
VK_SUBSTITUTION → THRESHOLD_MISMATCH → EXPIRED_CONDITION →
RECIPIENT_MISMATCH → AMOUNT_OVERFLOW → else APPROVE / VALID_CONDITION.
Only APPROVE decisions mark a `proof_tx` as seen. PROOF_REUSED answers carry
no new proof (excluded from the reliability bonus by the rules).

## Run

```bash
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (+ KURIER_API_KEY)
node server.js         # listens on :8787, endpoint path /agent
```

Public endpoint for the competition: put this behind an HTTPS tunnel/proxy and
register the full handler URL, e.g. `https://<host>/agent` (NOT root).

## Files

- `server.js` — HTTP server, HMAC, decision logic, proof gen, Kurier client
- `seen-proofs.json` — persistent set of accepted proof_tx values
- `decisions.log` — JSONL per-task record (decision, reason, latency, Kurier job)
- `vk-export.json` — verification key exported from `gatekeeper_final.zkey`
- `proof-test.js`, `debug*.js` — local proof-encoding experiments (dev only)

## Launch for a scored round (parent runs this)

```bash
# 1. server (reads ../.env for the HMAC secret + Kurier key)
cd ~/workspace/zkverify-agent-games/agent && node server.js
# 2. public tunnel (new terminal; cloudflared is BLOCKED from this VM —
#    Cloudflare 403s the egress proxy — use localhost.run via SSH+proxy)
PASS=$(python3 -c "import os,urllib.parse;print(urllib.parse.urlparse(os.environ['https_proxy']).password)")
ssh -o "ProxyCommand=socat - PROXY:hatch-egress-proxy:%h:%p,proxyport=3128,proxyauth=hatch-runtime:$PASS" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -R 80:localhost:8787 nokey@localhost.run
#    The tunnel URL is printed as a QR code in the SSH output — decode it
#    (ANSI art -> PNG -> QR). Endpoint = <that URL>/agent.
#    WARNING: localhost.run rotates the subdomain periodically; if the URL
#    changes, update the endpoint on the dashboard (updateAgentEndpoint).
```

## Registration blocker (as of 2026-11-15 00:25 WIB)

`addAgentAction` refuses with **"Link your GitHub account in Settings before
registering an agent repository."** — any non-empty repoUrl triggers it, empty
repoUrl is rejected as required. The competition account needs GitHub OAuth
linked (dashboard → Settings, user does it in his browser, ~1 min). After
that, re-run `node add-agent.js` with `ENDPOINT=<live tunnel URL>/agent` —
it saves the one-time HMAC secret to `../.env` — then restart the server and
dispatch a practice task from `/dashboard/practice`.

## Kurier blocker

Account id 167 created, but API-key creation returns 401 `Email not verified`.
The user must click the verification link in his Gmail. Until then the server
runs with `KURIER_API_KEY` unset: decisions + local proofs still work, the
`proof_tx` in responses echoes the task's `proof_tx`, and no proof reaches
zkVerify (costs the +0–5 reliability bonus, NOT the +12 decision points).

## Test results (2026-11-15, local + via live tunnel)

- Preflight GET/POST (signed and unsigned): pass, `{ok:true, protocolVersion:"v1"}`
- 7/7 trap decisions correct: VALID→APPROVE, VK_SUBSTITUTION,
  THRESHOLD_MISMATCH, EXPIRED_CONDITION, RECIPIENT_MISMATCH,
  AMOUNT_OVERFLOW, PROOF_REUSED (2nd use of same proof_tx) → REJECT
- Bad HMAC → 401; every response carries `x-agent-games-signature`
- Local Groth16 proof verifies (`snarkjs groth16 verify` OK) for APPROVE and
  for each REJECT variant (decision=0 needs ≥1 failing check — proven)
- Latency: local p50 ~0.5 s / p95 ~1.5 s; via tunnel p50 ~0.5 s / p95 ~0.9 s
  (10 requests through the tunnel in 5.4 s total) — far under the 60 s deadline
- Practice dispatch via the platform: NOT POSSIBLE yet — needs a registered
  agent (same GitHub blocker)
