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
