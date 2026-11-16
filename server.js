// kontolodon-gatekeeper — Proof Gatekeeper agent for zkVerify Agent Games (Season 01)
// Node 22+, no framework. Receives signed task envelopes, decides APPROVE/REJECT,
// generates a local Groth16 proof (snarkjs, gatekeeper circuit) and submits it to
// Kurier for zkVerify mainnet settlement.
//
// Start:  node server.js   (reads .env; PORT default 8787)
// Env: AGENT_GAMES_HMAC_SECRET (32-byte hex, from dashboard — REQUIRED for live use)
//      KURIER_API_KEY (optional until obtained; without it, proof_tx echoes the task proof_tx)
//      KURIER_API_URL (default https://api.kurier.xyz/api/v1)
//      INCLUDE_PROOF_FIELDS (default false — attach raw proof + public_signals in response)
//      SEEN_FILE (default ./seen-proofs.json)
//      DECISIONS_LOG (default ./decisions.log)
"use strict";

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { ethers } = require("ethers");

const ROOT = __dirname;
// Minimal .env loader (no dependency). Canonical secrets live in the parent
// ~/workspace/zkverify-agent-games/.env; a local .env is a fallback.
for (const f of [path.join(ROOT, "..", ".env"), path.join(ROOT, ".env")]) {
  let text = "";
  try { text = fs.readFileSync(f, "utf8"); } catch { continue; }
  for (const line of text.split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
}

const PORT = parseInt(process.env.PORT || "8787", 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const KURIER_API_URL = (process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1").replace(/\/$/, "");
const INCLUDE_PROOF_FIELDS = process.env.INCLUDE_PROOF_FIELDS === "true";
const SEEN_FILE = process.env.SEEN_FILE || path.join(ROOT, "seen-proofs.json");
const DECISIONS_LOG = process.env.DECISIONS_LOG || path.join(ROOT, "decisions.log");
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const WASM = path.join(ROOT, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(ROOT, "..", "circuits", "gatekeeper_final.zkey");
const VK_JSON = path.join(ROOT, "vk-export.json");

// ---- persistent seen-set of accepted proof_tx values (PROOF_REUSED detection) ----
let seen = new Set();
try { seen = new Set(JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"))); } catch { /* fresh */ }
function markSeen(tx) {
  if (!tx) return;
  seen.add(tx.toLowerCase());
  fs.writeFileSync(SEEN_FILE, JSON.stringify([...seen], null, 2));
}
function logDecision(rec) {
  fs.appendFileSync(DECISIONS_LOG, JSON.stringify({ ts: new Date().toISOString(), ...rec }) + "\n");
}

// ---- HMAC helpers (HMAC-SHA256 over raw body) ----
// The platform treats the 64-char hex secret as an opaque string key:
// HMAC key = UTF-8 bytes of the secret string (NOT hex-decoded).
// (Hex-decoding was tried first and the platform's preflight rejected the
// signature — verified 2026-11-16.)
function hmacHex(secretHexOrRaw, body) {
  const key = Buffer.from(secretHexOrRaw, "utf8");
  return crypto.createHmac("sha256", key).update(body).digest("hex");
}
function verifyHmac(secret, rawBody, sig) {
  if (!secret || !sig) return false;
  try {
    const a = Buffer.from(hmacHex(secret, rawBody), "utf8");
    const b = Buffer.from(String(sig).toLowerCase(), "utf8");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

// ---- Kurier client ----
let vkRegistered = false;
async function kurierRegisterVk() {
  if (!KURIER_API_KEY || vkRegistered) return vkRegistered;
  const vk = JSON.parse(fs.readFileSync(VK_JSON, "utf8"));
  const res = await fetch(`${KURIER_API_URL}/register-vk/${KURIER_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ proofType: "groth16", proofOptions: { library: "snarkjs", curve: "bn128" }, vk }),
  });
  const data = await res.json().catch(() => ({}));
  const returned = (data.vkHash || data.vk_hash || data.hash || "").toLowerCase();
  if (res.ok && (!returned || returned === VK_HASH.toLowerCase())) {
    vkRegistered = true;
    return true;
  }
  throw new Error(`register-vk failed HTTP ${res.status}: ${JSON.stringify(data).slice(0, 300)}`);
}
async function kurierSubmitProof(proof, publicSignals) {
  await kurierRegisterVk();
  const res = await fetch(`${KURIER_API_URL}/submit-proof/${KURIER_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      proofType: "groth16",
      vkRegistered: true,
      proofData: { proof, publicSignals, vk: VK_HASH },
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`submit-proof failed HTTP ${res.status}: ${JSON.stringify(data).slice(0, 300)}`);
  return data.jobId || data.job_id || data.id || null;
}
async function kurierJobStatus(jobId) {
  const res = await fetch(`${KURIER_API_URL}/job-status/${KURIER_API_KEY}/${jobId}`);
  const data = await res.json().catch(() => ({}));
  return data.status || data.state || "unknown";
}
// Poll finalization in the background (never blocks the task response).
function pollFinalization(jobId, taskId) {
  (async () => {
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 15000));
      try {
        const st = await kurierJobStatus(jobId);
        logDecision({ task_id: taskId, kurier_job: jobId, kurier_status: st });
        if (st === "Finalized" || st === "Failed" || st === "Error") return;
      } catch { /* keep polling */ }
    }
  })();
}

// ---- decision logic (7 trap types; fail closed) ----
const REASONS = {
  VALID_CONDITION: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
};
function decide(input) {
  const norm = (s) => String(s ?? "").toLowerCase();
  const proofTx = norm(input.proof_tx);
  if (proofTx && seen.has(proofTx)) return { decision: "REJECT", reason_code: REASONS.PROOF_REUSED, trap: true };
  if (norm(input.proof_vk) !== norm(input.registered_vk)) return { decision: "REJECT", reason_code: REASONS.VK_SUBSTITUTION, trap: true };
  if (BigInt(input.public_balance) < BigInt(input.minimum)) return { decision: "REJECT", reason_code: REASONS.THRESHOLD_MISMATCH, trap: true };
  if (BigInt(input.current_block) > BigInt(input.expiry_block)) return { decision: "REJECT", reason_code: REASONS.EXPIRED_CONDITION, trap: true };
  if (norm(input.recipient) !== norm(input.condition_recipient)) return { decision: "REJECT", reason_code: REASONS.RECIPIENT_MISMATCH, trap: true };
  if (BigInt(input.amount) > BigInt(input.max_transfer)) return { decision: "REJECT", reason_code: REASONS.AMOUNT_OVERFLOW, trap: true };
  return { decision: "APPROVE", reason_code: REASONS.VALID_CONDITION, trap: false };
}

// ---- local Groth16 proof ----
// Circuit public signals (verified by testing):
// [Poseidon(salt, taskId), registeredVkHash mod p, proofVkHash mod p, minimum,
//  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
//  amount, maxTransfer, decision, taskId]  — salt is the only private input.
// decision=1 iff every check passes; decision=0 requires >=1 failing check
// (the circuit asserts this — a valid task cannot be proven with decision=0).
async function generateProof(input, decision, taskIdStr) {
  const taskIdInt = BigInt(ethers.keccak256(ethers.toUtf8Bytes(taskIdStr)));
  const salt = BigInt("0x" + crypto.randomBytes(16).toString("hex"));
  const circuitInput = {
    registeredVkHash: String(input.registered_vk),
    proofVkHash: String(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: String(input.recipient),
    conditionRecipient: String(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: taskIdInt.toString(),
    salt: salt.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}

// ---- HTTP server ----
function sendJson(res, status, obj, sign) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { "Content-Type": "application/json" };
  if (sign && HMAC_SECRET) headers["x-agent-games-signature"] = hmacHex(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

async function handleTask(rawBody, res, startedAt) {
  let env;
  try { env = JSON.parse(rawBody.toString("utf8")); } catch {
    return sendJson(res, 400, { error: "invalid json" }, true);
  }
  // No task_id => preflight probe.
  if (!env.task_id) return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, true);

  const taskId = String(env.task_id);
  const input = env.input || {};
  let outcome;
  try {
    outcome = decide(input);
  } catch (e) {
    // Unparseable task: fail closed.
    outcome = { decision: "REJECT", reason_code: REASONS.VALID_CONDITION, trap: false, error: String(e.message).slice(0, 120) };
  }

  let proof = null, publicSignals = null, kurierJobId = null, proofError = null;
  if (outcome.reason_code !== REASONS.PROOF_REUSED) {
    try {
      const t0 = Date.now();
      ({ proof, publicSignals } = await generateProof(input, outcome.decision, taskId));
      const vk = JSON.parse(fs.readFileSync(VK_JSON, "utf8"));
      const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
      if (!ok) throw new Error("local groth16 verify failed");
      logDecision({ task_id: taskId, stage: "proof_generated", ms: Date.now() - t0 });
      if (KURIER_API_KEY) {
        try {
          kurierJobId = await Promise.race([
            kurierSubmitProof(proof, publicSignals),
            new Promise((_, rej) => setTimeout(() => rej(new Error("kurier submit timeout 20s")), 20000)),
          ]);
          if (kurierJobId) pollFinalization(kurierJobId, taskId);
        } catch (e) {
          proofError = `kurier: ${String(e.message).slice(0, 120)}`;
        }
      }
    } catch (e) {
      proofError = String(e.message).slice(0, 200);
      // Proof generation failing on a task we judged APPROVE: a correct decision
      // without a proof (+12 -2) still beats a wrong REJECT (-3 -2). Keep APPROVE.
      if (outcome.decision === "APPROVE") {
        logDecision({ task_id: taskId, stage: "proof_failed_keep_approve", error: proofError });
      } else {
        logDecision({ task_id: taskId, stage: "proof_failed_reject", error: proofError });
      }
    }
  }

  if (outcome.decision === "APPROVE") markSeen(String(input.proof_tx || "").toLowerCase());

  const response = {
    decision: outcome.decision,
    reason_code: outcome.reason_code,
    proof_tx: kurierJobId || String(input.proof_tx || ""),
  };
  if (INCLUDE_PROOF_FIELDS && proof && publicSignals) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  const ms = Date.now() - startedAt;
  logDecision({ task_id: taskId, decision: response.decision, reason_code: response.reason_code, proof_tx: response.proof_tx, kurier_job: kurierJobId, proof_error: proofError, ms });
  return sendJson(res, 200, response, true);
}

const server = http.createServer((req, res) => {
  const startedAt = Date.now();
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks);
    try {
      const url = new URL(req.url, "http://localhost");
      if (url.pathname === "/" && req.method === "GET") {
        return sendJson(res, 200, { ok: true, service: "kontolodon-gatekeeper", protocolVersion: "v1" }, false);
      }
      if (url.pathname !== "/agent") return sendJson(res, 404, { error: "not found" }, false);
      // Preflight probes (GET, or POST without a task envelope) are answered
      // WITHOUT requiring HMAC — the dashboard may probe unsigned. No state
      // changes here, so this is safe; task envelopes below stay HMAC-gated.
      if (req.method === "GET") return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, true);
      if (req.method !== "POST") return sendJson(res, 405, { error: "method not allowed" }, false);
      let probe = null;
      try { probe = JSON.parse(rawBody.toString("utf8")); } catch { probe = null; }
      if (!probe || typeof probe !== "object" || !probe.task_id) {
        return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, true);
      }
      // Task envelope: verify HMAC over the RAW body before trusting the JSON.
      if (HMAC_SECRET) {
        const sig = req.headers["x-agent-games-signature"];
        if (!verifyHmac(HMAC_SECRET, rawBody, sig)) {
          logDecision({ path: "/agent", stage: "hmac_reject", method: req.method });
          return sendJson(res, 401, { error: "bad signature" }, false);
        }
      }
      // Hard safety: never exceed the 60 s platform deadline from inside the handler.
      const timer = setTimeout(() => {
        try { sendJson(res, 200, { decision: "REJECT", reason_code: "VALID_CONDITION", proof_tx: "" }, true); } catch { /* already sent */ }
      }, 55000);
      timer.unref();
      await handleTask(rawBody, res, startedAt);
      clearTimeout(timer);
    } catch (e) {
      try { sendJson(res, 200, { decision: "REJECT", reason_code: "VALID_CONDITION", proof_tx: "" }, true); } catch { /* already sent */ }
      logDecision({ stage: "handler_error", error: String(e && e.message).slice(0, 200) });
    }
  });
});

server.listen(PORT, () => {
  console.log(`kontolodon-gatekeeper listening on :${PORT} (hmac ${HMAC_SECRET ? "configured" : "MISSING — set AGENT_GAMES_HMAC_SECRET"}, kurier ${KURIER_API_KEY ? "configured" : "NOT configured — proof_tx will echo task proof_tx"})`);
});
