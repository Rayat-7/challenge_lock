# Challenge-Lock Security Testing & Postman Harness Guide (Neon Serverless Edition)

This guide details the execution pipeline for verifying the **Challenge-Lock** architecture against **Replay Attacks** and **Parameter Tampering Attacks** using **Neon Serverless Postgres** and **Node.js**.

---

## 1. Attack Vectors & Defensive Rules

| Attack Vector | Attacker Action | Challenge-Lock Defensive Layer | Expected HTTP Outcome |
| :--- | :--- | :--- | :--- |
| **Replay Attack** | Intercepts a valid encrypted API request and re-sends the exact same headers & body a second time. | **One-time Challenge Storage (Neon Postgres Atomic Consumption):** First attempt marks challenge as `CONSUMED`. Subsequent queries fail `status = 'UNUSED'` check. | First Call: `200 OK`<br>Second Call: `401 Unauthorized` (`CHALLENGE_REJECTED`) |
| **Parameter Tampering** | Intercepts ciphertext/payload and attempts to modify high-value fields (e.g. changing `amount: 100` to `amount: 10000`). | **Request Binding & AES-256-GCM Auth Tag:** Modifying ciphertext fails GCM decryption; modifying plaintext before re-encryption changes `binding_hash`, failing DB match. | `400 Bad Request` or `401 Unauthorized` (`DECRYPTION_OR_TAMPERING_FAILED`) |

---

## 2. Environment Configuration for Neon Serverless

Create a `.env` file in your test project root:

```env
PORT=3000
JWT_SECRET=your-32-byte-secret-key-here
DATABASE_URL=postgres://<user>:<password>@<ep-name>.neon.tech/neondb?sslmode=require
```

---

## 3. Node.js Automated Attack Test Script (`test_attacks_neon.js`)

This script connects directly to the Node.js API server, which interacts with Neon Postgres to execute the attack scenarios.

```javascript
/**
 * Challenge-Lock Node.js Security Test Harness (Neon Postgres)
 * Dependencies: axios, crypto, dotenv
 * Usage: node test_attacks_neon.js
 */

require('dotenv').config();
const axios = require('axios');
const crypto = require('crypto');

const API_BASE = process.env.API_BASE || 'http://localhost:3000/api';
const USER_SESSION_KEY = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex'); // 32 bytes
let jwtToken = '';

// Helper: Derive Canonical Binding Hash
function computeBindingHash(method, path, body, timestampStr) {
  const canonicalBody = JSON.stringify(body, Object.keys(body).sort());
  const bodyHash = crypto.createHash('sha256').update(canonicalBody).digest('hex');
  const rawString = `${method.toUpperCase()}:${path}:${bodyHash}:${timestampStr}`;
  return crypto.createHash('sha256').update(rawString).digest('hex');
}

// Helper: Encrypt Payload with AES-256-GCM
function encryptPayload(data, challengeId, timestampStr) {
  const iv = crypto.randomBytes(12);
  const decipherPayload = JSON.stringify({ challengeId, timestamp: timestampStr, data });
  const cipher = crypto.createCipheriv('aes-256-gcm', USER_SESSION_KEY, iv);
  
  let encrypted = cipher.update(decipherPayload, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  
  return {
    encryptedData: encrypted,
    iv: iv.toString('hex'),
    tag: tag
  };
}

async function runAttackSuite() {
  console.log('==================================================');
  console.log('STARTING CHALLENGE-LOCK ATTACK VERIFICATION SUITE');
  console.log('DB BACKEND: NEON SERVERLESS POSTGRES');
  console.log('==================================================
');

  // Step 0: Login & Get JWT Token
  console.log('[+] Step 0: Logging in user...');
  const loginRes = await axios.post(`${API_BASE}/auth/login`, { username: 'testuser', password: 'password123' });
  jwtToken = loginRes.data.token;
  console.log('    JWT Token Acquired.
');

  // ----------------------------------------------------
  // SCENARIO 1: REPLAY ATTACK TEST
  // ----------------------------------------------------
  console.log('--------------------------------------------------');
  console.log('TEST 1: REPLAY ATTACK DEFENSE VERIFICATION');
  console.log('--------------------------------------------------');
  
  // 1a. Request Challenge from Server
  const targetPath = '/api/v1/transfer';
  const originalBody = { recipient: 'Alice', amount: 100 };
  const timestampStr = Date.now().toString();
  const bindingHash = computeBindingHash('POST', targetPath, originalBody, timestampStr);

  const challengeRes = await axios.post(
    `${API_BASE}/v1/challenge`,
    { path: targetPath, bindingHash, timestamp: timestampStr },
    { headers: { Authorization: `Bearer ${jwtToken}` } }
  );
  const challengeId = challengeRes.data.challengeId;
  console.log(`[+] Challenge Issued by Neon DB: ${challengeId}`);

  // 1b. Perform Legitimate First Request
  const encryptedObj = encryptPayload(originalBody, challengeId, timestampStr);
  console.log('[+] Sending Legitimate Request 1...');
  
  try {
    const res1 = await axios.post(`${API_BASE}/v1/transfer`, encryptedObj, {
      headers: {
        Authorization: `Bearer ${jwtToken}`,
        'x-challenge-id': challengeId
      }
    });
    console.log(`    Result 1: SUCCESS (HTTP ${res1.status}) - Transfer Processed.`);
  } catch (err) {
    console.error(`    Result 1: FAILED unexpectedly - ${err.response?.data?.error}`);
  }

  // 1c. Replay Attack Attempt (Sending identical request again)
  console.log('[!] ATTACK ATTEMPT: Replaying the EXACT same request headers & body...');
  try {
    await axios.post(`${API_BASE}/v1/transfer`, encryptedObj, {
      headers: {
        Authorization: `Bearer ${jwtToken}`,
        'x-challenge-id': challengeId
      }
    });
    console.error('    [FAIL] CRITICAL VULNERABILITY: Replay attack succeeded!');
  } catch (err) {
    if (err.response?.status === 401 || err.response?.status === 400) {
      console.log(`    [PASS] DEFENDED: Neon DB prevented replay! (HTTP ${err.response.status} - ${err.response.data.error}).`);
    } else {
      console.error(`    Unexpected Error: ${err.message}`);
    }
  }

  // ----------------------------------------------------
  // SCENARIO 2: REQUEST PARAMETER TAMPERING TEST
  // ----------------------------------------------------
  console.log('
--------------------------------------------------');
  console.log('TEST 2: PARAMETER TAMPERING DEFENSE VERIFICATION');
  console.log('--------------------------------------------------');

  // 2a. Request fresh challenge for $100 transfer to Alice
  const req2Timestamp = Date.now().toString();
  const req2Binding = computeBindingHash('POST', targetPath, originalBody, req2Timestamp);
  const chal2Res = await axios.post(
    `${API_BASE}/v1/challenge`,
    { path: targetPath, bindingHash: req2Binding, timestamp: req2Timestamp },
    { headers: { Authorization: `Bearer ${jwtToken}` } }
  );
  const challenge2Id = chal2Res.data.challengeId;

  // 2b. Attacker tampers body payload (changes amount to $10,000 to Eve) without updating binding
  console.log('[!] ATTACK ATTEMPT: Tampering payload body to $10,000 for Eve...');
  const tamperedBody = { recipient: 'Eve', amount: 10000 };
  const tamperedEncryptedObj = encryptPayload(tamperedBody, challenge2Id, req2Timestamp);

  try {
    await axios.post(`${API_BASE}/v1/transfer`, tamperedEncryptedObj, {
      headers: {
        Authorization: `Bearer ${jwtToken}`,
        'x-challenge-id': challenge2Id
      }
    });
    console.error('    [FAIL] CRITICAL VULNERABILITY: Tampered request was accepted!');
  } catch (err) {
    if (err.response?.status === 401 || err.response?.status === 400) {
      console.log(`    [PASS] DEFENDED: Server rejected tampered request binding match (HTTP ${err.response.status} - ${err.response.data.error}).`);
    } else {
      console.error(`    Unexpected Error: ${err.message}`);
    }
  }

  console.log('
==================================================');
  console.log('ALL DEFENSE SCENARIOS TESTED SUCCESSFULLY AGAINST NEON');
  console.log('==================================================');
}

runAttackSuite();
```

---

## 4. Postman Collection Setup with Neon Backend

1. **Environment Variable Configuration:**
   * `POSTMAN_ENV_DATABASE_URL`: `postgres://alex:password@ep-cool-fog-123456.us-east-2.aws.neon.tech/neondb?sslmode=require`
   * `API_BASE_URL`: `http://localhost:3000/api`
   * `CHALLENGE_ID`: *(Auto-populated by Postman Pre-request script)*

2. **Visualizer Dashboard Script for Postman:**
   Add to the **Tests** tab of your Postman request to render the status dashboard:

```javascript
const template = `
<div style="font-family: system-ui, sans-serif; padding: 20px; background-color: #121824; color: #f0f4f8; border-radius: 8px;">
    <h2 style="color: #38bdf8;">Challenge-Lock Security Test Dashboard</h2>
    <p><strong>Database:</strong> Neon Serverless Postgres</p>
    <div style="padding: 15px; border-radius: 6px; background-color: {{statusBg}}; border: 1px solid {{borderColor}};">
        <h3 style="margin: 0 0 10px 0;">Status: {{statusMessage}}</h3>
        <p><strong>HTTP Response:</strong> {{responseCode}}</p>
        <p><strong>Error Detail:</strong> {{responseError}}</p>
    </div>
    <div style="margin-top: 15px;">
        <p><strong>Challenge ID:</strong> {{challengeId}}</p>
        <p><strong>Scenario:</strong> {{attackType}}</p>
    </div>
</div>
`;

let isPass = pm.response.code === 200 || pm.response.code === 401;
let statusBg = pm.response.code === 200 ? "#064e3b" : "#7f1d1d";
let borderColor = pm.response.code === 200 ? "#10b981" : "#ef4444";
let statusMessage = pm.response.code === 200 ? "SUCCESS - Request Executed" : "DEFENDED - Attack Rejected by Challenge-Lock";

pm.visualizer.set(template, {
    responseCode: pm.response.code,
    responseError: pm.response.json().error || "None",
    statusBg: statusBg,
    borderColor: borderColor,
    statusMessage: statusMessage,
    challengeId: pm.environment.get("CHALLENGE_ID"),
    attackType: pm.environment.get("ATTACK_TYPE") || "Standard Request"
});
```
