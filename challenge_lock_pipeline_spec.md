# Challenge-Lock Pipeline Specification

This document provides a dedicated, end-to-end technical specification of the **Challenge-Lock Processing Pipeline**, spanning challenge issuance, client-side encryption assembly, server middleware verification, and database state transitions.

---

## 1. High-Level Pipeline Sequence Diagram

```text
  [ Client Application ]             [ Express Middleware ]             [ Neon Postgres DB ]
           |                                  |                                  |
           |====== PHASE 1: CHALLENGE ISSUANCE PIPELINE =========================|
           |                                  |                                  |
 1.01      |--- 1. Compute Binding Hash ----->|                                  |
           |    (Method + Path + BodyHash)    |                                  |
 1.02      |--- POST /api/v1/challenge ------>|                                  |
           |    { path, bindingHash, ts }     |                                  |
 1.03      |                                  |--- INSERT INTO challenges ------>|
           |                                  |    (status = 'UNUSED')           |
 1.04      |<-- Return challengeId -----------|                                  |
           |                                  |                                  |
           |====== PHASE 2: CLIENT ENCRYPTION & ASSEMBLY PIPELINE ===============|
           |                                  |                                  |
 2.01      | Canonicalize payload (RFC 8785)  |                                  |
 2.02      | Encrypt body using AES-256-GCM    |                                  |
 2.03      | Assemble x-challenge-id & Auth   |                                  |
           |                                  |                                  |
           |====== PHASE 3: SERVER VERIFICATION PIPELINE ========================|
           |                                  |                                  |
 3.01      |--- POST /api/v1/transfer ------->|                                  |
           |    Headers: JWT + ChallengeID    |                                  |
           |    Body: { encryptedData, iv, tag }|                                |
 3.02      |                                  | Verify JWT & Extract SessionKey  |
 3.03      |                                  | Decrypt Payload (AES-256-GCM)    |
           |                                  | -> Fail if Tag invalid (400)     |
 3.04      |                                  | Re-derive Expected Binding Hash  |
 3.05      |                                  |                                  |
           |                                  |--- Atomic UPDATE challenges ---->|
           |                                  |    SET status = 'CONSUMED'       |
           |                                  |    WHERE challenge_id = $1       |
           |                                  |      AND user_id = $2            |
           |                                  |      AND status = 'UNUSED'       |
           |                                  |      AND binding_hash = $3       |
           |                                  |      AND expires_at > NOW()      |
 3.06      |                                  |<-- RETURNING challenge_id -------|
           |                                  |    (rowCount == 1 => SUCCESS)    |
 3.07      |<-- 200 OK (Processed) -----------| Attach req.decryptedBody -> Next |
           |    OR 401 Rejection              |                                  |
```

---

## 2. Phase 1: Challenge Request & Issuance Pipeline

### Step 1.1: Pre-Challenge Binding Hash Computation
Before requesting a challenge token, the client computes a deterministic SHA-256 binding hash matching the intended transaction.

$$\\text{BindingHash} = \\text{SHA256}(\\text{HTTP\\_METHOD} \\parallel \\text{PATH} \\parallel \\text{SHA256}(\\text{CanonicalJSON}(\\text{Body})) \\parallel \\text{Timestamp})$$

* **Canonicalization Rule:** JSON keys must be lexicographically sorted (RFC 8785) prior to hashing.

```javascript
// Node.js Client Helper
const crypto = require('crypto');

function computeBindingHash(method, path, body, timestampStr) {
  const canonicalBody = JSON.stringify(body, Object.keys(body).sort());
  const bodyHash = crypto.createHash('sha256').update(canonicalBody).digest('hex');
  const rawString = `${method.toUpperCase()}:${path}:${bodyHash}:${timestampStr}`;
  return crypto.createHash('sha256').update(rawString).digest('hex');
}
```

### Step 1.2: Challenge Request Payload
```http
POST /api/v1/challenge HTTP/1.1
Host: api.example.com
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "path": "/api/v1/transfer",
  "bindingHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestamp": "1700000000000"
}
```

### Step 1.3: Server Persistence (Neon Postgres)
Upon validating the JWT, the server generates a cryptographically secure 32-byte challenge ID (`chl_` + random hex) and persists it:

```sql
INSERT INTO challenges (
    challenge_id,
    user_id,
    binding_hash,
    status,
    expires_at
) VALUES (
    'chl_9a8b7c6d5e4f3a2b1c',
    'usr_123456',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'UNUSED',
    NOW() + INTERVAL '5 minutes'
);
```

---

## 3. Phase 2: Client Payload Encryption & Assembly Pipeline

### Step 2.1: Inner Envelope Assembly
The client wraps the actual business body inside an inner envelope alongside the challenge ID and timestamp:

```json
{
  "challengeId": "chl_9a8b7c6d5e4f3a2b1c",
  "timestamp": "1700000000000",
  "data": {
    "recipient": "Alice",
    "amount": 100
  }
}
```

### Step 2.2: AES-256-GCM Encrypted Payload Assembly
```javascript
function assembleEncryptedRequest(innerPayload, sessionKeyBuffer) {
  const iv = crypto.randomBytes(12); // 96-bit IV
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKeyBuffer, iv);
  
  let encryptedHex = cipher.update(JSON.stringify(innerPayload), 'utf8', 'hex');
  encryptedHex += cipher.final('hex');
  const tagHex = cipher.getAuthTag().toString('hex');

  return {
    encryptedData: encryptedHex,
    iv: iv.toString('hex'),
    tag: tagHex
  };
}
```

### Step 2.3: Final HTTP Wire Request
```http
POST /api/v1/transfer HTTP/1.1
Host: api.example.com
Authorization: Bearer <JWT_TOKEN>
x-challenge-id: chl_9a8b7c6d5e4f3a2b1c
Content-Type: application/json

{
  "encryptedData": "a1f2c3d4e5f6...",
  "iv": "3f8a9b2c1d0e4f5a6b7c8d9e",
  "tag": "1029384756afbecd"
}
```

---

## 4. Phase 3: Server Verification & Execution Pipeline

The server processes incoming sensitive requests through a 5-stage middleware pipeline:

```text
[ Incoming Request ]
         │
         ▼
┌─────────────────────────────────┐
│ Stage 1: Header Validation      │ ──► Missing Headers? ──► [ 400 Bad Request ]
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Stage 2: JWT Identity Extraction│ ──► Invalid Token?   ──► [ 401 Unauthorized ]
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Stage 3: AES-256-GCM Decryption │ ──► Auth Tag Mismatch?─► [ 400 Bad Request ]
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Stage 4: Binding Hash Derivation│ ──► Tampered Params? ──► [ 401 Unauthorized ]
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Stage 5: Atomic DB Consumption  │ ──► Row Count == 0?  ──► [ 401 Replayed/Expired ]
└─────────────────────────────────┘
         │
         ▼
[ Pass to Business Controller (200 OK) ]
```

### Complete Express Middleware Implementation Pipeline

```javascript
// middleware/challengeLockPipeline.js
const crypto = require('crypto');
const { dbPool } = require('../db');

function computeBindingHash(method, path, body, timestampStr) {
  const canonicalBody = JSON.stringify(body, Object.keys(body).sort());
  const bodyHash = crypto.createHash('sha256').update(canonicalBody).digest('hex');
  const rawString = `${method.toUpperCase()}:${path}:${bodyHash}:${timestampStr}`;
  return crypto.createHash('sha256').update(rawString).digest('hex');
}

async function challengeLockPipelineMiddleware(req, res, next) {
  try {
    // Stage 1: Validate required headers & body fields
    const challengeHeader = req.headers['x-challenge-id'];
    const { encryptedData, iv, tag } = req.body;

    if (!challengeHeader || !encryptedData || !iv || !tag) {
      return res.status(400).json({ error: 'MISSING_CHALLENGE_LOCK_PARAMETERS' });
    }

    // Stage 2: Retrieve user identity and encryption key (populated by JWT middleware)
    const userId = req.user.id;
    const sessionKey = Buffer.from(req.user.sessionKeyHex, 'hex');

    // Stage 3: AES-256-GCM Decryption
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    
    let decryptedStr = decipher.update(encryptedData, 'hex', 'utf8');
    decryptedStr += decipher.final('utf8'); // Throws if ciphertext or tag was altered
    
    const decryptedPayload = JSON.parse(decryptedStr);

    // Stage 4: Re-derive expected binding hash
    const expectedBinding = computeBindingHash(
      req.method,
      req.path,
      decryptedPayload.data,
      decryptedPayload.timestamp
    );

    // Stage 5: Atomic Single-Use Consumption in Neon Postgres
    const consumeQuery = `
      UPDATE challenges
      SET status = 'CONSUMED', consumed_at = NOW()
      WHERE challenge_id = $1 
        AND user_id = $2 
        AND status = 'UNUSED' 
        AND expires_at > NOW() 
        AND binding_hash = $3
      RETURNING challenge_id;
    `;

    const dbResult = await dbPool.query(consumeQuery, [challengeHeader, userId, expectedBinding]);

    if (dbResult.rowCount === 0) {
      return res.status(401).json({
        error: 'CHALLENGE_REJECTED',
        message: 'Request failed pipeline checks (Challenge spent, expired, invalid user, or binding mismatched).'
      });
    }

    // Pipeline complete - Attach sanitized body and move to business controller
    req.decryptedBody = decryptedPayload.data;
    next();
  } catch (err) {
    return res.status(400).json({
      error: 'DECRYPTION_OR_TAMPERING_FAILED',
      details: err.message
    });
  }
}

module.exports = { challengeLockPipelineMiddleware, computeBindingHash };
```

---

## 5. Pipeline Error & Failure Modes Matrix

| Pipeline Stage | Exception Trigger | System Failure Code | HTTP Response | Defensive Vector |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 1** | Header missing (`x-challenge-id`) | `MISSING_CHALLENGE_LOCK_PARAMETERS` | `400 Bad Request` | Form enforcement |
| **Stage 2** | JWT signature invalid or expired | `UNAUTHORIZED` | `401 Unauthorized` | Identity verification |
| **Stage 3** | AES-GCM Auth tag mismatch / Modified ciphertext | `DECRYPTION_OR_TAMPERING_FAILED` | `400 Bad Request` | Payload integrity |
| **Stage 4** | Binding hash mismatch (Tampered endpoint/payload) | `CHALLENGE_REJECTED` | `401 Unauthorized` | Request parameter tampering |
| **Stage 5** | `status != 'UNUSED'` (Replayed Challenge ID) | `CHALLENGE_REJECTED` | `401 Unauthorized` | Replay Attack protection |
| **Stage 5** | `expires_at <= NOW()` (Expired Nonce) | `CHALLENGE_REJECTED` | `401 Unauthorized` | Stale request protection |
| **Stage 5** | Concurrent duplicate requests | `CHALLENGE_REJECTED` | `401 Unauthorized` | Race condition protection |
