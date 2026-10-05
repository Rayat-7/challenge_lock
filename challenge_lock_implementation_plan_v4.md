# Challenge-Lock Implementation Plan (v4) - Production Specification

## 1. System Architecture & Tech Stack

Challenge-Lock is an application-layer request verification framework layered on top of standard JWT authentication for sensitive, state-changing API endpoints (e.g., money transfers, account modifications).

### Tech Stack Specification
* **Runtime & Framework:** Node.js (v18+ LTS / v20+) with Express.js (`express`)
* **Database & Persistence:** **Neon Serverless Postgres** using native `pg` driver (Connection Pool with SSL) or `@neondatabase/serverless`
* **Authentication Layer:** JSON Web Tokens (`jsonwebtoken`) for user identity & session management
* **Cryptographic Suite:** Node.js native `crypto` module (`crypto.randomBytes`, `crypto.createCipheriv`, `crypto.createDecipheriv`, `crypto.createHash`)
* **Security Primitive:** AES-256-GCM authenticated encryption + SHA-256 canonical request binding
* **Data Format:** Base64url, UTF-8, RFC 8785 JSON canonicalization

---

## 2. Neon Serverless Postgres Database Schema & Atomic State Transition

Challenge freshness requires tracking issued nonces. To maintain high throughput and prevent concurrency race conditions (double-spending nonces), challenge state transition MUST occur atomically in PostgreSQL.

```sql
-- DDL Schema for Neon Postgres
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    binding_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'UNUSED', -- Allowed values: UNUSED, CONSUMED, EXPIRED
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);

-- Performance & State Cleanup Indexes
CREATE INDEX IF NOT EXISTS idx_challenges_user_status ON challenges(user_id, status);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at) WHERE status = 'UNUSED';
```

### Atomic Consumption SQL Query
```javascript
// Atomic SQL execution in Node.js using pg pool
const consumeChallengeQuery = `
  UPDATE challenges
  SET status = 'CONSUMED', consumed_at = NOW()
  WHERE challenge_id = $1 
    AND user_id = $2 
    AND status = 'UNUSED' 
    AND expires_at > NOW()
    AND binding_hash = $3
  RETURNING challenge_id;
`;

const result = await dbPool.query(consumeChallengeQuery, [challengeId, userId, expectedBinding]);

if (result.rowCount === 0) {
  // Triggers fail-closed rejection: invalid, replayed, expired, or tampered payload
  throw new Error('CHALLENGE_REJECTED');
}
```

---

## 3. Cryptographic Pipeline & Context Binding

### 3.1 SHA-256 Deterministic Context Binding
The request binding hash ties a challenge to a specific HTTP method, path, stringified payload, and issuance timestamp.

```javascript
const crypto = require('crypto');

function computeBindingHash(method, path, body, timestampStr) {
  // Sort JSON keys deterministically per RFC 8785
  const canonicalBody = JSON.stringify(body, Object.keys(body).sort());
  const bodyHash = crypto.createHash('sha256').update(canonicalBody).digest('hex');
  const rawString = `${method.toUpperCase()}:${path}:${bodyHash}:${timestampStr}`;
  return crypto.createHash('sha256').update(rawString).digest('hex');
}
```

### 3.2 AES-256-GCM Authenticated Decryption
```javascript
function decryptPayload(encryptedHex, ivHex, tagHex, sessionKeyBuffer) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKeyBuffer, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  
  let decryptedStr = decipher.update(encryptedHex, 'hex', 'utf8');
  decryptedStr += decipher.final('utf8'); // Throws if ciphertext or tag was tampered
  return JSON.parse(decryptedStr);
}
```

---

## 4. Complete Node.js Express Middleware Implementation

```javascript
// middleware/challengeLockMiddleware.js
const crypto = require('crypto');
const { dbPool } = require('../db');

function computeBindingHash(method, path, body, timestampStr) {
  const canonicalBody = JSON.stringify(body, Object.keys(body).sort());
  const bodyHash = crypto.createHash('sha256').update(canonicalBody).digest('hex');
  const rawString = `${method.toUpperCase()}:${path}:${bodyHash}:${timestampStr}`;
  return crypto.createHash('sha256').update(rawString).digest('hex');
}

async function challengeLockMiddleware(req, res, next) {
  try {
    const challengeHeader = req.headers['x-challenge-id'];
    const { encryptedData, iv, tag } = req.body;

    if (!challengeHeader || !encryptedData || !iv || !tag) {
      return res.status(400).json({ error: 'MISSING_CHALLENGE_LOCK_HEADERS' });
    }

    // req.user populated by preceding JWT authentication middleware
    const userId = req.user.id;
    const sessionKey = Buffer.from(req.user.sessionKeyHex, 'hex');

    // 1. AES-256-GCM Decryption (Verifies Integrity)
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let decryptedStr = decipher.update(encryptedData, 'hex', 'utf8');
    decryptedStr += decipher.final('utf8');
    
    const decryptedPayload = JSON.parse(decryptedStr);

    // 2. Derive & Match Request Binding
    const expectedBinding = computeBindingHash(
      req.method,
      req.path,
      decryptedPayload.data,
      decryptedPayload.timestamp
    );

    // 3. Atomic Single-Use Check in Neon Postgres
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

    const dbRes = await dbPool.query(consumeQuery, [challengeHeader, userId, expectedBinding]);
    
    if (dbRes.rowCount === 0) {
      return res.status(401).json({ 
        error: 'CHALLENGE_REJECTED', 
        message: 'Challenge is invalid, expired, consumed, or bound request parameters were tampered.' 
      });
    }

    req.decryptedBody = decryptedPayload.data;
    next();
  } catch (err) {
    return res.status(400).json({ error: 'DECRYPTION_OR_TAMPERING_FAILED', details: err.message });
  }
}

module.exports = { challengeLockMiddleware, computeBindingHash };
```

---

## 5. Coding Agent Rules & Guardrails
1. **Always use Atomic SQL:** Never run separate `SELECT` then `UPDATE` statements for challenge consumption.
2. **Fail Closed:** Any cryptographic error or SQL match count of 0 must immediately abort request execution with `401 Unauthorized` or `400 Bad Request`.
3. **Strict SSL for Neon:** Ensure PostgreSQL connection string specifies `?sslmode=require` or `ssl: { rejectUnauthorized: false }`.
