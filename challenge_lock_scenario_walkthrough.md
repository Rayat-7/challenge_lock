# Challenge-Lock Scenario Walkthrough: End-to-End Sensitive API Call & Attack Defenses

This document presents a complete, scenario-based walkthrough of a sensitive REST API operation protected by the **Challenge-Lock** framework. It traces the lifecycle of a legitimate transaction step-by-step and demonstrates how Challenge-Lock's multi-layered cryptographic and database controls neutralize real-world attack vectors.

---

## 1. Scenario Context & Initial Setup

* **User:** Alice (User ID: `usr_alice_99`)
* **Operation:** High-value money transfer of **$5,000.00 USD** to Bob (`usr_bob_42`).
* **Endpoint:** `POST /api/v1/transfer`
* **Pre-existing Security State:** Alice is authenticated via a standard JWT bearer token (`JWT_ALICE_VALID`). Alice shares an established session key with the server (`SESSION_KEY_ALICE` = 32-byte AES-256 key).
* **Attacker:** Eve (a malicious network observer capable of intercepting and modifying transit traffic).

```
 +-----------------------------------------------------------------------------------+
 |                                SCENARIO OVERVIEW                                  |
 |                                                                                   |
 |  [Alice] --(1. Pre-flight Challenge)--> [Server / Express]                       |
 |  [Alice] <--(2. Returns Challenge)---- [Server] <== (Stores UNUSED) ==> [Neon DB] |
 |  [Alice] --(3. Encrypted Transfer)----> [Server] <== (Atomic CONSUMED) => [Neon DB] |
 |                                                                                   |
 |  [Eve]   --(Intercept & Replay)-------> [Server] ==> REJECTED (Already Consumed)  |
 |  [Eve]   --(Tamper Payload)----------> [Server] ==> REJECTED (GCM / Binding Error)|
 +-----------------------------------------------------------------------------------+
```

---

## 2. Happy Path: The Legitimate Sensitive API Call Walkthrough

### Phase 1: Pre-flight Challenge Issuance

Before executing the transfer, Alice's client application must obtain a short-lived, single-use challenge from the server.

1. **Client Pre-computes Request Binding:**
   Alice's app prepares the raw payload:
   ```json
   { "recipient": "usr_bob_42", "amount": 5000 }
   ```
   It calculates a SHA-256 request binding hash over the canonical JSON string, path, method, and timestamp:
   $$\text{Binding} = \text{SHA256}(\text{"POST:/api/v1/transfer:"} \parallel \text{SHA256}(\text{CanonicalBody}) \parallel \text{":"} \parallel \text{Timestamp})$$
   * Computed `binding_hash`: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
   * Timestamp: `1700000000000`

2. **Client Sends Pre-flight Request:**
   ```http
   POST /api/v1/challenge HTTP/1.1
   Host: api.bank.com
   Authorization: Bearer JWT_ALICE_VALID
   Content-Type: application/json

   {
     "path": "/api/v1/transfer",
     "bindingHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "timestamp": "1700000000000"
   }
   ```

3. **Server Generates & Stores Challenge in Neon Postgres:**
   * Server validates Alice's JWT token.
   * Server generates a unique cryptographically secure challenge ID: `chl_8f9a2b4c6d`.
   * Server inserts a record into Neon Serverless Postgres:
     ```sql
     INSERT INTO challenges (challenge_id, user_id, binding_hash, status, expires_at)
     VALUES ('chl_8f9a2b4c6d', 'usr_alice_99', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'UNUSED', NOW() + INTERVAL '2 minutes');
     ```
4. **Server Returns Challenge ID:**
   ```json
   {
     "challengeId": "chl_8f9a2b4c6d",
     "expiresInSeconds": 120
   }
   ```

---

### Phase 2: Payload Packaging & AES-256-GCM Encryption

1. **Client Assembles Inner Envelope:**
   ```json
   {
     "challengeId": "chl_8f9a2b4c6d",
     "timestamp": "1700000000000",
     "data": { "recipient": "usr_bob_42", "amount": 5000 }
   }
   ```

2. **Client Encrypts Payload:**
   * Generates a random 12-byte IV: `a1b2c3d4e5f6789012345678`.
   * Encrypts the envelope string using `SESSION_KEY_ALICE` with `AES-256-GCM`.
   * Produces Ciphertext (`3f8a...`) and Auth Tag (`9d2e...`).

3. **Client Submits Sensitive API Call:**
   ```http
   POST /api/v1/transfer HTTP/1.1
   Host: api.bank.com
   Authorization: Bearer JWT_ALICE_VALID
   x-challenge-id: chl_8f9a2b4c6d
   Content-Type: application/json

   {
     "encryptedData": "3f8a92b110cd...",
     "iv": "a1b2c3d4e5f6789012345678",
     "tag": "9d2e4f6a8b0c1d2e3f4a5b6c7d8e9f0a"
   }
   ```

---

### Phase 3: Server Middleware Verification & Atomic Execution

When the request reaches the Express backend, the `challengeLockMiddleware` executes the following step-by-step verification pipeline:

```
  [HTTP Request]
        │
        ▼
  [1. JWT Authentication] ─── (Validates user: usr_alice_99)
        │
        ▼
  [2. AES-256-GCM Decrypt] ── (Auth Tag Valid? Decrypts Inner Envelope)
        │
        ▼
  [3. Derive Binding Hash] ── (Recomputes SHA-256 from Method+Path+Body+TS)
        │
        ▼
  [4. Atomic SQL Update] ──── (UPDATE challenges SET status='CONSUMED'
        │                      WHERE id='chl_8f9a2b4c6d' AND status='UNUSED'...)
        ├──► rowCount == 1 : [SUCCESS] ──► Proceed to Business Logic (Transfer $5,000)
        └──► rowCount == 0 : [REJECT]  ──► HTTP 401 Unauthorized
```

1. **Step 1: Identity Extraction:** Middleware verifies `JWT_ALICE_VALID` and attaches `req.user = { id: 'usr_alice_99', sessionKey: SESSION_KEY_ALICE }`.
2. **Step 2: Cryptographic Decryption & Integrity:** Using `SESSION_KEY_ALICE`, IV, and Auth Tag, `crypto.createDecipheriv('aes-256-gcm', ...)` decrypts the ciphertext. GCM authentication tag verifies payload integrity.
3. **Step 3: Context Binding Verification:** Middleware extracts `decryptedPayload.data` (`{ recipient: 'usr_bob_42', amount: 5000 }`) and `decryptedPayload.timestamp`. It recalculates the SHA-256 binding hash and confirms it equals `e3b0c442...`.
4. **Step 4: Atomic Single-Use Consumption in Neon Postgres:**
   The server executes the atomic SQL query:
   ```sql
   UPDATE challenges
   SET status = 'CONSUMED', consumed_at = NOW()
   WHERE challenge_id = 'chl_8f9a2b4c6d'
     AND user_id = 'usr_alice_99'
     AND status = 'UNUSED'
     AND binding_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
     AND expires_at > NOW()
   RETURNING challenge_id;
   ```
   * **Database Result:** `rowCount = 1`. The challenge status transitions from `UNUSED` to `CONSUMED`.
5. **Step 5: Business Logic Execution:**
   The middleware passes control to `transferRoutes.js`. $5,000 is transferred from Alice to Bob, and the server responds with `HTTP 200 OK`.

---

## 3. Attack Scenario A: Replay Attack Walkthrough & Defense

### The Attacker's Strategy
Eve intercepts Alice's encrypted network transmission. Since the payload is encrypted with AES-256-GCM, Eve cannot read the contents. However, Eve attempts a **Replay Attack** by copying the exact raw HTTP headers and JSON body and sending the same request again 10 seconds later, hoping to trigger a duplicate $5,000 transfer to Bob.

### Step-by-Step Server Response to Replay Attack

```http
POST /api/v1/transfer HTTP/1.1
Host: api.bank.com
Authorization: Bearer JWT_ALICE_VALID
x-challenge-id: chl_8f9a2b4c6d
Content-Type: application/json

{
  "encryptedData": "3f8a92b110cd...",
  "iv": "a1b2c3d4e5f6789012345678",
  "tag": "9d2e4f6a8b0c1d2e3f4a5b6c7d8e9f0a"
}
```

1. **JWT Verification:** Pass (`JWT_ALICE_VALID` is still unexpired).
2. **AES-256-GCM Decryption:** Pass (The raw ciphertext, IV, and tag are untouched, so decryption succeeds).
3. **Binding Hash Calculation:** Pass (Decrypted payload matches the original binding).
4. **Atomic Neon Postgres Query Execution:**
   The server attempts to execute:
   ```sql
   UPDATE challenges
   SET status = 'CONSUMED', consumed_at = NOW()
   WHERE challenge_id = 'chl_8f9a2b4c6d'
     AND user_id = 'usr_alice_99'
     AND status = 'UNUSED'
     AND binding_hash = 'e3b0c442...'
     AND expires_at > NOW()
   RETURNING challenge_id;
   ```
   * **Database Result:** `rowCount = 0`.
   * **Why it failed:** During Alice's legitimate request, the challenge's status was set to `CONSUMED`. The `WHERE status = 'UNUSED'` clause evaluates to `FALSE`.

5. **Defense Outcome:**
   The middleware catches `rowCount === 0` and immediately halts execution without invoking the transfer controller:
   ```http
   HTTP/1.1 401 Unauthorized
   Content-Type: application/json

   {
     "error": "CHALLENGE_REJECTED",
     "message": "Challenge is invalid, expired, consumed, or bound request parameters were tampered."
   }
   ```
   **Security Result:** **REPLAY DEFENDED.** No duplicate money is transferred.

---

## 4. Attack Scenario B: Parameter Tampering Attack Walkthrough & Defense

### The Attacker's Strategy
Eve intercepts the transmission and attempts to modify the transaction parameters. Eve wants to alter the recipient from Bob (`usr_bob_42`) to Eve (`usr_eve_66`) or change the amount from `$5,000` to `$50,000`.

Eve attempts two different technical vectors:

---

### Vector B.1: Direct Ciphertext Manipulation

Eve alters several bytes in the `encryptedData` hex string before forwarding the packet to the server.

1. **Express Middleware Processing:**
   * JWT verification passes.
   * Middleware calls `decipher.final('utf8')`.
2. **Cryptographic Check:**
   AES-256-GCM authenticated encryption checks the Auth Tag (`tag`) against the modified ciphertext bytes.
3. **Defense Outcome:**
   Node.js `crypto` throws a bit-level authentication failure error: `Error: Unsupported state or unable to authenticate data`.
   Middleware returns immediately:
   ```http
   HTTP/1.1 400 Bad Request
   Content-Type: application/json

   {
     "error": "DECRYPTION_OR_TAMPERING_FAILED",
     "details": "Unsupported state or unable to authenticate data"
   }
   ```
   **Security Result:** **TAMPERING DEFENDED at Cryptographic Layer.**

---

### Vector B.2: Re-encryption with Compromised Session Key or Known Context

Suppose Eve obtains a valid challenge ID (`chl_8f9a2b4c6d`) and tries to forge an encrypted payload with modified contents (`{ "recipient": "usr_eve_66", "amount": 50000 }`).

1. **Express Middleware Processing:**
   * JWT verification passes.
   * Decryption succeeds (yielding `{ "recipient": "usr_eve_66", "amount": 50000 }`).
2. **Context Binding Verification:**
   * Middleware computes SHA-256 binding hash for the decrypted payload (`{ "recipient": "usr_eve_66", "amount": 50000 }`):
     $$\text{DerivedBinding} = \text{"f9d8a7c6..."}$$
3. **Atomic Neon Postgres Query Execution:**
   ```sql
   UPDATE challenges
   SET status = 'CONSUMED', consumed_at = NOW()
   WHERE challenge_id = 'chl_8f9a2b4c6d'
     AND user_id = 'usr_alice_99'
     AND status = 'UNUSED'
     AND binding_hash = 'f9d8a7c6...' -- Does NOT match 'e3b0c442...' stored in DB!
     AND expires_at > NOW()
   RETURNING challenge_id;
   ```
   * **Database Result:** `rowCount = 0`.
   * **Why it failed:** The challenge `chl_8f9a2b4c6d` stored in Neon Postgres was locked to Alice's original binding hash (`e3b0c442...`). The tampered binding hash (`f9d8a7c6...`) fails the `WHERE binding_hash = $3` condition.

4. **Defense Outcome:**
   Middleware returns `HTTP 401 Unauthorized (CHALLENGE_REJECTED)`.
   **Security Result:** **TAMPERING DEFENDED at Context-Binding Layer.**

---

## 5. Comparative Summary: Call Outcomes Matrix

| Call Type | JWT Status | AES-GCM Decryption | DB Status Check (`status = 'UNUSED'`) | DB Binding Check (`binding_hash = $3`) | System Action | Final Response Code |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Legitimate Call** | Valid | Passed | Passed (`UNUSED`) | Passed (Matches) | Challenge marked `CONSUMED`; Transfer Executed | `200 OK` |
| **Replay Attack** | Valid | Passed | **FAILED (`CONSUMED`)** | N/A | Execution Aborted; Zero Database Changes | `401 Unauthorized` |
| **Tampered Ciphertext** | Valid | **FAILED (GCM Tag Mismatch)** | Not Reached | Not Reached | Execution Aborted on Decryption Exception | `400 Bad Request` |
| **Tampered Payload** | Valid | Passed | Passed (`UNUSED`) | **FAILED (Hash Mismatch)** | Execution Aborted; Zero Database Changes | `401 Unauthorized` |
| **Expired Challenge** | Valid | Passed | **FAILED (`expires_at < NOW()`)** | N/A | Execution Aborted; Challenge Rejected | `401 Unauthorized` |

---

## 6. Key Takeaways for Developers & Security Auditors

1. **Defense-in-Depth:** Identity (JWT), Authenticated Encryption (AES-GCM), Context Integrity (SHA-256 Binding), and Freshness (Single-Use Database Nonces) operate as an integrated chain.
2. **Race-Condition Safety:** By enforcing single-use state updates inside a single atomic SQL `UPDATE ... WHERE status = 'UNUSED'` statement, Challenge-Lock eliminates time-of-check to time-of-use (TOCTOU) race conditions in high-concurrency environments.
3. **Fail-Closed Architecture:** Any breakdown in decryption, binding re-derivation, or database match count immediately halts API execution before business logic or database writes occur.
