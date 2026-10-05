# 🔐 Challenge-Lock: Application-Layer API Security Framework

> **A Lightweight Context-Bound Verification Protocol for Protecting Sensitive REST APIs Against Replay Attacks and Parameter Tampering.**

[![Node.js](https://img.shields.io/badge/Node.js-v18%2B%20LTS-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-v4.18-000000?logo=express&logoColor=white)](https://expressjs.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon%20Serverless-4169E1?logo=postgresql&logoColor=white)](https://neon.tech/)
[![Security](https://img.shields.io/badge/AES--256--GCM-Authenticated%20Encryption-red?logo=shield&logoColor=white)](#security-architecture)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Executive Summary & Problem Statement

Standard **JWT bearer token authentication** verifies *who* the caller is, but fails to guarantee request *freshness* or payload *integrity*. Once a valid JWT is issued, an adversary in the network path can intercept requests and execute two devastating attacks:

1. **Replay Attacks:** Intercepting a valid high-value transaction request (e.g., `$100 bank transfer`) and submitting it repeatedly to cause unauthorized double-spending.
2. **Parameter Tampering:** Modifying critical payload properties in transit (e.g., changing recipient to `Attacker` or amount to `$10,000`) before forwarding to the server.

**Challenge-Lock** solves this gap by layering an application-level, context-bound verification chain over sensitive endpoints without forcing full-session statefulness or imposing mTLS/client-side key management overhead on routine API calls.

---

## 🛡️ Security Architecture & Defensive Layers

Challenge-Lock enforces a 4-tier cryptographic verification pipeline for state-changing REST API operations:

```
                  ┌─────────────────────────────────────────────────────────┐
                  │              Client Request Pipeline                    │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                                               ▼
         ┌────────────────────────────────────────────────────────────────────────┐
         │ 1. JWT Bearer Auth    : Verifies caller identity & session key.       │
         ├────────────────────────────────────────────────────────────────────────┤
         │ 2. One-Time Challenge : Server-issued nonce tracked in Neon Postgres.  │
         ├────────────────────────────────────────────────────────────────────────┤
         │ 3. SHA-256 Binding    : Deterministic hash over Method+Path+Body+Time. │
         ├────────────────────────────────────────────────────────────────────────┤
         │ 4. AES-256-GCM Crypt  : Authenticated encryption over request body.    │
         └─────────────────────────────────────┬──────────────────────────────────┘
                                               │
                                               ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │       Server Enforcement & Atomic Consumption          │
                  └─────────────────────────────────────────────────────────┘
```

### Key Security Primitives

* **Atomic Challenge Consumption:** Challenges are stored in **Neon Serverless Postgres** and consumed in a single atomic `UPDATE ... WHERE status = 'UNUSED'` query. This guarantees true single-use semantics and eliminates double-spend concurrency race conditions.
* **Deterministic Request Binding (SHA-256):** Ties the challenge ID directly to the canonicalized HTTP Method, Request Path, SHA-256 Body Hash (RFC 8785), and Issuance Timestamp.
* **Authenticated Encryption (AES-256-GCM):** Encrypts sensitive payload attributes and validates authenticity via a 16-byte Auth Tag, instantly catching any in-flight ciphertext modifications.

---

## 🔁 Replay & Tampering Attack Mapping

| Threat Vector | Attacker Action | Defensive Mechanism | Expected Result |
| :--- | :--- | :--- | :--- |
| **Replay Attack** | Intercepts a valid request and re-submits identical headers and payload. | **Atomic PostgreSQL Consumption:** First request updates challenge state to `CONSUMED`. Subsequent queries fail `WHERE status = 'UNUSED'`. | **1st Request:** `200 OK`<br>**2nd Request:** `401 Unauthorized` (`CHALLENGE_REJECTED`) |
| **Parameter Tampering** | Modifies request attributes in transit (e.g. `amount: 100` $ightarrow$ `10000`). | **GCM Integrity & Context Binding:** Ciphertext modifications break GCM Auth Tag verification; body modifications invalidate `binding_hash`. | `400 Bad Request` or `401 Unauthorized` (`DECRYPTION_OR_TAMPERING_FAILED`) |

---

## ⚡ Tech Stack & Requirements

* **Runtime:** Node.js (v18+ LTS or v20+)
* **Framework:** Express.js (`express`)
* **Database:** [Neon Serverless Postgres](https://neon.tech) via native `pg` pool
* **Authentication:** JSON Web Tokens (`jsonwebtoken`)
* **Cryptography:** Native Node.js `crypto` module (`AES-256-GCM`, `HMAC-SHA256`, `crypto.randomBytes`)

---

## 📁 Repository Structure

```text
challenge-lock-api/
├── .env.example                     # Environment variables template
├── .gitignore                        # Git exclusion rules
├── package.json                      # Project dependencies & scripts
├── README.md                         # Main repository documentation
├── db.js                             # Neon Postgres SSL connection pool
├── server.js                         # Express server initialization
├── middleware/
│   ├── authJwt.js                    # JWT identity verification
│   └── challengeLockMiddleware.js    # Challenge-Lock security enforcement
├── routes/
│   ├── authRoutes.js                 # Authentication (/api/auth/login)
│   ├── challengeRoutes.js            # Nonce issuance (/api/v1/challenge)
│   └── transferRoutes.js             # Protected endpoint (/api/v1/transfer)
├── test_attacks_neon.js              # Automated attack verification test suite
├── challenge_lock_implementation_plan_v4.md # AI Coding Agent Technical Spec
└── vscode_setup_and_execution_guide.md       # VS Code setup instructions
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
Ensure you have installed:
* [Node.js (v18+)](https://nodejs.org/)
* A free [Neon Postgres](https://neon.tech) account

### 2. Installation & Setup
Clone the repository and install dependencies:
```bash
git clone https://github.com/your-username/challenge-lock-api.git
cd challenge-lock-api
npm install
```

### 3. Database Schema Migration
Log into your **Neon Console** -> **SQL Editor** and run:

```sql
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    binding_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'UNUSED',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_challenges_user_status ON challenges(user_id, status);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at) WHERE status = 'UNUSED';
```

### 4. Configure Environment Variables
Create a `.env` file in the project root based on `.env.example`:

```env
PORT=3000
DATABASE_URL=postgres://username:password@ep-xyz-pooler.region.aws.neon.tech/neondb?sslmode=require
JWT_SECRET=super_secret_jwt_key_12345
SESSION_KEY_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### 5. Launch Application
```bash
# Production Start
npm start

# Development Mode (Hot Reloading)
npm run dev
```

The Express API server will start on `http://localhost:3000`.

---

## 🧪 Automated Attack Verification

This repository includes an executable test harness (`test_attacks_neon.js`) to prove security against live attacks.

### Running the Attack Test Suite
In a new terminal window (while the server is running):

```bash
node test_attacks_neon.js
```

### Expected Test Output
```text
==================================================
STARTING CHALLENGE-LOCK ATTACK VERIFICATION SUITE
==================================================

[+] Step 0: Logging in user...
    JWT Token Acquired.

--------------------------------------------------
TEST 1: REPLAY ATTACK DEFENSE VERIFICATION
--------------------------------------------------
[+] Challenge Issued: chl_8f9a2b1c3d4e...
[+] Sending Legitimate Request 1...
    Result 1: SUCCESS (HTTP 200) - Transfer Processed.
[!] ATTACK ATTEMPT: Replaying the EXACT same request headers & body...
    [PASS] DEFENDED: Server rejected replayed challenge (HTTP 401 - CHALLENGE_REJECTED).

--------------------------------------------------
TEST 2: PARAMETER TAMPERING DEFENSE VERIFICATION
--------------------------------------------------
[+] Challenge Issued: chl_9e8d7c6b5a4f...
[!] ATTACK ATTEMPT: Tampering payload body to $10,000 for Eve...
    [PASS] DEFENDED: Server rejected tampered request binding match (HTTP 401 - CHALLENGE_REJECTED).

==================================================
ALL DEFENSE SCENARIOS TESTED SUCCESSFULLY
==================================================
```

---

## 🤖 AI Coding Agent Integration

This repository includes `challenge_lock_implementation_plan_v4.md`, a machine-readable specification formatted for AI coding assistants (such as **Claude Code**, **Cursor**, **Aider**, or **GitHub Copilot**).

To prompt an AI agent to extend or re-implement this protocol:
```text
"Read challenge_lock_implementation_plan_v4.md and generate a new middleware implementation in Python/FastAPI using PostgreSQL and AES-256-GCM."
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.
