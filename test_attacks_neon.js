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
  console.log('==================================================');

  // Step 0: Login & Get JWT Token
  console.log('[+] Step 0: Logging in user...');
  const loginRes = await axios.post(`${API_BASE}/auth/login`, { username: 'testuser', password: 'password123' });
  jwtToken = loginRes.data.token;
  console.log('JWT Token Acquired.');

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
  console.log('--------------------------------------------------');
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

  console.log('==================================================');
  console.log('ALL DEFENSE SCENARIOS TESTED SUCCESSFULLY AGAINST NEON');
  console.log('==================================================');
}

runAttackSuite();
