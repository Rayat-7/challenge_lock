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

    const userId = req.user.id;
    const sessionKey = Buffer.from(req.user.sessionKeyHex, 'hex');

    // 1. Decrypt AES-256-GCM Payload
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let decryptedStr = decipher.update(encryptedData, 'hex', 'utf8');
    decryptedStr += decipher.final('utf8');

    const decryptedPayload = JSON.parse(decryptedStr);

    // 2. Compute Binding Hash
    const expectedBinding = computeBindingHash(
      req.method,
      req.path,
      decryptedPayload.data,
      decryptedPayload.timestamp
    );

    // 3. Atomic Single-Use Query in Neon Postgres
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
        message: 'Challenge is invalid, expired, consumed, or bound parameters were tampered.'
      });
    }

    req.decryptedBody = decryptedPayload.data;
    next();
  } catch (err) {
    return res.status(400).json({ error: 'DECRYPTION_OR_TAMPERING_FAILED', details: err.message });
  }
}

module.exports = { challengeLockMiddleware, computeBindingHash };
