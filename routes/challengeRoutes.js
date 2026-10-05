const express = require('express');
const crypto = require('crypto');
const { verifyJwt } = require('../middleware/authJwt');
const { dbPool } = require('../db');
const router = express.Router();

router.post('/challenge', verifyJwt, async (req, res) => {
  try {
    const { path, bindingHash, timestamp } = req.body;
    const userId = req.user.id;

    if (!path || !bindingHash || !timestamp) {
      return res.status(400).json({ error: 'MISSING_CHALLENGE_PARAMETERS' });
    }

    const challengeId = 'chl_' + crypto.randomBytes(16).toString('hex');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minute TTL

    const insertQuery = `
      INSERT INTO challenges (challenge_id, user_id, binding_hash, expires_at)
      VALUES ($1, $2, $3, $4)
      RETURNING challenge_id, expires_at;
    `;

    await dbPool.query(insertQuery, [challengeId, userId, bindingHash, expiresAt]);

    return res.json({ challengeId, expiresAt });
  } catch (err) {
    return res.status(500).json({ error: 'CHALLENGE_ISSUANCE_FAILED', details: err.message });
  }
});

module.exports = router;
