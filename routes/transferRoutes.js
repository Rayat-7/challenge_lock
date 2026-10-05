const express = require('express');
const { verifyJwt } = require('../middleware/authJwt');
const { challengeLockMiddleware } = require('../middleware/challengeLockMiddleware');
const router = express.Router();

router.post('/transfer', verifyJwt, challengeLockMiddleware, (req, res) => {
  const { recipient, amount } = req.decryptedBody;
  return res.json({
    status: 'SUCCESS',
    message: `Transferred $${amount} to ${recipient} successfully.`,
    transactionId: 'tx_' + Date.now()
  });
});

module.exports = router;
