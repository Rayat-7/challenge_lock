const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
require('dotenv').config();

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'testuser' && password === 'password123') {
    const token = jwt.sign({ userId: 'user_1001', username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token });
  }
  return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
});

module.exports = router;
