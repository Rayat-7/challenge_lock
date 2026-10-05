const jwt = require('jsonwebtoken');
require('dotenv').config();

function verifyJwt(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'MISSING_OR_INVALID_JWT' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = {
      id: decoded.userId,
      sessionKeyHex: process.env.SESSION_KEY_HEX
    };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'INVALID_JWT_TOKEN' });
  }
}

module.exports = { verifyJwt };
