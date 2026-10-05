const express = require('express');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/authRoutes');
const challengeRoutes = require('./routes/challengeRoutes');
const transferRoutes = require('./routes/transferRoutes');

const app = express();
app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/v1', challengeRoutes);
app.use('/api/v1', transferRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[+] Challenge-Lock Server listening on port ${PORT}`);
});
