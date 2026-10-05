const { Pool } = require('pg');
require('dotenv').config();

const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

dbPool.on('connect', () => {
  console.log('[+] Connected to Neon Serverless Postgres');
});

module.exports = { dbPool };
