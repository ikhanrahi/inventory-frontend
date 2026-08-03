const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Supabase Cloud SSL কানেকশনের জন্য প্রয়োজন
    }
});

pool.connect((err, client, release) => {
    if (err) {
        return console.error('❌ Connection Error:', err.stack);
    }
    console.log('⚡ Connected to PostgreSQL Database on Supabase successfully!');
    release();
});

module.exports = pool;