const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'url_shortner',
    password: 'Password@1234',
    port: 5432, // default PostgreSQL port
});

module.exports = pool;

