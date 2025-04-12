const express = require('express');
const { Client } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();

// --- Route Imports ---
const authRoutes = require('./auth');
const urlRoutes = require('./urls');
const blogRoutes = require('./blogs');
const dashboardRoutes = require('./dashboard');
const logoutRoute = require('./logout');
const publicUrlRoutes = require('./publicUrls');
const userProfileRoutes = require('./userprofile');

const app = express();
const port = process.env.PORT || 3000;

// --- Configuration Constants ---
const SECRET_KEY = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;

// --- Basic Checks ---
if (!SECRET_KEY) {
    console.error("FATAL ERROR: JWT_SECRET is not defined in .env file.");
    process.exit(1);
}
if (!FRONTEND_ORIGIN) {
    console.warn("WARNING: FRONTEND_ORIGIN is not defined in .env file. CORS might block frontend requests.");
}

// --- Database Configuration ---
const client = new Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432,
});

// --- CORS Configuration ---
const corsOptions = {
    origin: FRONTEND_ORIGIN,
    methods: 'POST, GET, DELETE, PUT, PATCH',
    allowedHeaders: 'Content-Type, Authorization',
    credentials: true
};

// --- Global Middleware ---
app.use(cors(corsOptions));
app.use(express.json());

// --- Authentication Middleware Function ---
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') && authHeader.split(' ')[1];

    if (token == null) {
        console.log(`Auth Middleware: Denied - No token provided for ${req.method} ${req.originalUrl}`);
        return res.status(401).json({ error: 'Access token is required.' });
    }

    try {
        const blacklistCheck = await client.query('SELECT 1 FROM blacklist WHERE token = $1 LIMIT 1', [token]);
        if (blacklistCheck.rows.length > 0) {
            console.log(`Auth Middleware: Denied - Token is blacklisted for ${req.method} ${req.originalUrl}`);
            return res.status(401).json({ error: 'Token has been invalidated (logged out).' });
        }

        jwt.verify(token, SECRET_KEY, (err, userPayload) => {
            if (err) {
                let message = 'Invalid token.';
                if (err.name === 'TokenExpiredError') {
                    message = 'Access token has expired.';
                    console.log(`Auth Middleware: Denied - Token expired for ${req.method} ${req.originalUrl}`);
                    return res.status(401).json({ error: message, code: 'TOKEN_EXPIRED' });
                } else if (err.name === 'JsonWebTokenError') {
                    message = 'Invalid token signature or format.';
                    console.log(`Auth Middleware: Denied - Invalid JWT (${err.message}) for ${req.method} ${req.originalUrl}`);
                } else {
                    console.log(`Auth Middleware: Denied - Unknown JWT error (${err.name}) for ${req.method} ${req.originalUrl}`);
                }
                return res.status(403).json({ error: message });
            }
            req.user = userPayload;
            next();
        });
    } catch (dbError) {
        console.error('Auth Middleware: Database error during blacklist check:', dbError);
        return res.status(500).json({ error: 'Internal server error during authentication check.' });
    }
};

// --- Route Mounting ---

// Initialize blog routes
const blogRouters = blogRoutes(client, jwt);

// Public routes
app.use('/api/blogs', blogRouters.public);

// Protected routes - Mount the /me route BEFORE the generic /:postId routes
const protectedBlogRouter = express.Router();
protectedBlogRouter.use(authenticateToken);
protectedBlogRouter.use('/', (req, res, next) => {
    // Log the incoming request to the protected blog routes for debugging
    console.log(`Protected Blog Route Hit: ${req.method} ${req.originalUrl}`);
    next();
});
protectedBlogRouter.get('/me', blogRouters.protected); // Mount /me specifically
protectedBlogRouter.use('/', blogRouters.protected);    // Mount the rest of the protected routes
app.use('/api/blogs', protectedBlogRouter);

app.use('/api/auth', authRoutes(client, SECRET_KEY, bcrypt, jwt));
app.use('/api/public', publicUrlRoutes(client));
app.use('/api/urls', authenticateToken, urlRoutes.protectedRouter(client, jwt, SECRET_KEY));
app.use('/api/dashboard', authenticateToken, dashboardRoutes(client));
app.post('/api/auth/logout', authenticateToken, logoutRoute(client));
app.use('/api/user', authenticateToken, userProfileRoutes);

// Public Redirect Route
app.get('/:shortUrl', urlRoutes.redirect(client));

// --- Error Handling Middleware ---
app.use((req, res, next) => {
    res.status(404).json({ error: `Not Found - Cannot ${req.method} ${req.originalUrl}` });
});

app.use((err, req, res, next) => {
    console.error(`Unhandled Error on ${req.method} ${req.originalUrl}:`, err.stack || err.message || err);
    res.status(err.status || 500).json({
        error: 'Internal Server Error',
    });
});

// --- Database Connection and Initialization ---
client.connect()
    .then(() => {
        console.log('Successfully connected to PostgreSQL database.');
        return createTables();
    })
    .then(() => {
        console.log('Database tables checked/created successfully.');
        app.listen(port, () => {
            console.log(`Server listening for requests at http://localhost:${port}`);
        });
        setInterval(cleanupExpiredItems, 60 * 60 * 1000);
        cleanupExpiredItems();
    })
    .catch(err => {
        console.error('FATAL: Error connecting to or setting up PostgreSQL database:', err);
        process.exit(1);
    });

// --- Database Schema Creation Function ---
async function createTables() {
    console.log('Checking and creating database tables if they do not exist...');
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                email VARCHAR(255) UNIQUE,
                full_name VARCHAR(255),
                bactive INTEGER DEFAULT 1
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(LOWER(username));`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(LOWER(email));`);
        console.log('-> Users table checked/created.');

        await client.query(`
            CREATE TABLE IF NOT EXISTS urls (
                id SERIAL PRIMARY KEY,
                short_url VARCHAR(10) UNIQUE NOT NULL,
                original_url TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_urls_short_url ON urls(short_url);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_urls_user_id ON urls(user_id);`);
        console.log('-> URLs (Permanent) table checked/created.');

        await client.query(`
            CREATE TABLE IF NOT EXISTS temp_urls (
                id SERIAL PRIMARY KEY,
                short_url VARCHAR(10) UNIQUE NOT NULL,
                original_url TEXT NOT NULL,
                expiry TIMESTAMP WITH TIME ZONE NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                creator_ip VARCHAR(45),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_temp_urls_short_url ON temp_urls(short_url);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_temp_urls_expiry ON temp_urls(expiry);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_temp_urls_user_id ON temp_urls(user_id);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_temp_urls_creator_ip ON temp_urls(creator_ip);`);
        console.log('-> Temporary URLs table checked/created.');

        await client.query(`
            CREATE TABLE IF NOT EXISTS blacklist (
                token TEXT UNIQUE NOT NULL,
                expiry TIMESTAMP WITH TIME ZONE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_blacklist_token ON blacklist USING HASH(token);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_blacklist_expiry ON blacklist(expiry);`);
        console.log('-> Blacklist table checked/created.');

        await client.query(`
            CREATE TABLE IF NOT EXISTS analytics (
                id SERIAL PRIMARY KEY,
                short_url VARCHAR(10) NOT NULL,
                click_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT,
                referrer TEXT,
                ip_address VARCHAR(45)
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_analytics_short_url_ts ON analytics(short_url, click_timestamp DESC);`);
        console.log('-> Analytics table checked/created.');

        await client.query(`
            CREATE TABLE IF NOT EXISTS blogposts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_blogposts_user_id ON blogposts(user_id);`);
        console.log('-> Blogposts table checked/created.');

    } catch (err) {
        console.error('Error during table creation:', err);
        throw err;
    }
}

// --- Periodic Cleanup Function ---
async function cleanupExpiredItems() {
    console.log(`[${new Date().toISOString()}] Running periodic cleanup task...`);
    let cleanedUrls = 0;
    let cleanedTokens = 0;
    try {
        const deletedUrls = await client.query(`DELETE FROM temp_urls WHERE expiry <= NOW() RETURNING 1`);
        cleanedUrls = deletedUrls.rowCount;
        const deletedTokens = await client.query(`DELETE FROM blacklist WHERE expiry <= NOW()`);
        cleanedTokens = deletedTokens.rowCount;
    } catch (err) {
        console.error(`[${new Date().toISOString()}] Error during periodic cleanup task:`, err);
    } finally {
        if (cleanedUrls > 0 || cleanedTokens > 0) {
            console.log(`[${new Date().toISOString()}] Cleanup finished: Removed ${cleanedUrls} expired temp URLs and ${cleanedTokens} expired blacklist tokens.`);
        }
    }
}