// File: ./routes/logout.js

const express = require('express');
const jwt = require('jsonwebtoken'); // Needed to decode token for expiry

/**
 * Exports a function that configures the logout route.
 * @param {object} client - The connected pg Client instance.
 * @returns {object} The configured express router.
 */
module.exports = (client) => {
    const router = express.Router(); // Create router instance

    // Path: POST /api/auth/logout (relative to mount point in app.js)
    // `authenticateToken` middleware runs BEFORE this in app.js
    router.post('/', async (req, res) => { // Path is relative to mount point
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.startsWith('Bearer ') && authHeader.split(' ')[1];

        if (!token) {
            // Should ideally not happen if authenticateToken runs first, but good safety check
            return res.status(400).json({ error: 'Token required for logout.' });
        }

        try {
            // --- Determine Expiry for Blacklist Entry ---
            // Decode the token to get its 'exp' claim for accurate blacklist expiry
            let decoded;
            // Default expiry for blacklist entry if token decoding fails (e.g., 2 hours from now)
            let expiryTime = new Date(Date.now() + 2 * 60 * 60 * 1000);
            try {
                 decoded = jwt.decode(token); // Does not verify signature, just decodes payload
                 if (decoded && typeof decoded.exp === 'number') {
                     // Use token's actual expiry time (exp is in seconds, convert to milliseconds)
                     expiryTime = new Date(decoded.exp * 1000);
                 } else {
                     console.warn(`Could not decode expiry from token for user ${req.user?.userId}, using default blacklist expiry.`);
                 }
            } catch (decodeErr) {
                console.warn(`Error decoding token during logout for user ${req.user?.userId}: ${decodeErr.message}`);
            }

            // --- Add Token to Blacklist ---
            // Insert the token and its calculated expiry time.
            // ON CONFLICT DO NOTHING prevents errors if token somehow already blacklisted.
            await client.query(
                'INSERT INTO blacklist (token, expiry) VALUES ($1, $2) ON CONFLICT (token) DO NOTHING',
                [token, expiryTime]
            );

            console.log(`User ${req.user.userId} logged out. Token blacklisted until ${expiryTime.toISOString()}.`);
            res.status(200).json({ message: 'Logged out successfully.' });

        } catch (err) {
            console.error(`Error blacklisting token for user ${req.user.userId}:`, err);
            res.status(500).json({ error: 'Internal server error during logout.' });
        }
    });

    return router; // Return the configured router instance
};