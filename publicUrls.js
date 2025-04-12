// File: ./routes/publicUrls.js

const express = require('express');
const { nanoid } = require('nanoid'); // Assuming nanoid v3 for CommonJS

// --- Configuration ---
const ANONYMOUS_URL_LIMIT = 15; // Limit for anonymous users per IP
const TEMP_URL_EXPIRY_DAYS = 30; // Standard expiry for temp URLs
const SHORT_URL_LENGTH = 8;

// --- Helper Function (copied or imported from urls.js/utils) ---
// Ensure this function is available here
async function generateUniqueShortUrl(client) {
    let shortUrl;
    let isUnique = false;
    let attempts = 0;
    const maxAttempts = 10;

    while (!isUnique && attempts < maxAttempts) {
        shortUrl = nanoid(SHORT_URL_LENGTH);
        const urlCheck = await client.query('SELECT EXISTS(SELECT 1 FROM urls WHERE short_url = $1)', [shortUrl]);
        const tempUrlCheck = await client.query('SELECT EXISTS(SELECT 1 FROM temp_urls WHERE short_url = $1)', [shortUrl]);

        if (!urlCheck.rows[0].exists && !tempUrlCheck.rows[0].exists) {
            isUnique = true;
        }
        attempts++;
    }
    if (!isUnique) {
        throw new Error("Could not generate unique short URL.");
    }
    return shortUrl;
}

/**
 * Exports a function that configures public URL routes.
 * @param {object} client - The connected pg Client instance.
 * @returns {object} The configured express router.
 */
module.exports = (client) => {
    const router = express.Router();

    // --- Shorten URL Endpoint for Anonymous Users ---
    // Path: POST /api/public/shorten (relative to mount point in app.js)
    router.post('/shorten', async (req, res) => {
        const { url } = req.body;
    
        // Try to get the real client IP address, handling potential proxies
        const forwardedFor = req.headers['x-forwarded-for'];
        const ipAddress = forwardedFor ? forwardedFor.split(',')[0].trim() : req.ip;
    
        // --- Input Validation ---
        // ... (rest of your input validation code)
    
        console.log(`Anonymous shorten request from IP: ${ipAddress} for URL: ${url}`);
    
        try {
            // --- Check Anonymous Limit ---
            const anonymousCountResult = await client.query(
                `SELECT COUNT(*) FROM temp_urls
                 WHERE creator_ip = $1 AND user_id IS NULL AND expiry > NOW()`,
                [ipAddress]
            );
            const anonymousCount = parseInt(anonymousCountResult.rows[0].count);
    
            if (anonymousCount >= ANONYMOUS_URL_LIMIT) {
                console.log(`Anonymous limit reached for IP: ${ipAddress}`);
                return res.status(403).json({ error: `Anonymous URL limit (${ANONYMOUS_URL_LIMIT}) reached. Please log in to create more URLs.` });
            }
    
            // --- If Limit Not Reached, Create Temp URL ---
            const shortUrl = await generateUniqueShortUrl(client);
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + TEMP_URL_EXPIRY_DAYS);
    
            await client.query(
                'INSERT INTO temp_urls (short_url, original_url, expiry, user_id, creator_ip) VALUES ($1, $2, $3, NULL, $4)',
                [shortUrl, url, expiryDate, ipAddress]
            );
    
            console.log(`Anonymous temp URL created: ${shortUrl} for IP: ${ipAddress}`);
            return res.status(201).json({
                shortUrl,
                type: 'temporary',
                message: `Temporary URL created successfully. It will expire in ${TEMP_URL_EXPIRY_DAYS} days.`
            });
    
        } catch (err) {
            console.error(`Error shortening URL for anonymous IP ${ipAddress}:`, err);
            if (err.message.includes("unique short URL")) {
                return res.status(500).json({ error: 'Could not generate unique URL ID. Please try again.' });
            }
            return res.status(500).json({ error: 'Internal server error during URL shortening.' });
        }
    });

    // Return the configured router
    return router;
};