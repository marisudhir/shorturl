// File: ./routes/urls.js

const express = require('express');
const { nanoid } = require('nanoid'); // Use nanoid v3 for CommonJS require()

// --- Configuration ---
// TEMP_URL_LIMIT is no longer used for logged-in creation logic, but kept for reference/context
const TEMP_URL_LIMIT = 25;
const TEMP_URL_EXPIRY_DAYS = 30; // Still used for anonymous temp urls via publicUrls.js
const SHORT_URL_LENGTH = 8; // Length of generated short IDs

// --- Error Type for Unique ID Generation Failure ---
class UniqueIdError extends Error {
    constructor(message) {
        super(message);
        this.name = "UniqueIdError";
    }
}

// --- Helper Functions ---

/**
 * Generates a unique short URL identifier that doesn't exist in urls or temp_urls.
 * @param {object} client - The connected pg Client instance.
 * @returns {Promise<string>} A unique short URL string.
 * @throws {UniqueIdError} If a unique ID cannot be generated after max attempts.
 */
async function generateUniqueShortUrl(client) {
    let shortUrl;
    let isUnique = false;
    let attempts = 0;
    const maxAttempts = 10; // Prevent potential infinite loops

    while (!isUnique && attempts < maxAttempts) {
        shortUrl = nanoid(SHORT_URL_LENGTH);
        // Check efficiently if the generated ID exists in either table
        const existsCheck = await client.query(
            'SELECT EXISTS(SELECT 1 FROM urls WHERE short_url = $1 UNION ALL SELECT 1 FROM temp_urls WHERE short_url = $1)',
            [shortUrl]
        );
        if (!existsCheck.rows[0].exists) {
            isUnique = true;
        }
        attempts++;
    }
    if (!isUnique) {
        console.error(`[generateUniqueShortUrl] Failed after ${maxAttempts} attempts.`);
        throw new UniqueIdError(`Could not generate unique short URL after ${maxAttempts} attempts.`);
    }
    return shortUrl;
}

/**
 * Checks if a user owns a specific short URL (either permanent or temporary).
 * @param {object} client - The connected pg Client instance.
 * @param {string} shortUrl - The short URL to check.
 * @param {number} userId - The ID of the user.
 * @returns {Promise<{owned: boolean, exists: boolean}>} Object indicating ownership and existence.
 */
async function checkUrlOwnership(client, shortUrl, userId) {
    // Check if the URL exists and if the user ID matches in either table
    const ownerCheck = await client.query(
        `SELECT
            EXISTS(SELECT 1 FROM urls WHERE short_url = $1 AND user_id = $2) AS owned_perm,
            EXISTS(SELECT 1 FROM temp_urls WHERE short_url = $1 AND user_id = $2 AND expiry > NOW()) AS owned_temp_active, -- Only check active temp
            EXISTS(SELECT 1 FROM urls WHERE short_url = $1 AND user_id != $2) AS exists_other_perm,
            EXISTS(SELECT 1 FROM temp_urls WHERE short_url = $1 AND user_id != $2) AS exists_other_temp,
            EXISTS(SELECT 1 FROM temp_urls WHERE short_url = $1 AND user_id IS NULL) AS exists_anon
        `,
        [shortUrl, userId]
    );

    const result = ownerCheck.rows[0];
    const isOwned = result.owned_perm || result.owned_temp_active; // Ownership means it's theirs AND active if temp
    // Exists if owned OR exists but belongs to someone else OR exists as anonymous
    const doesExist = isOwned || result.exists_other_perm || result.exists_other_temp || result.exists_anon;

    return { owned: isOwned, exists: doesExist };
}

// --- Public Redirect Logic ---
/**
 * Handles the redirection of short URLs.
 * @param {object} client - The connected pg Client instance.
 * @returns {Function} Express middleware function.
 */
const redirectLogic = (client) => async (req, res) => {
    const { shortUrl } = req.params;

    // Stricter validation on the input parameter length
    if (!shortUrl || shortUrl.length !== SHORT_URL_LENGTH) {
        return res.status(404).send('Short URL not found.'); // Generic message for invalid format
    }
    console.log(`[Redirect] Attempt for: ${shortUrl}`);

    try {
        // Check permanent URLs
        const urlResult = await client.query(
            'SELECT original_url FROM urls WHERE short_url = $1',
             [shortUrl]
        );

        if (urlResult.rows.length > 0) {
            const originalUrl = urlResult.rows[0].original_url;
            console.log(`[Redirect] Permanent URL found: ${shortUrl} -> ${originalUrl}`);
            // Log analytics asynchronously
            client.query(
                'INSERT INTO analytics (short_url, user_agent, referrer, ip_address) VALUES ($1, $2, $3, $4)',
                [shortUrl, req.headers['user-agent'], req.headers['referer'], req.ip]
            ).catch(err => console.error(`[Analytics] Logging error (permanent URL ${shortUrl}):`, err));

            return res.redirect(301, originalUrl); // 301 Permanent Redirect
        }

        // Check temporary URLs if not found in permanent
        const tempUrlResult = await client.query(
            'SELECT original_url, expiry FROM temp_urls WHERE short_url = $1',
             [shortUrl]
        );

        if (tempUrlResult.rows.length > 0) {
            const { original_url, expiry } = tempUrlResult.rows[0];
            // Check if the temporary URL is still valid
            if (new Date(expiry) > new Date()) {
                 console.log(`[Redirect] Temporary URL found: ${shortUrl} -> ${original_url}`);
                 // Log analytics asynchronously
                 client.query(
                    'INSERT INTO analytics (short_url, user_agent, referrer, ip_address) VALUES ($1, $2, $3, $4)',
                    [shortUrl, req.headers['user-agent'], req.headers['referer'], req.ip]
                 ).catch(err => console.error(`[Analytics] Logging error (temp URL ${shortUrl}):`, err));

                return res.redirect(302, original_url); // 302 Temporary Redirect
            } else {
                // Temp URL has expired - delete it now
                console.log(`[Redirect] Temporary URL ${shortUrl} expired. Deleting.`);
                await client.query('DELETE FROM temp_urls WHERE short_url = $1', [shortUrl]);
                // Consider deleting associated analytics data if desired
                // await client.query('DELETE FROM analytics WHERE short_url = $1', [shortUrl]);
                return res.status(404).send('Short URL expired.'); // Specific message
            }
        }

        // If not found in either table
        console.log(`[Redirect] Short URL ${shortUrl} not found.`);
        return res.status(404).send('Short URL not found.');

    } catch (err) {
        console.error(`[Redirect] Error during redirect for ${shortUrl}:`, err);
        return res.status(500).send('Internal server error during redirection.');
    }
};


// --- Protected Router Logic ---
/**
 * Creates and configures the router for authenticated URL actions.
 * @param {object} client - The connected pg Client instance.
 * @param {object} jwt - The jsonwebtoken library instance (optional if not used directly here).
 * @param {string} secretKey - The JWT secret key (optional if not used directly here).
 * @returns {object} The configured express router.
 */
const protectedRouterLogic = (client, jwt, secretKey) => {
    const router = express.Router(); // Create router instance inside the function

    // --- Shorten URL Endpoint (Authenticated) ---
    // Path: POST /api/urls/shorten
    // `authenticateToken` middleware runs BEFORE this
    router.post('/shorten', async (req, res) => {
        const { url } = req.body;
        const userId = req.user.userId; // Get user ID from middleware

        // --- Input Validation ---
        if (!url) {
            return res.status(400).json({ error: 'URL is required.' });
        }
        try {
            // Validate URL format and protocol
             const validUrl = new URL(url);
             if (!['http:', 'https:'].includes(validUrl.protocol)) {
                 throw new Error('Invalid protocol');
             }
        } catch (err) {
            console.warn(`[Shorten] Invalid URL format provided by user ${userId}: ${url}`);
            return res.status(400).json({ error: 'Invalid URL format or protocol (http/https) provided.' });
        }

        // --- Create Permanent URL ---
        try {
            // Generate a unique short ID
            const shortUrl = await generateUniqueShortUrl(client); // Use the existing helper

            // Logged-in users ALWAYS create permanent URLs directly
            await client.query(
                'INSERT INTO urls (short_url, original_url, user_id) VALUES ($1, $2, $3)',
                [shortUrl, url, userId]
            );

            console.log(`[Shorten] User ${userId} created permanent URL: ${shortUrl}`);

            // Prepare response data
            const resultData = {
                shortUrl,
                type: 'permanent',
                message: 'Permanent URL created successfully.'
            };

            return res.status(201).json(resultData); // Use 201 Created status

        } catch (err) {
            // Handle potential errors (unique ID generation, database insert)
            console.error(`[Shorten] Error shortening URL for user ${userId}:`, err);
            if (err instanceof UniqueIdError) { // Check specific error from helper
                 return res.status(500).json({ error: 'Could not generate unique URL ID. Please try again.' });
            }
            // Check for potential unique constraint violation on short_url
            if (err.code === '23505') { // PostgreSQL unique violation
                 console.error(`[Shorten] Collision occurred even after check for user ${userId}. Retrying might be needed or increase ID length.`);
                 return res.status(500).json({ error: 'Failed to save URL due to conflict. Please try again.' });
            }
            return res.status(500).json({ error: 'Internal server error during URL shortening.' });
        }
    });

    // --- Get User's URLs Endpoint ---
    // Path: GET /api/urls/myurls
    router.get('/myurls', async (req, res) => {
        const userId = req.user.userId;
        console.log(`[MyURLs] Fetching URLs for user ${userId}`);
        try {
            // Fetch both permanent and *active* temporary URLs
            // Note: Logged-in users only create permanent now, but they might have old temp ones.
            // Or anonymous URLs might be linked later? Keeping temp check for flexibility.
            const urlsResult = await client.query(
                'SELECT id, short_url, original_url, created_at FROM urls WHERE user_id = $1 ORDER BY created_at DESC',
                [userId]
            );
            const tempUrlsResult = await client.query(
                'SELECT id, short_url, original_url, expiry, created_at FROM temp_urls WHERE user_id = $1 AND expiry > NOW() ORDER BY created_at DESC',
                [userId]
            );
            res.status(200).json({ permanent: urlsResult.rows, temporary: tempUrlsResult.rows });
        } catch (err) {
            console.error(`[MyURLs] Error fetching URLs for user ${userId}:`, err);
            res.status(500).json({ error: 'Internal server error fetching user URLs.' });
        }
    });

     // --- Get Analytics Endpoint ---
     // Path: GET /api/urls/analytics/:shortUrl
    router.get('/analytics/:shortUrl', async (req, res) => {
        const { shortUrl } = req.params;
        const userId = req.user.userId;

        if (!shortUrl || shortUrl.length !== SHORT_URL_LENGTH) {
             return res.status(400).json({ error: 'Invalid short URL format.' });
        }
        console.log(`[Analytics] User ${userId} requesting analytics for ${shortUrl}`);

        try {
            // Check ownership using the helper function
            const { owned, exists } = await checkUrlOwnership(client, shortUrl, userId);

            if (!owned) {
                if (!exists) {
                     console.log(`[Analytics] Failed for user ${userId}: URL ${shortUrl} not found.`);
                     return res.status(404).json({ error: 'Short URL not found.' });
                } else {
                    console.warn(`[Analytics] Authz Failed: User ${userId} tried to access analytics for ${shortUrl} (not owner).`);
                    return res.status(403).json({ error: 'You are not authorized to view analytics for this short URL.' });
                }
            }

            // --- If Owner, Fetch Analytics ---
            const analyticsPromise = client.query(
                'SELECT id, click_timestamp, user_agent, referrer, ip_address FROM analytics WHERE short_url = $1 ORDER BY click_timestamp DESC',
                [shortUrl]
            );
            const clickCountPromise = client.query(
                'SELECT COUNT(*) AS total_clicks FROM analytics WHERE short_url = $1',
                 [shortUrl]
            );
            const [analyticsResult, clickCountResult] = await Promise.all([analyticsPromise, clickCountPromise]);

            console.log(`[Analytics] Successfully fetched analytics for ${shortUrl} by user ${userId}`);
            return res.status(200).json({
                totalClicks: parseInt(clickCountResult.rows[0].total_clicks || 0),
                clicks: analyticsResult.rows
            });

        } catch (err) {
            console.error(`[Analytics] Error fetching analytics for ${shortUrl} by user ${userId}:`, err);
            return res.status(500).json({ error: 'Internal server error fetching analytics.' });
        }
    });

     // --- Delete URL Endpoint ---
     // Path: DELETE /api/urls/:shortUrl
    router.delete('/:shortUrl', async (req, res) => {
        const { shortUrl } = req.params;
        const userId = req.user.userId;

        if (!shortUrl || shortUrl.length !== SHORT_URL_LENGTH) {
             return res.status(400).json({ error: 'Invalid short URL format.' });
        }
        console.log(`[Delete] User ${userId} attempting to delete URL ${shortUrl}`);

        try {
            // Check ownership *before* attempting delete
            const { owned, exists } = await checkUrlOwnership(client, shortUrl, userId);

             if (!owned) {
                if (!exists) {
                     console.log(`[Delete] Failed for user ${userId}: URL ${shortUrl} not found.`);
                     return res.status(404).json({ error: 'Short URL not found.' });
                } else {
                    console.warn(`[Delete] Authz Failed: User ${userId} tried to delete ${shortUrl} (not owner).`);
                    return res.status(403).json({ error: 'You are not authorized to delete this URL.' });
                }
            }

            // If owner, proceed with deletion from both tables (although logged-in users now only create permanent,
            // they might have old temp ones, or ownership rules could change, so check both is safer)
            await client.query('DELETE FROM urls WHERE short_url = $1 AND user_id = $2', [shortUrl, userId]);
            await client.query('DELETE FROM temp_urls WHERE short_url = $1 AND user_id = $2', [shortUrl, userId]);

            console.log(`[Delete] User ${userId} successfully deleted URL ${shortUrl}.`);
            // Optional: Clean up analytics data asynchronously
            client.query('DELETE FROM analytics WHERE short_url = $1', [shortUrl])
               .catch(err => console.error(`[Delete] Error cleaning up analytics for deleted URL ${shortUrl}:`, err));

            return res.status(200).json({ message: `Short URL ${shortUrl} deleted successfully.` });

        } catch (err) {
            console.error(`[Delete] Error deleting URL ${shortUrl} by user ${userId}:`, err);
            res.status(500).json({ error: 'Internal server error during URL deletion.' });
        }
    });

    // Return the configured router instance
    return router;
};

// --- Export Both Parts ---
module.exports = {
    redirect: redirectLogic,                // Function to handle redirection logic
    protectedRouter: protectedRouterLogic   // Function that creates the protected routes router
};