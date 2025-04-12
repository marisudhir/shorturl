// File: ./routes/dashboard.js
// Placeholder - Implement actual dashboard data aggregation here

const express = require('express');

/**
 * Exports a function that configures the dashboard route.
 * @param {object} client - The connected pg Client instance.
 * @returns {object} The configured express router.
 */
module.exports = (client) => {
    const router = express.Router();

    // Path: GET /api/dashboard (relative to mount point in app.js)
    // `authenticateToken` middleware runs BEFORE this in app.js
    router.get('/', async (req, res) => {
        const userId = req.user.userId;
        console.log(`Workspaceing dashboard data for user ${userId}`);

        try {
            // --- Fetch data needed for the dashboard ---

            // Example: Get counts of permanent and temporary URLs
            const permUrlCountPromise = client.query(
                'SELECT COUNT(*) FROM urls WHERE user_id = $1', [userId]
            );
            const tempUrlCountPromise = client.query(
                'SELECT COUNT(*) FROM temp_urls WHERE user_id = $1 AND expiry > NOW()', [userId]
            );

            // Example: Get total clicks across all user's URLs (can be slow without good indexing)
             const totalClicksPromise = client.query(
                 `SELECT COUNT(a.id)
                  FROM analytics a
                  WHERE a.short_url IN (SELECT short_url FROM urls WHERE user_id = $1 UNION ALL SELECT short_url FROM temp_urls WHERE user_id = $1)`,
                  [userId]
             );

            // Example: Get recent URLs (e.g., last 5)
            const recentUrlsPromise = client.query(
                `(SELECT id, short_url, original_url, created_at, 'permanent' as type FROM urls WHERE user_id = $1 ORDER BY created_at DESC LIMIT 5)
                 UNION ALL
                 (SELECT id, short_url, original_url, created_at, 'temporary' as type FROM temp_urls WHERE user_id = $1 AND expiry > NOW() ORDER BY created_at DESC LIMIT 5)
                 ORDER BY created_at DESC LIMIT 5`, // Combine and get overall last 5
                 [userId]
            );


            // Wait for all promises to resolve
            const [
                permUrlCountResult,
                tempUrlCountResult,
                totalClicksResult,
                recentUrlsResult
            ] = await Promise.all([
                permUrlCountPromise,
                tempUrlCountPromise,
                totalClicksPromise,
                recentUrlsPromise
            ]);

            // --- Assemble dashboard data ---
            const dashboardData = {
                username: req.user.username,
                urlCounts: {
                    permanent: parseInt(permUrlCountResult.rows[0].count || 0),
                    temporary: parseInt(tempUrlCountResult.rows[0].count || 0),
                },
                 totalClicks: parseInt(totalClicksResult.rows[0].count || 0),
                 recentUrls: recentUrlsResult.rows,
                 // Add more data as needed (e.g., top URLs, click trends)
            };

            res.status(200).json(dashboardData);

        } catch (err) {
            console.error(`Error fetching dashboard data for user ${userId}:`, err);
            res.status(500).json({ error: 'Internal server error fetching dashboard data.' });
        }
    });

    // Return the configured router
    return router;
};