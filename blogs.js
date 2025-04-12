const express = require('express');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// --- Public Logic ---

// GET /api/blogs/list (Public)
const getBlogListLogic = (client) => async (req, res) => {
    console.log("Fetching public blog list...");
    try {
        const result = await client.query(
            `SELECT b.id, b.title, LEFT(b.content, 200) AS content_preview, b.created_at, u.username AS author
             FROM blogposts b
             JOIN users u ON b.user_id = u.id
             ORDER BY b.created_at DESC`
        );
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error fetching blog posts:', error);
        res.status(500).json({ error: 'Failed to fetch blog posts.' });
    }
};

// GET /api/blogs/:postId (Public)
const getBlogPostByIdLogic = (client) => async (req, res) => {
    const { postId } = req.params;

    if (!/^\d+$/.test(postId)) {
        return res.status(400).json({ error: 'Invalid post ID format.' });
    }

    console.log(`Fetching public blog post with ID: ${postId}`);
    try {
        const result = await client.query(
            `SELECT b.id, b.title, b.content, b.created_at, u.username AS author
             FROM blogposts b
             JOIN users u ON b.user_id = u.id
             WHERE b.id = $1`,
            [postId]
        );
        if (result.rows.length > 0) {
            res.status(200).json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'Blog post not found.' });
        }
    } catch (error) {
        console.error(`Error fetching blog post with ID ${postId}:`, error);
        res.status(500).json({ error: 'Failed to fetch blog post.' });
    }
};

// --- Protected Logic ---
const protectedRouterLogic = (client) => {
    const router = express.Router();

    const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) return res.sendStatus(401);

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    };

    router.use(authenticateToken);

    // POST /api/blogs/create
    router.post('/create', async (req, res) => {
        const { title, content } = req.body;
        const userId = req.user.userId;

        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required for blog post.' });
        }

        console.log(`User ${userId} attempting to create blog post titled: ${title}`);
        try {
            const result = await client.query(
                'INSERT INTO blogposts (user_id, title, content) VALUES ($1, $2, $3) RETURNING *',
                [userId, title, content]
            );
            res.status(201).json(result.rows[0]);
        } catch (error) {
            console.error('Error creating blog post:', error);
            res.status(500).json({ error: 'Failed to create blog post.' });
        }
    });

    // DELETE /api/blogs/:postId
    router.delete('/:postId', async (req, res) => {
        const { postId } = req.params;
        const userId = req.user.userId;

        if (!/^\d+$/.test(postId)) {
            return res.status(400).json({ error: 'Invalid post ID format.' });
        }

        console.log(`User ${userId} attempting to delete blog post ID: ${postId}`);
        try {
            const deleteResult = await client.query(
                'DELETE FROM blogposts WHERE id = $1 AND user_id = $2 RETURNING id',
                [postId, userId]
            );
            if (deleteResult.rowCount > 0) {
                res.status(200).json({ message: 'Blog post deleted successfully.' });
            } else {
                const existsCheck = await client.query('SELECT 1 FROM blogposts WHERE id = $1', [postId]);
                if (existsCheck.rows.length > 0) {
                    res.status(403).json({ error: 'You are not authorized to delete this post.' });
                } else {
                    res.status(404).json({ error: 'Blog post not found.' });
                }
            }
        } catch (error) {
            console.error(`Error deleting blog post ${postId} by user ${userId}:`, error);
            res.status(500).json({ error: 'Failed to delete blog post.' });
        }
    });

    // PUT /api/blogs/:postId
    router.put('/:postId', async (req, res) => {
        const { postId } = req.params;
        const userId = req.user.userId;
        const { title, content } = req.body;

        if (!/^\d+$/.test(postId)) {
            return res.status(400).json({ error: 'Invalid post ID format.' });
        }

        if (!title && !content) {
            return res.status(400).json({ error: 'At least one field (title or content) is required for update.' });
        }

        console.log(`User ${userId} attempting to update blog post ID: ${postId}`);
        try {
            let updateQuery = 'UPDATE blogposts SET ';
            const values = [];
            let index = 1;

            if (title) {
                updateQuery += `title = $${index++}, `;
                values.push(title);
            }
            if (content) {
                updateQuery += `content = $${index++}, `;
                values.push(content);
            }

            updateQuery = updateQuery.slice(0, -2); // remove trailing comma
            updateQuery += ` WHERE id = $${index++} AND user_id = $${index++} RETURNING *`;
            values.push(postId, userId);

            const updateResult = await client.query(updateQuery, values);

            if (updateResult.rowCount > 0) {
                res.status(200).json(updateResult.rows[0]);
            } else {
                const existsCheck = await client.query('SELECT 1 FROM blogposts WHERE id = $1', [postId]);
                if (existsCheck.rows.length > 0) {
                    res.status(403).json({ error: 'You are not authorized to update this post.' });
                } else {
                    res.status(404).json({ error: 'Blog post not found.' });
                }
            }
        } catch (error) {
            console.error(`Error updating blog post ${postId} by user ${userId}:`, error);
            res.status(500).json({ error: 'Failed to update blog post.' });
        }
    });

    // GET /api/blogs/me
    router.get('/me', async (req, res) => {
        const userId = req.user.userId;
        console.log(`Fetching blog posts for user ID: ${userId}`);
        try {
            const result = await client.query(
                `SELECT b.id, b.title, LEFT(b.content, 200) AS content_preview, b.created_at
                 FROM blogposts b
                 WHERE b.user_id = $1
                 ORDER BY b.created_at DESC`,
                [userId]
            );
            res.status(200).json(result.rows);
        } catch (error) {
            console.error(`Error fetching blog posts for user ${userId}:`, error);
            res.status(500).json({ error: 'Failed to fetch your blog posts.' });
        }
    });

    // POST /api/blogs/:postId/archive
    router.post('/:postId/archive', async (req, res) => {
        const { postId } = req.params;
        const userId = req.user.userId;

        if (!/^\d+$/.test(postId)) {
            return res.status(400).json({ error: 'Invalid post ID format.' });
        }

        console.log(`User ${userId} attempting to archive blog post ID: ${postId}`);
        try {
            const updateResult = await client.query(
                'UPDATE blogposts SET archived = TRUE WHERE id = $1 AND user_id = $2 RETURNING id',
                [postId, userId]
            );
            if (updateResult.rowCount > 0) {
                res.status(200).json({ message: 'Blog post archived successfully.' });
            } else {
                const existsCheck = await client.query('SELECT 1 FROM blogposts WHERE id = $1', [postId]);
                if (existsCheck.rows.length > 0) {
                    res.status(403).json({ error: 'You are not authorized to archive this post.' });
                } else {
                    res.status(404).json({ error: 'Blog post not found.' });
                }
            }
        } catch (error) {
            console.error(`Error archiving blog post ${postId} by user ${userId}:`, error);
            res.status(500).json({ error: 'Failed to archive blog post.' });
        }
    });

    return router;
};

module.exports = (client) => {
    const publicRouter = express.Router();
    publicRouter.get('/list', getBlogListLogic(client));
    publicRouter.get('/:postId', getBlogPostByIdLogic(client));

    const protectedRoutes = protectedRouterLogic(client);

    return {
        public: publicRouter,
        protected: protectedRoutes
    };
};
