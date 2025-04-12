const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');

// Use environment variables for database configuration
const client = new Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5432,
});

client.connect().catch(err => console.error('Error connecting to PostgreSQL:', err));

// Middleware to authenticate user (assuming you're using JWT)
const authenticateUser = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1]; // Bearer <token>

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.user = user; // Attach user information to the request
        next();
    });
};

// --- Get User Profile ---
router.get('/profile', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.userId; // Assuming your JWT payload has userId

        const result = await client.query(
            'SELECT id, username, email, full_name, bactive FROM users WHERE id = $1',
            [userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userDetails = result.rows[0];
        res.status(200).json({ user: userDetails });

    } catch (err) {
        console.error('Error fetching user profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- Change Password ---
router.put('/profile/password', authenticateUser, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.userId;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ error: 'Old and new passwords are required' });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }

    try {
        const userResult = await client.query(
            'SELECT password FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const hashedPasswordFromDb = userResult.rows[0].password;
        const isPasswordMatch = await bcrypt.compare(oldPassword, hashedPasswordFromDb);

        if (!isPasswordMatch) {
            return res.status(401).json({ error: 'Invalid old password' });
        }

        const newHashedPassword = await bcrypt.hash(newPassword, 12);
        await client.query(
            'UPDATE users SET password = $1 WHERE id = $2',
            [newHashedPassword, userId]
        );

        res.status(200).json({ message: 'Password updated successfully' });

    } catch (err) {
        console.error('Error changing password:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- Deactivate Account ---
router.put('/profile/deactivate', authenticateUser, async (req, res) => {
    const userId = req.user.userId;

    try {
        await client.query(
            'UPDATE users SET bactive = $1 WHERE id = $2',
            [0, userId] // Set bactive to 0 for inactive
        );

        // Assuming you have a separate table for URLs linked to users
        await client.query(
            'UPDATE urls SET is_active = $1 WHERE user_id = $2',
            [false, userId] // Stop making associated URLs work
        );

        res.status(200).json({ message: 'Account deactivated successfully. Associated URLs will stop working.' });

    } catch (err) {
        console.error('Error deactivating account:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;