// File: ./routes/auth.js

const express = require('express');
const router = express.Router(); // Create a new router instance

/**
 * Exports a function that configures authentication routes.
 * @param {object} client - The connected pg Client instance.
 * @param {string} secretKey - The JWT secret key.
 * @param {object} bcrypt - The bcrypt library instance.
 * @param {object} jwt - The jsonwebtoken library instance.
 * @returns {object} The configured express router.
 */
module.exports = (client, secretKey, bcrypt, jwt) => {

    // --- Registration Route ---
    // Path: POST /api/auth/register (relative to mount point in app.js)
    router.post('/register', async (req, res) => {
        const username = req.body.username?.trim(); // Get username, remove whitespace
        const password = req.body.password;
        const email = req.body.email?.trim();
        const fullName = req.body.fullName?.trim();

        // --- Input Validation ---
        if (!username || !password || !email || !fullName) {
            return res.status(400).json({ error: 'Username, password, email, and full name are required.' });
        }
        // Example: Basic password length check
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
        }
        // Example: Basic username validation (optional)
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) { // Allow letters, numbers, underscore, 3-20 chars
            return res.status(400).json({ error: 'Username must be 3-20 characters and contain only letters, numbers, or underscores.' });
        }
        // Example: Basic email validation
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }
        // Example: Basic full name validation (optional)
        if (!/^[a-zA-Z\s]{2,100}$/.test(fullName)) {
            return res.status(400).json({ error: 'Full name must be 2-100 characters and contain only letters and spaces.' });
        }

        try {
            // --- Hash Password ---
            // Use bcrypt to securely hash the password before storing
            // 10 or 12 is the number of salt rounds - a good balance
            const hashedPassword = await bcrypt.hash(password, 12);

            // --- Store User in Database ---
            // Use the passed-in 'client' for database operations
            // Parameterized query ($1, $2, $3, $4, $5) prevents SQL injection
            await client.query(
                'INSERT INTO users (username, password, email, full_name, bactive) VALUES (LOWER($1), $2, LOWER($3), $4, $5)', // Store username and email lowercase, set bactive to 1
                [username, hashedPassword, email, fullName, 1]
            );

            console.log(`User registered successfully: ${username} (${email})`);
            // Send success response
            res.status(201).json({ message: 'User registered successfully.' });

        } catch (err) {
            console.error(`Error registering user ${username} (${email}):`, err);
            // Handle specific database errors (like username or email already exists)
            if (err.code === '23505') { // PostgreSQL unique violation error code
                if (err.constraint === 'users_username_key') {
                    return res.status(400).json({ error: 'Username already exists. Please choose another.' });
                } else if (err.constraint === 'users_email_key') {
                    return res.status(400).json({ error: 'Email address already exists. Please use another.' });
                }
            }
            // Handle generic server errors
            res.status(500).json({ error: 'Internal server error during registration.' });
        }
    });

    // --- Login Route ---
    // Path: POST /api/auth/login (relative to mount point in app.js)
    router.post('/login', async (req, res) => {
        const username = req.body.username?.trim();
        const password = req.body.password;

        // --- Input Validation ---
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required.' });
        }

        try {
            // --- Find User (case-insensitive) ---
            // Query the database for the user by username (stored as lowercase)
            const result = await client.query(
                'SELECT id, username, password FROM users WHERE username = LOWER($1)',
                [username]
            );

            // Check if user exists
            if (result.rows.length === 0) {
                console.log(`Login attempt failed: User not found - ${username}`);
                // Use a generic error message for security (don't reveal if username exists)
                return res.status(401).json({ error: 'Invalid username or password.' });
            }

            const user = result.rows[0]; // Get the user data

            // --- Compare Passwords ---
            // Use bcrypt.compare to check if the provided password matches the stored hash
            const isPasswordMatch = await bcrypt.compare(password, user.password);

            if (!isPasswordMatch) {
                console.log(`Login attempt failed: Invalid password for user - ${username}`);
                // Generic error message
                return res.status(401).json({ error: 'Invalid username or password.' });
            }

            // --- Generate JWT ---
            // If passwords match, create a JWT payload
            const payload = {
                userId: user.id,
                username: user.username // Send back the actual stored username casing
                // Add other non-sensitive info if needed (e.g., roles), but keep payload small
            };

            // Sign the token using the secret key and set an expiration time
            const token = jwt.sign(
                payload,
                secretKey,
                { expiresIn: '8h' } // Token valid for 8 hours (adjust as needed)
            );

            console.log(`Login successful: User ${user.id} (${user.username})`);
            // Send the token back to the client
            res.status(200).json({
                token: token,
                userId: user.id, // Optionally send userId and username too
                username: user.username
            });

        } catch (err) {
            console.error(`Login error for user ${username}:`, err);
            // Handle generic server errors
            res.status(500).json({ error: 'Internal server error during login.' });
        }
    });

    // --- Return the configured router ---
    return router;
};