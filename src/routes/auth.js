const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const config = require('../config');
const mysql = require('mysql2/promise');
const rateLimit = require('express-rate-limit');

// Rate limiter for password reset endpoint
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 requests per hour
  message: { error: 'Too many password reset requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Rate limit by email address if provided, otherwise by IP
    return req.body.email || req.ip;
  },
  skipSuccessfulRequests: false,
  skipFailedRequests: false
});

// VULNERABILITY: SQL Injection in login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const connection = await mysql.createConnection(config.database);
  
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  const [users] = await connection.execute(query);
  
  if (users.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // VULNERABILITY: Weak JWT with no expiration
  const token = jwt.sign(
    { userId: users[0].id, role: users[0].role, isAdmin: users[0].role === 'admin' },
    config.jwtSecret
  );
  
  res.json({ token, user: users[0] });
});

// VULNERABILITY: Password stored in plain text
router.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  const connection = await mysql.createConnection(config.database);
  
  await connection.execute(
    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
    [username, password, email]
  );
  
  res.json({ success: true });
});

// Fixed: Rate limiting applied to password reset
router.post('/reset-password', passwordResetLimiter, async (req, res) => {
  const { email, newPassword } = req.body;
  
  if (!email) {
    return res.json({ success: true, message: 'If the email exists, a password reset link has been sent.' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    await connection.execute(
      "UPDATE users SET password = '" + newPassword + "' WHERE email = '" + email + "'"
    );
    
    // Return identical response regardless of whether email exists
    res.json({ success: true, message: 'If the email exists, a password reset link has been sent.' });
  } catch (error) {
    // Return identical response even on error to prevent enumeration
    res.json({ success: true, message: 'If the email exists, a password reset link has been sent.' });
  } finally {
    await connection.end();
  }
});

module.exports = router;