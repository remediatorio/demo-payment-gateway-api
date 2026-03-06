const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const config = require('../config');
const mysql = require('mysql2/promise');
const crypto = require('crypto');

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

// FIXED: Secure password reset flow - Step 1: Request reset token
router.post('/request-password-reset', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    const [users] = await connection.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    
    // Always return success to prevent email enumeration
    if (users.length === 0) {
      return res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
    }
    
    // Generate cryptographically secure token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour expiration
    
    // Store token hash with expiration
    await connection.execute(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?',
      [tokenHash, expiresAt, email]
    );
    
    // In production, send email with reset link containing the token
    // For now, we'll just return success (token would be sent via email)
    // Example: sendEmail(email, `Reset link: ${config.appUrl}/reset-password?token=${resetToken}`);
    
    res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
  } finally {
    await connection.end();
  }
});

// FIXED: Secure password reset flow - Step 2: Reset password with token
router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }
  
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  
  const connection = await mysql.createConnection(config.database);
  
  try {
    // Hash the provided token to compare with stored hash
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    
    // Find user with valid token
    const [users] = await connection.execute(
      'SELECT id FROM users WHERE reset_token = ? AND reset_token_expires > NOW()',
      [tokenHash]
    );
    
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    // Update password and clear reset token
    await connection.execute(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
      [newPassword, users[0].id]
    );
    
    res.json({ success: true, message: 'Password has been reset successfully' });
  } finally {
    await connection.end();
  }
});

module.exports = router;