const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const config = require('../config');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

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

// FIXED: Using parameterized queries to prevent SQL injection
router.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  const connection = await mysql.createConnection(config.database);
  
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  
  await connection.execute(
    'UPDATE users SET password = ? WHERE email = ?',
    [hashedPassword, email]
  );
  
  res.json({ success: true });
});

module.exports = router;