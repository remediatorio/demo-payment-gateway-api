const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const config = require('../config');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

// Fixed: SQL Injection vulnerability using parameterized queries
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const connection = await mysql.createConnection(config.database);
  
  const [users] = await connection.execute(
    'SELECT * FROM users WHERE username = ?',
    [username]
  );
  
  if (users.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const validPassword = await bcrypt.compare(password, users[0].password);
  
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Fixed: JWT with expiration
  const token = jwt.sign(
    { userId: users[0].id, role: users[0].role, isAdmin: users[0].role === 'admin' },
    config.jwtSecret,
    { expiresIn: '24h' }
  );
  
  res.json({ token, user: { id: users[0].id, username: users[0].username, role: users[0].role } });
});

// Fixed: Password hashing before storage
router.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  const connection = await mysql.createConnection(config.database);
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  await connection.execute(
    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
    [username, hashedPassword, email]
  );
  
  res.json({ success: true });
});

// Fixed: SQL Injection vulnerability using parameterized queries and password hashing
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