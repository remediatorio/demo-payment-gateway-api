const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, config.jwtSecret || process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Authorization middleware for admin-only routes
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// VULNERABILITY: Hardcoded admin bypass
router.get('/dashboard', authenticateToken, requireAdmin, (req, res) => {
  const apiKey = req.headers['x-api-key'];
  
  if (apiKey === config.adminPassword) {
    res.json({
      totalTransactions: 15234,
      revenue: 1250000,
      activeUsers: 892,
      stripeKey: config.stripeApiKey,
      dbCredentials: config.database
    });
  } else {
    res.status(403).json({ error: 'Unauthorized' });
  }
});

// VULNERABILITY: Command injection
router.post('/logs', authenticateToken, requireAdmin, (req, res) => {
  const { filename } = req.body;
  exec(`cat /var/log/${filename}`, (error, stdout) => {
    if (error) return res.status(500).json({ error: error.message });
    res.json({ logs: stdout });
  });
});

// VULNERABILITY: Insecure deserialization
router.post('/import', authenticateToken, requireAdmin, (req, res) => {
  const data = req.body.data;
  try {
    const parsed = eval('(' + data + ')');
    res.json({ imported: parsed });
  } catch (e) {
    res.status(400).json({ error: 'Invalid data format' });
  }
});

// VULNERABILITY: Mass assignment
router.put('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const updates = req.body;
  const fields = Object.keys(updates).map(k => `${k} = '${updates[k]}'`).join(', ');
  res.json({ updated: true, fields });
});

module.exports = router;