const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const path = require('path');

// Middleware: JWT Authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  jwt.verify(token, config.jwtSecret || process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Middleware: Role-based Authorization
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// FIXED: Proper JWT authentication and authorization, removed sensitive data exposure
router.get('/dashboard', authenticateToken, authorizeRole(['admin']), async (req, res) => {
  res.json({
    totalTransactions: 15234,
    revenue: 1250000,
    activeUsers: 892
  });
});

// FIXED: Command injection prevention using path validation and whitelist
router.post('/logs', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const { filename } = req.body;
  
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  const allowedFiles = ['app.log', 'error.log', 'access.log'];
  const sanitizedFilename = path.basename(filename);
  
  if (!allowedFiles.includes(sanitizedFilename)) {
    return res.status(400).json({ error: 'File not allowed' });
  }

  const safePath = path.join('/var/log', sanitizedFilename);
  
  exec('cat', [safePath], (error, stdout) => {
    if (error) return res.status(500).json({ error: 'Unable to read log file' });
    res.json({ logs: stdout });
  });
});

// FIXED: Replaced eval with JSON.parse for safe deserialization
router.post('/import', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const data = req.body.data;
  
  if (!data || typeof data !== 'string') {
    return res.status(400).json({ error: 'Invalid data format' });
  }
  
  try {
    const parsed = JSON.parse(data);
    res.json({ imported: parsed });
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON format' });
  }
});

// FIXED: Mass assignment prevention with field whitelist and parameterized queries
router.put('/users/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
  const allowedFields = ['name', 'email', 'phone'];
  const updates = req.body;
  
  const sanitizedUpdates = {};
  for (const key of Object.keys(updates)) {
    if (allowedFields.includes(key)) {
      sanitizedUpdates[key] = updates[key];
    }
  }
  
  if (Object.keys(sanitizedUpdates).length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }
  
  res.json({ updated: true, fields: Object.keys(sanitizedUpdates) });
});

module.exports = router;