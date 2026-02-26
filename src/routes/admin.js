const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const path = require('path');

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, config.jwtSecret || process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Authorization middleware
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Secure dashboard endpoint with proper authentication
router.get('/dashboard', authenticateToken, authorizeRole(['admin']), (req, res) => {
  res.json({
    totalTransactions: 15234,
    revenue: 1250000,
    activeUsers: 892
  });
});

// Secure logs endpoint with input validation
router.post('/logs', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const { filename } = req.body;
  
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  const sanitizedFilename = path.basename(filename);
  const allowedFiles = ['app.log', 'error.log', 'access.log'];
  
  if (!allowedFiles.includes(sanitizedFilename)) {
    return res.status(400).json({ error: 'File not allowed' });
  }

  const logPath = path.join('/var/log', sanitizedFilename);
  
  exec('cat', [logPath], (error, stdout) => {
    if (error) return res.status(500).json({ error: 'Unable to read log file' });
    res.json({ logs: stdout });
  });
});

// Secure import endpoint with JSON parsing
router.post('/import', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const data = req.body.data;
  
  if (!data) {
    return res.status(400).json({ error: 'No data provided' });
  }

  try {
    const parsed = JSON.parse(data);
    res.json({ imported: parsed });
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON format' });
  }
});

// Secure user update endpoint with field whitelisting
router.put('/users/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
  const userId = req.params.id;
  const updates = req.body;
  
  if (!userId || isNaN(parseInt(userId))) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const allowedFields = ['email', 'firstName', 'lastName', 'phone'];
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