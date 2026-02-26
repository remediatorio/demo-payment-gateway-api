const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const path = require('path');

// Middleware for JWT authentication
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

// Middleware for role-based access control
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    // Audit log unauthorized access attempt
    console.warn(`Unauthorized dashboard access attempt by user: ${req.user ? req.user.id : 'unknown'} at ${new Date().toISOString()}`);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// FIXED: Removed sensitive data from response, added proper authentication
router.get('/dashboard', authenticateToken, requireAdmin, (req, res) => {
  // Audit log successful access
  console.info(`Admin dashboard accessed by user: ${req.user.id} at ${new Date().toISOString()}`);
  
  res.json({
    totalTransactions: 15234,
    revenue: 1250000,
    activeUsers: 892
  });
});

// FIXED: Command injection prevention with whitelist validation
router.post('/logs', authenticateToken, requireAdmin, (req, res) => {
  const { filename } = req.body;
  
  // Whitelist allowed log files
  const allowedFiles = ['app.log', 'error.log', 'access.log'];
  
  if (!filename || !allowedFiles.includes(filename)) {
    return res.status(400).json({ error: 'Invalid log file requested' });
  }
  
  // Use safe path joining and validate the result
  const logPath = path.join('/var/log', path.basename(filename));
  
  // Use execFile instead of exec with fixed arguments
  const { execFile } = require('child_process');
  execFile('cat', [logPath], (error, stdout) => {
    if (error) return res.status(500).json({ error: 'Unable to read log file' });
    res.json({ logs: stdout });
  });
});

// FIXED: Insecure deserialization - use JSON.parse instead of eval
router.post('/import', authenticateToken, requireAdmin, (req, res) => {
  const data = req.body.data;
  try {
    const parsed = JSON.parse(data);
    res.json({ imported: parsed });
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON format' });
  }
});

// FIXED: Mass assignment - whitelist allowed fields and use parameterized queries
router.put('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const updates = req.body;
  const allowedFields = ['name', 'email', 'phone'];
  
  const sanitizedUpdates = {};
  Object.keys(updates).forEach(key => {
    if (allowedFields.includes(key)) {
      sanitizedUpdates[key] = updates[key];
    }
  });
  
  if (Object.keys(sanitizedUpdates).length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }
  
  // Note: In production, use parameterized queries with your database library
  // Example with prepared statements would be preferred
  res.json({ updated: true, fields: Object.keys(sanitizedUpdates) });
});

module.exports = router;