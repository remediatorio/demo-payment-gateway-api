const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const path = require('path');

// Middleware to authenticate JWT tokens
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, config.jwtSecret, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Middleware to authorize admin role
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Middleware to log admin actions
const logAdminAction = (action) => {
  return (req, res, next) => {
    const logEntry = {
      timestamp: new Date().toISOString(),
      userId: req.user.id,
      username: req.user.username,
      action: action,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    };
    console.log('[ADMIN_AUDIT]', JSON.stringify(logEntry));
    next();
  };
};

// Admin dashboard - secured with authentication and authorization
router.get('/dashboard', authenticateToken, authorizeRole(['admin']), logAdminAction('VIEW_DASHBOARD'), (req, res) => {
  res.json({
    totalTransactions: 15234,
    revenue: 1250000,
    activeUsers: 892
  });
});

// Logs endpoint - secured and sanitized
router.post('/logs', authenticateToken, authorizeRole(['admin']), logAdminAction('VIEW_LOGS'), (req, res) => {
  const { filename } = req.body;
  
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  // Whitelist allowed log files
  const allowedFiles = ['application.log', 'error.log', 'access.log', 'audit.log'];
  
  if (!allowedFiles.includes(filename)) {
    return res.status(400).json({ error: 'Access to this log file is not permitted' });
  }

  // Sanitize filename to prevent path traversal
  const sanitizedFilename = path.basename(filename);
  const logPath = path.join('/var/log', sanitizedFilename);

  // Use safer file reading method instead of exec
  const fs = require('fs');
  fs.readFile(logPath, 'utf8', (error, data) => {
    if (error) {
      return res.status(500).json({ error: 'Unable to read log file' });
    }
    res.json({ logs: data });
  });
});

// Import endpoint - secured and using safe JSON parsing
router.post('/import', authenticateToken, authorizeRole(['admin']), logAdminAction('IMPORT_DATA'), (req, res) => {
  const data = req.body.data;
  
  if (!data || typeof data !== 'string') {
    return res.status(400).json({ error: 'Invalid data format' });
  }

  try {
    // Use JSON.parse instead of eval
    const parsed = JSON.parse(data);
    
    // Validate parsed data structure
    if (typeof parsed !== 'object' || parsed === null) {
      return res.status(400).json({ error: 'Data must be a valid JSON object' });
    }
    
    res.json({ imported: parsed });
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON format' });
  }
});

// User update endpoint - secured with parameterized queries
router.put('/users/:id', authenticateToken, authorizeRole(['admin']), logAdminAction('UPDATE_USER'), async (req, res) => {
  const userId = req.params.id;
  const updates = req.body;

  // Validate user ID
  if (!userId || !/^\d+$/.test(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  // Whitelist allowed fields to prevent mass assignment
  const allowedFields = ['email', 'firstName', 'lastName', 'phone', 'status'];
  const sanitizedUpdates = {};

  for (const key of Object.keys(updates)) {
    if (allowedFields.includes(key)) {
      // Validate and sanitize each field
      if (typeof updates[key] === 'string' && updates[key].length <= 255) {
        sanitizedUpdates[key] = updates[key];
      }
    }
  }

  if (Object.keys(sanitizedUpdates).length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  // In production, use parameterized queries with your database library
  // Example with a hypothetical database module:
  // const db = require('../database');
  // await db.query('UPDATE users SET ? WHERE id = ?', [sanitizedUpdates, userId]);

  res.json({ 
    updated: true, 
    userId: userId,
    fields: Object.keys(sanitizedUpdates)
  });
});

module.exports = router;