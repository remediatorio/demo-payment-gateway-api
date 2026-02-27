const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

// Middleware for JWT authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const jwt = require('jsonwebtoken');
  jwt.verify(token, config.jwtSecret || process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Middleware for role-based authorization
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ error: 'Access denied: No role assigned' });
    }
    
    if (!roles.includes(req.user.role)) {
      auditLog(req.user.id, 'UNAUTHORIZED_ACCESS_ATTEMPT', req.path);
      return res.status(403).json({ error: 'Access denied: Insufficient permissions' });
    }
    
    next();
  };
};

// Audit logging function
const auditLog = (userId, action, details) => {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] User: ${userId} | Action: ${action} | Details: ${details}\n`;
  
  fs.appendFile(path.join(__dirname, '../logs/audit.log'), logEntry, (err) => {
    if (err) console.error('Audit log error:', err);
  });
};

// Admin dashboard with proper authentication
router.get('/dashboard', authenticateToken, authorizeRole(['admin']), (req, res) => {
  auditLog(req.user.id, 'DASHBOARD_ACCESS', 'Admin dashboard accessed');
  
  res.json({
    totalTransactions: 15234,
    revenue: 1250000,
    activeUsers: 892
  });
});

// Secure log viewing with input validation
router.post('/logs', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const { filename } = req.body;
  
  auditLog(req.user.id, 'LOG_ACCESS', `Requested log: ${filename}`);
  
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  const allowedLogs = ['application.log', 'error.log', 'access.log', 'audit.log'];
  if (!allowedLogs.includes(filename)) {
    return res.status(400).json({ error: 'Log file not allowed' });
  }
  
  const sanitizedFilename = path.basename(filename);
  const logPath = path.join('/var/log', sanitizedFilename);
  
  fs.readFile(logPath, 'utf8', (error, data) => {
    if (error) {
      return res.status(500).json({ error: 'Unable to read log file' });
    }
    res.json({ logs: data });
  });
});

// Secure data import with JSON parsing
router.post('/import', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const data = req.body.data;
  
  auditLog(req.user.id, 'DATA_IMPORT', 'Import operation initiated');
  
  try {
    const parsed = JSON.parse(data);
    
    if (typeof parsed !== 'object' || parsed === null) {
      return res.status(400).json({ error: 'Invalid data format' });
    }
    
    res.json({ imported: parsed });
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON format' });
  }
});

// Secure user update with field whitelisting
router.put('/users/:id', authenticateToken, authorizeRole(['admin']), async (req, res) => {
  const userId = req.params.id;
  const updates = req.body;
  
  auditLog(req.user.id, 'USER_UPDATE', `Updated user: ${userId}`);
  
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