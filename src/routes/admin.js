const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    const jwt = require('jsonwebtoken');
    const user = jwt.verify(token, config.jwtSecret);
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Authorization middleware for admin
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Audit logging function
const auditLog = (action, userId, targetUserId, changes, req) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    action,
    performedBy: userId,
    targetUser: targetUserId,
    changes,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent']
  };
  console.log('AUDIT:', JSON.stringify(logEntry));
};

// VULNERABILITY: Hardcoded admin bypass
router.get('/dashboard', (req, res) => {
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
router.post('/logs', (req, res) => {
  const { filename } = req.body;
  exec(`cat /var/log/${filename}`, (error, stdout) => {
    if (error) return res.status(500).json({ error: error.message });
    res.json({ logs: stdout });
  });
});

// VULNERABILITY: Insecure deserialization
router.post('/import', (req, res) => {
  const data = req.body.data;
  try {
    const parsed = eval('(' + data + ')');
    res.json({ imported: parsed });
  } catch (e) {
    res.status(400).json({ error: 'Invalid data format' });
  }
});

// FIXED: User update with authentication and authorization
router.put('/users/:id', authenticateToken, async (req, res) => {
  const targetUserId = req.params.id;
  const updates = req.body;
  
  // Check authorization: user can only update their own account or must be admin
  const isOwnAccount = req.user.id === targetUserId;
  const isAdmin = req.user.role === 'admin';
  
  if (!isOwnAccount && !isAdmin) {
    auditLog('UNAUTHORIZED_UPDATE_ATTEMPT', req.user.id, targetUserId, updates, req);
    return res.status(403).json({ error: 'Unauthorized: You can only update your own account' });
  }
  
  // Field-level access control: define allowed fields
  const allowedFieldsUser = ['email', 'name', 'phone', 'address'];
  const allowedFieldsAdmin = ['email', 'name', 'phone', 'address', 'role', 'status', 'permissions'];
  const sensitiveFields = ['role', 'permissions', 'status'];
  
  const allowedFields = isAdmin ? allowedFieldsAdmin : allowedFieldsUser;
  
  // Filter updates to only allowed fields
  const filteredUpdates = {};
  const rejectedFields = [];
  
  for (const key of Object.keys(updates)) {
    if (allowedFields.includes(key)) {
      filteredUpdates[key] = updates[key];
    } else {
      rejectedFields.push(key);
    }
  }
  
  if (Object.keys(filteredUpdates).length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }
  
  // Check if sensitive fields are being modified (require additional verification)
  const modifyingSensitiveFields = Object.keys(filteredUpdates).some(field => 
    sensitiveFields.includes(field)
  );
  
  if (modifyingSensitiveFields && !isAdmin) {
    auditLog('UNAUTHORIZED_SENSITIVE_UPDATE', req.user.id, targetUserId, filteredUpdates, req);
    return res.status(403).json({ error: 'Admin privileges required for this modification' });
  }
  
  // Sanitize values to prevent SQL injection
  const sanitizedUpdates = {};
  for (const [key, value] of Object.entries(filteredUpdates)) {
    if (typeof value === 'string') {
      sanitizedUpdates[key] = value.replace(/'/g, "''");
    } else {
      sanitizedUpdates[key] = value;
    }
  }
  
  const fields = Object.keys(sanitizedUpdates).map(k => `${k} = '${sanitizedUpdates[k]}'`).join(', ');
  
  // Audit log the successful update
  auditLog('USER_UPDATE', req.user.id, targetUserId, sanitizedUpdates, req);
  
  res.json({ 
    updated: true, 
    fields,
    rejectedFields: rejectedFields.length > 0 ? rejectedFields : undefined
  });
});

module.exports = router;