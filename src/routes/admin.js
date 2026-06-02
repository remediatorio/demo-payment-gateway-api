const express = require('express');
const router = express.Router();
const config = require('../config');
const fs = require('fs').promises;
const path = require('path');

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

// FIXED: Command injection vulnerability
router.post('/logs', async (req, res) => {
  const { filename } = req.body;
  
  // Validate filename is provided
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename parameter' });
  }
  
  // Whitelist allowed characters (alphanumeric, dash, underscore, dot)
  const filenameRegex = /^[a-zA-Z0-9_\-\.]+$/;
  if (!filenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format' });
  }
  
  // Reject path traversal attempts
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Path traversal not allowed' });
  }
  
  // Construct safe path using path.join to prevent traversal
  const logDirectory = '/var/log';
  const safePath = path.join(logDirectory, filename);
  
  // Verify the resolved path is still within the log directory
  const resolvedPath = path.resolve(safePath);
  const resolvedLogDir = path.resolve(logDirectory);
  if (!resolvedPath.startsWith(resolvedLogDir + path.sep) && resolvedPath !== resolvedLogDir) {
    return res.status(400).json({ error: 'Access denied' });
  }
  
  try {
    // Use fs.readFile instead of exec
    const logs = await fs.readFile(safePath, 'utf8');
    res.json({ logs });
  } catch (error) {
    if (error.code === 'ENOENT') {
      return res.status(404).json({ error: 'Log file not found' });
    }
    if (error.code === 'EACCES') {
      return res.status(403).json({ error: 'Permission denied' });
    }
    return res.status(500).json({ error: 'Failed to read log file' });
  }
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

// VULNERABILITY: Mass assignment
router.put('/users/:id', async (req, res) => {
  const updates = req.body;
  const fields = Object.keys(updates).map(k => `${k} = '${updates[k]}'`).join(', ');
  res.json({ updated: true, fields });
});

module.exports = router;