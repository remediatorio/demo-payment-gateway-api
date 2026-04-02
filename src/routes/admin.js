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

// FIXED: Command injection vulnerability resolved
router.post('/logs', async (req, res) => {
  const { filename } = req.body;
  
  // Validate filename is provided
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Whitelist allowed characters (alphanumeric, dash, underscore, dot)
  const filenameRegex = /^[a-zA-Z0-9_\-\.]+$/;
  if (!filenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename format' });
  }
  
  // Use path.basename to prevent directory traversal
  const sanitizedFilename = path.basename(filename);
  
  // Resolve to absolute path and ensure it's within the logs directory
  const logDir = '/var/log';
  const filePath = path.resolve(logDir, sanitizedFilename);
  
  // Verify the resolved path is still within the log directory
  if (!filePath.startsWith(path.resolve(logDir) + path.sep)) {
    return res.status(400).json({ error: 'Invalid file path' });
  }
  
  try {
    // Use fs.readFile instead of exec
    const logs = await fs.readFile(filePath, 'utf8');
    res.json({ logs });
  } catch (error) {
    if (error.code === 'ENOENT') {
      return res.status(404).json({ error: 'Log file not found' });
    }
    return res.status(500).json({ error: 'Error reading log file' });
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