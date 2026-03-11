const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

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

// FIXED: Path traversal and command injection vulnerabilities
router.post('/logs', (req, res) => {
  const { filename } = req.body;
  
  // Validate filename is provided
  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Strip any directory components to prevent path traversal
  const sanitizedFilename = path.basename(filename);
  
  // Validate filename contains only allowed characters (alphanumeric, dash, underscore, dot)
  if (!/^[a-zA-Z0-9._-]+$/.test(sanitizedFilename)) {
    return res.status(400).json({ error: 'Invalid filename format' });
  }
  
  // Whitelist allowed log file extensions
  const allowedExtensions = ['.log', '.txt'];
  const fileExtension = path.extname(sanitizedFilename);
  if (!allowedExtensions.includes(fileExtension)) {
    return res.status(400).json({ error: 'Invalid file type' });
  }
  
  // Construct the full path
  const logDir = '/var/log/';
  const fullPath = path.join(logDir, sanitizedFilename);
  
  // Verify the resolved path is still within the log directory
  const resolvedPath = path.resolve(fullPath);
  const resolvedLogDir = path.resolve(logDir);
  if (!resolvedPath.startsWith(resolvedLogDir)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Use fs.readFile instead of exec to avoid command injection
  fs.readFile(resolvedPath, 'utf8', (error, data) => {
    if (error) {
      if (error.code === 'ENOENT') {
        return res.status(404).json({ error: 'Log file not found' });
      }
      return res.status(500).json({ error: 'Error reading log file' });
    }
    res.json({ logs: data });
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

// VULNERABILITY: Mass assignment
router.put('/users/:id', async (req, res) => {
  const updates = req.body;
  const fields = Object.keys(updates).map(k => `${k} = '${updates[k]}'`).join(', ');
  res.json({ updated: true, fields });
});

module.exports = router;