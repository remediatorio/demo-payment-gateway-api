const express = require('express');
const router = express.Router();
const config = require('../config');
const { exec } = require('child_process');

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

// FIXED: Use JSON.parse() instead of eval()
router.post('/import', (req, res) => {
  const data = req.body.data;
  try {
    const parsed = JSON.parse(data);
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