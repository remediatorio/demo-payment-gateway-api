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

// FIXED: SQL Injection vulnerability - using whitelisted fields and parameterized query structure
router.put('/users/:id', async (req, res) => {
  const updates = req.body;
  const userId = req.params.id;
  
  // Whitelist of allowed fields
  const allowedFields = ['email', 'phone', 'name', 'address'];
  
  const setClauses = [];
  const values = [];
  
  allowedFields.forEach(field => {
    if (updates[field] !== undefined) {
      setClauses.push(`${field} = ?`);
      values.push(updates[field]);
    }
  });
  
  if (setClauses.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }
  
  // Add userId to values array for WHERE clause
  values.push(userId);
  
  const query = `UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`;
  
  // Note: In production, this would execute against actual database connection
  // Example: await connection.execute(query, values);
  
  res.json({ 
    updated: true, 
    fields: setClauses.join(', '),
    query: query,
    parameterCount: values.length
  });
});

module.exports = router;