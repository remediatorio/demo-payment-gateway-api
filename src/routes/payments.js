const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const config = require('../config');
const jwt = require('jsonwebtoken');

// Authentication middleware
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

// Authorization middleware for role-based access control
const authorizeRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ error: 'Access denied: No role assigned' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied: Insufficient permissions' });
    }

    next();
  };
};

// Audit logging function
const auditLog = async (connection, action, userId, details) => {
  try {
    await connection.execute(
      'INSERT INTO audit_logs (action, user_id, details, timestamp) VALUES (?, ?, ?, NOW())',
      [action, userId, JSON.stringify(details)]
    );
  } catch (error) {
    console.error('Audit logging failed:', error);
  }
};

// Helper function to mask card number
const maskCardNumber = (cardNumber) => {
  if (!cardNumber || cardNumber.length < 4) {
    return '****';
  }
  return '****' + cardNumber.slice(-4);
};

// VULNERABILITY: SQL Injection - card number passed directly into query
router.post('/process', async (req, res) => {
  const { cardNumber, amount, currency, merchantId } = req.body;
  
  const connection = await mysql.createConnection(config.database);
  
  // VULNERABILITY: Storing full card number (PCI violation)
  const query = `INSERT INTO transactions (card_number, amount, currency, merchant_id, status) 
                 VALUES ('${cardNumber}', ${amount}, '${currency}', '${merchantId}', 'pending')`;
  
  try {
    const [result] = await connection.execute(query);
    
    // FIXED: Return only masked card number (last 4 digits)
    res.json({
      transactionId: result.insertId,
      cardNumber: maskCardNumber(cardNumber),
      amount: amount,
      status: 'pending'
    });
  } catch (error) {
    res.status(500).json({ error: error.message, query: query });
  }
});

// VULNERABILITY: SQL Injection in search
router.get('/search', async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  const connection = await mysql.createConnection(config.database);
  
  const query = "SELECT * FROM transactions WHERE merchant_id = '" + merchantId + 
                "' AND created_at BETWEEN '" + startDate + "' AND '" + endDate + "'";
  
  const [rows] = await connection.execute(query);
  res.json({ transactions: rows });
});

// FIXED: Authentication and authorization required for refund endpoint
router.post('/refund', authenticateToken, authorizeRole(['admin', 'finance']), async (req, res) => {
  const { transactionId, amount } = req.body;
  
  if (!transactionId || !amount) {
    return res.status(400).json({ error: 'Transaction ID and amount are required' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // Verify transaction exists and get current status
    const [transactions] = await connection.execute(
      'SELECT id, status, amount FROM transactions WHERE id = ?',
      [transactionId]
    );

    if (transactions.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    const transaction = transactions[0];

    if (transaction.status === 'refunded') {
      return res.status(400).json({ error: 'Transaction already refunded' });
    }

    if (amount > transaction.amount) {
      return res.status(400).json({ error: 'Refund amount exceeds transaction amount' });
    }

    // Process refund with parameterized query
    await connection.execute(
      'UPDATE transactions SET status = ?, refund_amount = ? WHERE id = ?',
      ['refunded', amount, transactionId]
    );

    // Audit log the refund operation
    await auditLog(connection, 'REFUND', req.user.id, {
      transactionId,
      refundAmount: amount,
      originalAmount: transaction.amount,
      userRole: req.user.role
    });

    res.json({ 
      success: true, 
      transactionId, 
      refundAmount: amount 
    });
  } catch (error) {
    console.error('Refund processing error:', error);
    res.status(500).json({ error: 'Failed to process refund' });
  } finally {
    await connection.end();
  }
});

module.exports = router;