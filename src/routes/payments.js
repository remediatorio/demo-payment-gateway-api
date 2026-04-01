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

// Authorization middleware to verify merchant access
const authorizeMerchantAccess = async (req, res, next) => {
  const merchantId = req.query.merchantId || req.body.merchantId;
  
  if (!merchantId) {
    return res.status(400).json({ error: 'Merchant ID is required' });
  }

  if (!req.user || !req.user.id) {
    return res.status(403).json({ error: 'Access denied: User not authenticated' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // Check if user has access to this merchant
    // Admins have access to all merchants
    if (req.user.role === 'admin') {
      await connection.end();
      return next();
    }

    // Check if user is associated with the merchant
    const [rows] = await connection.execute(
      'SELECT id FROM user_merchant_access WHERE user_id = ? AND merchant_id = ?',
      [req.user.id, merchantId]
    );

    if (rows.length === 0) {
      await connection.end();
      return res.status(403).json({ error: 'Access denied: You do not have permission to access this merchant\'s data' });
    }

    await connection.end();
    next();
  } catch (error) {
    await connection.end();
    console.error('Authorization check failed:', error);
    return res.status(500).json({ error: 'Authorization check failed' });
  }
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

// VULNERABILITY: SQL Injection - card number passed directly into query
router.post('/process', async (req, res) => {
  const { cardNumber, amount, currency, merchantId } = req.body;
  
  const connection = await mysql.createConnection(config.database);
  
  // VULNERABILITY: Storing full card number (PCI violation)
  const query = `INSERT INTO transactions (card_number, amount, currency, merchant_id, status) 
                 VALUES ('${cardNumber}', ${amount}, '${currency}', '${merchantId}', 'pending')`;
  
  try {
    const [result] = await connection.execute(query);
    
    // VULNERABILITY: Returning full card number in response
    res.json({
      transactionId: result.insertId,
      cardNumber: cardNumber,
      amount: amount,
      status: 'pending'
    });
  } catch (error) {
    res.status(500).json({ error: error.message, query: query });
  }
});

// FIXED: Authentication and authorization required for search endpoint
router.get('/search', authenticateToken, authorizeMerchantAccess, async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  
  if (!merchantId || !startDate || !endDate) {
    return res.status(400).json({ error: 'merchantId, startDate, and endDate are required' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // Use parameterized query to prevent SQL injection
    const [rows] = await connection.execute(
      'SELECT * FROM transactions WHERE merchant_id = ? AND created_at BETWEEN ? AND ?',
      [merchantId, startDate, endDate]
    );
    
    // Audit log the search operation
    await auditLog(connection, 'TRANSACTION_SEARCH', req.user.id, {
      merchantId,
      startDate,
      endDate,
      resultCount: rows.length
    });
    
    res.json({ transactions: rows });
  } catch (error) {
    console.error('Transaction search error:', error);
    res.status(500).json({ error: 'Failed to search transactions' });
  } finally {
    await connection.end();
  }
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