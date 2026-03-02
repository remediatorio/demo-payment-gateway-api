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

// FIXED: Authentication, authorization, and audit logging for transaction search
router.get('/search', authenticateToken, authorizeRole(['merchant', 'admin']), async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  
  if (!merchantId || !startDate || !endDate) {
    return res.status(400).json({ error: 'merchantId, startDate, and endDate are required' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // Merchant-specific access control: merchants can only search their own transactions
    let query;
    let params;
    
    if (req.user.role === 'merchant') {
      // Ensure merchant can only access their own data
      if (req.user.merchantId && req.user.merchantId.toString() !== merchantId.toString()) {
        await auditLog(connection, 'SEARCH_UNAUTHORIZED_ATTEMPT', req.user.id, {
          requestedMerchantId: merchantId,
          userMerchantId: req.user.merchantId,
          startDate,
          endDate
        });
        return res.status(403).json({ error: 'Access denied: Cannot access other merchant data' });
      }
      
      query = 'SELECT * FROM transactions WHERE merchant_id = ? AND created_at BETWEEN ? AND ?';
      params = [merchantId, startDate, endDate];
    } else if (req.user.role === 'admin') {
      // Admins can search any merchant's transactions
      query = 'SELECT * FROM transactions WHERE merchant_id = ? AND created_at BETWEEN ? AND ?';
      params = [merchantId, startDate, endDate];
    }
    
    const [rows] = await connection.execute(query, params);
    
    // Audit log the search operation
    await auditLog(connection, 'TRANSACTION_SEARCH', req.user.id, {
      merchantId,
      startDate,
      endDate,
      resultCount: rows.length,
      userRole: req.user.role
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