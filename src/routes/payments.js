const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const config = require('../config');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

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

// Rate limiting for payment processing
const paymentRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: 'Too many payment requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

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

// Merchant validation middleware
const validateMerchantAccess = async (req, res, next) => {
  const { merchantId } = req.body;
  
  if (!merchantId) {
    return res.status(400).json({ error: 'Merchant ID is required' });
  }

  // Verify that the authenticated user has access to this merchant account
  if (req.user.merchantId && req.user.merchantId !== merchantId) {
    return res.status(403).json({ error: 'Access denied: Merchant ID mismatch' });
  }

  next();
};

// FIXED: Authentication, authorization, rate limiting, and audit logging added
router.post('/process', authenticateToken, authorizeRole(['merchant', 'admin']), paymentRateLimiter, validateMerchantAccess, async (req, res) => {
  const { cardNumber, amount, currency, merchantId } = req.body;
  
  if (!cardNumber || !amount || !currency || !merchantId) {
    return res.status(400).json({ error: 'All payment fields are required' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // Audit log the payment processing attempt
    await auditLog(connection, 'PAYMENT_PROCESS_ATTEMPT', req.user.id, {
      merchantId,
      amount,
      currency,
      userRole: req.user.role,
      ipAddress: req.ip
    });

    // FIXED: Using parameterized query to prevent SQL injection
    // FIXED: Storing only last 4 digits of card number (PCI compliance)
    const lastFourDigits = cardNumber.slice(-4);
    const [result] = await connection.execute(
      'INSERT INTO transactions (card_number_last4, amount, currency, merchant_id, status) VALUES (?, ?, ?, ?, ?)',
      [lastFourDigits, amount, currency, merchantId, 'pending']
    );
    
    // Audit log successful payment processing
    await auditLog(connection, 'PAYMENT_PROCESSED', req.user.id, {
      transactionId: result.insertId,
      merchantId,
      amount,
      currency,
      userRole: req.user.role
    });

    // FIXED: Returning only last 4 digits of card number in response
    res.json({
      transactionId: result.insertId,
      cardNumberLast4: lastFourDigits,
      amount: amount,
      status: 'pending'
    });
  } catch (error) {
    console.error('Payment processing error:', error);
    
    // Audit log failed payment processing
    await auditLog(connection, 'PAYMENT_PROCESS_FAILED', req.user.id, {
      merchantId,
      amount,
      currency,
      error: error.message
    });
    
    res.status(500).json({ error: 'Failed to process payment' });
  } finally {
    await connection.end();
  }
});

// FIXED: Authentication, authorization, and parameterized queries added
router.get('/search', authenticateToken, authorizeRole(['merchant', 'admin', 'finance']), async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  
  if (!merchantId || !startDate || !endDate) {
    return res.status(400).json({ error: 'Merchant ID, start date, and end date are required' });
  }

  // Verify merchant access for non-admin users
  if (req.user.role !== 'admin' && req.user.merchantId && req.user.merchantId !== merchantId) {
    return res.status(403).json({ error: 'Access denied: Cannot search transactions for other merchants' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // FIXED: Using parameterized query to prevent SQL injection
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