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

// Rate limiting middleware
const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false
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

// Helper function to mask card number
const maskCardNumber = (cardNumber) => {
  if (!cardNumber || cardNumber.length < 4) {
    return '****';
  }
  return '****' + cardNumber.slice(-4);
};

// FIXED: Authentication, authorization, and secure payment processing
router.post('/process', authenticateToken, authorizeRole(['merchant', 'admin']), paymentLimiter, async (req, res) => {
  const { cardNumber, amount, currency, merchantId } = req.body;
  
  // Validate merchant ownership
  if (req.user.role === 'merchant' && req.user.merchantId !== merchantId) {
    return res.status(403).json({ error: 'Access denied: Cannot process payments for other merchants' });
  }

  // Input validation
  if (!cardNumber || !amount || !currency || !merchantId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // Hash or tokenize card number (PCI DSS compliance)
    const lastFourDigits = cardNumber.slice(-4);
    const cardToken = require('crypto').createHash('sha256').update(cardNumber).digest('hex');
    
    // FIXED: Use parameterized query to prevent SQL injection
    const query = 'INSERT INTO transactions (card_token, last_four, amount, currency, merchant_id, status) VALUES (?, ?, ?, ?, ?, ?)';
    const [result] = await connection.execute(query, [cardToken, lastFourDigits, amount, currency, merchantId, 'pending']);
    
    // Audit log the payment operation
    await auditLog(connection, 'PAYMENT_PROCESS', req.user.id, {
      transactionId: result.insertId,
      amount,
      currency,
      merchantId,
      userRole: req.user.role
    });
    
    // FIXED: Return masked card number only
    res.json({
      transactionId: result.insertId,
      cardNumber: maskCardNumber(cardNumber),
      amount: amount,
      currency: currency,
      status: 'pending'
    });
  } catch (error) {
    console.error('Payment processing error:', error);
    res.status(500).json({ error: 'Failed to process payment' });
  } finally {
    await connection.end();
  }
});

// FIXED: Authentication, authorization, and secure search
router.get('/search', authenticateToken, authorizeRole(['merchant', 'admin', 'finance']), paymentLimiter, async (req, res) => {
  const { merchantId, startDate, endDate } = req.query;
  
  // Validate merchant ownership for non-admin users
  if (req.user.role === 'merchant' && req.user.merchantId !== parseInt(merchantId)) {
    return res.status(403).json({ error: 'Access denied: Cannot view transactions for other merchants' });
  }

  // Input validation
  if (!merchantId || !startDate || !endDate) {
    return res.status(400).json({ error: 'Missing required query parameters' });
  }

  const connection = await mysql.createConnection(config.database);
  
  try {
    // FIXED: Use parameterized query to prevent SQL injection
    const query = 'SELECT id, last_four, amount, currency, merchant_id, status, created_at FROM transactions WHERE merchant_id = ? AND created_at BETWEEN ? AND ?';
    const [rows] = await connection.execute(query, [merchantId, startDate, endDate]);
    
    // Audit log the search operation
    await auditLog(connection, 'PAYMENT_SEARCH', req.user.id, {
      merchantId,
      startDate,
      endDate,
      resultCount: rows.length,
      userRole: req.user.role
    });
    
    res.json({ transactions: rows });
  } catch (error) {
    console.error('Search error:', error);
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